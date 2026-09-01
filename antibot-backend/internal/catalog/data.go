// Typed data for the eight Channel C catalogs the backend serves to the
// edges, per the contract in docs/architecture/config-distribution.md
// (§"The 'catalog' concept"). Only the in-memory representation and the YAML
// loader live here; HTTP delivery is in server.go and snapshot assembly in store.go.
//
// Per-resource data (`policy`, custom UA patterns, attack_mode) lives
// in map[host]Policy; the shared lists are flat structures. Per the config-
// distribution decision, the per-resource key is `host`, not `cdn_resource_id`.
package catalog

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
)

// defaultVersion — the semver Store serves before the first load. It also
// goes into X-Catalog-Version (the header is always set — the §C1 contract).
// "0.0.0" in semver means "pre-release / empty"; the edge can rely on a
// change of the major segment to detect a breaking change in the payload schema.
const defaultVersion = "0.0.0"

// Data — a snapshot of the whole catalog store. It changes atomically as a whole through
// Store.Replace; references to an old *Data stay correct for the duration of a read, and there are no
// partial updates across catalogs.
type Data struct {
	// Version — the semver placed into X-Catalog-Version on every response.
	// It is changed by hand or by the dashboard, not generated: the edge needs to distinguish
	// "the same schema, new content" (only the ETag changes) from "a new schema"
	// (the parser needs updating). Content freshness is the ETag's job, not Version's.
	Version string `yaml:"version"`

	TLSFPBlocklist       map[string]string         `yaml:"tls_fp_blocklist"`        // fp → status (active|staging); wire format "<status>:block" (A11)
	UABlacklist          []string                  `yaml:"ua_blacklist"`            // the active global regex patterns
	UABlacklistStaging   []string                  `yaml:"-"`                       // staging patterns (A11): a separate combined regex; the edge writes staging_match and does not block
	IPBlocklist          map[string]string         `yaml:"ip_blocklist"`            // CIDR → status (active|staging); wire format "<status>:block" (A11)
	IPWhitelist          []string                  `yaml:"ip_whitelist"`            // CIDR (the system one)
	ASNDatacenters       []uint32                  `yaml:"asn_datacenters"`         // ASN numbers
	TLSFPCatalog         map[string]TLSFPCatalog   `yaml:"tls_fp_catalog"`          // hash_b → { family, status }; the tls_fp_impersonator rule
	TLSFPBrowserProfiles map[string]BrowserProfile `yaml:"tls_fp_browser_profiles"` // family → { expected_cipher_cnt, status }; the tls_fp_suspicious_ciphers rule
	VerifiedBotIPs       map[string]string         `yaml:"verified_bot_ips"`        // IP → "<status>:<family>" where status ∈ {verified, rejected}, family ∈ {google, bing, yandex, ddg}. A missing key means provisional (see vision §Stage 2.2).
	Policy               map[string]Policy         `yaml:"policy"`                  // host → policy (including attack_mode)
}

// TLSFPCatalog — one entry of the automation signature catalog (Phase 2+).
// Used by the tls_fp_impersonator rule in [tls_fp.lua].
//
// The Channel C wire format of the payload is `<status>:<family>` (symmetric with
// verified_bot_ips, so that the edge's shared_dict stores strings with no per-entry
// JSON parsing). See buildTLSFPCatalog in store.go.
type TLSFPCatalog struct {
	Family string `yaml:"family" json:"family"`
	Status string `yaml:"status" json:"status"` // active | staging
}

// BrowserProfile — the expected cipher_cnt for a browser family (Phase 2+).
// Used by the tls_fp_suspicious_ciphers rule.
//
// The wire format is `<status>:<expected_cipher_cnt>` (the number as a decimal string).
type BrowserProfile struct {
	ExpectedCipherCnt int    `yaml:"expected_cipher_cnt" json:"expected_cipher_cnt"`
	Status            string `yaml:"status" json:"status"` // active | staging
}

// Policy — the per-resource settings of one host. NO field carries omitempty:
// the `/catalog/policy?site=…` contract promises map(host → policy json) with a
// predictable shape; a consumer (the dashboard or the edge) must see "field = zero"
// and "field absent" identically, without distinguishing them. If a field appears later,
// we will give it its own major Version bump.
type Policy struct {
	Mode         string     `yaml:"mode" json:"mode"`                   // shadow / active
	Strictness   string     `yaml:"strictness" json:"strictness"`       // standard / permissive
	UABlacklist  []string   `yaml:"ua_blacklist" json:"ua_blacklist"`   // the customer's custom regexes
	IPWhitelist  []string   `yaml:"ip_whitelist" json:"ip_whitelist"`   // per-resource allow CIDR
	IPBlocklist  []string   `yaml:"ip_blocklist" json:"ip_blocklist"`   // per-resource deny CIDR
	ASNBlock     []uint32   `yaml:"asn_block" json:"asn_block"`         // per-resource deny ASN
	GeoWhitelist []string   `yaml:"geo_whitelist" json:"geo_whitelist"` // when set, everything else is blocked
	RateRules    []RateRule `yaml:"rate_rules" json:"rate_rules"`       // the customer's per-path rate rules
	AttackMode   bool       `yaml:"attack_mode" json:"attack_mode"`     // the only source; the map above is gone
	OriginIP     string     `yaml:"origin_ip" json:"origin_ip"`         // the backend's bare IPv4/IPv6 for multi-tenant routing; "" means a non-proxied tenant
}

// RateRule — one customer rate rule from docs/product/config-templates.md
// §"policy/<host>.yaml". On the stand, Lua does not read this field yet (edge B11);
// the backend stores and serves it as-is for the dashboard [B10] and for future phases.
type RateRule struct {
	Path    string   `yaml:"path" json:"path"`
	Methods []string `yaml:"methods" json:"methods"`
	RPS     int      `yaml:"rps" json:"rps"`
	Burst   int      `yaml:"burst" json:"burst"`
	Action  string   `yaml:"action" json:"action"` // block | challenge | log_only
}

// SlowData — the catalog layer product maintains through PRs to the
// catalogs/ git repo. Per ADR-006 it is the single source of truth for the slow
// catalogs; the database is no longer used for them. It is parsed from the YAML files
// by the filesource package and merged into *Data on every reloader tick.
//
// The catalog version (for X-Catalog-Version) comes from the catalogs/version file
// and is stored here: it is part of the "config" rather than runtime state.
type SlowData struct {
	Version              string
	TLSFPBlocklist       map[string]string // fp → status (active|staging)
	UABlacklist          []string          // the active patterns
	UABlacklistStaging   []string          // the staging patterns (A11)
	IPBlocklist          map[string]string // CIDR → status (active|staging)
	IPWhitelist          []string
	ASNDatacenters       []uint32
	TLSFPCatalog         map[string]TLSFPCatalog
	TLSFPBrowserProfiles map[string]BrowserProfile
}

// RuntimeData — the layer of runtime state written by the backend's other
// subsystems: policy through antibotapi (the dashboard), verified_bot_ips through the
// rDNS worker. This is NOT config — the data changes automatically, SLA ≤ 30 s.
// It stays in the database (see ADR-005 §Variant 3 rejected — files do not
// suit its cadence).
type RuntimeData struct {
	VerifiedBotIPs map[string]string
	Policy         map[string]Policy
}

// Merge assembles a *Data from the two partial snapshots. It accepts nil pointers
// (as a stand-in for "the layer has not loaded yet") and returns a correct *Data
// with empty collections instead of a panic — the handler above answers 503 by
// IsLoaded when both layers are empty at startup.
//
// The catalog version comes from SlowData (which also holds the version file). If
// SlowData == nil we set defaultVersion — semantically "we have not read it
// yet", the same signal as in emptyData().
func Merge(s *SlowData, r *RuntimeData) *Data {
	d := &Data{
		Version:              defaultVersion,
		TLSFPBlocklist:       map[string]string{},
		IPBlocklist:          map[string]string{},
		TLSFPCatalog:         map[string]TLSFPCatalog{},
		TLSFPBrowserProfiles: map[string]BrowserProfile{},
		VerifiedBotIPs:       map[string]string{},
		Policy:               map[string]Policy{},
	}
	if s != nil {
		if s.Version != "" {
			d.Version = s.Version
		}
		if s.TLSFPBlocklist != nil {
			d.TLSFPBlocklist = s.TLSFPBlocklist
		}
		d.UABlacklist = s.UABlacklist
		d.UABlacklistStaging = s.UABlacklistStaging
		if s.IPBlocklist != nil {
			d.IPBlocklist = s.IPBlocklist
		}
		d.IPWhitelist = s.IPWhitelist
		d.ASNDatacenters = s.ASNDatacenters
		if s.TLSFPCatalog != nil {
			d.TLSFPCatalog = s.TLSFPCatalog
		}
		if s.TLSFPBrowserProfiles != nil {
			d.TLSFPBrowserProfiles = s.TLSFPBrowserProfiles
		}
	}
	if r != nil {
		if r.VerifiedBotIPs != nil {
			d.VerifiedBotIPs = r.VerifiedBotIPs
		}
		if r.Policy != nil {
			d.Policy = r.Policy
		}
	}
	return d
}

// PoolDefault — what is served for an unregistered host:
// "a new domain with no record → the pool default (mode=shadow, observe-only)"
// (config-distribution §"Per-resource lookup", task B4). It is implemented
// as a function rather than a global variable: every call yields a fresh
// nil-zero slice — so no caller can accidentally mutate a
// shared object.
func PoolDefault() Policy {
	return Policy{
		Mode:         "shadow",
		Strictness:   "standard",
		UABlacklist:  []string{},
		IPWhitelist:  []string{},
		IPBlocklist:  []string{},
		ASNBlock:     []uint32{},
		GeoWhitelist: []string{},
		RateRules:    []RateRule{},
	}
}

// emptyData — a deterministic zero for Store before the first Replace.
// Version=defaultVersion (not ""), so that X-Catalog-Version is a valid
// semver even on an empty instance — the edge must not have to distinguish "header
// present" from "header absent" on the wire.
func emptyData() *Data {
	return &Data{
		Version:              defaultVersion,
		TLSFPBlocklist:       map[string]string{},
		UABlacklist:          nil,
		IPBlocklist:          map[string]string{},
		IPWhitelist:          nil,
		ASNDatacenters:       nil,
		TLSFPCatalog:         map[string]TLSFPCatalog{},
		TLSFPBrowserProfiles: map[string]BrowserProfile{},
		VerifiedBotIPs:       map[string]string{},
		Policy:               map[string]Policy{},
	}
}

// normalize brings Data into canonical form: it sorts every slice and
// deduplicates them (for a deterministic payload and a stable ETag —
// two identical records must not inflate the combined regex and must not
// produce a different ETag from a single record).
//
// Called from Store.Replace on every merge (filesource plus dbloader).
// Idempotent.
func normalize(d *Data) {
	// The system slices: dedup+sort plus a nil coercion. Without ensure*, json.Marshal
	// would emit `null` on an empty database (the DB loader does not initialise empty
	// slices — the append loop is empty), and the ETag would drift between "there were never
	// any records" and "there was one and it was deleted". From review (a follow-up).
	d.UABlacklist = ensureStringSlice(dedupSortStrings(d.UABlacklist))
	d.UABlacklistStaging = ensureStringSlice(dedupSortStrings(d.UABlacklistStaging))
	d.IPWhitelist = ensureStringSlice(dedupSortStrings(d.IPWhitelist))
	d.ASNDatacenters = ensureUint32Slice(dedupSortUint32(d.ASNDatacenters))
	for h, p := range d.Policy {
		// Every []T field: dedup+sort, then nil → an empty slice. The nil →
		// `[]T{}` coercion is critical for JSON stability: an operator writing
		// `ua_blacklist = 'null'::jsonb` through the DB loader arrives as a
		// nil slice; json.Marshal serialises it as `null`, and the ETag differs
		// from the logically equivalent record with an empty array and from
		// `PoolDefault()`. This closes the review point.
		p.UABlacklist = ensureStringSlice(dedupSortStrings(p.UABlacklist))
		p.IPWhitelist = ensureStringSlice(dedupSortStrings(p.IPWhitelist))
		p.IPBlocklist = ensureStringSlice(dedupSortStrings(p.IPBlocklist))
		p.GeoWhitelist = ensureStringSlice(dedupSortStrings(p.GeoWhitelist))
		p.ASNBlock = ensureUint32Slice(dedupSortUint32(p.ASNBlock))
		// RateRules — the order is set by the operator (rule priority), so it
		// must not be sorted; we do not deduplicate either (two identical
		// records may be a deliberate repeat).
		if p.RateRules == nil {
			p.RateRules = []RateRule{}
		}
		d.Policy[h] = p
	}
}

func ensureStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func ensureUint32Slice(s []uint32) []uint32 {
	if s == nil {
		return []uint32{}
	}
	return s
}

func dedupSortStrings(s []string) []string {
	if len(s) < 2 {
		return s
	}
	sort.Strings(s)
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func dedupSortUint32(s []uint32) []uint32 {
	if len(s) < 2 {
		return s
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// Validate checks:
//   - UA regexes (system and per host) through regexp.Compile;
//   - CIDR strings (the system ip_blocklist / ip_whitelist and the per-host
//     variants) through `ValidateCIDR`, which mirrors the tolerance of
//     lua-resty-ipmatcher: a bare IP with no `/N` is accepted as a host route
//     (/32 for v4, /128 for v6), and a CIDR with host bits set
//     (`10.0.0.5/8`) is valid too, since ipmatcher masks them anyway.
//
// Regexes: the RE2 grammar — not PCRE, but the edge is on ngx.re (PCRE) with a common
// subset; syntax errors (`bot[a-z`, an unbalanced `(`, a
// trailing `\`) are caught identically. If the edge ever wants a PCRE-specific feature
// (lookarounds), it must be gated separately in the spec.
//
// CIDR: migration 0001 does NOT hold `inet` columns (the schema comment says
// "validation lives in the loader" — review closed that promise).
// The validation is deliberately symmetric with the edge: otherwise the backend would be stricter,
// and an operator inserting `203.0.113.5` without a `/32` would hit fail-stale
// even though ipmatcher would have accepted the record.
//
// It is exported so that any source of *Data (LoadYAML, dbloader.Load, a
// future B10 admin API) is obliged to call it before Store.Replace —
// fail-stale only works if a broken pattern is caught BEFORE publication.
func Validate(d *Data) error {
	for i, p := range d.UABlacklist {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("ua_blacklist[%d]: invalid regex %q: %w", i, p, err)
		}
	}
	// Staging patterns are validated by the same predicate as active ones (A11): they
	// travel in a separate combined regex and are compiled on the edge the same way, so a
	// broken staging regex must fail the Load before publication rather than later.
	for i, p := range d.UABlacklistStaging {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("ua_blacklist(staging)[%d]: invalid regex %q: %w", i, p, err)
		}
	}
	for cidr := range d.IPBlocklist {
		if err := ValidateCIDR(cidr); err != nil {
			return fmt.Errorf("ip_blocklist[%q]: %w", cidr, err)
		}
	}
	for i, cidr := range d.IPWhitelist {
		if err := ValidateCIDR(cidr); err != nil {
			return fmt.Errorf("ip_whitelist[%d] %q: %w", i, cidr, err)
		}
	}
	for host, pol := range d.Policy {
		for i, p := range pol.UABlacklist {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("policy[%s].ua_blacklist[%d]: invalid regex %q: %w", host, i, p, err)
			}
		}
		for i, cidr := range pol.IPBlocklist {
			if err := ValidateCIDR(cidr); err != nil {
				return fmt.Errorf("policy[%s].ip_blocklist[%d] %q: %w", host, i, cidr, err)
			}
		}
		for i, cidr := range pol.IPWhitelist {
			if err := ValidateCIDR(cidr); err != nil {
				return fmt.Errorf("policy[%s].ip_whitelist[%d] %q: %w", host, i, cidr, err)
			}
		}
		if err := ValidateOriginIP(pol.OriginIP); err != nil {
			return fmt.Errorf("policy[%s].origin_ip %q: %w", host, pol.OriginIP, err)
		}
	}
	// tls_fp_catalog (Phase 2+, ADR-006): hash_b → {family, status}. Family
	// must be non-empty (on the edge it goes into attrs.family for is_impersonator);
	// status is active | staging. A broken status or an empty family is caught here
	// before Store.Replace, otherwise the edge would hash pending deductions.
	for hb, entry := range d.TLSFPCatalog {
		if hb == "" {
			return fmt.Errorf("tls_fp_catalog: empty hash_b key")
		}
		if entry.Family == "" {
			return fmt.Errorf("tls_fp_catalog[%q]: empty family", hb)
		}
		if !isValidEntryStatus(entry.Status) {
			return fmt.Errorf("tls_fp_catalog[%q]: invalid status %q (expected active | staging)", hb, entry.Status)
		}
	}
	// tls_fp_browser_profiles (Phase 2+): family → {expected_cipher_cnt, status}.
	// expected_cipher_cnt > 0 is mandatory for ALL entries (active AND staging).
	// From re-audit: it must not be relaxed for staging — the edge's build_profiles
	// filters `if n and n > 0` symmetrically out of defence in depth, and a record
	// with staging:0 silently disappears from the edge in BOTH the active and staging tables →
	// staging_match never fires and the promotion workflow breaks.
	// If product wants to "register a family in advance", they must SIMULTANEOUSLY
	// set a sensible initial cipher_cnt; recalibrating is a separate PR.
	for family, prof := range d.TLSFPBrowserProfiles {
		if family == "" {
			return fmt.Errorf("tls_fp_browser_profiles: empty family key")
		}
		if !isValidEntryStatus(prof.Status) {
			return fmt.Errorf("tls_fp_browser_profiles[%q]: invalid status %q (expected active | staging)", family, prof.Status)
		}
		if prof.ExpectedCipherCnt <= 0 {
			return fmt.Errorf("tls_fp_browser_profiles[%q]: expected_cipher_cnt must be > 0 (got %d) — edge filters non-positive in both active and staging tables, entry would be invisible", family, prof.ExpectedCipherCnt)
		}
	}
	return nil
}

// isValidEntryStatus — the shared predicate for a slow-catalog entry status with
// staged rollout support (see catalogs/README.md, A11). Symmetric with the
// CHECK constraint that lived in migration 0001 before ADR-006.
func isValidEntryStatus(s string) bool {
	return s == "active" || s == "staging"
}

// ValidateCIDR accepts either a "raw" IP ("1.2.3.4", "2001:db8::1")
// or a prefix ("10.0.0.0/8", or "10.0.0.5/8" with host bits set).
// This is symmetric with lua-resty-ipmatcher on the edge: it accepts the same
// subset and masks the host bits itself. netip.ParsePrefix is stricter than
// netip.ParseAddr, so we try both. It is exported for
// reuse in [internal/antibotapi] (B10): an admin mutation must
// validate its input with the same predicate as the reloader, otherwise any record
// from the dashboard would break the reloader's next tick through catalog.Validate.
func ValidateCIDR(s string) error {
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP/CIDR")
}

// ValidateOriginIP accepts an empty string (the tenant is not proxied / the field was
// cleared) or a SINGLE bare address (IPv4 or IPv6) — unlike
// ValidateCIDR, prefixes are forbidden here: origin_ip is the network
// destination of one backend, not a subnet. The edge substitutes this value
// into the proxy_pass URL (origin_resolve), where a CIDR is meaningless. It is exported
// for reuse in [internal/antibotapi]: an admin mutation validates with
// the same predicate as the reloader through Validate, otherwise a record from
// the dashboard would break the reloader's next tick.
func ValidateOriginIP(s string) error {
	if s == "" {
		return nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("must be a bare IPv4/IPv6 address (no prefix)")
	}
	// Reject a zone-scoped address (`fe80::1%eth0`): netip.ParseAddr accepts
	// it, but the `%` is a non-routable scope id AND it would be treated as a
	// Lua gsub replacement escape when origin_resolve.resolve() builds the
	// proxy URL, corrupting the upstream for that tenant (codex P2 on PR #94).
	if addr.Zone() != "" {
		return fmt.Errorf("must not carry an IPv6 zone (got %q)", s)
	}
	// origin_ip is used verbatim as a proxy_pass destination, so reject
	// addresses that can't be a real tenant backend and would instead point
	// the edge at itself or at infrastructure:
	//   - unspecified (0.0.0.0, ::) — silent connect failure, no real target
	//   - loopback (127.0.0.0/8, ::1) — the edge proxying to itself
	//   - link-local (169.254.0.0/16, fe80::/10) — incl. 169.254.169.254
	//     cloud metadata (SSRF-style misroute)
	//   - multicast — not a unicast backend
	// Private/global unicast stay allowed: a tenant origin may legitimately
	// be a private IP (gemini/codex review on PR #94). Operators set this via
	// the authenticated dashboard, but validating here is cheap defence.
	switch {
	case addr.IsUnspecified():
		return fmt.Errorf("must not be the unspecified address (got %q)", s)
	case addr.IsLoopback():
		return fmt.Errorf("must not be a loopback address (got %q)", s)
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return fmt.Errorf("must not be a link-local address (got %q)", s)
	case addr.IsMulticast() || addr.IsInterfaceLocalMulticast():
		return fmt.Errorf("must not be a multicast address (got %q)", s)
	}
	return nil
}
