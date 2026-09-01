// Typed data for the catalogs the backend serves to the edges. This file holds
// the in-memory representation and the loader; delivery and snapshot assembly
// live alongside it.
//
// Per-resource data is keyed by host rather than by a provider-side resource
// id, so the edge can look it up straight from the request.
package catalog

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
)

// What is served before the first load. The header is always set, so the edge
// never has to distinguish a missing one from an empty catalog.
const defaultVersion = "0.0.0"

// Data — a snapshot of the whole catalog store. It changes atomically as a whole through
// Store.Replace; references to an old *Data stay correct for the duration of a read, and there are no
// partial updates across catalogs.
type Data struct {
	// Deliberately hand-maintained rather than generated: it marks a schema
	// change, while content freshness is the ETag's job.
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

// TLSFPCatalog is one automation signature. It goes over the wire as
// "<status>:<family>", so the edge can store it without parsing JSON per entry.
type TLSFPCatalog struct {
	Family string `yaml:"family" json:"family"`
	Status string `yaml:"status" json:"status"` // active | staging
}

// BrowserProfile is the cipher count a browser family is expected to offer.
type BrowserProfile struct {
	ExpectedCipherCnt int    `yaml:"expected_cipher_cnt" json:"expected_cipher_cnt"`
	Status            string `yaml:"status" json:"status"` // active | staging
}

// Policy holds one host's settings. No field is omitempty: consumers rely on a
// predictable shape, where an absent field and a zero value read the same.
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

// SlowData is the layer product maintains through pull requests. The git repo
// is its only source of truth, and the version travels with it as config rather
// than as runtime state.
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

// RuntimeData is written by the system itself — policy by the dashboard,
// verified bots by the rDNS worker. It changes on its own and lives in the
// database, which files would not suit.
type RuntimeData struct {
	VerifiedBotIPs map[string]string
	Policy         map[string]Policy
}

// Merge combines the two layers. A nil layer means it has not loaded yet and
// yields empty collections rather than a panic; the handler answers 503 while
// both are empty.
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

// PoolDefault is what an unregistered host gets: observe-only. A function
// rather than a variable, so no caller can mutate a shared instance.
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

// emptyData is the deterministic zero value, carrying a valid version so the
// header is well-formed even on an empty instance.
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

// normalize sorts and deduplicates every slice, so the payload and its ETag are
// deterministic. Idempotent.
func normalize(d *Data) {
	// The nil coercion matters: json.Marshal writes `null` for a nil slice, so
	// the ETag would differ between "never had records" and "had one, deleted".
	d.UABlacklist = ensureStringSlice(dedupSortStrings(d.UABlacklist))
	d.UABlacklistStaging = ensureStringSlice(dedupSortStrings(d.UABlacklistStaging))
	d.IPWhitelist = ensureStringSlice(dedupSortStrings(d.IPWhitelist))
	d.ASNDatacenters = ensureUint32Slice(dedupSortUint32(d.ASNDatacenters))
	for h, p := range d.Policy {
		// Same coercion per field: a JSONB null arrives as a nil slice and would
		// serialise differently from the equivalent empty array.
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

// Validate compiles every UA regex and parses every CIDR.
//
// CIDR validation deliberately mirrors what the edge matcher accepts — a bare
// IP, or a prefix with host bits set — so the backend is never the stricter of
// the two and an operator cannot hit fail-stale on a record the edge would have
// taken.
//
// Exported so every source of *Data must call it before publishing: fail-stale
// only works if a broken pattern is caught first.
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
	// The family must be non-empty: the edge uses it for the impersonator rule.
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
// staged rollout support (see catalogs/README.md).
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
	// proxy URL, corrupting the upstream for that tenant.
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
	// be a private IP. Operators set this via
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
