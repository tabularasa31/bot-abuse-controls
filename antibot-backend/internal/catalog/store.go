// Store — the atomic holder of *Data plus the deterministic assembler of snapshots
// for the HTTP response. Reads are lock-free through atomic.Pointer; writes (Replace)
// are sequential and replace the pointer wholesale — a read never sees a partial update
// across catalogs.
//
// A snapshot is assembled on every read: at ~12 req/s (config-distribution
// §Channel C / Load) caching to save a hash buys nothing, and an ETag cache
// would add invalidation.
//
// A deterministic payload is needed for ETag stability and rests on two
// invariants:
//   - every slice in Data is sorted by Normalize() on input (once per
//     load, not per request — see review);
//   - every map is serialised through json.Marshal — encoding/json
//     documentedly writes map keys in lexicographic order.

package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync/atomic"
)

// Snapshot — what we serve in the HTTP response. The body is already serialised, and the etag
// is computed over it — deterministically for the same Data+site.
type Snapshot struct {
	Body    []byte
	ETag    string
	Version string
}

// Store — read-mostly storage. It is created with empty catalogs and
// Version=defaultVersion ("0.0.0"); with that version the server answers 503
// until Replace puts a real snapshot in — otherwise the edge would be stuck on empty
// data while seeing a "successful" 200 (see server.handle).
type Store struct {
	data atomic.Pointer[Data]
	// loaded — a separate "data was put in at least once" signal rather than comparing
	// Version with defaultVersion. Otherwise an operator who legitimately sets
	// `version: "0.0.0"` in the YAML (a bootstrap or pre-release) would get a 503
	// forever — the handler could not tell "not loaded yet" from "we loaded
	// data carrying that version" (a follow-up from review).
	loaded atomic.Bool
}

func NewStore() *Store {
	s := &Store{}
	s.data.Store(emptyData())
	return s
}

// Replace swaps the data wholesale. It is safe from any number of goroutines (though in the
// real topology there is one writer — the YAML reloader / the B4 DB poller).
// It normalises d before publishing: it sorts every slice and deduplicates ASNs,
// so that the build* functions on the hot path simply read an already-prepared array.
func (s *Store) Replace(d *Data) {
	if d == nil {
		d = emptyData()
	}
	normalize(d)
	s.data.Store(d)
	s.loaded.Store(true)
}

// HasVerifiedBotIP — whether there is a record (verified OR rejected) for an IP in the
// verified_bot_ips catalog. The rDNS worker (B7) uses it so as
// not to touch DNS again — no record means we have not checked yet
// (provisional on the edge); any status means we already know the verdict
// within the TTL and there is no point rechecking.
//
// Lock-free: data.Load() is atomic, a map[string]string is replaced
// wholesale by Replace, and reading without locks is safe.
func (s *Store) HasVerifiedBotIP(ip string) bool {
	d := s.data.Load()
	if d == nil {
		return false
	}
	_, ok := d.VerifiedBotIPs[ip]
	return ok
}

// IsLoaded returns true once Replace has been called at least once.
// The handler decides 200 versus 503 by it — not by comparing Version with a defensive
// sentinel, so as not to fail on a legitimate version: "0.0.0".
func (s *Store) IsLoaded() bool { return s.loaded.Load() }

// Snapshot assembles the payload for (catalog, site). err != nil for an unknown
// catalog name or a serialisation error; the handler separates 404 from 500.
//
// site="" means the global payload (for catalogs where per-tenant does not apply, the
// payload is identical to a request with any site).
func (s *Store) Snapshot(catalog, site string) (Snapshot, error) {
	d := s.data.Load()
	if d == nil {
		// Should never happen — emptyData is set in NewStore. A guard against
		// somebody trying to push a nil into the atomic.Pointer.
		d = emptyData()
	}

	var (
		body []byte
		err  error
	)
	switch catalog {
	case "tls_fp_blocklist":
		body, err = buildTLSFPBlocklist(d)
	case "ua_blacklist":
		body, err = buildUABlacklist(d, site)
	case "ip_blocklist":
		body, err = buildIPBlocklist(d, site)
	case "ip_whitelist":
		body, err = buildIPWhitelist(d, site)
	case "asn_datacenters":
		body = buildASNDatacenters(d) // assembled by hand for numeric sorting; no errors
	case "tls_fp_catalog":
		body, err = buildTLSFPCatalog(d)
	case "tls_fp_browser_profiles":
		body, err = buildTLSFPBrowserProfiles(d)
	case "verified_bot_ips":
		body, err = jsonBytes(d.VerifiedBotIPs)
	case "policy":
		body, err = buildPolicy(d, site)
	case "attack_mode":
		body, err = buildAttackMode(d, site)
	default:
		return Snapshot{}, errUnknownCatalog{name: catalog}
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("build %s: %w", catalog, err)
	}

	sum := sha256.Sum256(body)
	// A strong ETag (no weak W/) — the payload is assembled deterministically, so byte
	// equality means semantic equality and there are no whitespace differences.
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	return Snapshot{Body: body, ETag: etag, Version: d.Version}, nil
}

// errUnknownCatalog separates 404 (a name outside the list) from 500 (serialisation
// failed): the handler checks errors.As, so as not to emit a 500 on a typo in the URL.
type errUnknownCatalog struct{ name string }

func (e errUnknownCatalog) Error() string { return "unknown catalog: " + e.name }

// ----- builders -------------------------------------------------------------
//
// Every builder must be deterministic in the content of Data+site —
// otherwise the ETag would "jitter" on every request and If-None-Match would break.

// buildUABlacklist returns the JSON object `{"active": "<combined-regex>",
// "staging": ["<pattern>", …]}` (A11). The shape used to be a single combined-regex
// string (config-distribution.md §"The 'catalog' concept"); to deliver
// staging, the payload became an object. The wire-schema change is minor
// (X-Catalog-Version 1.2.0), and the edge parser is updated in the same change.
//
//   - active  — the combined regex (the global UABlacklist plus, when a site is given,
//     the per-resource policy[site].UABlacklist). The edge compiles it once per swap
//     and emits verdict=block on a match.
//   - staging — the LIST of individual system staging patterns (not combined):
//     the edge matches each one separately in order to record a staging_match with the specific
//     pattern_id (`ua_blacklist:<pattern>`); a combined string would lose which
//     pattern actually fired. A per-resource policy is runtime state, and staged
//     rollout does not apply to it, so staging holds system patterns only.
//
// Every pattern is validated in Validate through regexp.Compile, so only
// syntactically correct RE2 reaches the payload.
func buildUABlacklist(d *Data, site string) ([]byte, error) {
	// The slices are already sorted by normalize(). We simply concatenate — the order
	// "system, then per-resource" is fixed: if we change it, remember
	// X-Catalog-Version major.
	active := make([]string, 0, len(d.UABlacklist)+4)
	active = append(active, d.UABlacklist...)
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			active = append(active, p.UABlacklist...)
		}
	}
	staging := d.UABlacklistStaging
	if staging == nil {
		staging = []string{}
	}
	out := struct {
		Active  string   `json:"active"`
		Staging []string `json:"staging"`
	}{
		Active:  combineRegex(active),
		Staging: staging,
	}
	return jsonBytes(out)
}

// combineRegex joins the patterns into one alternation `(?:p1)|(?:p2)|…`.
// A non-capturing group: we need no $1/$2 on the edge, but the alternation must
// bind to one pattern rather than to an arbitrary `|` inside it. An empty input
// → "" (the edge treats an empty string as "no patterns").
func combineRegex(patterns []string) string {
	var combined string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if combined != "" {
			combined += "|"
		}
		combined += "(?:" + p + ")"
	}
	return combined
}

// buildTLSFPBlocklist encodes every record as "<status>:block" (A11),
// symmetrically with tls_fp_catalog / verified_bot_ips: the edge's shared_dict stores a
// ready string with no per-entry JSON parsing. The verdict for this catalog is
// always block; the status separates active (the edge emits verdict=block) from staging
// (the edge writes staging_match and does not block). The edge parses by splitting on the first `:`.
func buildTLSFPBlocklist(d *Data) ([]byte, error) {
	out := make(map[string]string, len(d.TLSFPBlocklist))
	for fp, status := range d.TLSFPBlocklist {
		out[fp] = status + ":block"
	}
	return jsonBytes(out)
}

func buildIPBlocklist(d *Data, site string) ([]byte, error) {
	// The system ip_blocklist plus the per-resource policy[site].IPBlocklist. The edge
	// tells the source apart through rule_source in a separate log mapping — here we
	// simply merge them; the payload contract is `{cidr: "<status>:block"}` (A11):
	// the status separates active (verdict=block) from staging (staging_match with no
	// block). System records carry their own status; per-resource ones are always
	// active (a policy is runtime state and staged rollout does not apply to it).
	out := make(map[string]string, len(d.IPBlocklist)+4)
	for cidr, status := range d.IPBlocklist {
		out[cidr] = status + ":block"
	}
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			for _, cidr := range p.IPBlocklist {
				out[cidr] = "active:block"
			}
		}
	}
	return jsonBytes(out)
}

func buildIPWhitelist(d *Data, site string) ([]byte, error) {
	// System plus per-resource. Deduplicated through a set: both sources may
	// independently hold the same CIDR (a corporate subnet, say).
	if site == "" {
		return jsonBytes(d.IPWhitelist)
	}
	p, ok := d.Policy[site]
	if !ok || len(p.IPWhitelist) == 0 {
		return jsonBytes(d.IPWhitelist)
	}
	seen := make(map[string]struct{}, len(d.IPWhitelist)+len(p.IPWhitelist))
	merged := make([]string, 0, len(d.IPWhitelist)+len(p.IPWhitelist))
	for _, c := range d.IPWhitelist {
		if _, dup := seen[c]; !dup {
			seen[c] = struct{}{}
			merged = append(merged, c)
		}
	}
	for _, c := range p.IPWhitelist {
		if _, dup := seen[c]; !dup {
			seen[c] = struct{}{}
			merged = append(merged, c)
		}
	}
	sort.Strings(merged) // both branches are already sorted by normalize, but the merge breaks the order
	return jsonBytes(merged)
}

// buildASNDatacenters writes the JSON object by hand: the keys are numbers, and
// json.Marshal(map[uint32]int) would emit them in lexicographic order
// ("10" < "2"), whereas the §C1 contract is numeric order (which reads better in diffs
// between catalog versions).
func buildASNDatacenters(d *Data) []byte {
	asns := d.ASNDatacenters // already sorted and deduped in normalize()
	buf := make([]byte, 0, len(asns)*16+2)
	buf = append(buf, '{')
	for i, asn := range asns {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, '"')
		buf = strconv.AppendUint(buf, uint64(asn), 10)
		buf = append(buf, '"', ':', '1')
	}
	buf = append(buf, '}')
	return buf
}

func buildPolicy(d *Data, site string) ([]byte, error) {
	if site != "" {
		// Per tenant: one host. A missing record means the B4 pool default
		// (mode=shadow, observe-only), not a 404 and not an empty Policy{} —
		// the edge must immediately see a valid mode and must not break on "" in the
		// mode switch. See PoolDefault and config-distribution.md
		// §"Per-resource lookup — keyed by Host".
		if p, ok := d.Policy[site]; ok {
			return jsonBytes(p)
		}
		return jsonBytes(PoolDefault())
	}
	// Without a site — the full map. In practice the edge always calls with a site (it knows
	// $host), but the contract keeps the lookup mode for the dashboard [B10] and for audits.
	return jsonBytes(d.Policy)
}

// buildTLSFPCatalog puts each record into the payload as the composite string
// `<status>:<family>` — symmetrically with verified_bot_ips ("<status>:<family>"),
// so that the edge's shared_dict stores a ready value with no per-entry JSON
// parsing. The edge splits on the first `:` and decides active versus staging
// with its own logic (build_catalog in tls_fp.lua returns an (active, staging) tuple).
func buildTLSFPCatalog(d *Data) ([]byte, error) {
	out := make(map[string]string, len(d.TLSFPCatalog))
	for hb, entry := range d.TLSFPCatalog {
		out[hb] = entry.Status + ":" + entry.Family
	}
	return jsonBytes(out)
}

// buildTLSFPBrowserProfiles — the same composite encoding, but the second
// position is a number (a decimal string). The edge compares cipher_count numerically,
// hence the tonumber on the Lua side.
func buildTLSFPBrowserProfiles(d *Data) ([]byte, error) {
	out := make(map[string]string, len(d.TLSFPBrowserProfiles))
	for family, prof := range d.TLSFPBrowserProfiles {
		out[family] = prof.Status + ":" + strconv.Itoa(prof.ExpectedCipherCnt)
	}
	return jsonBytes(out)
}

func buildAttackMode(d *Data, site string) ([]byte, error) {
	// A single source of truth: policy[host].AttackMode. The duplicating top-level
	// map is gone — two sources created a split brain (an OR merge made it impossible
	// to switch the flag off through one source while it remained set in the other).
	// An emergency override from B10 must go the SAME way (by writing Policy),
	// so that the behaviour is observable through one catalog.
	if site != "" {
		on := false
		if p, ok := d.Policy[site]; ok {
			on = p.AttackMode
		}
		return jsonBytes(map[string]bool{"on": on})
	}
	// Without a site — the full host→on map. We include an explicit false too: the dashboard
	// must see "managed but off" separately from "not configured".
	out := make(map[string]bool, len(d.Policy))
	for h, p := range d.Policy {
		out[h] = p.AttackMode
	}
	return jsonBytes(out)
}

// jsonBytes — a wrapper over json.Marshal, so that calling code stays
// uniform. It does not panic on an error: the builders return it upwards and the
// handler answers 500 — which is better than killing the process because of our own
// unexpected structure (from review: an error path, not a panic).
func jsonBytes(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	return b, nil
}
