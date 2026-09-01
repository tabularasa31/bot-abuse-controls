// Store holds the catalog data and assembles the payloads served over HTTP.
// Reads are lock-free; a write replaces the whole pointer, so a reader never
// sees a partially updated set of catalogs.
//
// A snapshot is assembled per read: at this request rate caching one would only
// buy an invalidation problem.
//
// Payloads must be byte-stable or the ETag would change on every request. That
// rests on slices being sorted once at load time and on maps being marshalled
// by encoding/json, which orders keys.

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

// Store starts empty, and the server answers 503 until real data arrives —
// otherwise the edge would take an empty catalog for a successful response.
type Store struct {
	data atomic.Pointer[Data]
	// A separate flag rather than comparing against the default version: an
	// operator may legitimately publish that version, and would then be stuck on
	// 503 forever.
	loaded atomic.Bool
}

func NewStore() *Store {
	s := &Store{}
	s.data.Store(emptyData())
	return s
}

// Replace swaps the data wholesale, normalising it first so the builders on the
// read path work from already-sorted input.
func (s *Store) Replace(d *Data) {
	if d == nil {
		d = emptyData()
	}
	normalize(d)
	s.data.Store(d)
	s.loaded.Store(true)
}

// HasVerifiedBotIP reports whether an IP has any verdict yet. The rDNS worker
// uses it to avoid resolving an address it has already decided about.
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

// Snapshot assembles the payload for one catalog. An empty site means the
// global payload.
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

// Every builder below must be deterministic, or the ETag would change on every
// request and conditional requests would stop working.

// buildUABlacklist returns the active patterns as one combined regex, and the
// staged ones as a list: the edge matches those individually, because a combined
// string would lose which pattern fired. Staged rollout does not apply to
// per-host policy, so staging carries system patterns only.
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

// combineRegex joins the patterns into one alternation. The groups are
// non-capturing but required: without them an alternation inside a pattern would
// bind wrongly.
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

// buildTLSFPBlocklist encodes each record as "<status>:block", so the edge can
// store a ready string with no per-entry JSON parsing.
func buildTLSFPBlocklist(d *Data) ([]byte, error) {
	out := make(map[string]string, len(d.TLSFPBlocklist))
	for fp, status := range d.TLSFPBlocklist {
		out[fp] = status + ":block"
	}
	return jsonBytes(out)
}

func buildIPBlocklist(d *Data, site string) ([]byte, error) {
	// System and per-host lists merge here. Per-host records are always active:
	// staged rollout does not apply to policy.
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

// buildASNDatacenters writes the object by hand: json.Marshal would order the
// numeric keys lexicographically, so "10" would precede "2".
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
		// A missing record yields the pool default, not a 404 or an empty
		// Policy: the edge must always see a valid mode.
		if p, ok := d.Policy[site]; ok {
			return jsonBytes(p)
		}
		return jsonBytes(PoolDefault())
	}
	// Without a site — the full map. In practice the edge always calls with a site (it knows
	// $host), but the contract keeps the lookup mode for the dashboard [B10] and for audits.
	return jsonBytes(d.Policy)
}

// buildTLSFPCatalog encodes each record as "<status>:<family>", so the edge can
// store a ready value with no per-entry JSON parsing. It splits on the first `:`
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
// unexpected structure — an error path, not a panic.
func jsonBytes(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	return b, nil
}
