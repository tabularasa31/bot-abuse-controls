// Package filesource — the catalogs git repo as the source of the slow
// Channel C catalogs (ADR-006).
//
// The contract matches what dbloader used to do for the slow
// tables: on every reloader tick, Load returns a *catalog.SlowData;
// the reloader merges it with the runtime part (verified_bot_ips, policy) from
// the database and publishes it into the Store. Regex/CIDR validation is the same as in dbloader:
// one broken record fails the whole Load (fail-stale) and the Store is left alone.
//
// The file layout:
//
//	<dir>/version                 — a singleton semver (text, one line).
//	<dir>/tls_fp_blocklist.yaml   — map(fp → "active"|"staging").
//	<dir>/ua_blacklist.yaml       — map(pattern → "active"|"staging").
//	<dir>/ip_blocklist.yaml       — map(cidr → "active"|"staging").
//	<dir>/ip_whitelist.yaml       — a sequence of cidr (no status).
//	<dir>/asn_datacenters.yaml    — a sequence of uint32 (no status).
//
// `status` for the catalogs supporting staged rollout (A11): both "active" and
// "staging" land in SlowData with the status preserved. Serialisation into Channel
// C carries the status in the payload ("<status>:block" for fp/ip; a separate staging
// combined regex for ua), and the edge separates active from staging itself: active →
// verdict=block, staging → staging_match with no block. (Staging used to be
// filtered out here — now it is delivered, see the build* functions in store.go.)
//
// An empty file, or one holding only comments, means an empty catalog. A missing file is
// an error (protection from a typo in the name).
package filesource

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
)

// The list of files we track for the mtime cache. When a new catalog is added,
// add it here and in Load().
var trackedFiles = []string{
	"version",
	"tls_fp_blocklist.yaml",
	"ua_blacklist.yaml",
	"ip_blocklist.yaml",
	"ip_whitelist.yaml",
	"asn_datacenters.yaml",
	"tls_fp_catalog.yaml",
	"tls_fp_browser_profiles.yaml",
}

// validStatuses — what counts as a valid status value. Any other
// value in a file fails the Load: symmetrically with the DB schema (CHECK (status IN
// ('active','staging'))).
var validStatuses = map[string]struct{}{
	"active":  {},
	"staging": {},
}

type Loader struct {
	dir    string
	mtimes map[string]time.Time
}

// New creates a Loader bound to the directory dir. dir need not yet
// exist at the time of New — the check is deferred to Load(), so that the
// constructor stays cheap and needs no error return.
func New(dir string) *Loader {
	return &Loader{
		dir:    dir,
		mtimes: map[string]time.Time{},
	}
}

// Dir returns the catalogs' root directory. Useful for logs and health checks.
func (l *Loader) Dir() string { return l.dir }

// Changed returns true when at least one file's mtime differs from the
// cached one, OR the cache is still empty (the first call). Reading the mtime does not
// raise an error — a missing file reaches Load as an explicit fail-stale there,
// the reloader sees the error, and the operator sees it in the logs plus reload_failures.
func (l *Loader) Changed() bool {
	if len(l.mtimes) == 0 {
		return true
	}
	for _, name := range trackedFiles {
		path := filepath.Join(l.dir, name)
		info, err := os.Stat(path)
		if err != nil {
			// The file vanished between ticks — that is a change; let Load
			// catch it and return an error (fail-stale with a visible cause).
			return true
		}
		if cached, ok := l.mtimes[name]; !ok || !info.ModTime().Equal(cached) {
			return true
		}
	}
	return false
}

// Load reads every catalog, validates it and returns a *catalog.SlowData with the
// active records. On any error (IO, parse, validate) it returns
// it — the caller (the reloader) does NOT touch the Store and the edge keeps working from the
// previous good payload. It updates the mtime cache only on success:
// a partial success (version was read but ua_blacklist failed) must not
// "lose" the change signal on the next tick.
//
// Blast radius (from audit): Load is atomic across the whole slow layer — one
// broken record in any of the 8 files fails the publication of ALL the slow catalogs
// (ua/ip/asn/fp/tls_fp_*) at once. The runtime layer (policy,
// verified_bot_ips) is NOT affected; dbloader.LoadRuntime is an independent
// path. That is deliberate: per-catalog loading would create a window of partial
// consistency where the ETags of different files change in a different order —
// the edge would see an old UA blacklist with a new IP blacklist, or the reverse.
// Better an explicit fail-stale: the operator sees `antibot_backend_catalog_reload_failures_total`
// plus a log error, fixes it in one PR, and on the edge everything stays in the last good
// state.
func (l *Loader) Load() (*catalog.SlowData, error) {
	mtimes := make(map[string]time.Time, len(trackedFiles))

	// version: a text file, not YAML. Trim — a trailing newline is acceptable.
	versionRaw, vmtime, err := readFile(l.dir, "version")
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	version := strings.TrimSpace(string(versionRaw))
	if version == "" {
		return nil, fmt.Errorf("version: file is empty (expected semver like \"1.0.0\")")
	}
	mtimes["version"] = vmtime

	slow := &catalog.SlowData{
		Version:              version,
		TLSFPBlocklist:       map[string]string{},
		IPBlocklist:          map[string]string{},
		UABlacklist:          []string{},
		UABlacklistStaging:   []string{},
		IPWhitelist:          []string{},
		ASNDatacenters:       []uint32{},
		TLSFPCatalog:         map[string]catalog.TLSFPCatalog{},
		TLSFPBrowserProfiles: map[string]catalog.BrowserProfile{},
	}

	// tls_fp_blocklist: map(fp → status). Both active and staging → fp: status
	// in SlowData (A11); the serialiser encodes "<status>:block" into the payload.
	if mt, err := loadStatusMap(l.dir, "tls_fp_blocklist.yaml", func(entries map[string]string) error {
		for fp, status := range entries {
			slow.TLSFPBlocklist[fp] = status
		}
		return nil
	}); err != nil {
		return nil, err
	} else {
		mtimes["tls_fp_blocklist.yaml"] = mt
	}

	// ua_blacklist: map(pattern → status). active → UABlacklist, staging →
	// UABlacklistStaging (A11); the serialiser emits two combined regexes.
	if mt, err := loadStatusMap(l.dir, "ua_blacklist.yaml", func(entries map[string]string) error {
		for pat, status := range entries {
			if status == "staging" {
				slow.UABlacklistStaging = append(slow.UABlacklistStaging, pat)
			} else {
				slow.UABlacklist = append(slow.UABlacklist, pat)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	} else {
		mtimes["ua_blacklist.yaml"] = mt
	}

	// ip_blocklist: map(cidr → status). Both active and staging → cidr: status
	// (A11); the serialiser encodes "<status>:block".
	if mt, err := loadStatusMap(l.dir, "ip_blocklist.yaml", func(entries map[string]string) error {
		for cidr, status := range entries {
			slow.IPBlocklist[cidr] = status
		}
		return nil
	}); err != nil {
		return nil, err
	} else {
		mtimes["ip_blocklist.yaml"] = mt
	}

	// ip_whitelist: a top-level sequence of strings (no status).
	wl, mt, err := loadStringSlice(l.dir, "ip_whitelist.yaml")
	if err != nil {
		return nil, err
	}
	slow.IPWhitelist = wl
	mtimes["ip_whitelist.yaml"] = mt

	// asn_datacenters: a top-level sequence of uint32 (no status).
	asns, mt, err := loadASNs(l.dir, "asn_datacenters.yaml")
	if err != nil {
		return nil, err
	}
	slow.ASNDatacenters = asns
	mtimes["asn_datacenters.yaml"] = mt

	// tls_fp_catalog: top-level map(hash_b → {family, status}). Validate
	// does the structural checks (a non-empty family, a valid status); here we
	// simply store the decodeYAML result.
	tlsCat, mt, err := loadTLSFPCatalog(l.dir, "tls_fp_catalog.yaml")
	if err != nil {
		return nil, err
	}
	slow.TLSFPCatalog = tlsCat
	mtimes["tls_fp_catalog.yaml"] = mt

	// tls_fp_browser_profiles: top-level map(family → {expected_cipher_cnt, status}).
	tlsProf, mt, err := loadBrowserProfiles(l.dir, "tls_fp_browser_profiles.yaml")
	if err != nil {
		return nil, err
	}
	slow.TLSFPBrowserProfiles = tlsProf
	mtimes["tls_fp_browser_profiles.yaml"] = mt

	// The final validation through catalog.Validate: regexes compile and
	// CIDRs parse symmetrically with ipmatcher. The same model as in
	// dbloader.Load: we fail before the Store ever sees a broken payload.
	// Merging with a nil runtime part means Validate checks only the slow layer
	// (Policy is empty → the per-host validation is skipped).
	if err := catalog.Validate(catalog.Merge(slow, nil)); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	// Applying the cache atomically. Up to this point the mtimes are a local map; so that a
	// partial failure (ip_whitelist read but asn failed) does not shift
	// l.mtimes, we update it wholesale on success.
	l.mtimes = mtimes
	return slow, nil
}

// readFile reads a file from dir and returns the bytes plus the mtime. A missing
// file is an error (protection from a typo in the name; an empty catalog must
// be represented by an empty file or one with only comments).
func readFile(dir, name string) ([]byte, time.Time, error) {
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("stat %s: %w", name, err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // the path is operator-controlled, not from a request
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read %s: %w", name, err)
	}
	return data, info.ModTime(), nil
}

// loadStatusMap reads a YAML file of the form map[string]string, validates the
// statuses and hands the WHOLE validated map (key → status) to the callback —
// both active and staging (A11): delivering staging is the serialiser's decision, not this
// loader's. An empty file or one with only comments → an empty map (the normal
// state, "the catalog is still empty").
//
// It returns the file's mtime so that the reloader can cache it, and an error
// when the YAML is broken, a key is not a string, or a status is unknown.
func loadStatusMap(dir, name string, apply func(entries map[string]string) error) (time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return time.Time{}, err
	}
	var m map[string]string
	if err := decodeYAML(data, &m, name); err != nil {
		return time.Time{}, err
	}
	for key, status := range m {
		if _, ok := validStatuses[status]; !ok {
			return time.Time{}, fmt.Errorf("%s: entry %q has invalid status %q (expected one of: active, staging)", name, key, status)
		}
	}
	if err := apply(m); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", name, err)
	}
	return mt, nil
}

// loadStringSlice reads a YAML file whose top level is a sequence of
// strings. An empty file → an empty slice.
func loadStringSlice(dir, name string) ([]string, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	var s []string
	if err := decodeYAML(data, &s, name); err != nil {
		return nil, time.Time{}, err
	}
	if s == nil {
		s = []string{}
	}
	return s, mt, nil
}

// loadTLSFPCatalog reads a YAML map(hash_b → {family, status}). An empty file or
// one with only comments means an empty catalog. The structural checks (a non-empty family,
// a valid status) are done by catalog.Validate at the next step of Load.
func loadTLSFPCatalog(dir, name string) (map[string]catalog.TLSFPCatalog, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	m := map[string]catalog.TLSFPCatalog{}
	if err := decodeYAML(data, &m, name); err != nil {
		return nil, time.Time{}, err
	}
	if m == nil {
		m = map[string]catalog.TLSFPCatalog{}
	}
	return m, mt, nil
}

// loadBrowserProfiles reads a YAML map(family → {expected_cipher_cnt, status}).
// Symmetric with loadTLSFPCatalog: the checks live in catalog.Validate.
func loadBrowserProfiles(dir, name string) (map[string]catalog.BrowserProfile, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	m := map[string]catalog.BrowserProfile{}
	if err := decodeYAML(data, &m, name); err != nil {
		return nil, time.Time{}, err
	}
	if m == nil {
		m = map[string]catalog.BrowserProfile{}
	}
	return m, mt, nil
}

// loadASNs reads a YAML file with a sequence of numbers and converts it to
// []uint32. Any integer is accepted; the bounds 0..2^32-1 come from ASNs being
// 32-bit (RFC 6793). Negative or above uint32 is an error (as in
// dbloader.loadUint32List).
func loadASNs(dir, name string) ([]uint32, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	var raw []int64
	if err := decodeYAML(data, &raw, name); err != nil {
		return nil, time.Time{}, err
	}
	out := make([]uint32, 0, len(raw))
	for _, n := range raw {
		if n < 0 || n > 0xFFFFFFFF {
			return nil, time.Time{}, fmt.Errorf("%s: ASN %d out of uint32 range", name, n)
		}
		out = append(out, uint32(n)) //nolint:gosec // G115: bounds checked above
	}
	return out, mt, nil
}

// decodeYAML — a wrapper with strict mode (KnownFields(true)) and a human-readable
// error carrying the file name. An empty document (only comments or
// whitespace) makes yaml.NewDecoder return io.EOF — we treat that as "nothing was put
// into dst", which the caller supports (a nil map / nil slice).
func decodeYAML(data []byte, dst any, name string) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: yaml decode: %w", name, err)
	}
	return nil
}
