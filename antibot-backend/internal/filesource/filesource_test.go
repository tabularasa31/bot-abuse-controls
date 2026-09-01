package filesource

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seed creates a temporary directory with a minimally valid set of catalogs.
// It returns its path. Tests can then rewrite any file and call
// Load again.
func seed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"version":                      "1.0.0\n",
		"tls_fp_blocklist.yaml":        "# empty seed\n",
		"ua_blacklist.yaml":            "# empty seed\n",
		"ip_blocklist.yaml":            "# empty seed\n",
		"ip_whitelist.yaml":            "# empty seed\n",
		"asn_datacenters.yaml":         "# empty seed\n",
		"tls_fp_catalog.yaml":          "# empty seed\n",
		"tls_fp_browser_profiles.yaml": "# empty seed\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_EmptySeed(t *testing.T) {
	dir := seed(t)
	l := New(dir)
	s, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Version != "1.0.0" {
		t.Errorf("Version=%q want 1.0.0", s.Version)
	}
	if len(s.TLSFPBlocklist) != 0 || len(s.UABlacklist) != 0 ||
		len(s.IPBlocklist) != 0 || len(s.IPWhitelist) != 0 ||
		len(s.ASNDatacenters) != 0 ||
		len(s.TLSFPCatalog) != 0 || len(s.TLSFPBrowserProfiles) != 0 {
		t.Errorf("expected an empty slow layer, got: %+v", s)
	}
}

func TestLoad_TLSFPCatalogAndProfiles(t *testing.T) {
	dir := seed(t)
	write(t, dir, "tls_fp_catalog.yaml", `
"1ed0482b9b4c":
  family: python-requests
  status: active
"a1b2c3d4e5f6":
  family: curl
  status: staging
`)
	write(t, dir, "tls_fp_browser_profiles.yaml", `
chrome:
  expected_cipher_cnt: 15
  status: active
firefox:
  expected_cipher_cnt: 16
  status: active
`)
	s, err := New(dir).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(s.TLSFPCatalog); got != 2 {
		t.Errorf("tls_fp_catalog len=%d want 2 (active+staging both stay)", got)
	}
	if s.TLSFPCatalog["1ed0482b9b4c"].Family != "python-requests" ||
		s.TLSFPCatalog["1ed0482b9b4c"].Status != "active" {
		t.Errorf("tls_fp_catalog[python-requests] = %+v", s.TLSFPCatalog["1ed0482b9b4c"])
	}
	if s.TLSFPCatalog["a1b2c3d4e5f6"].Status != "staging" {
		t.Errorf("tls_fp_catalog[curl].Status = %q, want staging", s.TLSFPCatalog["a1b2c3d4e5f6"].Status)
	}
	if got := len(s.TLSFPBrowserProfiles); got != 2 {
		t.Errorf("tls_fp_browser_profiles len=%d want 2", got)
	}
	if s.TLSFPBrowserProfiles["chrome"].ExpectedCipherCnt != 15 {
		t.Errorf("chrome.ExpectedCipherCnt=%d want 15", s.TLSFPBrowserProfiles["chrome"].ExpectedCipherCnt)
	}
}

func TestLoad_TLSFPCatalogInvalidStatus(t *testing.T) {
	dir := seed(t)
	write(t, dir, "tls_fp_catalog.yaml", `
"deadbeef":
  family: curl
  status: rolled-out
`)
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for status=rolled-out in tls_fp_catalog")
	}
}

func TestLoad_TLSFPCatalogEmptyFamily(t *testing.T) {
	dir := seed(t)
	write(t, dir, "tls_fp_catalog.yaml", `
"deadbeef":
  family: ""
  status: active
`)
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for an empty family in tls_fp_catalog")
	}
}

func TestLoad_BrowserProfileZeroCipherCnt(t *testing.T) {
	dir := seed(t)
	write(t, dir, "tls_fp_browser_profiles.yaml", `
chrome:
  expected_cipher_cnt: 0
  status: active
`)
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for expected_cipher_cnt=0")
	}
}

func TestLoad_PopulatedActiveAndStaging(t *testing.T) {
	dir := seed(t)
	// tls_fp_blocklist: one active, one staging.
	write(t, dir, "tls_fp_blocklist.yaml", `
"L13i17h2_aaa_bbb": active
"L12i14h1_ccc_ddd": staging
`)
	// ua_blacklist: active plus staging too.
	write(t, dir, "ua_blacklist.yaml", `
"curl/.*": active
"python-requests/.*": active
"scrapy/.*": staging
`)
	// ip_blocklist: active+staging.
	write(t, dir, "ip_blocklist.yaml", `
"203.0.113.0/24": active
"198.51.100.42/32": staging
`)
	// ip_whitelist: no status.
	write(t, dir, "ip_whitelist.yaml", `
- 10.0.0.5/32
- 198.51.100.5
`)
	// asn_datacenters: no status.
	write(t, dir, "asn_datacenters.yaml", `
- 14061
- 16509
`)

	s, err := New(dir).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(s.TLSFPBlocklist), 2; got != want {
		t.Errorf("tls_fp_blocklist len=%d want %d (active+staging are both preserved)", got, want)
	}
	if s.TLSFPBlocklist["L13i17h2_aaa_bbb"] != "active" {
		t.Errorf("tls_fp_blocklist active status missing: %+v", s.TLSFPBlocklist)
	}
	if s.TLSFPBlocklist["L12i14h1_ccc_ddd"] != "staging" {
		t.Errorf("tls_fp_blocklist staging status missing: %+v", s.TLSFPBlocklist)
	}
	if got, want := len(s.UABlacklist), 2; got != want {
		t.Errorf("ua_blacklist(active) len=%d want %d", got, want)
	}
	if got, want := len(s.UABlacklistStaging), 1; got != want {
		t.Errorf("ua_blacklist(staging) len=%d want %d", got, want)
	}
	if got, want := len(s.IPBlocklist), 2; got != want {
		t.Errorf("ip_blocklist len=%d want %d (active+staging)", got, want)
	}
	if s.IPBlocklist["203.0.113.0/24"] != "active" || s.IPBlocklist["198.51.100.42/32"] != "staging" {
		t.Errorf("ip_blocklist statuses wrong: %+v", s.IPBlocklist)
	}
	if got, want := len(s.IPWhitelist), 2; got != want {
		t.Errorf("ip_whitelist len=%d want %d", got, want)
	}
	if got, want := len(s.ASNDatacenters), 2; got != want {
		t.Errorf("asn_datacenters len=%d want %d", got, want)
	}
}

func TestLoad_MissingVersionFile(t *testing.T) {
	dir := seed(t)
	if err := os.Remove(filepath.Join(dir, "version")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for a missing version")
	}
}

func TestLoad_EmptyVersionFile(t *testing.T) {
	dir := seed(t)
	write(t, dir, "version", "   \n  \n")
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for an empty version")
	}
}

func TestLoad_MissingCatalogFile(t *testing.T) {
	dir := seed(t)
	if err := os.Remove(filepath.Join(dir, "ip_whitelist.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for a missing catalog file")
	}
}

func TestLoad_InvalidStatus(t *testing.T) {
	dir := seed(t)
	write(t, dir, "tls_fp_blocklist.yaml", `"L13i17h2_aaa_bbb": rolled-out`)
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for status=rolled-out")
	}
}

func TestLoad_InvalidRegex(t *testing.T) {
	dir := seed(t)
	// A broken regex — Compile must fail and Load must return an error.
	write(t, dir, "ua_blacklist.yaml", `"bot[a-z": active`)
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for a broken regex")
	}
}

func TestLoad_InvalidCIDR(t *testing.T) {
	dir := seed(t)
	write(t, dir, "ip_blocklist.yaml", `"999.0.0.0/33": active`)
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for a broken CIDR in ip_blocklist")
	}

	dir2 := seed(t)
	write(t, dir2, "ip_whitelist.yaml", `- not-a-cidr`)
	if _, err := New(dir2).Load(); err == nil {
		t.Fatal("an error was expected for a broken CIDR in ip_whitelist")
	}
}

func TestLoad_ASNOutOfRange(t *testing.T) {
	dir := seed(t)
	write(t, dir, "asn_datacenters.yaml", "- -1\n")
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("an error was expected for a negative ASN")
	}

	dir2 := seed(t)
	write(t, dir2, "asn_datacenters.yaml", "- 4294967296\n") // > uint32 max
	if _, err := New(dir2).Load(); err == nil {
		t.Fatal("an error was expected for an ASN > uint32 max")
	}
}

func TestChanged_InitialTrueThenFalseThenTrue(t *testing.T) {
	dir := seed(t)
	l := New(dir)
	if !l.Changed() {
		t.Error("Changed on an empty cache must be true")
	}
	if _, err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if l.Changed() {
		t.Error("Changed after a successful Load must be false; the files did not change")
	}
	// We change one file — Changed must become true again.
	// We use os.Chtimes so that the mtime is guaranteed to differ from the
	// previous one (on fast filesystems a rewrite within the same second can give
	// the same mtime and make the test flaky).
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "ua_blacklist.yaml"), future, future); err != nil {
		t.Fatal(err)
	}
	if !l.Changed() {
		t.Error("Changed after an mtime change must become true")
	}
}

func TestLoad_AtomicMtimeUpdate(t *testing.T) {
	// A regression: if Load failed halfway (with a broken ua_blacklist, say),
	// the mtime cache must NOT be updated partially — otherwise on the next tick
	// Changed() returns false and the reloader skips the fixed file.
	dir := seed(t)
	l := New(dir)
	// An initially successful Load.
	if _, err := l.Load(); err != nil {
		t.Fatalf("the first Load: %v", err)
	}
	// We break one file and rewrite the second.
	future := time.Now().Add(2 * time.Second)
	write(t, dir, "ua_blacklist.yaml", `"bot[a-z": active`)
	write(t, dir, "ip_whitelist.yaml", "- 10.0.0.5\n")
	if err := os.Chtimes(filepath.Join(dir, "ua_blacklist.yaml"), future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, "ip_whitelist.yaml"), future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Load(); err == nil {
		t.Fatal("an error was expected from Load with a broken regex")
	}
	// Changed must now stay true — the cache did not move.
	if !l.Changed() {
		t.Error("Changed after a failed Load must stay true (the cache was not updated)")
	}
}
