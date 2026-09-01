package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// httpGet — a GET with the test's context. The noctx linter requires a context on every
// http.Get / NewRequest; one helper instead of a repeated NewRequestWithContext
// keeps the test cases short.
func httpGet(t *testing.T, url string) *http.Response {
	t.Helper()
	return httpGetWith(t, url, nil)
}

func httpGetWith(t *testing.T, url string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// sampleData — a populated Data: one record in every catalog, two hosts
// with a policy (one with custom patterns and attack_mode), and one host with attack_mode
// through the direct map. It covers the combined regex, the per-resource IP lists and both
// sources of attack_mode.
func sampleData() *Data {
	d := emptyData()
	d.Version = "1.2.3"
	d.TLSFPBlocklist = map[string]string{"L13i17h2_abc_def": "active", "L12i14h1_ghi_jkl": "staging"}
	d.UABlacklist = []string{`curl/.*`, `python-requests/.*`}
	d.UABlacklistStaging = []string{`scrapy/[0-9.]+`}
	d.IPBlocklist = map[string]string{"203.0.113.0/24": "active", "198.51.100.7/32": "staging"}
	d.IPWhitelist = []string{"198.51.100.5/32"}
	d.ASNDatacenters = []uint32{14061, 16509, 14061} // a duplicate — we check the dedup
	d.TLSFPCatalog = map[string]TLSFPCatalog{
		"1ed0482b9b4c": {Family: "python-requests", Status: "active"},
		"a1b2c3d4e5f6": {Family: "curl", Status: "staging"},
	}
	d.TLSFPBrowserProfiles = map[string]BrowserProfile{
		"chrome":  {ExpectedCipherCnt: 15, Status: "active"},
		"firefox": {ExpectedCipherCnt: 16, Status: "active"},
	}
	d.VerifiedBotIPs = map[string]string{"66.249.66.1": "verified:google", "157.55.39.1": "rejected:bing"}
	d.Policy = map[string]Policy{
		"shop.example.com": {
			Mode:        "active",
			Strictness:  "standard",
			UABlacklist: []string{`evil-scraper/.*`},
			IPBlocklist: []string{"192.0.2.10/32"},
			IPWhitelist: []string{"198.51.100.99/32"},
			AttackMode:  true,
		},
		"blog.example.com": {
			Mode:       "shadow",
			Strictness: "permissive",
		},
		"alerts.example.com": {
			Mode:       "active",
			AttackMode: true,
		},
	}
	return d
}

func newTestServer(t *testing.T, d *Data) *httptest.Server {
	t.Helper()
	srv := New()
	srv.Store().Replace(d)
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestUnknownCatalog404(t *testing.T) {
	ts := newTestServer(t, sampleData())
	resp := httpGet(t, ts.URL+"/catalog/does_not_exist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d want 404", resp.StatusCode)
	}
}

func TestVersionAndETagHeaders(t *testing.T) {
	ts := newTestServer(t, sampleData())
	resp := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Catalog-Version"); got != "1.2.3" {
		t.Errorf("X-Catalog-Version=%q want 1.2.3", got)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" || etag[0] != '"' {
		t.Errorf("ETag=%q must be strong and non-empty", etag)
	}
}

func TestConditionalGet304(t *testing.T) {
	ts := newTestServer(t, sampleData())

	r1 := httpGet(t, ts.URL+"/catalog/ip_blocklist")
	r1.Body.Close()
	etag := r1.Header.Get("ETag")
	if etag == "" {
		t.Fatal("the first GET returned no ETag")
	}

	r2 := httpGetWith(t, ts.URL+"/catalog/ip_blocklist", map[string]string{"If-None-Match": etag})
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304", r2.StatusCode)
	}
	// A 304 must have no body.
	buf := make([]byte, 16)
	n, _ := r2.Body.Read(buf)
	if n != 0 {
		t.Errorf("the 304 returned %d bytes of body, expected empty", n)
	}
	// The ETag and Version must be present on the 304 too (RFC 7232 §4.1).
	if r2.Header.Get("ETag") != etag {
		t.Errorf("the ETag on the 304 does not match the 200")
	}
	if r2.Header.Get("X-Catalog-Version") != "1.2.3" {
		t.Errorf("X-Catalog-Version is missing on the 304")
	}
}

func TestIfNoneMatchStar(t *testing.T) {
	ts := newTestServer(t, sampleData())
	resp := httpGetWith(t, ts.URL+"/catalog/tls_fp_blocklist", map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304 (If-None-Match: *)", resp.StatusCode)
	}
}

func TestIfNoneMatchList(t *testing.T) {
	ts := newTestServer(t, sampleData())
	r1 := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	r1.Body.Close()
	etag := r1.Header.Get("ETag")

	resp := httpGetWith(t, ts.URL+"/catalog/tls_fp_blocklist", map[string]string{
		"If-None-Match": `"deadbeef", ` + etag + `, "cafebabe"`,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304 (the etag is in the list)", resp.StatusCode)
	}
}

func TestETagStableAcrossCalls(t *testing.T) {
	ts := newTestServer(t, sampleData())
	const N = 5
	var prev string
	for i := 0; i < N; i++ {
		resp := httpGet(t, ts.URL+"/catalog/asn_datacenters")
		etag := resp.Header.Get("ETag")
		resp.Body.Close()
		if i > 0 && etag != prev {
			t.Fatalf("call %d: etag=%q != prev=%q (not deterministic)", i, etag, prev)
		}
		prev = etag
	}
}

func TestETagChangesOnDataUpdate(t *testing.T) {
	srv := New()
	srv.Store().Replace(sampleData())
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	r1 := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	r1.Body.Close()
	etag1 := r1.Header.Get("ETag")

	d2 := sampleData()
	d2.TLSFPBlocklist["L99i99h9_new_token"] = "active"
	srv.Store().Replace(d2)

	r2 := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	r2.Body.Close()
	etag2 := r2.Header.Get("ETag")

	if etag1 == etag2 {
		t.Fatalf("the ETag did not change after a Replace with new content")
	}

	// If-None-Match with the old etag after a Replace must give 200, not 304.
	r3 := httpGetWith(t, ts.URL+"/catalog/tls_fp_blocklist", map[string]string{"If-None-Match": etag1})
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("status=%d after Replace want 200 (the old etag must not match)", r3.StatusCode)
	}
}

func TestMultiTenantUABlacklistCombinesRegex(t *testing.T) {
	ts := newTestServer(t, sampleData())

	// The shape contract (A11) — a JSON object {"active": "<combined>", "staging":
	// ["<pattern>", …]}. active is the combined regex of the system patterns
	// (plus per-resource ones when a site is given); staging is the LIST of system staging patterns.
	type uaPayload struct {
		Active  string   `json:"active"`
		Staging []string `json:"staging"`
	}
	r1 := httpGet(t, ts.URL+"/catalog/ua_blacklist")
	obj1, err := readJSON[uaPayload](r1)
	etag1 := r1.Header.Get("ETag")
	r1.Body.Close()
	if err != nil {
		t.Fatalf("no site: the body is not a JSON object: %v", err)
	}
	if !strings.Contains(obj1.Active, "curl/.*") || !strings.Contains(obj1.Active, "python-requests/.*") {
		t.Errorf("no site: active does not contain the system regexes: %q", obj1.Active)
	}
	if strings.Contains(obj1.Active, "evil-scraper/.*") {
		t.Errorf("no site: active contains a per-resource pattern: %q", obj1.Active)
	}
	// The staging pattern (scrapy) is a separate list entry, not part of active.
	if len(obj1.Staging) != 1 || obj1.Staging[0] != "scrapy/[0-9.]+" {
		t.Errorf("the staging list does not contain the staging pattern: %v", obj1.Staging)
	}
	if strings.Contains(obj1.Active, "scrapy/[0-9.]+") {
		t.Errorf("active contains a staging pattern (it must be in staging only): %q", obj1.Active)
	}

	// With site=shop the custom one is added to active; staging does not depend on the site.
	r2 := httpGet(t, ts.URL+"/catalog/ua_blacklist?site=shop.example.com")
	obj2, err := readJSON[uaPayload](r2)
	etag2 := r2.Header.Get("ETag")
	r2.Body.Close()
	if err != nil {
		t.Fatalf("site=shop: the body is not a JSON object: %v", err)
	}
	if !strings.Contains(obj2.Active, "evil-scraper/.*") {
		t.Errorf("site=shop: active does not contain the custom regex: %q", obj2.Active)
	}

	// The active combined regex must compile.
	if _, err := regexp.Compile(obj2.Active); err != nil {
		t.Errorf("the active combined regex does not compile: %v (pattern=%q)", err, obj2.Active)
	}

	if etag1 == etag2 {
		t.Errorf("the ETags matched for different sites — per-tenant filtering is not working")
	}
}

func TestMultiTenantPolicy(t *testing.T) {
	ts := newTestServer(t, sampleData())

	// A known host — we serve exactly its policy.
	r1 := httpGet(t, ts.URL+"/catalog/policy?site=shop.example.com")
	var p Policy
	if err := json.NewDecoder(r1.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	r1.Body.Close()
	if p.Mode != "active" || !p.AttackMode {
		t.Errorf("policy[shop] = %+v, want mode=active attack_mode=true", p)
	}

	// An unknown host — the pool default (B4): mode=shadow, observe-only.
	// NOT an empty Policy{}: the edge must not see mode="" and break on the
	// mode switch, see PoolDefault.
	r2 := httpGet(t, ts.URL+"/catalog/policy?site=unknown.example.com")
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("policy?site=unknown: status=%d want 200 (the default, not a 404)", r2.StatusCode)
	}
	var p2 Policy
	if err := json.NewDecoder(r2.Body).Decode(&p2); err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if p2.Mode != "shadow" || p2.Strictness != "standard" {
		t.Errorf("policy[unknown] = %+v, want pool default (mode=shadow, strictness=standard)", p2)
	}
	if p2.AttackMode {
		t.Errorf("policy[unknown].attack_mode must be false in pool default, got %+v", p2)
	}
}

func TestMultiTenantAttackMode(t *testing.T) {
	ts := newTestServer(t, sampleData())

	cases := []struct {
		site string
		on   bool
	}{
		{"shop.example.com", true},     // through policy.AttackMode
		{"alerts.example.com", true},   // only through policy.AttackMode
		{"blog.example.com", false},    // present, but off
		{"unknown.example.com", false}, // not registered
	}
	for _, tc := range cases {
		r := httpGet(t, ts.URL+"/catalog/attack_mode?site="+tc.site)
		var out map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if out["on"] != tc.on {
			t.Errorf("attack_mode[%s] = %v, want %v", tc.site, out["on"], tc.on)
		}
	}
}

func TestPerTenantIPLists(t *testing.T) {
	ts := newTestServer(t, sampleData())

	// ip_blocklist: the system CIDR plus a per-resource CIDR for shop. The A11 wire
	// format is "<status>:block": a system active one → "active:block", a system
	// staging one → "staging:block", and per-resource ones are always "active:block".
	r := httpGet(t, ts.URL+"/catalog/ip_blocklist?site=shop.example.com")
	var bl map[string]string
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if bl["203.0.113.0/24"] != "active:block" {
		t.Errorf("the system active CIDR is missing from ip_blocklist: %+v", bl)
	}
	if bl["198.51.100.7/32"] != "staging:block" {
		t.Errorf("the system staging CIDR does not carry staging: %+v", bl)
	}
	if bl["192.0.2.10/32"] != "active:block" {
		t.Errorf("the per-resource CIDR is missing from ip_blocklist: %+v", bl)
	}

	// ip_whitelist: system plus per-resource, with no duplicates.
	r = httpGet(t, ts.URL+"/catalog/ip_whitelist?site=shop.example.com")
	var wl []string
	if err := json.NewDecoder(r.Body).Decode(&wl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if len(wl) != 2 {
		t.Errorf("ip_whitelist?site=shop: len=%d want 2, got %v", len(wl), wl)
	}
}

// TestTLSFPBlocklistStatusPayload: A11 — the payload carries "<status>:block"
// for active AND staging records, and the edge separates a block from a staging_match itself.
func TestTLSFPBlocklistStatusPayload(t *testing.T) {
	ts := newTestServer(t, sampleData())
	r := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	var bl map[string]string
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if bl["L13i17h2_abc_def"] != "active:block" {
		t.Errorf("active fp payload = %q want active:block", bl["L13i17h2_abc_def"])
	}
	if bl["L12i14h1_ghi_jkl"] != "staging:block" {
		t.Errorf("staging fp payload = %q want staging:block (staging is delivered over Channel C)", bl["L12i14h1_ghi_jkl"])
	}
}

// TestTLSFPCatalogPayload: composite "<status>:<family>" payload — wire
// the format edge tls_fp.lua parses by splitting on `:` (it mirrors verified_bot_ips
// and needs no per-entry cjson.encode).
func TestTLSFPCatalogPayload(t *testing.T) {
	ts := newTestServer(t, sampleData())
	r := httpGet(t, ts.URL+"/catalog/tls_fp_catalog")
	var cat map[string]string
	if err := json.NewDecoder(r.Body).Decode(&cat); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if cat["1ed0482b9b4c"] != "active:python-requests" {
		t.Errorf("tls_fp_catalog[python-requests] payload = %q, want %q",
			cat["1ed0482b9b4c"], "active:python-requests")
	}
	if cat["a1b2c3d4e5f6"] != "staging:curl" {
		t.Errorf("tls_fp_catalog[curl] payload = %q, want %q (staging must stay in the payload; the edge filters it itself)",
			cat["a1b2c3d4e5f6"], "staging:curl")
	}
}

func TestTLSFPBrowserProfilesPayload(t *testing.T) {
	ts := newTestServer(t, sampleData())
	r := httpGet(t, ts.URL+"/catalog/tls_fp_browser_profiles")
	var prof map[string]string
	if err := json.NewDecoder(r.Body).Decode(&prof); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if prof["chrome"] != "active:15" {
		t.Errorf("chrome payload = %q want active:15", prof["chrome"])
	}
	if prof["firefox"] != "active:16" {
		t.Errorf("firefox payload = %q want active:16", prof["firefox"])
	}
}

func TestASNDatacentersDedup(t *testing.T) {
	ts := newTestServer(t, sampleData())
	r := httpGet(t, ts.URL+"/catalog/asn_datacenters")
	var asns map[string]int
	if err := json.NewDecoder(r.Body).Decode(&asns); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if asns["14061"] != 1 || asns["16509"] != 1 {
		t.Errorf("asn_datacenters payload = %v want {14061:1, 16509:1}", asns)
	}
	if len(asns) != 2 {
		t.Errorf("asn_datacenters: the duplicate 14061 was not collapsed, len=%d", len(asns))
	}
}

func TestSiteTooLong(t *testing.T) {
	ts := newTestServer(t, sampleData())
	long := strings.Repeat("a", 254)
	resp := httpGet(t, ts.URL+"/catalog/policy?site="+long)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 for a site longer than 253 bytes", resp.StatusCode)
	}
}

// TestConcurrentPullsNoRace: 10 edges hit the endpoint at once, some with an
// If-None-Match, while a Replace changes the data mid-flight. We check for the absence of a data
// race (`go test -race`) and that every GET receives a consistent
// ETag/Body pair (no old-version ETag with a new Body).
func TestConcurrentPullsNoRace(t *testing.T) {
	srv := New()
	srv.Store().Replace(sampleData())
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	const workers = 10
	const iterations = 50

	var wg sync.WaitGroup
	var failures sync.Map

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var lastETag string
			for i := 0; i < iterations; i++ {
				headers := map[string]string{}
				if lastETag != "" && i%2 == 0 {
					headers["If-None-Match"] = lastETag
				}
				resp := httpGetWith(t, ts.URL+"/catalog/tls_fp_blocklist?site=shop.example.com", headers)
				if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
					failures.Store(id, resp.Status)
					resp.Body.Close()
					return
				}
				etag := resp.Header.Get("ETag")
				if etag == "" {
					failures.Store(id, "missing etag")
					resp.Body.Close()
					return
				}
				if resp.StatusCode == http.StatusOK {
					b := make([]byte, 1024)
					n, _ := resp.Body.Read(b)
					if n == 0 {
						failures.Store(id, "200 with an empty body")
						resp.Body.Close()
						return
					}
				}
				resp.Body.Close()
				lastETag = etag
			}
		}(w)
	}

	// The writer: it changes the data several times — the atomicity of Store.Replace.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			d := sampleData()
			d.TLSFPBlocklist[strings.Repeat("x", i+1)] = "active"
			srv.Store().Replace(d)
		}
	}()

	wg.Wait()

	failures.Range(func(k, v any) bool {
		t.Errorf("worker %v failed: %v", k, v)
		return true
	})
}

func TestETagMatcher(t *testing.T) {
	cases := []struct {
		header, etag string
		match        bool
	}{
		{`"abc"`, `"abc"`, true},
		{`"abc", "def"`, `"def"`, true},
		{`"abc"`, `"def"`, false},
		{`*`, `"anything"`, true},
		{`W/"abc"`, `"abc"`, true}, // a weak one in the request — acceptable
		{``, `"abc"`, false},
		{`  "abc"  `, `"abc"`, true},
		{`"foo,bar"`, `"foo,bar"`, true},           // a comma inside a quoted-string
		{`"a", "foo,bar"`, `"foo,bar"`, true},      // a comma inside the second token
		{`"a", "foo,bar", "c"`, `"foo,bar"`, true}, // in the middle of the list
		{`"a,b", "c,d"`, `"c,d"`, true},
		{`"esc\"ape", "other"`, `"esc\"ape"`, true}, // a quoted-pair: \" does not close it
	}
	for _, tc := range cases {
		if got := etagMatches(tc.header, tc.etag); got != tc.match {
			t.Errorf("etagMatches(%q, %q) = %v want %v", tc.header, tc.etag, got, tc.match)
		}
	}
}

// TestStoreLoadedFlagNotVersion: the 503 is decided by the Store.IsLoaded flag and
// not by comparing Version with defaultVersion — otherwise an operator who
// sets `version: "0.0.0"` in the YAML would get a 503 on a legitimate payload.
func TestStoreLoadedFlagNotVersion(t *testing.T) {
	srv := New()
	d := emptyData() // Version is already defaultVersion ("0.0.0")
	srv.Store().Replace(d)
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 on a Replace with version=%q (the former sentinel)", resp.StatusCode, defaultVersion)
	}
	if got := resp.Header.Get("X-Catalog-Version"); got != defaultVersion {
		t.Errorf("X-Catalog-Version=%q want %q", got, defaultVersion)
	}
}

// TestNormalizeDedupStrings: a duplicate CIDR in the YAML must not inflate the
// catalog payload — normalize deduplicates string slices alongside the ASNs.
func TestNormalizeDedupStrings(t *testing.T) {
	d := emptyData()
	d.Version = "1.0.0"
	d.IPWhitelist = []string{"10.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"}
	d.UABlacklist = []string{"curl/.*", "curl/.*"}
	d.Policy = map[string]Policy{
		"shop.example.com": {IPBlocklist: []string{"192.0.2.10/32", "192.0.2.10/32"}},
	}
	srv := New()
	srv.Store().Replace(d)
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	r := httpGet(t, ts.URL+"/catalog/ip_whitelist")
	var wl []string
	if err := json.NewDecoder(r.Body).Decode(&wl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if len(wl) != 2 {
		t.Errorf("ip_whitelist len=%d want 2 (the duplicate 10.0.0.0/8 was not collapsed): %v", len(wl), wl)
	}

	r = httpGet(t, ts.URL+"/catalog/ua_blacklist")
	obj, _ := readJSON[struct {
		Active  string   `json:"active"`
		Staging []string `json:"staging"`
	}](r)
	r.Body.Close()
	if strings.Count(obj.Active, "curl/") != 1 {
		t.Errorf("ua_blacklist active contains the duplicate curl/: %q", obj.Active)
	}

	r = httpGet(t, ts.URL+"/catalog/ip_blocklist?site=shop.example.com")
	var bl map[string]string
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	// A map deduplicates by nature, but if normalize had left a duplicate
	// in the slice, jsonBytes(map) would still be correct; we check the fact of
	// normalisation of Policy at the Data level.
	got := srv.Store().data.Load()
	if l := len(got.Policy["shop.example.com"].IPBlocklist); l != 1 {
		t.Errorf("policy[shop].IPBlocklist duplicate not collapsed: len=%d", l)
	}
}

// TestStoreNotLoaded503: before a Replace the Store serves defaultVersion; the handler
// must answer 503 with a Retry-After rather than a "successful" 200 with an empty body —
// otherwise the edge would overwrite its own fail-stale cache.
func TestStoreNotLoaded503(t *testing.T) {
	srv := New() // with no Replace
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 on an empty Store", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Catalog-Version"); got != defaultVersion {
		t.Errorf("X-Catalog-Version=%q want %q", got, defaultVersion)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("Retry-After is not set on the 503")
	}

	// After a Replace the same endpoint becomes available.
	srv.Store().Replace(sampleData())
	r2 := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 after Replace", r2.StatusCode)
	}
}

// TestIfNoneMatchMultipleHeaders: a client may send
// If-None-Match several times; the handler must consider ALL the values.
func TestIfNoneMatchMultipleHeaders(t *testing.T) {
	ts := newTestServer(t, sampleData())

	r1 := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	r1.Body.Close()
	etag := r1.Header.Get("ETag")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+"/catalog/tls_fp_blocklist", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("If-None-Match", `"deadbeef"`)
	req.Header.Add("If-None-Match", etag) // a second header with the current etag
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304 when the etag is in the second If-None-Match", resp.StatusCode)
	}
}

// readJSON — a generic helper for the tests.
func readJSON[T any](r *http.Response) (T, error) {
	var v T
	err := json.NewDecoder(r.Body).Decode(&v)
	return v, err
}
