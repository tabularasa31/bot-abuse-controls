package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// httpGet — GET с контекстом теста. Линтер noctx требует контекст у каждого
// http.Get / NewRequest; один хелпер вместо повторяющегося NewRequestWithContext
// держит тест-кейсы короткими.
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

// sampleData — наполненная Data: по одной записи в каждом каталоге, два host'a
// с policy (один с custom-паттернами и attack_mode), один host attack_mode
// через прямой map. Покрывает combined regex, per-resource ip-листы и оба
// источника attack_mode.
func sampleData() *Data {
	d := emptyData()
	d.Version = "1.2.3"
	d.FPBlocklist = map[string]string{"L13i17h2_abc_def": "block", "L12i14h1_ghi_jkl": "block"}
	d.UABlacklist = []string{`curl/.*`, `python-requests/.*`}
	d.IPBlocklist = map[string]string{"203.0.113.0/24": "block"}
	d.IPWhitelist = []string{"198.51.100.5/32"}
	d.ASNDatacenters = []uint32{14061, 16509, 14061} // дубликат — проверяем dedup
	d.VerifiedBotIPs = map[string]string{"66.249.66.1": "google", "157.55.39.1": "bing"}
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
	}
	d.AttackMode = map[string]bool{"alerts.example.com": true}
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
	resp := httpGet(t, ts.URL+"/catalog/fp_blocklist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Catalog-Version"); got != "1.2.3" {
		t.Errorf("X-Catalog-Version=%q want 1.2.3", got)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" || etag[0] != '"' {
		t.Errorf("ETag=%q должен быть strong и непустой", etag)
	}
}

func TestConditionalGet304(t *testing.T) {
	ts := newTestServer(t, sampleData())

	r1 := httpGet(t, ts.URL+"/catalog/ip_blocklist")
	r1.Body.Close()
	etag := r1.Header.Get("ETag")
	if etag == "" {
		t.Fatal("первый GET не дал ETag")
	}

	r2 := httpGetWith(t, ts.URL+"/catalog/ip_blocklist", map[string]string{"If-None-Match": etag})
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304", r2.StatusCode)
	}
	// 304 не должен иметь body.
	buf := make([]byte, 16)
	n, _ := r2.Body.Read(buf)
	if n != 0 {
		t.Errorf("304 вернул %d байт тела, ожидался пустой", n)
	}
	// ETag и Version должны быть и на 304 (RFC 7232 §4.1).
	if r2.Header.Get("ETag") != etag {
		t.Errorf("ETag на 304 не совпадает с 200")
	}
	if r2.Header.Get("X-Catalog-Version") != "1.2.3" {
		t.Errorf("X-Catalog-Version отсутствует на 304")
	}
}

func TestIfNoneMatchStar(t *testing.T) {
	ts := newTestServer(t, sampleData())
	resp := httpGetWith(t, ts.URL+"/catalog/fp_blocklist", map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304 (If-None-Match: *)", resp.StatusCode)
	}
}

func TestIfNoneMatchList(t *testing.T) {
	ts := newTestServer(t, sampleData())
	r1 := httpGet(t, ts.URL+"/catalog/fp_blocklist")
	r1.Body.Close()
	etag := r1.Header.Get("ETag")

	resp := httpGetWith(t, ts.URL+"/catalog/fp_blocklist", map[string]string{
		"If-None-Match": `"deadbeef", ` + etag + `, "cafebabe"`,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304 (etag в списке)", resp.StatusCode)
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
			t.Fatalf("call %d: etag=%q != prev=%q (не детерминирован)", i, etag, prev)
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

	r1 := httpGet(t, ts.URL+"/catalog/fp_blocklist")
	r1.Body.Close()
	etag1 := r1.Header.Get("ETag")

	d2 := sampleData()
	d2.FPBlocklist["L99i99h9_new_token"] = "block"
	srv.Store().Replace(d2)

	r2 := httpGet(t, ts.URL+"/catalog/fp_blocklist")
	r2.Body.Close()
	etag2 := r2.Header.Get("ETag")

	if etag1 == etag2 {
		t.Fatalf("ETag не изменился после Replace с новым контентом")
	}

	// If-None-Match со старым etag после Replace должен дать 200, не 304.
	r3 := httpGetWith(t, ts.URL+"/catalog/fp_blocklist", map[string]string{"If-None-Match": etag1})
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("status=%d after Replace want 200 (старый etag не должен матчиться)", r3.StatusCode)
	}
}

func TestMultiTenantUABlacklistCombinesRegex(t *testing.T) {
	ts := newTestServer(t, sampleData())

	// Без site — только системные.
	r1 := httpGet(t, ts.URL+"/catalog/ua_blacklist")
	body1, _ := readJSON[map[string]any](r1)
	etag1 := r1.Header.Get("ETag")
	r1.Body.Close()
	sys := int(body1["system_count"].(float64))
	per := int(body1["per_resource_count"].(float64))
	if sys != 2 || per != 0 {
		t.Errorf("без site: system_count=%d per_resource_count=%d want 2,0", sys, per)
	}
	pat1, _ := body1["pattern"].(string)
	if !strings.Contains(pat1, "curl/.*") || !strings.Contains(pat1, "python-requests/.*") {
		t.Errorf("без site: pattern не содержит системных regex'ов: %q", pat1)
	}

	// С site=shop — добавляется кастомный.
	r2 := httpGet(t, ts.URL+"/catalog/ua_blacklist?site=shop.example.com")
	body2, _ := readJSON[map[string]any](r2)
	etag2 := r2.Header.Get("ETag")
	r2.Body.Close()
	sys = int(body2["system_count"].(float64))
	per = int(body2["per_resource_count"].(float64))
	if sys != 2 || per != 1 {
		t.Errorf("с site=shop: system_count=%d per_resource_count=%d want 2,1", sys, per)
	}
	pat2, _ := body2["pattern"].(string)
	if !strings.Contains(pat2, "evil-scraper/.*") {
		t.Errorf("с site=shop: pattern не содержит кастомного regex'a: %q", pat2)
	}

	if etag1 == etag2 {
		t.Errorf("ETag совпали для разных site — per-tenant фильтрация не работает")
	}
}

func TestMultiTenantPolicy(t *testing.T) {
	ts := newTestServer(t, sampleData())

	// Известный host — отдаём именно его policy.
	r1 := httpGet(t, ts.URL+"/catalog/policy?site=shop.example.com")
	var p Policy
	if err := json.NewDecoder(r1.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	r1.Body.Close()
	if p.Mode != "active" || !p.AttackMode {
		t.Errorf("policy[shop] = %+v, want mode=active attack_mode=true", p)
	}

	// Неизвестный host — дефолтная пустая policy, не 404.
	r2 := httpGet(t, ts.URL+"/catalog/policy?site=unknown.example.com")
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("policy?site=unknown: status=%d want 200 (дефолт, не 404)", r2.StatusCode)
	}
	var p2 Policy
	if err := json.NewDecoder(r2.Body).Decode(&p2); err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if p2.Mode != "" {
		t.Errorf("policy[unknown] should be empty Policy, got %+v", p2)
	}
}

func TestMultiTenantAttackMode(t *testing.T) {
	ts := newTestServer(t, sampleData())

	cases := []struct {
		site string
		on   bool
	}{
		{"shop.example.com", true},     // через policy.AttackMode
		{"alerts.example.com", true},   // через AttackMode map
		{"blog.example.com", false},    // присутствует, но off
		{"unknown.example.com", false}, // не зарегистрирован
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

	// ip_blocklist: системный CIDR + per-resource CIDR для shop.
	r := httpGet(t, ts.URL+"/catalog/ip_blocklist?site=shop.example.com")
	var bl map[string]string
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if bl["203.0.113.0/24"] != "block" {
		t.Errorf("системный CIDR не в ip_blocklist: %+v", bl)
	}
	if bl["192.0.2.10/32"] != "block" {
		t.Errorf("per-resource CIDR не в ip_blocklist: %+v", bl)
	}

	// ip_whitelist: системный + per-resource, без дублей.
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
		t.Errorf("asn_datacenters: дубликат 14061 не схлопнут, len=%d", len(asns))
	}
}

func TestSiteTooLong(t *testing.T) {
	ts := newTestServer(t, sampleData())
	long := strings.Repeat("a", 254)
	resp := httpGet(t, ts.URL+"/catalog/policy?site="+long)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 для site длиннее 253 байт", resp.StatusCode)
	}
}

// TestConcurrentPullsNoRace: 10 эджей одновременно дёргают endpoint, часть с
// If-None-Match, в середине Replace меняет данные. Проверяем отсутствие data
// race (`go test -race`), и что каждый GET получает согласованную пару
// ETag/Body (нет ETag старой версии + Body новой).
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
				resp := httpGetWith(t, ts.URL+"/catalog/fp_blocklist?site=shop.example.com", headers)
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
						failures.Store(id, "200 с пустым телом")
						resp.Body.Close()
						return
					}
				}
				resp.Body.Close()
				lastETag = etag
			}
		}(w)
	}

	// Писатель: меняет данные несколько раз — atomicity Store.Replace.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			d := sampleData()
			d.FPBlocklist[strings.Repeat("x", i+1)] = "block"
			srv.Store().Replace(d)
		}
	}()

	wg.Wait()

	failures.Range(func(k, v any) bool {
		t.Errorf("worker %v failed: %v", k, v)
		return true
	})
}

func TestLoadYAML(t *testing.T) {
	yaml := `version: "2.0.0"
fp_blocklist:
  "L13i17h2_aaa_bbb": "block"
ua_blacklist:
  - "curl/.*"
ip_blocklist:
  "203.0.113.0/24": "block"
ip_whitelist:
  - "10.0.0.0/8"
asn_datacenters:
  - 14061
verified_bot_ips:
  "66.249.66.1": "google"
policy:
  shop.example.com:
    mode: active
    strictness: standard
    ua_blacklist:
      - "evil/.*"
    attack_mode: true
attack_mode:
  manual.example.com: true
`
	dir := t.TempDir()
	p := filepath.Join(dir, "catalogs.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := LoadYAML(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != "2.0.0" {
		t.Errorf("Version=%q want 2.0.0", d.Version)
	}
	if d.FPBlocklist["L13i17h2_aaa_bbb"] != "block" {
		t.Errorf("fp_blocklist не загружен")
	}
	if pol := d.Policy["shop.example.com"]; pol.Mode != "active" || !pol.AttackMode {
		t.Errorf("policy[shop] = %+v", pol)
	}
	if !d.AttackMode["manual.example.com"] {
		t.Errorf("attack_mode[manual] не загружен")
	}
}

func TestLoadYAMLMissingVersion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("fp_blocklist: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadYAML(p); err == nil {
		t.Fatal("LoadYAML без version должен возвращать ошибку")
	}
}

func TestLoadYAMLUnknownField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("version: \"1.0.0\"\nfp_block_list: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadYAML(p); err == nil {
		t.Fatal("LoadYAML с опечаткой в ключе должен возвращать ошибку (strict mode)")
	}
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
		{`W/"abc"`, `"abc"`, true}, // weak в запросе — допустим
		{``, `"abc"`, false},
		{`  "abc"  `, `"abc"`, true},
	}
	for _, tc := range cases {
		if got := etagMatches(tc.header, tc.etag); got != tc.match {
			t.Errorf("etagMatches(%q, %q) = %v want %v", tc.header, tc.etag, got, tc.match)
		}
	}
}

// readJSON — generic helper для тестов.
func readJSON[T any](r *http.Response) (T, error) {
	var v T
	err := json.NewDecoder(r.Body).Decode(&v)
	return v, err
}
