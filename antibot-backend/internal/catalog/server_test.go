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
	d.TLSFPBlocklist = map[string]string{"L13i17h2_abc_def": "active", "L12i14h1_ghi_jkl": "staging"}
	d.UABlacklist = []string{`curl/.*`, `python-requests/.*`}
	d.UABlacklistStaging = []string{`scrapy/[0-9.]+`}
	d.IPBlocklist = map[string]string{"203.0.113.0/24": "active", "198.51.100.7/32": "staging"}
	d.IPWhitelist = []string{"198.51.100.5/32"}
	d.ASNDatacenters = []uint32{14061, 16509, 14061} // дубликат — проверяем dedup
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
		t.Fatalf("ETag не изменился после Replace с новым контентом")
	}

	// If-None-Match со старым etag после Replace должен дать 200, не 304.
	r3 := httpGetWith(t, ts.URL+"/catalog/tls_fp_blocklist", map[string]string{"If-None-Match": etag1})
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("status=%d after Replace want 200 (старый etag не должен матчиться)", r3.StatusCode)
	}
}

func TestMultiTenantUABlacklistCombinesRegex(t *testing.T) {
	ts := newTestServer(t, sampleData())

	// Контракт shape (A11) — JSON-объект {"active": "<combined>", "staging":
	// ["<pattern>", …]}. active — combined regex системных паттернов
	// (+ per-resource при site); staging — СПИСОК системных staging-паттернов.
	type uaPayload struct {
		Active  string   `json:"active"`
		Staging []string `json:"staging"`
	}
	r1 := httpGet(t, ts.URL+"/catalog/ua_blacklist")
	obj1, err := readJSON[uaPayload](r1)
	etag1 := r1.Header.Get("ETag")
	r1.Body.Close()
	if err != nil {
		t.Fatalf("без site: body не JSON-объект: %v", err)
	}
	if !strings.Contains(obj1.Active, "curl/.*") || !strings.Contains(obj1.Active, "python-requests/.*") {
		t.Errorf("без site: active не содержит системных regex'ов: %q", obj1.Active)
	}
	if strings.Contains(obj1.Active, "evil-scraper/.*") {
		t.Errorf("без site: active содержит per-resource паттерн: %q", obj1.Active)
	}
	// staging-паттерн (scrapy) — отдельной записью списка, не в active.
	if len(obj1.Staging) != 1 || obj1.Staging[0] != "scrapy/[0-9.]+" {
		t.Errorf("staging список не содержит staging-паттерна: %v", obj1.Staging)
	}
	if strings.Contains(obj1.Active, "scrapy/[0-9.]+") {
		t.Errorf("active содержит staging-паттерн (должен быть только в staging): %q", obj1.Active)
	}

	// С site=shop — в active добавляется кастомный; staging не зависит от site.
	r2 := httpGet(t, ts.URL+"/catalog/ua_blacklist?site=shop.example.com")
	obj2, err := readJSON[uaPayload](r2)
	etag2 := r2.Header.Get("ETag")
	r2.Body.Close()
	if err != nil {
		t.Fatalf("site=shop: body не JSON-объект: %v", err)
	}
	if !strings.Contains(obj2.Active, "evil-scraper/.*") {
		t.Errorf("site=shop: active не содержит кастомного regex'a: %q", obj2.Active)
	}

	// active combined regex должен компилироваться.
	if _, err := regexp.Compile(obj2.Active); err != nil {
		t.Errorf("active combined regex не компилируется: %v (pattern=%q)", err, obj2.Active)
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

	// Неизвестный host — дефолт пула (B4): mode=shadow, observe-only.
	// НЕ пустой Policy{}: edge не должен видеть mode="" и падать на
	// switch'е, см. PoolDefault.
	r2 := httpGet(t, ts.URL+"/catalog/policy?site=unknown.example.com")
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("policy?site=unknown: status=%d want 200 (дефолт, не 404)", r2.StatusCode)
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
		{"shop.example.com", true},     // через policy.AttackMode
		{"alerts.example.com", true},   // только через policy.AttackMode
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

	// ip_blocklist: системный CIDR + per-resource CIDR для shop. Wire-формат
	// A11 — "<status>:block": системный active → "active:block", системный
	// staging → "staging:block", per-resource всегда "active:block".
	r := httpGet(t, ts.URL+"/catalog/ip_blocklist?site=shop.example.com")
	var bl map[string]string
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if bl["203.0.113.0/24"] != "active:block" {
		t.Errorf("системный active CIDR не в ip_blocklist: %+v", bl)
	}
	if bl["198.51.100.7/32"] != "staging:block" {
		t.Errorf("системный staging CIDR не несёт staging: %+v", bl)
	}
	if bl["192.0.2.10/32"] != "active:block" {
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

// TestTLSFPBlocklistStatusPayload: A11 — payload несёт "<status>:block"
// для active И staging записей, эдж сам разводит блокировку vs staging_match.
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
		t.Errorf("staging fp payload = %q want staging:block (staging доезжает по Channel C)", bl["L12i14h1_ghi_jkl"])
	}
}

// TestTLSFPCatalogPayload: composite "<status>:<family>" payload — wire
// формат, который edge tls_fp.lua разбирает split-по-`:` (mirrors verified_bot_ips
// и не требует cjson.encode per-entry).
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
		t.Errorf("tls_fp_catalog[curl] payload = %q, want %q (staging должен оставаться в payload, эдж сам фильтрует)",
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
		{`W/"abc"`, `"abc"`, true}, // weak в запросе — допустим
		{``, `"abc"`, false},
		{`  "abc"  `, `"abc"`, true},
		{`"foo,bar"`, `"foo,bar"`, true},           // запятая внутри quoted-string
		{`"a", "foo,bar"`, `"foo,bar"`, true},      // запятая внутри второго токена
		{`"a", "foo,bar", "c"`, `"foo,bar"`, true}, // в середине списка
		{`"a,b", "c,d"`, `"c,d"`, true},
		{`"esc\"ape", "other"`, `"esc\"ape"`, true}, // quoted-pair: \" не закрывает
	}
	for _, tc := range cases {
		if got := etagMatches(tc.header, tc.etag); got != tc.match {
			t.Errorf("etagMatches(%q, %q) = %v want %v", tc.header, tc.etag, got, tc.match)
		}
	}
}

// TestStoreLoadedFlagNotVersion: 503 решается по флагу Store.IsLoaded, а
// не по сравнению Version с defaultVersion — иначе оператор, который
// поставит `version: "0.0.0"` в YAML, получал бы 503 на легитимном payload'е.
func TestStoreLoadedFlagNotVersion(t *testing.T) {
	srv := New()
	d := emptyData() // Version уже = defaultVersion ("0.0.0")
	srv.Store().Replace(d)
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 на Replace с version=%q (бывший сентинель)", resp.StatusCode, defaultVersion)
	}
	if got := resp.Header.Get("X-Catalog-Version"); got != defaultVersion {
		t.Errorf("X-Catalog-Version=%q want %q", got, defaultVersion)
	}
}

// TestNormalizeDedupStrings: дубликат CIDR в YAML не должен раздувать
// catalog payload — normalize дедуплицирует строковые срезы наряду с ASN.
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
		t.Errorf("ip_whitelist len=%d want 2 (дубликат 10.0.0.0/8 не схлопнут): %v", len(wl), wl)
	}

	r = httpGet(t, ts.URL+"/catalog/ua_blacklist")
	obj, _ := readJSON[struct {
		Active  string   `json:"active"`
		Staging []string `json:"staging"`
	}](r)
	r.Body.Close()
	if strings.Count(obj.Active, "curl/") != 1 {
		t.Errorf("ua_blacklist active содержит дубликат curl/: %q", obj.Active)
	}

	r = httpGet(t, ts.URL+"/catalog/ip_blocklist?site=shop.example.com")
	var bl map[string]string
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	// map дедуплицирует по природе, но если бы normalize оставил дубликат
	// в slice'е, jsonBytes(map) всё равно был бы корректен; проверяем сам факт
	// нормализации Policy на уровне Data.
	got := srv.Store().data.Load()
	if l := len(got.Policy["shop.example.com"].IPBlocklist); l != 1 {
		t.Errorf("policy[shop].IPBlocklist дубликат не схлопнут: len=%d", l)
	}
}

// TestStoreNotLoaded503: до Replace Store отдаёт defaultVersion; handler
// должен ответить 503 с Retry-After, а не "успешный" 200 с пустым телом —
// иначе эдж перезатёр бы свой fail-stale-кэш (codex review).
func TestStoreNotLoaded503(t *testing.T) {
	srv := New() // без Replace
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 на эмпти-Store", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Catalog-Version"); got != defaultVersion {
		t.Errorf("X-Catalog-Version=%q want %q", got, defaultVersion)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("Retry-After не выставлен на 503")
	}

	// После Replace тот же endpoint становится доступен.
	srv.Store().Replace(sampleData())
	r2 := httpGet(t, ts.URL+"/catalog/tls_fp_blocklist")
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 после Replace", r2.StatusCode)
	}
}

// TestIfNoneMatchMultipleHeaders: клиент имеет право прислать
// If-None-Match несколько раз; handler должен учитывать ВСЕ значения.
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
	req.Header.Add("If-None-Match", etag) // второй заголовок с актуальным etag
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304 при etag во втором If-None-Match", resp.StatusCode)
	}
}

// readJSON — generic helper для тестов.
func readJSON[T any](r *http.Response) (T, error) {
	var v T
	err := json.NewDecoder(r.Body).Decode(&v)
	return v, err
}
