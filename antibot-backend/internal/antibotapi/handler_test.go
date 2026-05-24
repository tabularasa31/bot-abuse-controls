// Integration-тесты handler+store против реального PostgreSQL.
// Гейтятся POSTGRES_TEST_DSN — паттерн из internal/dbloader/dbloader_test.go.
// Без DSN тест SkipNow'ит (локальная разработка без БД не ломается).
//
// Покрытие из плана B10:
//   - auth: bad token → 401, missing → 401, valid → 200
//   - PATCH attack_mode: new site → row создан с PoolDefault + patch;
//     existing → UPSERT; idempotent повтор → updated_at не дёргается;
//     невалидный mode → 400 без записи; unknown ключ → 400 strict-decode
//   - PATCH multi-field: оба применяются атомарно; ошибка в одном — ни одно
//     поле не записано
//   - JSONB array append/delete: dedup, 404 на отсутствующий, валидация
//   - GET policy: 404 для нового host'a, эквивалентность с PoolDefault
//     после первого PATCH
//   - logs sink не сюда: API не пишет audit-таблицу (см. план B10).
package antibotapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tabularasa31/antibot-backend/internal/antibotapi"
	"github.com/tabularasa31/antibot-backend/internal/dbloader"
	"github.com/tabularasa31/antibot-backend/internal/logger"
)

func dsn(t *testing.T) string {
	t.Helper()
	v := os.Getenv("POSTGRES_TEST_DSN")
	if v == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping antibotapi integration test")
	}
	return v
}

func newTestServer(t *testing.T) (*httptest.Server, *pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn(t))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	// Чистая схема — DROP+Migrate. Тесты не должны зависеть от соседей.
	tables := []string{
		"catalog_version", "fp_blocklist", "ua_blacklist",
		"ip_blocklist", "ip_whitelist", "asn_datacenters",
		"verified_bot_ips", "policy", "logs",
	}
	for _, tbl := range tables {
		if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS "+tbl); err != nil {
			t.Fatalf("drop %s: %v", tbl, err)
		}
	}
	if err := dbloader.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	reg := prometheus.NewRegistry()
	auth := antibotapi.NewAuthenticator("s3cret", reg)
	srv := antibotapi.New(pool, auth, logger.New(), reg)
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, pool, "s3cret"
}

// do — авторизованный (если token!="") HTTP-запрос. Возвращает status и
// raw body для последующего json.Unmarshal в конкретные структуры.
func do(t *testing.T, ts *httptest.Server, method, path, token, body string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestAuth(t *testing.T) {
	ts, _, tok := newTestServer(t)
	cases := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"bad", "wrong", http.StatusUnauthorized},
		{"valid", tok, http.StatusNotFound}, // GET на несуществующий site = 404, но auth прошёл
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := do(t, ts, http.MethodGet, "/antibot/v1/policy/foo.example", tc.token, "")
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

func TestPatchAttackMode_NewSite(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	status, body := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok, `{"attack_mode":true}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var r struct {
		Changed bool     `json:"changed"`
		Diff    []string `json:"diff"`
	}
	_ = json.Unmarshal(body, &r)
	if !r.Changed || len(r.Diff) != 1 || r.Diff[0] != "attack_mode" {
		t.Errorf("unexpected response: %+v (body=%s)", r, body)
	}
	// Row создан с PoolDefault + патч.
	var mode, strictness string
	var attack bool
	if err := pool.QueryRow(context.Background(),
		`SELECT mode, strictness, attack_mode FROM policy WHERE host = 'foo.example'`,
	).Scan(&mode, &strictness, &attack); err != nil {
		t.Fatalf("select: %v", err)
	}
	if mode != "shadow" || strictness != "standard" || !attack {
		t.Errorf("row = (%s,%s,%v), want (shadow,standard,true)", mode, strictness, attack)
	}
}

func TestPatchIdempotent_UpdatedAtPreserved(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	// Первый PATCH — создаёт row.
	if status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok, `{"attack_mode":true}`); status != http.StatusOK {
		t.Fatalf("first patch: %d", status)
	}
	var ts1 time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT updated_at FROM policy WHERE host='foo.example'`,
	).Scan(&ts1); err != nil {
		t.Fatalf("select1: %v", err)
	}
	// Небольшая пауза, чтобы NOW() гарантированно отличался при write.
	time.Sleep(50 * time.Millisecond)

	// Повтор того же патча.
	status, body := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok, `{"attack_mode":true}`)
	if status != http.StatusOK {
		t.Fatalf("second patch: %d body=%s", status, body)
	}
	var r struct {
		Changed bool `json:"changed"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Changed {
		t.Errorf("idempotent patch reported changed=true, body=%s", body)
	}
	var ts2 time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT updated_at FROM policy WHERE host='foo.example'`,
	).Scan(&ts2); err != nil {
		t.Fatalf("select2: %v", err)
	}
	if !ts1.Equal(ts2) {
		t.Errorf("updated_at changed on no-op: ts1=%v ts2=%v", ts1, ts2)
	}
}

func TestPatch_InvalidMode_NotWritten(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok, `{"mode":"bogus"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", status)
	}
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM policy WHERE host='foo.example'`,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("row created on invalid PATCH: count=%d", count)
	}
}

func TestPatch_MultiField_AtomicValidation(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	// attack_mode=true валиден, но mode=invalid — handler должен 400 и
	// НЕ применять attack_mode.
	status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok,
		`{"attack_mode":true,"mode":"invalid"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", status)
	}
	var count int
	_ = pool.QueryRow(context.Background(),
		`SELECT count(*) FROM policy WHERE host='foo.example'`,
	).Scan(&count)
	if count != 0 {
		t.Errorf("partial write happened: count=%d", count)
	}
}

func TestPatch_UnknownKey_400(t *testing.T) {
	ts, _, tok := newTestServer(t)
	status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok,
		`{"foo":1}`)
	if status != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (DisallowUnknownFields)", status)
	}
}

func TestUABlacklist_AppendDedupDelete(t *testing.T) {
	ts, _, tok := newTestServer(t)
	// First append.
	status, body := do(t, ts, http.MethodPost, "/antibot/v1/policy/foo.example/ua_blacklist", tok,
		`{"pattern":"curl/[0-9]"}`)
	if status != http.StatusOK {
		t.Fatalf("append: status=%d body=%s", status, body)
	}
	// Repeat — dedup, changed=false.
	status, body = do(t, ts, http.MethodPost, "/antibot/v1/policy/foo.example/ua_blacklist", tok,
		`{"pattern":"curl/[0-9]"}`)
	if status != http.StatusOK || !strings.Contains(string(body), `"changed":false`) {
		t.Errorf("dedup: status=%d body=%s", status, body)
	}
	// GET array — содержит элемент.
	status, body = do(t, ts, http.MethodGet, "/antibot/v1/policy/foo.example/ua_blacklist", tok, "")
	if status != http.StatusOK || !strings.Contains(string(body), `curl/[0-9]`) {
		t.Errorf("get: status=%d body=%s", status, body)
	}
	// Delete существующий.
	status, _ = do(t, ts, http.MethodDelete, "/antibot/v1/policy/foo.example/ua_blacklist", tok,
		`{"pattern":"curl/[0-9]"}`)
	if status != http.StatusOK {
		t.Errorf("delete: status=%d", status)
	}
	// Delete несуществующий → 404.
	status, _ = do(t, ts, http.MethodDelete, "/antibot/v1/policy/foo.example/ua_blacklist", tok,
		`{"pattern":"curl/[0-9]"}`)
	if status != http.StatusNotFound {
		t.Errorf("delete absent: status=%d, want 404", status)
	}
}

func TestUABlacklist_InvalidRegex_400_NoWrite(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	status, _ := do(t, ts, http.MethodPost, "/antibot/v1/policy/foo.example/ua_blacklist", tok,
		`{"pattern":"bot[a-z"}`)
	if status != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", status)
	}
	var count int
	_ = pool.QueryRow(context.Background(),
		`SELECT count(*) FROM policy WHERE host='foo.example'`,
	).Scan(&count)
	if count != 0 {
		t.Errorf("row created on invalid regex: count=%d", count)
	}
}

func TestIPBlocklist_InvalidCIDR_400(t *testing.T) {
	ts, _, tok := newTestServer(t)
	status, _ := do(t, ts, http.MethodPost, "/antibot/v1/policy/foo.example/ip_blocklist", tok,
		`{"cidr":"not-a-cidr"}`)
	if status != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", status)
	}
}

func TestGetPolicy_NewSite_404(t *testing.T) {
	ts, _, tok := newTestServer(t)
	status, _ := do(t, ts, http.MethodGet, "/antibot/v1/policy/never-touched.example", tok, "")
	if status != http.StatusNotFound {
		t.Errorf("status=%d, want 404", status)
	}
}

func TestGetPolicy_AfterPatch(t *testing.T) {
	ts, _, tok := newTestServer(t)
	if status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok,
		`{"attack_mode":true}`); status != http.StatusOK {
		t.Fatalf("patch failed")
	}
	status, body := do(t, ts, http.MethodGet, "/antibot/v1/policy/foo.example", tok, "")
	if status != http.StatusOK {
		t.Fatalf("get: status=%d body=%s", status, body)
	}
	// Ожидаем PoolDefault + attack_mode=true.
	want := []string{`"mode":"shadow"`, `"strictness":"standard"`, `"attack_mode":true`}
	for _, sub := range want {
		if !strings.Contains(string(body), sub) {
			t.Errorf("body missing %q: %s", sub, body)
		}
	}
}

func TestASNBlock_AppendDeleteRoundtrip(t *testing.T) {
	ts, _, tok := newTestServer(t)
	status, _ := do(t, ts, http.MethodPost, "/antibot/v1/policy/foo.example/asn_block", tok,
		`{"asn":15169}`)
	if status != http.StatusOK {
		t.Fatalf("append asn: %d", status)
	}
	status, body := do(t, ts, http.MethodGet, "/antibot/v1/policy/foo.example/asn_block", tok, "")
	if status != http.StatusOK || !strings.Contains(string(body), "15169") {
		t.Errorf("get asn: status=%d body=%s", status, body)
	}
	status, _ = do(t, ts, http.MethodDelete, "/antibot/v1/policy/foo.example/asn_block", tok,
		`{"asn":15169}`)
	if status != http.StatusOK {
		t.Errorf("delete asn: %d", status)
	}
	status, _ = do(t, ts, http.MethodDelete, "/antibot/v1/policy/foo.example/asn_block", tok,
		`{"asn":15169}`)
	if status != http.StatusNotFound {
		t.Errorf("delete absent asn: %d, want 404", status)
	}
}
