// Integration tests of the handler plus the store against a real PostgreSQL.
// Gated on POSTGRES_TEST_DSN — the pattern from internal/dbloader/dbloader_test.go.
// Without a DSN the test calls SkipNow (local development without a database is not broken).
//
// Coverage:
//   - auth: bad token → 401, missing → 401, valid → 200
//   - PATCH attack_mode: a new site → the row is created with PoolDefault plus the patch;
//     an existing one → an UPSERT; an idempotent repeat → updated_at is not touched;
//     an invalid mode → 400 with no write; an unknown key → 400 from the strict decode
//   - PATCH multi-field: both apply atomically; an error in one means no
//     field is written
//   - JSONB array append/delete: dedup, 404 on a missing element, validation
//   - GET policy: 404 for a new host, equivalence with PoolDefault
//     after the first PATCH
//   - the logs sink is out of scope here: the API writes no audit table (see the B10 plan).
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

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/antibotapi"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/dbloader"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/logger"
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

	// A clean schema — DROP plus Migrate. The tests must not depend on their neighbours.
	tables := []string{
		// the legacy DB table is `fp_blocklist` (from 0001_init.sql),
		// NOT `tls_fp_blocklist` (the file-system name from the rename).
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

// do — an authorised (when token!="") HTTP request. It returns the status and the
// raw body for a later json.Unmarshal into concrete structures.
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
		{"valid", tok, http.StatusNotFound}, // a GET for a non-existent site is 404, but auth passed
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
	// The row is created with PoolDefault plus the patch.
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
	// The first PATCH creates the row.
	if status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/foo.example", tok, `{"attack_mode":true}`); status != http.StatusOK {
		t.Fatalf("first patch: %d", status)
	}
	var ts1 time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT updated_at FROM policy WHERE host='foo.example'`,
	).Scan(&ts1); err != nil {
		t.Fatalf("select1: %v", err)
	}
	// A short pause, so that NOW() is guaranteed to differ on the write.
	time.Sleep(50 * time.Millisecond)

	// A repeat of the same patch.
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
	// attack_mode=true is valid, but mode=invalid — the handler must return 400 and
	// NOT apply attack_mode.
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
	// GET array — it contains the element.
	status, body = do(t, ts, http.MethodGet, "/antibot/v1/policy/foo.example/ua_blacklist", tok, "")
	if status != http.StatusOK || !strings.Contains(string(body), `curl/[0-9]`) {
		t.Errorf("get: status=%d body=%s", status, body)
	}
	// Delete an existing one.
	status, _ = do(t, ts, http.MethodDelete, "/antibot/v1/policy/foo.example/ua_blacklist", tok,
		`{"pattern":"curl/[0-9]"}`)
	if status != http.StatusOK {
		t.Errorf("delete: status=%d", status)
	}
	// Delete a non-existent one → 404.
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
	// We expect PoolDefault plus attack_mode=true.
	want := []string{`"mode":"shadow"`, `"strictness":"standard"`, `"attack_mode":true`}
	for _, sub := range want {
		if !strings.Contains(string(body), sub) {
			t.Errorf("body missing %q: %s", sub, body)
		}
	}
}

func TestPatchOriginIP_RoundTrip(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	// Set a tenant origin_ip on a fresh site → row created, diff carries it.
	status, body := do(t, ts, http.MethodPatch, "/antibot/v1/policy/clientx.com", tok,
		`{"mode":"active","origin_ip":"203.0.113.9"}`)
	if status != http.StatusOK {
		t.Fatalf("patch: status=%d body=%s", status, body)
	}
	var r struct {
		Changed bool     `json:"changed"`
		Diff    []string `json:"diff"`
	}
	_ = json.Unmarshal(body, &r)
	if !r.Changed {
		t.Errorf("expected changed=true, body=%s", body)
	}
	var originIP string
	if err := pool.QueryRow(context.Background(),
		`SELECT origin_ip FROM policy WHERE host='clientx.com'`,
	).Scan(&originIP); err != nil {
		t.Fatalf("select: %v", err)
	}
	if originIP != "203.0.113.9" {
		t.Errorf("origin_ip = %q, want 203.0.113.9", originIP)
	}

	// GET surfaces it; clearing with "" works and is reflected.
	_, getBody := do(t, ts, http.MethodGet, "/antibot/v1/policy/clientx.com", tok, "")
	if !strings.Contains(string(getBody), `"origin_ip":"203.0.113.9"`) {
		t.Errorf("GET missing origin_ip: %s", getBody)
	}
	if status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/clientx.com", tok,
		`{"origin_ip":""}`); status != http.StatusOK {
		t.Fatalf("clear patch failed: %d", status)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT origin_ip FROM policy WHERE host='clientx.com'`,
	).Scan(&originIP); err != nil {
		t.Fatalf("select after clear: %v", err)
	}
	if originIP != "" {
		t.Errorf("origin_ip after clear = %q, want empty", originIP)
	}
}

func TestPatchOriginIP_Invalid_NotWritten(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	// A CIDR is not a bare address → 400, no row written.
	status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/clientx.com", tok,
		`{"origin_ip":"203.0.113.0/24"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", status)
	}
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM policy WHERE host='clientx.com'`,
	).Scan(&count); err != nil {
		t.Fatalf("select: %v", err)
	}
	if count != 0 {
		t.Errorf("row written despite invalid origin_ip (count=%d)", count)
	}
}

func TestASNBlock_MissingAsnField_400(t *testing.T) {
	// an empty body `{}` → asn=0 without an explicit required check
	// silently mutated ASN 0. Now it is an *int64 pointer plus a nil check.
	ts, pool, tok := newTestServer(t)
	cases := []struct{ name, body string }{
		{"empty object", `{}`},
		{"asn null", `{"asn":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name+"_append", func(t *testing.T) {
			status, body := do(t, ts, http.MethodPost,
				"/antibot/v1/policy/foo.example/asn_block", tok, tc.body)
			if status != http.StatusBadRequest {
				t.Errorf("status=%d body=%s, want 400 missing_asn", status, body)
			}
		})
		t.Run(tc.name+"_delete", func(t *testing.T) {
			status, body := do(t, ts, http.MethodDelete,
				"/antibot/v1/policy/foo.example/asn_block", tok, tc.body)
			if status != http.StatusBadRequest {
				t.Errorf("status=%d body=%s, want 400 missing_asn", status, body)
			}
		})
	}
	// Not a single row after the series of bad requests — the site is untouched.
	var count int
	_ = pool.QueryRow(context.Background(),
		`SELECT count(*) FROM policy WHERE host='foo.example'`,
	).Scan(&count)
	if count != 0 {
		t.Errorf("row created on missing-asn requests: count=%d", count)
	}
}

func TestDeletePolicy_RoundTrip(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	const site = "del-me.example"

	// We create the host with the first mutation.
	if status, body := do(t, ts, http.MethodPatch, "/antibot/v1/policy/"+site, tok,
		`{"attack_mode":true}`); status != http.StatusOK {
		t.Fatalf("seed patch: status=%d body=%s", status, body)
	}
	// GET sees it.
	if status, _ := do(t, ts, http.MethodGet, "/antibot/v1/policy/"+site, tok, ""); status != http.StatusOK {
		t.Fatalf("get before delete: status=%d, want 200", status)
	}

	// DELETE the whole host.
	status, body := do(t, ts, http.MethodDelete, "/antibot/v1/policy/"+site, tok, "")
	if status != http.StatusOK || !strings.Contains(string(body), `"changed":true`) {
		t.Fatalf("delete: status=%d body=%s", status, body)
	}
	// The row physically disappeared from the database.
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM policy WHERE host=$1`, site,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("row still present after delete: count=%d", count)
	}
	// GET is now 404.
	if status, _ := do(t, ts, http.MethodGet, "/antibot/v1/policy/"+site, tok, ""); status != http.StatusNotFound {
		t.Errorf("get after delete: status=%d, want 404", status)
	}
}

func TestDeletePolicy_Absent_404(t *testing.T) {
	ts, _, tok := newTestServer(t)
	status, _ := do(t, ts, http.MethodDelete, "/antibot/v1/policy/never-existed.example", tok, "")
	if status != http.StatusNotFound {
		t.Errorf("delete absent host: status=%d, want 404", status)
	}
}

// doNoFatal — a concurrency-safe HTTP helper: it does NOT call t.Fatalf
// (the testing.T.FailNow family is undefined behaviour outside the test goroutine, see the Go testing docs).
// It returns only err; the status does not interest us in concurrency tests —
// the final state is asserted through a SELECT from the database after the Wait.
func doNoFatal(ts *httptest.Server, method, path, token, body string) error {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, rdr)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// TestPatchScalars_ConcurrentDifferentFields covers review finding #1:
// two concurrent PATCHes to DIFFERENT scalars must not clobber each other.
// Before the fix, `UPDATE ... SET mode=$2, strictness=$3, attack_mode=$4` silently
// rolled back the other field; now the UPSERT-with-lock serialises the PATCHes, the
// loser sees the updated state and preserves what was already applied.
func TestPatchScalars_ConcurrentDifferentFields(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	const site = "concurrent.example"

	const N = 8
	errCh := make(chan error, N*2)
	done := make(chan struct{}, N*2)
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			if err := doNoFatal(ts, http.MethodPatch,
				"/antibot/v1/policy/"+site, tok, `{"mode":"active"}`); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			if err := doNoFatal(ts, http.MethodPatch,
				"/antibot/v1/policy/"+site, tok, `{"strictness":"permissive"}`); err != nil {
				errCh <- err
			}
		}()
	}
	for i := 0; i < N*2; i++ {
		<-done
	}
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent PATCH transport error: %v", err)
	}

	var mode, strictness string
	if err := pool.QueryRow(context.Background(),
		`SELECT mode, strictness FROM policy WHERE host=$1`, site,
	).Scan(&mode, &strictness); err != nil {
		t.Fatalf("select: %v", err)
	}
	// The final state: BOTH mutations must be applied (either winner
	// between mode=active and strictness=permissive).
	if mode != "active" {
		t.Errorf("mode=%q, want active (concurrent strictness PATCH overwrote it — lost-update regression)", mode)
	}
	if strictness != "permissive" {
		t.Errorf("strictness=%q, want permissive (concurrent mode PATCH overwrote it — lost-update regression)", strictness)
	}
}

// TestRemoveASN_ConcurrentAppendNotLost covers review finding #2:
// a concurrent AppendASN that committed between the CTE snapshot and the UPDATE
// was silently lost in the old implementation. After the fix (new_arr as a subquery
// in the SET) the operation is atomic.
func TestRemoveASN_ConcurrentAppendNotLost(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	const site = "remove-race.example"

	// Seed the initial state.
	if status, _ := do(t, ts, http.MethodPost,
		"/antibot/v1/policy/"+site+"/asn_block", tok, `{"asn":100}`); status != http.StatusOK {
		t.Fatalf("seed 100: %d", status)
	}
	if status, _ := do(t, ts, http.MethodPost,
		"/antibot/v1/policy/"+site+"/asn_block", tok, `{"asn":200}`); status != http.StatusOK {
		t.Fatalf("seed 200: %d", status)
	}

	// In parallel: DELETE 100 and POST 300. If RemoveASN uses a
	// stale snapshot, 300 is lost (asn_block becomes [200] instead of [200,300]).
	errCh := make(chan error, 2)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		if err := doNoFatal(ts, http.MethodDelete,
			"/antibot/v1/policy/"+site+"/asn_block", tok, `{"asn":100}`); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if err := doNoFatal(ts, http.MethodPost,
			"/antibot/v1/policy/"+site+"/asn_block", tok, `{"asn":300}`); err != nil {
			errCh <- err
		}
	}()
	<-done
	<-done
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent request transport error: %v", err)
	}

	var raw []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT asn_block::text FROM policy WHERE host=$1`, site,
	).Scan(&raw); err != nil {
		t.Fatalf("select: %v", err)
	}
	got := string(raw)
	// The final state must contain 200 and 300; 100 may or may not be there, depending
	// on the commit order of DELETE versus POST 300, but 300 must DEFINITELY be.
	if !strings.Contains(got, "200") {
		t.Errorf("asn_block=%s, lost 200", got)
	}
	if !strings.Contains(got, "300") {
		t.Errorf("asn_block=%s, lost concurrent append of 300 (lost-update regression)", got)
	}
}

// TestDeletePolicy_ConcurrentAppend — a smoke test: a DELETE of the whole host and a
// POST append to that same host run in parallel and must not panic,
// tear transactions apart, or leave a row written in a "holed" state.
// The invariant checked: "the row exists ⟹ the value was written".
//
// NOTE — this is NOT a regression guard for the silent-loss bug
// The real guarantee is the row lock in ensureRowTx (`DO UPDATE SET host=EXCLUDED.host`,
// see store.go), not this test. That bug showed up as "the append returned 200
// changed:false while the row ended up deleted"; under the buggy code EVERY
// possible interleaving produced either "no row" or "a row WITH the
// pattern" — never "a row without the pattern". This test's final SELECT invariant
// is green on the buggy code too (the "no row" outcome is treated here
// as a pass), so it does not distinguish the regression. Catching silent loss
// deterministically through the database state after a race is impossible — it is about a lying
// HTTP response rather than the final state. We keep it as protection against gross
// breakage of the concurrent path.
func TestDeletePolicy_ConcurrentAppend(t *testing.T) {
	ts, pool, tok := newTestServer(t)
	const site = "del-append-race.example"
	const pattern = "curl/[0-9]"

	// We seed the row with the first mutation, so that the append hits the ensure conflict.
	if status, _ := do(t, ts, http.MethodPatch, "/antibot/v1/policy/"+site, tok,
		`{"attack_mode":true}`); status != http.StatusOK {
		t.Fatalf("seed: %d", status)
	}

	errCh := make(chan error, 2)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		if err := doNoFatal(ts, http.MethodDelete, "/antibot/v1/policy/"+site, tok, ""); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if err := doNoFatal(ts, http.MethodPost, "/antibot/v1/policy/"+site+"/ua_blacklist", tok,
			`{"pattern":"`+pattern+`"}`); err != nil {
			errCh <- err
		}
	}()
	<-done
	<-done
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent request transport error: %v", err)
	}

	// The invariant: if the row exists, it MUST contain the appended
	// pattern. "The row exists but the value does not" is a silent-loss regression.
	var raw []byte
	err := pool.QueryRow(context.Background(),
		`SELECT ua_blacklist::text FROM policy WHERE host=$1`, site,
	).Scan(&raw)
	if err != nil {
		// There is no row — the DELETE won. An acceptable outcome.
		return
	}
	if !strings.Contains(string(raw), pattern) {
		t.Errorf("row present but appended pattern lost: ua_blacklist=%s (silent-loss regression)", raw)
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
