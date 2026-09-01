// The dbloader integration tests run against a real PostgreSQL: there is nothing reliable
// to emulate the pgxpool layer with (sqlmock does not cover the pgx protocol). They are gated on
// the POSTGRES_TEST_DSN variable; in CI or under `make test-it` a
// postgres:16-alpine is brought up through docker and the DSN is exported.
//
// When the DSN is unset the tests call SkipNow, so local development without a database
// is not broken.
//
// After ADR-006 dbloader is responsible only for the runtime tables; the slow catalogs are
// tested in internal/filesource. The reloader tests below use an empty
// seed catalog (version only), to isolate the DB part.
package dbloader_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
	"github.com/tabularasa31/antibot-backend/internal/dbloader"
	"github.com/tabularasa31/antibot-backend/internal/filesource"
)

func dsn(t *testing.T) string {
	t.Helper()
	v := os.Getenv("POSTGRES_TEST_DSN")
	if v == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping dbloader integration test")
	}
	return v
}

func openPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn(t))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// resetSchema — DROPs every potentially existing table (including the
// historical ones dropped by migration 0004) and runs Migrate again. We use it
// instead of TRUNCATE, so that any ALTERs from future migrations do not "stick"
// between tests.
func resetSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	tables := []string{
		// The current runtime tables.
		"verified_bot_ips", "policy", "logs",
		// Dropped by 0004, but possible in older databases — IF EXISTS protects us.
		// From audit: the legacy DB table name is `fp_blocklist` (from 0001),
		// NOT `tls_fp_blocklist` (that is the file-system / wire name from the rename).
		"catalog_version", "fp_blocklist", "ua_blacklist",
		"ip_blocklist", "ip_whitelist", "asn_datacenters",
	}
	for _, tbl := range tables {
		if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS "+tbl); err != nil {
			t.Fatalf("drop %s: %v", tbl, err)
		}
	}
	if err := dbloader.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// seedCatalogs creates a minimally valid catalog repo for filesource:
// empty YAML files plus a version. It returns the Loader. Tests that check
// purely the DB part put empty seeds here — the slow layer in the merge will be empty.
func seedCatalogs(t *testing.T) *filesource.Loader {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"version":               "1.0.0\n",
		"tls_fp_blocklist.yaml": "# empty\n",
		"ua_blacklist.yaml":     "# empty\n",
		"ip_blocklist.yaml":     "# empty\n",
		"ip_whitelist.yaml":     "# empty\n",
		"asn_datacenters.yaml":  "# empty\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filesource.New(dir)
}

func TestMigrate_Idempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)
	// A re-apply without a DROP — the migrations are idempotent (IF NOT EXISTS on 0001/0002/0003
	// and IF EXISTS on 0004). After two runs the schema must match:
	// the runtime tables exist and the slow tables (catalog_version included) do not.
	if err := dbloader.Migrate(ctx, pool); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	for _, expected := range []string{"verified_bot_ips", "policy"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
                           WHERE table_schema='public' AND table_name=$1)`,
			expected).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("expected runtime table %q to exist after Migrate", expected)
		}
	}
	for _, dropped := range []string{"catalog_version", "tls_fp_blocklist", "ua_blacklist", "ip_blocklist", "ip_whitelist", "asn_datacenters"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
                           WHERE table_schema='public' AND table_name=$1)`,
			dropped).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Errorf("table %q should be dropped by migration 0004, but exists", dropped)
		}
	}
}

func TestLoadRuntime_EmptyDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	r, err := dbloader.LoadRuntime(ctx, pool)
	if err != nil {
		t.Fatalf("LoadRuntime: %v", err)
	}
	if len(r.Policy) != 0 || len(r.VerifiedBotIPs) != 0 {
		t.Errorf("empty DB should produce empty runtime, got policy=%d verified=%d", len(r.Policy), len(r.VerifiedBotIPs))
	}
}

func TestLoadRuntime_RoundTripPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	// Insert: one host with a rich field set, to cover every JSONB
	// column and typed field (mode/strictness/attack_mode).
	_, err := pool.Exec(ctx, `
		INSERT INTO policy (host, mode, strictness, attack_mode,
		                    ua_blacklist, ip_whitelist, ip_blocklist,
		                    asn_block, geo_whitelist, rate_rules)
		VALUES ('shop.example.com', 'active', 'standard', true,
		        $1, $2, $3, $4, $5, $6)`,
		`["evil-scraper/.*"]`,
		`["198.51.100.99/32"]`,
		`["192.0.2.10/32"]`,
		`[12345, 67890]`,
		`["RU", "BY"]`,
		`[{"path":"/login","methods":["POST"],"rps":5,"burst":10,"action":"challenge"}]`,
	)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	r, err := dbloader.LoadRuntime(ctx, pool)
	if err != nil {
		t.Fatalf("LoadRuntime: %v", err)
	}
	p, ok := r.Policy["shop.example.com"]
	if !ok {
		t.Fatal("policy[shop] missing")
	}
	if p.Mode != "active" || p.Strictness != "standard" || !p.AttackMode {
		t.Errorf("policy[shop] tail fields = %+v", p)
	}
	if len(p.UABlacklist) != 1 || p.UABlacklist[0] != "evil-scraper/.*" {
		t.Errorf("UABlacklist=%v", p.UABlacklist)
	}
	if len(p.RateRules) != 1 || p.RateRules[0].Action != "challenge" || p.RateRules[0].RPS != 5 {
		t.Errorf("RateRules=%+v", p.RateRules)
	}
	if len(p.ASNBlock) != 2 || p.ASNBlock[0] != 12345 {
		t.Errorf("ASNBlock=%v", p.ASNBlock)
	}
}

func TestLoadRuntime_RejectsInvalidPolicyRegex(t *testing.T) {
	// The slow catalogs moved into files; here we check the per-host policy:
	// an operator can write a broken regex through antibotapi → the reloader
	// must catch it before Store.Replace, otherwise the combined regex takes the
	// UA stage down across the edges.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, ua_blacklist) VALUES ('shop.example.com', '["(unbalanced"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbloader.LoadRuntime(ctx, pool); err == nil {
		t.Fatal("LoadRuntime: a broken per-host regex must fail the load")
	}
}

func TestLoadRuntime_RejectsInvalidPolicyCIDR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, ip_whitelist)
		VALUES ('shop.example.com', '["not-a-cidr"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbloader.LoadRuntime(ctx, pool); err == nil {
		t.Fatal("LoadRuntime: a broken per-host CIDR must fail the load")
	}
}

func TestLoadRuntime_NormalizesJSONBNull(t *testing.T) {
	// A jsonb null in a policy.* JSONB column arrived as a nil slice; normalize
	// in Store.Replace must coerce nil → []T{}, so that the edge payload
	// is stable (with no `null` in the JSON).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, mode, strictness, ua_blacklist,
		                    ip_whitelist, ip_blocklist, asn_block,
		                    geo_whitelist, rate_rules)
		VALUES ('shop.example.com', 'shadow', 'standard',
		        'null'::jsonb, 'null'::jsonb, 'null'::jsonb,
		        'null'::jsonb, 'null'::jsonb, 'null'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	r, err := dbloader.LoadRuntime(ctx, pool)
	if err != nil {
		t.Fatalf("LoadRuntime: %v", err)
	}

	// A run through Merge → Store.Replace calls normalize(); we check the
	// final payload rather than the raw value from LoadRuntime.
	store := catalog.NewStore()
	store.Replace(catalog.Merge(nil, r))
	snap, err := store.Snapshot("policy", "shop.example.com")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	body := string(snap.Body)
	for _, field := range []string{
		"ua_blacklist", "ip_whitelist", "ip_blocklist",
		"asn_block", "geo_whitelist", "rate_rules",
	} {
		nullForm := `"` + field + `":null`
		if strings.Contains(body, nullForm) {
			t.Errorf("the payload contains %q — normalize did not coerce the jsonb null into []: %s",
				nullForm, body)
		}
	}
}

func TestNewReloader_RejectsZeroInterval(t *testing.T) {
	// Defence in depth: an alternative caller with interval=0 used to hang
	// Bootstrap on an already-expired ctx, and `time.NewTicker(0)` would panic
	// in Run. NewReloader now refuses explicitly.
	fl := seedCatalogs(t)
	if _, err := dbloader.NewReloader(nil, catalog.NewStore(), fl, 0, discardLogger(t), discardReg()); err == nil {
		t.Fatal("NewReloader: an error was expected with interval=0")
	}
	if _, err := dbloader.NewReloader(nil, catalog.NewStore(), fl, -1, discardLogger(t), discardReg()); err == nil {
		t.Fatal("NewReloader: an error was expected with interval<0")
	}
}

func TestNewReloader_RejectsNilFileLoader(t *testing.T) {
	// After ADR-006 the fileLoader is mandatory — without it the merge would produce empty
	// slow catalogs and the edge would get a "successful" payload missing the records
	// product had already added to catalogs/ (a silent regression).
	if _, err := dbloader.NewReloader(nil, catalog.NewStore(), nil, 5*time.Second, discardLogger(t), discardReg()); err == nil {
		t.Fatal("NewReloader: an error was expected with fileLoader=nil")
	}
}

func TestReloader_BootstrapAndTick(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	fl := seedCatalogs(t)
	store := catalog.NewStore()
	r, err := dbloader.NewReloader(pool, store, fl, 50*time.Millisecond, discardLogger(t), discardReg())
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	if err := r.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !store.IsLoaded() {
		t.Fatal("Store not marked loaded after Bootstrap")
	}
	// The version comes from the version file (1.0.0).
	snap, err := store.Snapshot("policy", "")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Version != "1.0.0" {
		t.Errorf("Snapshot.Version=%q want 1.0.0 (from catalogs/version)", snap.Version)
	}

	// We start Run in the background and mutate the database — the next tick must pick it up
	// new policy row.
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(runCtx) }()

	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, mode) VALUES ('shop.example.com', 'active')`); err != nil {
		t.Fatal(err)
	}

	// Polling: we wait up to 2 s for policy[shop] to appear in the Store.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := store.Snapshot("policy", "shop.example.com")
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		if strings.Contains(string(snap.Body), `"mode":"active"`) {
			runCancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Reloader did not pick up DB change within 2s")
}
