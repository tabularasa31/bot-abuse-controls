// Интеграционные тесты dbloader идут через реальный PostgreSQL: эмулировать
// pgxpool слой надёжно нечем (sqlmock не покрывает pgx-протокол). Гейтятся
// переменной POSTGRES_TEST_DSN; в CI или при `make test-it` поднимается
// postgres:16-alpine через docker и DSN экспортируется.
//
// Если DSN не задан — тесты SkipNow'ятся, локальная разработка без БД
// не ломается.
//
// После ADR-006 dbloader отвечает только за runtime-таблицы; slow-каталоги
// тестируются в internal/filesource. Reloader-тесты ниже используют пустой
// seed-каталог (только version), чтобы изолировать DB-часть.
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

// resetSchema — DROP всех потенциально существующих таблиц (включая
// исторические, дропнутые миграцией 0004) и повторное Migrate. Используем
// вместо TRUNCATE, чтобы любые ALTER'ы из будущих миграций не "залипали"
// между тестами.
func resetSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	tables := []string{
		// Текущие runtime-таблицы.
		"verified_bot_ips", "policy", "logs",
		// Дропнуты 0004, но возможны в старых БД — IF EXISTS защищает.
		// PR-62 audit: имя legacy DB-таблицы — `fp_blocklist` (из 0001),
		// НЕ `tls_fp_blocklist` (это file-system / wire-имя из PR-62 rename).
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

// seedCatalogs создаёт минимально валидный каталог-репо для filesource:
// пустые YAML-файлы + version. Возвращает Loader. Тесты, которые проверяют
// чисто DB-часть, кладут сюда пустые seed'ы — slow-слой в merge будет пустым.
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
	// Re-apply без DROP — миграции идемпотентны (IF NOT EXISTS на 0001/0002/0003
	// и IF EXISTS на 0004). После двух прогонов schema должна совпадать:
	// runtime-таблицы есть, slow-таблицы (включая catalog_version) — нет.
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

	// Insert: один host с богатым набором полей, чтобы покрыть все JSONB-
	// колонки и тайповые поля (mode/strictness/attack_mode).
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
	// Slow-каталоги переехали в файлы; здесь проверяем per-host policy:
	// оператор может записать битый regex через antibotapi → reloader
	// должен поймать его до Store.Replace, иначе combined regex положит
	// UA-стадию на эджах.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, ua_blacklist) VALUES ('shop.example.com', '["(unbalanced"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbloader.LoadRuntime(ctx, pool); err == nil {
		t.Fatal("LoadRuntime: per-host битый regex должен валить загрузку")
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
		t.Fatal("LoadRuntime: per-host битый CIDR должен валить загрузку")
	}
}

func TestLoadRuntime_NormalizesJSONBNull(t *testing.T) {
	// jsonb-null в JSONB-колонке policy.* приходил как nil-slice; normalize
	// в Store.Replace должен coerce'нить nil → []T{}, чтобы payload эджа
	// был стабильным (без `null` в JSON).
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

	// Прогон через Merge → Store.Replace вызывает normalize(); проверяем
	// итоговый payload, не сырое значение из LoadRuntime.
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
			t.Errorf("payload содержит %q — normalize не coerce'нул jsonb-null в []: %s",
				nullForm, body)
		}
	}
}

func TestNewReloader_RejectsZeroInterval(t *testing.T) {
	// Defense-in-depth: альтернативный caller с interval=0 раньше повесил
	// бы Bootstrap на already-expired ctx и `time.NewTicker(0)` запаниковал
	// бы в Run. Сейчас NewReloader явно отказывает.
	fl := seedCatalogs(t)
	if _, err := dbloader.NewReloader(nil, catalog.NewStore(), fl, 0, discardLogger(t), discardReg()); err == nil {
		t.Fatal("NewReloader: ожидалась ошибка при interval=0")
	}
	if _, err := dbloader.NewReloader(nil, catalog.NewStore(), fl, -1, discardLogger(t), discardReg()); err == nil {
		t.Fatal("NewReloader: ожидалась ошибка при interval<0")
	}
}

func TestNewReloader_RejectsNilFileLoader(t *testing.T) {
	// После ADR-006 fileLoader обязателен — без него merge выдал бы пустые
	// slow-каталоги, эдж бы получил «успешный» payload без записей,
	// которые продакт уже добавил в catalogs/ (silent regression).
	if _, err := dbloader.NewReloader(nil, catalog.NewStore(), nil, 5*time.Second, discardLogger(t), discardReg()); err == nil {
		t.Fatal("NewReloader: ожидалась ошибка при fileLoader=nil")
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
	// Version приходит из файла version (1.0.0).
	snap, err := store.Snapshot("policy", "")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Version != "1.0.0" {
		t.Errorf("Snapshot.Version=%q want 1.0.0 (из catalogs/version)", snap.Version)
	}

	// Запускаем Run в фоне и мутируем БД — следующий тик должен подхватить
	// new policy row.
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(runCtx) }()

	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, mode) VALUES ('shop.example.com', 'active')`); err != nil {
		t.Fatal(err)
	}

	// Polling: ждём до 2с появления policy[shop] в Store.
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
