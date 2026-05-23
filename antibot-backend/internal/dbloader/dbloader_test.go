// Интеграционные тесты dbloader идут через реальный PostgreSQL: эмулировать
// pgxpool слой надёжно нечем (sqlmock не покрывает pgx-протокол). Гейтятся
// переменной POSTGRES_TEST_DSN; в CI или при `make test-it` поднимается
// postgres:16-alpine через docker и DSN экспортируется.
//
// Если DSN не задан — тесты SkipNow'ятся, локальная разработка без БД
// не ломается.
package dbloader_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
	"github.com/tabularasa31/antibot-backend/internal/dbloader"
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

// resetSchema — DROP всех таблиц схемы и повторное Migrate. Используем
// вместо TRUNCATE, чтобы любые ALTER'ы из будущих миграций не "залипали"
// между тестами.
func resetSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	tables := []string{
		"catalog_version", "fp_blocklist", "ua_blacklist",
		"ip_blocklist", "ip_whitelist", "asn_datacenters",
		"verified_bot_ips", "policy",
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

func TestMigrate_Idempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)
	// Re-apply без DROP — миграция написана через CREATE IF NOT EXISTS,
	// должна пройти без ошибок и не дублировать singleton-ряд
	// catalog_version.
	if err := dbloader.Migrate(ctx, pool); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM catalog_version").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("catalog_version rows = %d, want 1 (singleton)", count)
	}
}

func TestLoad_EmptyDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	d, err := dbloader.Load(ctx, pool)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d.Version != "1.0.0" {
		t.Errorf("version=%q, want 1.0.0", d.Version)
	}
	if len(d.Policy) != 0 || len(d.FPBlocklist) != 0 {
		t.Errorf("empty DB should produce empty maps, got policy=%d fp=%d", len(d.Policy), len(d.FPBlocklist))
	}
}

func TestLoad_RoundTripPolicy(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `INSERT INTO fp_blocklist (fp) VALUES ('L13i17h2_abc_def')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ua_blacklist (pattern) VALUES ('curl/.*')`); err != nil {
		t.Fatal(err)
	}

	d, err := dbloader.Load(ctx, pool)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := d.Policy["shop.example.com"]
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
	if d.FPBlocklist["L13i17h2_abc_def"] != "block" {
		t.Errorf("fp_blocklist not loaded: %+v", d.FPBlocklist)
	}
	if len(d.UABlacklist) != 1 || d.UABlacklist[0] != "curl/.*" {
		t.Errorf("UABlacklist=%v", d.UABlacklist)
	}
}

func TestLoad_StagingFiltered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	// staging-строки НЕ должны попасть в активный каталог (B4 отдает
	// только status='active'; staging-канал — отдельная задача A11).
	if _, err := pool.Exec(ctx, `
		INSERT INTO ua_blacklist (pattern, status)
		VALUES ('active/.*', 'active'), ('staging/.*', 'staging')`); err != nil {
		t.Fatal(err)
	}
	d, err := dbloader.Load(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.UABlacklist) != 1 || d.UABlacklist[0] != "active/.*" {
		t.Errorf("UABlacklist should only include active rows, got %v", d.UABlacklist)
	}
}

func TestLoad_RejectsInvalidRegex(t *testing.T) {
	// Codex PR-43 review (P1): DB-источник обязан валидировать regex'ы
	// так же, как LoadYAML — иначе битый паттерн в `ua_blacklist` уехал
	// бы в combined regex на edge и положил UA-стадию по всему пулу.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	// Системный ua_blacklist с битым regex'ом.
	if _, err := pool.Exec(ctx, `INSERT INTO ua_blacklist (pattern) VALUES ('bot[a-z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbloader.Load(ctx, pool); err == nil {
		t.Fatal("Load: ожидалась ошибка валидации regex, получили nil")
	}

	// Чистим, кладём такой же мусор уже в per-host policy.ua_blacklist.
	if _, err := pool.Exec(ctx, `DELETE FROM ua_blacklist`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, ua_blacklist) VALUES ('shop.example.com', '["(unbalanced"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbloader.Load(ctx, pool); err == nil {
		t.Fatal("Load: per-host битый regex тоже должен валить загрузку")
	}
}

func TestLoad_RejectsInvalidCIDR(t *testing.T) {
	// PR #43 review (Angle B): схема не держит inet-тип (валидация
	// делегирована loader'у), значит catalog.Validate ОБЯЗАН ловить
	// мусор. Проверяем системный ip_blocklist и per-host ip_whitelist.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	if _, err := pool.Exec(ctx, `INSERT INTO ip_blocklist (cidr) VALUES ('999.0.0.0/33')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbloader.Load(ctx, pool); err == nil {
		t.Fatal("Load: ожидалась ошибка валидации CIDR (системный ip_blocklist)")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM ip_blocklist`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO policy (host, ip_whitelist)
		VALUES ('shop.example.com', '["not-a-cidr"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbloader.Load(ctx, pool); err == nil {
		t.Fatal("Load: ожидалась ошибка валидации CIDR (per-host ip_whitelist)")
	}
}

func TestLoad_NormalizesJSONBNull(t *testing.T) {
	// PR #43 review (Angle A): jsonb-null в JSONB-колонке policy.* при
	// загрузке через unmarshalIfNonEmpty приходил как nil-slice, дальше
	// json.Marshal сериализовал его в `null`, а не `[]`. После фикса
	// normalize (в Store.Replace) должен coerce'нить nil → []T{}, чтобы
	// шов «нет записи vs nil-slice vs []» был незаметен наружу — payload
	// эджа стабильный, ETag не дрейфит.
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
	d, err := dbloader.Load(ctx, pool)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Прогон через Store.Replace вызывает normalize(); проверяем
	// итоговый payload, не сырое значение из Load.
	store := catalog.NewStore()
	store.Replace(d)
	snap, err := store.Snapshot("policy", "shop.example.com")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	body := string(snap.Body)
	// Без normalize — это были бы `"ua_blacklist":null` и т.д.
	for _, field := range []string{"ua_blacklist", "ip_whitelist", "ip_blocklist",
		"asn_block", "geo_whitelist", "rate_rules"} {
		nullForm := `"` + field + `":null`
		if strings.Contains(body, nullForm) {
			t.Errorf("payload содержит %q — normalize не coerce'нул jsonb-null в []: %s",
				nullForm, body)
		}
	}
}

func TestReloader_BootstrapAndTick(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openPool(t, ctx)
	resetSchema(t, ctx, pool)

	store := catalog.NewStore()
	r := dbloader.NewReloader(pool, store, 50*time.Millisecond, discardLogger(t), discardReg())
	if err := r.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !store.IsLoaded() {
		t.Fatal("Store not marked loaded after Bootstrap")
	}

	// Запускаем Run в фоне и мутируем БД — следующий тик должен подхватить.
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(runCtx) }()

	if _, err := pool.Exec(ctx, `INSERT INTO ip_whitelist (cidr) VALUES ('203.0.113.0/24')`); err != nil {
		t.Fatal(err)
	}

	// Polling: даём reloader'у до 2с подхватить — интервал 50мс,
	// в норме хватит ~100мс, но CI с busy postgres иногда медленнее.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := store.Snapshot("ip_whitelist", "")
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		if len(snap.Body) > len("[]") {
			runCancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Reloader did not pick up DB change within 2s")
}
