// Package dbloader — источник *catalog.Data из PostgreSQL ([B4]).
//
// Заменяет YAML-источник из B3 для прод-демо: backend стартует, прогоняет
// миграции (Migrate), затем периодически (Reloader) вычитывает все восемь
// каталогов в *catalog.Data и публикует через Store.Replace. Контракт
// Store.Replace не меняется — server/Snapshot/build* не отличают YAML
// source от DB source.
//
// Запросы идут одной транзакцией на тик, чтобы не получить data race
// между ip_blocklist и policy при параллельной правке оператором; pgx
// делает это дёшево.
package dbloader

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrateAdvisoryLockKey — произвольный 64-битный const'a для
// `pg_advisory_lock`. Изоляция от чужих lock'ов через random magic;
// `crc64(...)`-подобной схемы не используем, чтобы не зависеть от того,
// как именно генерируется ключ.
const migrateAdvisoryLockKey int64 = 0x616E7469626F7402 // "antibo\x02"

// Migrate выполняет встроенные SQL-файлы из migrations/ в лексикографическом
// порядке. Файлы написаны идемпотентно через CREATE TABLE IF NOT EXISTS,
// так что переприменение безопасно. Тяжёлую миграционную инфраструктуру
// (схема версий, down-шаги) принесёт B15 — пока хватает дёшевого ratchet'a.
//
// Concurrency: HA-пара backend'ов из `infra/demo-backend/` стартует обе
// реплики одновременно. На сегодняшнем 0001 это безвредно (только
// IF NOT EXISTS + ON CONFLICT DO NOTHING), но первая же non-idempotent DDL
// в 0002 даст один реплике 'relation already exists' и crash-loop.
// Берём session-scoped pg_advisory_lock — вторая реплика блокируется,
// пока первая не закончит, потом просто видит, что всё уже есть.
// PR #43 review (Angle B).
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	// Берём один коннект из пула и держим advisory lock в его scope;
	// pg_advisory_unlock на defer гарантирует, что лок отпустится даже
	// если миграция упала (а если коннект всё равно дропается — Postgres
	// автоматически снимает session-locks при close).
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn for migrate: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateAdvisoryLockKey); err != nil {
		return fmt.Errorf("pg_advisory_lock: %w", err)
	}
	defer func() {
		// Best-effort unlock. Используем СВОЙ короткий ctx, а не родительский
		// (родительский может быть уже cancel'нут — SIGTERM в середине
		// миграции), иначе `conn.Exec(canceled, …)` тихо возвращает ошибку
		// БЕЗ отправки SQL, лок остаётся на сессии, conn уезжает обратно в
		// пул живой → соседняя реплика блокируется до того, как pgxpool
		// отпустит коннект (MaxConnLifetime, по умолчанию час+). PR #43
		// review (Angle B).
		// context.WithoutCancel: сохраняем values из родителя (трейсинг,
		// логгер-keys), но рвём cancellation — нужно ИМЕННО чтобы
		// canceled-родитель не задушил unlock-Exec.
		releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer releaseCancel()
		_, _ = conn.Exec(releaseCtx, `SELECT pg_advisory_unlock($1)`, migrateAdvisoryLockKey)
	}()

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read embed migrations: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		// Один Exec на весь файл — pgx умеет multi-statement strings.
		// Если оператор ломает файл (синтаксис), валимся на старте,
		// не делая backend живым с частично применённой схемой.
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("apply %s: %w", e.Name(), err)
		}
	}
	return nil
}

// Load читает все каталоги одной read-only транзакцией и возвращает
// готовый *catalog.Data. catalog.Store.Replace сам нормализует payload
// (dedup+sort), но дешевле и предсказуемее, если БД уже отдаёт стабильный
// порядок (ORDER BY) — diff'ы между тиками тогда тривиально читаемы в
// логах debug-вывода.
func Load(ctx context.Context, pool *pgxpool.Pool) (*catalog.Data, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	d := &catalog.Data{
		FPBlocklist:    map[string]string{},
		IPBlocklist:    map[string]string{},
		VerifiedBotIPs: map[string]string{},
		Policy:         map[string]catalog.Policy{},
	}

	// version: singleton row. Если ряд исчез (оператор стрелял ногу),
	// валимся — лучше явный fail-stale на эджах, чем X-Catalog-Version=""
	// (см. data.go про обязательность semver).
	if err := tx.QueryRow(ctx, `SELECT version FROM catalog_version WHERE id = 1`).Scan(&d.Version); err != nil {
		return nil, fmt.Errorf("catalog_version: %w", err)
	}

	if err := loadKVString(ctx, tx, &d.FPBlocklist,
		`SELECT fp, 'block' FROM fp_blocklist WHERE status = 'active' ORDER BY fp`); err != nil {
		return nil, err
	}
	if err := loadStringList(ctx, tx, &d.UABlacklist,
		`SELECT pattern FROM ua_blacklist WHERE status = 'active' ORDER BY pattern`); err != nil {
		return nil, err
	}
	if err := loadKVString(ctx, tx, &d.IPBlocklist,
		`SELECT cidr, 'block' FROM ip_blocklist WHERE status = 'active' ORDER BY cidr`); err != nil {
		return nil, err
	}
	if err := loadStringList(ctx, tx, &d.IPWhitelist,
		`SELECT cidr FROM ip_whitelist ORDER BY cidr`); err != nil {
		return nil, err
	}
	if err := loadUint32List(ctx, tx, &d.ASNDatacenters,
		`SELECT asn FROM asn_datacenters ORDER BY asn`); err != nil {
		return nil, err
	}
	// verified_bot_ips: rDNS-воркер ([B7]) пишет ОБА исхода — verified и rejected
	// (vision §Шаг 2.2 + entities-reference.md bot_verification_status). Edge
	// различает их по значению — поэтому в payload идёт "<status>:<family>",
	// не просто family. expires_at > NOW() отсекает протухшие записи на
	// уровне БД: edge видит "ключа нет" и идёт по provisional fastpath, а
	// не по устаревшему verdict'у. Сам DELETE протухших строк — на воркере
	// (GC-тик); фильтр здесь — defence-in-depth, чтобы корректность не
	// зависела от того, успел ли GC. Миграция 0002 завела status/expires_at.
	if err := loadKVString(ctx, tx, &d.VerifiedBotIPs,
		`SELECT ip, status || ':' || bot_name FROM verified_bot_ips
		 WHERE expires_at > NOW() ORDER BY ip`); err != nil {
		return nil, err
	}
	if err := loadPolicy(ctx, tx, d); err != nil {
		return nil, err
	}
	// Те же regex-валидации, что в catalog.LoadYAML: один битый паттерн в
	// `ua_blacklist` / `policy[*].ua_blacklist` иначе уехал бы на edge внутри
	// combined regex и положил UA-стадию по всему пулу. Лучше fail-stale на
	// одном тике reloader'a, чем сломанный edge — Store при ошибке Load
	// не обновляется (см. Reloader.tick).
	if err := catalog.Validate(d); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	return d, nil
}

func loadKVString(ctx context.Context, tx pgx.Tx, dst *map[string]string, sql string) error {
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return fmt.Errorf("query %q: %w", sql, err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return fmt.Errorf("scan %q: %w", sql, err)
		}
		(*dst)[k] = v
	}
	return rows.Err()
}

func loadStringList(ctx context.Context, tx pgx.Tx, dst *[]string, sql string) error {
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return fmt.Errorf("query %q: %w", sql, err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return fmt.Errorf("scan %q: %w", sql, err)
		}
		*dst = append(*dst, s)
	}
	return rows.Err()
}

func loadUint32List(ctx context.Context, tx pgx.Tx, dst *[]uint32, sql string) error {
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return fmt.Errorf("query %q: %w", sql, err)
	}
	defer rows.Close()
	for rows.Next() {
		var n int64
		if err := rows.Scan(&n); err != nil {
			return fmt.Errorf("scan %q: %w", sql, err)
		}
		if n < 0 || n > 0xFFFFFFFF {
			return fmt.Errorf("asn out of uint32 range: %d", n)
		}
		*dst = append(*dst, uint32(n)) //nolint:gosec // G115: bounds checked on the line above
	}
	return rows.Err()
}

// loadPolicy читает строки `policy` и распаковывает JSONB-поля в срезы.
// Каждое JSONB поле декодируется отдельно — это позволяет в будущем
// добавлять поля без миграции (с осторожностью: новое поле должно быть
// optional и иметь дефолт).
func loadPolicy(ctx context.Context, tx pgx.Tx, d *catalog.Data) error {
	rows, err := tx.Query(ctx, `
		SELECT host, mode, strictness, attack_mode,
		       ua_blacklist, ip_whitelist, ip_blocklist,
		       asn_block, geo_whitelist, rate_rules
		FROM policy
		ORDER BY host`)
	if err != nil {
		return fmt.Errorf("query policy: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			host                                                        string
			p                                                           catalog.Policy
			uaJSON, ipWLJSON, ipBLJSON, asnJSON, geoJSON, rateRulesJSON []byte
		)
		if err := rows.Scan(
			&host, &p.Mode, &p.Strictness, &p.AttackMode,
			&uaJSON, &ipWLJSON, &ipBLJSON, &asnJSON, &geoJSON, &rateRulesJSON,
		); err != nil {
			return fmt.Errorf("scan policy: %w", err)
		}
		if err := unmarshalIfNonEmpty(uaJSON, &p.UABlacklist); err != nil {
			return fmt.Errorf("policy[%s].ua_blacklist: %w", host, err)
		}
		if err := unmarshalIfNonEmpty(ipWLJSON, &p.IPWhitelist); err != nil {
			return fmt.Errorf("policy[%s].ip_whitelist: %w", host, err)
		}
		if err := unmarshalIfNonEmpty(ipBLJSON, &p.IPBlocklist); err != nil {
			return fmt.Errorf("policy[%s].ip_blocklist: %w", host, err)
		}
		if err := unmarshalIfNonEmpty(asnJSON, &p.ASNBlock); err != nil {
			return fmt.Errorf("policy[%s].asn_block: %w", host, err)
		}
		if err := unmarshalIfNonEmpty(geoJSON, &p.GeoWhitelist); err != nil {
			return fmt.Errorf("policy[%s].geo_whitelist: %w", host, err)
		}
		if err := unmarshalIfNonEmpty(rateRulesJSON, &p.RateRules); err != nil {
			return fmt.Errorf("policy[%s].rate_rules: %w", host, err)
		}
		d.Policy[host] = p
	}
	return rows.Err()
}

func unmarshalIfNonEmpty(b []byte, dst any) error {
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, dst)
}
