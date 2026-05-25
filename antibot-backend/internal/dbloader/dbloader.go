// Package dbloader — источник runtime-слоя каталогов из PostgreSQL.
//
// После ADR-006 в БД лежат только данные, которые меняются автоматически
// (SLA ≤ 30 сек) и не подходят файлам по природе: `verified_bot_ips`
// пишет rDNS-воркер ([B7]), `policy` — antibotapi из дашборда ([B10]).
// Курируемые продактом «медленные» каталоги (fp_blocklist, ua_blacklist,
// ip_blocklist, ip_whitelist, asn_datacenters) переехали в git-репо
// catalogs/ и грузятся через internal/filesource.
//
// LoadRuntime читает только runtime-таблицы одной read-only транзакцией.
// Reloader мерджит её результат с *catalog.SlowData из filesource и
// публикует объединённый snapshot через Store.Replace — контракт
// Store/Snapshot/build* не меняется.
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

// LoadRuntime читает только runtime-таблицы (verified_bot_ips, policy)
// одной read-only транзакцией. Слой медленных каталогов теперь живёт в
// файлах (см. internal/filesource), мерджится в *catalog.Data в reloader.
//
// Версия каталога (для X-Catalog-Version) приходит из файла
// catalogs/version, не из БД — таблицу `catalog_version` дропнули в
// миграции 0004.
//
// Валидация regex/CIDR для per-host policy остаётся: оператор может
// записать битый policy.ua_blacklist через antibotapi, и без проверки на
// этом шаге combined regex положил бы UA-стадию на пуле эджей.
// Store.Replace не вызовется, если LoadRuntime вернул ошибку — эдж
// продолжит работать с предыдущим хорошим snapshot'ом (fail-stale).
func LoadRuntime(ctx context.Context, pool *pgxpool.Pool) (*catalog.RuntimeData, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	r := &catalog.RuntimeData{
		VerifiedBotIPs: map[string]string{},
		Policy:         map[string]catalog.Policy{},
	}

	// verified_bot_ips: rDNS-воркер ([B7]) пишет ОБА исхода — verified и rejected
	// (vision §Шаг 2.2 + entities-reference.md bot_verification_status). Edge
	// различает их по значению — поэтому в payload идёт "<status>:<family>",
	// не просто family. expires_at > NOW() отсекает протухшие записи на
	// уровне БД: edge видит "ключа нет" и идёт по provisional fastpath, а
	// не по устаревшему verdict'у. Сам DELETE протухших строк — на воркере
	// (GC-тик); фильтр здесь — defence-in-depth, чтобы корректность не
	// зависела от того, успел ли GC. Миграция 0002 завела status/expires_at.
	if err := loadKVString(ctx, tx, &r.VerifiedBotIPs,
		`SELECT ip, status || ':' || bot_name FROM verified_bot_ips
		 WHERE expires_at > NOW() ORDER BY ip`); err != nil {
		return nil, err
	}
	if err := loadPolicy(ctx, tx, r); err != nil {
		return nil, err
	}

	// Per-host policy regex/CIDR валидируем сразу: до Store.Replace
	// никто не увидит этот payload. Слой медленных каталогов придёт из
	// filesource (валидирован у себя); финальная сборка их merge'ом в
	// reloader тоже прогоняет catalog.Validate как defense-in-depth.
	if err := catalog.Validate(catalog.Merge(nil, r)); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	return r, nil
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

// loadPolicy читает строки `policy` и распаковывает JSONB-поля в срезы.
// Каждое JSONB поле декодируется отдельно — это позволяет в будущем
// добавлять поля без миграции (с осторожностью: новое поле должно быть
// optional и иметь дефолт).
func loadPolicy(ctx context.Context, tx pgx.Tx, r *catalog.RuntimeData) error {
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
		// asn_block: defensive decode через []*int64 + per-element фильтрацию
		// (PR-58 review #6). Прямой Unmarshal в []uint32 валился на любом
		// значении -1 / >2^32 одной строки и ронял весь catalog tick →
		// Store.Replace не вызывался → edge fail-stale для ВСЕХ клиентов.
		// Запись через admin API уже ловится `antibotapi.ValidateASN`, но
		// legacy/manual SQL/импорт могут оставить out-of-range или null —
		// они тихо скипаются (см. doc-комментарий decodeASNBlock).
		if err := decodeASNBlock(asnJSON, &p.ASNBlock); err != nil {
			return fmt.Errorf("policy[%s].asn_block: %w", host, err)
		}
		if err := unmarshalIfNonEmpty(geoJSON, &p.GeoWhitelist); err != nil {
			return fmt.Errorf("policy[%s].geo_whitelist: %w", host, err)
		}
		if err := unmarshalIfNonEmpty(rateRulesJSON, &p.RateRules); err != nil {
			return fmt.Errorf("policy[%s].rate_rules: %w", host, err)
		}
		r.Policy[host] = p
	}
	return rows.Err()
}

func unmarshalIfNonEmpty(b []byte, dst any) error {
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, dst)
}

// decodeASNBlock декодирует JSONB-массив ASN в []uint32 с per-element
// фильтрацией. Возвращает ошибку только если сам JSON битый (не массив,
// не числа).
//
// Скипаются БЕЗ ошибки (loader не валит весь tick из-за одной битой
// строки — иначе один out-of-range ASN кладёт edge для всего пула):
//   - элементы с n < 0 или n > 2^32-1 (out of uint32 range)
//   - JSON null (json.Unmarshal маппит null → zero-int64=0, что после
//     попадания в out выглядит как валидный ASN-0; легитимный admin-API
//     путь 0 принимает, но фантомные 0 из null-элементов — точно артефакт
//     legacy/manual SQL, симметрично 0-фильтру не делаем — пусть operator
//     явно вставит [0] если ему нужен ASN-0).
//
// Скип молчаливый — оператор увидит расхождение через дашборд/аналитику,
// не через логи backend'а. Сохранить host+raw-value для warn'а
// потребовало бы пробросить host вглубь, плюс slog spam'ил бы на каждом
// 5-секундном reloader-тике одно и то же — лучше fix-on-source.
func decodeASNBlock(b []byte, dst *[]uint32) error {
	if len(b) == 0 {
		// Empty bytes = «поле не пришло» (NULL column из БД). Контракт:
		// dst остаётся nil. Явно зануляем на случай, если caller
		// переиспользует slice (decode_asn_test проверяет).
		*dst = nil
		return nil
	}
	var raw []*int64
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	out := make([]uint32, 0, len(raw))
	for _, p := range raw {
		if p == nil {
			// JSON null — отбрасываем (не дефолтим в 0).
			continue
		}
		n := *p
		if n < 0 || n > 0xFFFFFFFF {
			continue
		}
		out = append(out, uint32(n)) //nolint:gosec // G115: range checked above
	}
	*dst = out
	return nil
}
