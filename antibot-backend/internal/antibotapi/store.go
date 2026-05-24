// Write-side для policy API. Каждая мутация — одна короткая транзакция:
// SELECT current → no-op detection → UPSERT с PoolDefault для новых host'ов.
// updated_at = NOW() пишется явно в UPDATE (без триггера БД — один путь записи).
package antibotapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
)

// ErrNotFound — row для site нет (GET; для array DELETE — элемент не существовал).
var ErrNotFound = errors.New("not found")

// allowedStringArrayFields — белый список JSONB-полей, с которыми работают
// array endpoints. Хардкод вместо динамики: иначе клиент мог бы передать
// `; DROP TABLE policy;--` в URL-path. Имя поля собирается в SQL через
// fmt.Sprintf — единственная защита от инъекции == white-list.
var allowedStringArrayFields = map[string]struct{}{
	"ua_blacklist":  {},
	"ip_blocklist":  {},
	"ip_whitelist":  {},
	"geo_whitelist": {},
}

// allowedASNField — единственное JSONB-поле с числами.
const allowedASNField = "asn_block"

// PoolDefault'ы для INSERT нового row'a — JSONB-массивы маршалятся один раз
// на старте, дальше идут как byte-slice'ы в Exec. Раньше делалось на каждый
// PatchScalars/ensureRow вызов (PR-58 review, gemini medium).
//
// PoolDefault() гарантирует не-nil пустые срезы, json.Marshal на них даёт
// "[]" — литералы (`[]`-jsonb-литерал в SQL) намеренно НЕ используем,
// чтобы инициализация шла через ту же типизированную точку, что и логика
// сравнения в дашборде / reloader'е.
var (
	poolDefaultUAJSON   = mustMarshalAtInit(catalog.PoolDefault().UABlacklist)
	poolDefaultIPWLJSON = mustMarshalAtInit(catalog.PoolDefault().IPWhitelist)
	poolDefaultIPBLJSON = mustMarshalAtInit(catalog.PoolDefault().IPBlocklist)
	poolDefaultASNJSON  = mustMarshalAtInit(catalog.PoolDefault().ASNBlock)
	poolDefaultGeoJSON  = mustMarshalAtInit(catalog.PoolDefault().GeoWhitelist)
	poolDefaultRateJSON = mustMarshalAtInit(catalog.PoolDefault().RateRules)
)

func mustMarshalAtInit(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// json.Marshal на наших фикс-типах не падает; если когда-нибудь
		// упадёт — поймаем на process start, не в request-handler.
		panic(fmt.Sprintf("antibotapi: marshal PoolDefault: %v", err))
	}
	return b
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// PolicyPatch — partial update скалярных полей. Nil-указатель = «не трогать».
type PolicyPatch struct {
	Mode       *string
	Strictness *string
	AttackMode *bool
}

// IsEmpty — все три nil. Handler 400-ит на пустой PATCH (бессмысленный запрос).
func (p PolicyPatch) IsEmpty() bool {
	return p.Mode == nil && p.Strictness == nil && p.AttackMode == nil
}

// PatchScalars применяет patch. Возвращает (changed, changedFields, err).
//
// Сценарии:
//   - row не существует → атомарный UPSERT (ON CONFLICT DO UPDATE
//     SET host=EXCLUDED.host) создаёт его с PoolDefault И берёт row lock
//     одной statement; RETURNING (xmax=0) отдаёт inserted-флаг.
//   - row существует и все переданные поля совпадают → no-op (changed=false,
//     updated_at НЕ дёргается).
//   - row существует и хоть одно поле отличается → UPDATE под тем же lock'ом,
//     changed=true.
//
// Concurrency: ВСЁ внутри одной транзакции (Read Committed по умолчанию).
// UPSERT с `DO UPDATE SET host=EXCLUDED.host` — это no-op assignment, но
// он триггерит UPDATE-ветку, которая берёт ROW SHARE+EXCLUSIVE lock на
// конфликтующую строку. Параллельные PATCH на тот же host теперь блокируют
// друг друга на этом lock'е (без 40001 — это RepeatableRead-only артефакт);
// loser ждёт, потом читает уже-обновлённое состояние и считает diff против
// него. Lost-update между независимыми полями исключён (PR-58 review,
// finding #1: до этого `mode=$2, strictness=$3, attack_mode=$4` молча
// перетирало concurrent PATCH на соседнее поле).
//
// `xmax = 0` — Postgres-трюк: только что вставленные строки имеют xmax=0,
// строки, попавшие в DO UPDATE ветку, имеют xmax = current xid. Так одна
// statement отдаёт и current values, и «был ли реальный insert».
//
// Trade-off (PR-58 round 2 review #5): `DO UPDATE SET host=EXCLUDED.host`
// — намеренно self-assignment, чтобы взять row lock на конфликте. Postgres
// в DO UPDATE ветке ВСЕГДА пишет новую heap-tuple, даже если SET присваивает
// то же значение (нет SET-to-same-value short-circuit). Это значит каждый
// PATCH (включая no-op) генерирует одну dead tuple → autovacuum bytes
// при высокой частоте идемпотентных PATCH'ей. Альтернатива (`DO NOTHING` +
// fallback `SELECT FOR UPDATE`) сложнее и теряет атомарность UPSERT'a;
// сознательно выбран churn вместо retry-loop'а. Если dashboard начнёт
// долбить одним и тем же payload (что в текущем дизайне не предусмотрено),
// придётся пересмотреть. updated_at сохраняется (см. ниже) — heap churn
// не виден через X-Catalog-Version.
func (s *Store) PatchScalars(ctx context.Context, site string, p PolicyPatch) (bool, []string, error) {
	if p.IsEmpty() {
		return false, nil, fmt.Errorf("empty patch")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	def := catalog.PoolDefault()
	var (
		inserted        bool
		curMode, curStr string
		curAttack       bool
	)
	if err := tx.QueryRow(ctx, `
		INSERT INTO policy (host, mode, strictness, attack_mode,
			ua_blacklist, ip_whitelist, ip_blocklist,
			asn_block, geo_whitelist, rate_rules)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb)
		ON CONFLICT (host) DO UPDATE SET host = EXCLUDED.host
		RETURNING (xmax = 0) AS inserted, mode, strictness, attack_mode`,
		site, def.Mode, def.Strictness, def.AttackMode,
		poolDefaultUAJSON, poolDefaultIPWLJSON, poolDefaultIPBLJSON,
		poolDefaultASNJSON, poolDefaultGeoJSON, poolDefaultRateJSON,
	).Scan(&inserted, &curMode, &curStr, &curAttack); err != nil {
		return false, nil, fmt.Errorf("upsert-lock: %w", err)
	}

	targetMode, targetStr, targetAttack := curMode, curStr, curAttack
	var changed []string
	if p.Mode != nil && *p.Mode != targetMode {
		changed = append(changed, "mode")
		targetMode = *p.Mode
	}
	if p.Strictness != nil && *p.Strictness != targetStr {
		changed = append(changed, "strictness")
		targetStr = *p.Strictness
	}
	if p.AttackMode != nil && *p.AttackMode != targetAttack {
		changed = append(changed, "attack_mode")
		targetAttack = *p.AttackMode
	}

	// UPDATE только если хоть одно поле отличается. Под row lock'ом из UPSERT
	// выше — concurrent PATCH ждёт на нашем lock'е, потом видит уже-новое
	// состояние и считает свой diff корректно.
	if len(changed) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE policy
			SET mode = $2, strictness = $3, attack_mode = $4, updated_at = NOW()
			WHERE host = $1`,
			site, targetMode, targetStr, targetAttack,
		); err != nil {
			return false, nil, fmt.Errorf("update: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, nil, fmt.Errorf("commit: %w", err)
	}

	switch {
	case inserted:
		// Новый row: changed=true (site впервые получил настройки). diff —
		// все ЯВНО переданные поля, чтобы dashboard видел, что именно из
		// его PATCH'а доехало. updated_at — schema default NOW() на INSERT.
		return true, patchFields(p), nil
	case len(changed) > 0:
		return true, changed, nil
	default:
		// Существующий row, все переданные поля совпали → no-op,
		// updated_at сохраняется.
		return false, nil, nil
	}
}

// patchFields — список имён полей, явно переданных в patch (для diff
// нового row'a, где сравнение с current бессмысленно).
func patchFields(p PolicyPatch) []string {
	var out []string
	if p.Mode != nil {
		out = append(out, "mode")
	}
	if p.Strictness != nil {
		out = append(out, "strictness")
	}
	if p.AttackMode != nil {
		out = append(out, "attack_mode")
	}
	return out
}

// AppendStringArray делает идемпотентный append в JSONB-string-массив.
// Создаёт row с PoolDefault, если site нет. changed=false → значение уже было.
//
// COALESCE(field, '[]'::jsonb) — defence-in-depth против row'ов с JSONB-null
// (legacy/manual SQL/test-фикстуры). Без него `null || x = null` → WHERE NOT
// (null @> ...) даёт null → false → silent no-op (PR-58 review #5).
func (s *Store) AppendStringArray(ctx context.Context, site, field, value string) (bool, error) {
	if _, ok := allowedStringArrayFields[field]; !ok {
		return false, fmt.Errorf("unknown field: %s", field)
	}
	if err := s.ensureRow(ctx, site); err != nil {
		return false, err
	}
	// fmt.Sprintf для имени колонки безопасен после white-list проверки выше.
	q := fmt.Sprintf(
		`UPDATE policy
		 SET %[1]s = COALESCE(%[1]s, '[]'::jsonb) || to_jsonb($2::text), updated_at = NOW()
		 WHERE host = $1 AND NOT (COALESCE(%[1]s, '[]'::jsonb) @> to_jsonb($2::text))`, field)
	tag, err := s.pool.Exec(ctx, q, site, value)
	if err != nil {
		return false, fmt.Errorf("append %s: %w", field, err)
	}
	return tag.RowsAffected() == 1, nil
}

// RemoveStringArray удаляет элемент. existed=false → элемента не было,
// handler возвращает 404 (отделяем «не было» от «было и удалили»).
// COALESCE против jsonb-null row'ов — см. AppendStringArray (PR-58 review #5).
func (s *Store) RemoveStringArray(ctx context.Context, site, field, value string) (bool, error) {
	if _, ok := allowedStringArrayFields[field]; !ok {
		return false, fmt.Errorf("unknown field: %s", field)
	}
	q := fmt.Sprintf(
		`UPDATE policy
		 SET %[1]s = COALESCE(%[1]s, '[]'::jsonb) - $2, updated_at = NOW()
		 WHERE host = $1 AND COALESCE(%[1]s, '[]'::jsonb) @> to_jsonb($2::text)`, field)
	tag, err := s.pool.Exec(ctx, q, site, value)
	if err != nil {
		return false, fmt.Errorf("remove %s: %w", field, err)
	}
	return tag.RowsAffected() == 1, nil
}

// AppendASN — симметрично AppendStringArray, но для числового asn_block.
// JSONB-containment работает на скалярных значениях, поэтому семантика та же.
func (s *Store) AppendASN(ctx context.Context, site string, asn uint32) (bool, error) {
	if err := s.ensureRow(ctx, site); err != nil {
		return false, err
	}
	q := `UPDATE policy
		  SET asn_block = COALESCE(asn_block, '[]'::jsonb) || to_jsonb($2::bigint), updated_at = NOW()
		  WHERE host = $1 AND NOT (COALESCE(asn_block, '[]'::jsonb) @> to_jsonb($2::bigint))`
	tag, err := s.pool.Exec(ctx, q, site, int64(asn))
	if err != nil {
		return false, fmt.Errorf("append asn_block: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RemoveASN удаляет ASN из массива.
//
// PR-58 review #2: предыдущая реализация считала new_arr в CTE до lock'а
// UPDATE-ом, поэтому concurrent AppendASN, успевший закоммитить между CTE
// и UPDATE, молча затирался — Read Committed re-locks row но НЕ переоценивает
// CTE. Новая версия вычисляет new_arr подзапросом В SET — этот подзапрос
// исполняется ПОСЛЕ row lock'а под актуальным состоянием.
//
// jsonb-null защита через COALESCE (PR-58 review #5): без неё
// jsonb_array_elements(null) бросает 'cannot extract elements from a scalar'.
//
// jsonb_typeof = 'number' (PR-58 round 2 review #3): схема не констрейнит
// типы элементов JSONB-массива; legacy/manual SQL может оставить строку
// (`'[15169, "13335"]'::jsonb`). Прямой cast `(elem)::bigint` тогда бросает
// «invalid input syntax for type bigint», DELETE для всего site'a возвращает
// 500 до ручной правки БД. Фильтр jsonb_typeof оставляет только числа;
// строки/null/массивы дропаются (defensive — но это та самая legacy-зона,
// которую decodeASNBlock на loader-стороне тоже защищает).
func (s *Store) RemoveASN(ctx context.Context, site string, asn uint32) (bool, error) {
	q := `UPDATE policy
		  SET asn_block = COALESCE(
		      (SELECT jsonb_agg(elem)
		       FROM jsonb_array_elements(COALESCE(asn_block, '[]'::jsonb)) AS elem
		       WHERE jsonb_typeof(elem) = 'number' AND (elem)::bigint <> $2),
		      '[]'::jsonb),
		      updated_at = NOW()
		  WHERE host = $1 AND COALESCE(asn_block, '[]'::jsonb) @> to_jsonb($2::bigint)`
	tag, err := s.pool.Exec(ctx, q, site, int64(asn))
	if err != nil {
		return false, fmt.Errorf("remove asn_block: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ensureRow создаёт row с PoolDefault если site нет. Идемпотентно через
// ON CONFLICT DO NOTHING — не перетирает существующие значения.
//
// PatchScalars свою UPSERT-with-lock делает сам (xmax=0 трюк), поэтому
// ensureRow используется только array-операциями (Append*), которым не
// нужен inserted-флаг.
func (s *Store) ensureRow(ctx context.Context, site string) error {
	def := catalog.PoolDefault()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy (host, mode, strictness, attack_mode,
			ua_blacklist, ip_whitelist, ip_blocklist,
			asn_block, geo_whitelist, rate_rules)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb)
		ON CONFLICT (host) DO NOTHING`,
		site, def.Mode, def.Strictness, def.AttackMode,
		poolDefaultUAJSON, poolDefaultIPWLJSON, poolDefaultIPBLJSON,
		poolDefaultASNJSON, poolDefaultGeoJSON, poolDefaultRateJSON,
	)
	if err != nil {
		return fmt.Errorf("ensure row: %w", err)
	}
	return nil
}

// GetPolicy возвращает полную Policy для site. ErrNotFound если row нет —
// handler различает «настроено в дефолт» от «не настроено» (последнее → 404).
func (s *Store) GetPolicy(ctx context.Context, site string) (catalog.Policy, error) {
	var (
		p                                                      catalog.Policy
		uaJSON, ipWLJSON, ipBLJSON, asnJSON, geoJSON, rateJSON []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT mode, strictness, attack_mode,
		       ua_blacklist, ip_whitelist, ip_blocklist,
		       asn_block, geo_whitelist, rate_rules
		FROM policy WHERE host = $1`, site,
	).Scan(&p.Mode, &p.Strictness, &p.AttackMode,
		&uaJSON, &ipWLJSON, &ipBLJSON, &asnJSON, &geoJSON, &rateJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return catalog.Policy{}, ErrNotFound
	}
	if err != nil {
		return catalog.Policy{}, fmt.Errorf("get policy: %w", err)
	}
	if err := unmarshalNonNil(uaJSON, &p.UABlacklist); err != nil {
		return catalog.Policy{}, fmt.Errorf("ua_blacklist: %w", err)
	}
	if err := unmarshalNonNil(ipWLJSON, &p.IPWhitelist); err != nil {
		return catalog.Policy{}, fmt.Errorf("ip_whitelist: %w", err)
	}
	if err := unmarshalNonNil(ipBLJSON, &p.IPBlocklist); err != nil {
		return catalog.Policy{}, fmt.Errorf("ip_blocklist: %w", err)
	}
	if err := unmarshalNonNil(asnJSON, &p.ASNBlock); err != nil {
		return catalog.Policy{}, fmt.Errorf("asn_block: %w", err)
	}
	if err := unmarshalNonNil(geoJSON, &p.GeoWhitelist); err != nil {
		return catalog.Policy{}, fmt.Errorf("geo_whitelist: %w", err)
	}
	if err := unmarshalNonNil(rateJSON, &p.RateRules); err != nil {
		return catalog.Policy{}, fmt.Errorf("rate_rules: %w", err)
	}
	// nil → []T{} для JSON-стабильности (как в catalog.normalize).
	if p.UABlacklist == nil {
		p.UABlacklist = []string{}
	}
	if p.IPWhitelist == nil {
		p.IPWhitelist = []string{}
	}
	if p.IPBlocklist == nil {
		p.IPBlocklist = []string{}
	}
	if p.ASNBlock == nil {
		p.ASNBlock = []uint32{}
	}
	if p.GeoWhitelist == nil {
		p.GeoWhitelist = []string{}
	}
	if p.RateRules == nil {
		p.RateRules = []catalog.RateRule{}
	}
	return p, nil
}

// GetStringArray возвращает один JSONB-массив-поле. Отсутствие row = []
// (не ErrNotFound: с точки зрения дашборда «у клиента ещё ничего нет»).
func (s *Store) GetStringArray(ctx context.Context, site, field string) ([]string, error) {
	if _, ok := allowedStringArrayFields[field]; !ok {
		return nil, fmt.Errorf("unknown field: %s", field)
	}
	q := fmt.Sprintf(`SELECT %s FROM policy WHERE host = $1`, field)
	var raw []byte
	err := s.pool.QueryRow(ctx, q, site).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", field, err)
	}
	out := []string{}
	if err := unmarshalNonNil(raw, &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", field, err)
	}
	if out == nil {
		return []string{}, nil
	}
	return out, nil
}

// GetASN — симметрично GetStringArray, но для числового asn_block.
func (s *Store) GetASN(ctx context.Context, site string) ([]uint32, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT asn_block FROM policy WHERE host = $1`, site).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return []uint32{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get asn_block: %w", err)
	}
	out := []uint32{}
	if err := unmarshalNonNil(raw, &out); err != nil {
		return nil, fmt.Errorf("decode asn_block: %w", err)
	}
	if out == nil {
		return []uint32{}, nil
	}
	return out, nil
}

func unmarshalNonNil(b []byte, dst any) error {
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, dst)
}
