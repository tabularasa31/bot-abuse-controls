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
// Новый host → INSERT с PoolDefault() + patch. Существующий с теми же
// значениями → changed=false, БЕЗ UPDATE (updated_at не дёргается).
func (s *Store) PatchScalars(ctx context.Context, site string, p PolicyPatch) (bool, []string, error) {
	if p.IsEmpty() {
		return false, nil, fmt.Errorf("empty patch")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return false, nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		curMode, curStr string
		curAttack       bool
		exists          = true
	)
	err = tx.QueryRow(ctx,
		`SELECT mode, strictness, attack_mode FROM policy WHERE host = $1 FOR UPDATE`,
		site,
	).Scan(&curMode, &curStr, &curAttack)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		exists = false
	case err != nil:
		return false, nil, fmt.Errorf("select current: %w", err)
	}

	// Сначала собираем target-значения, потом считаем diff. Если row нет —
	// базой служит PoolDefault.
	target := catalog.PoolDefault()
	if exists {
		target.Mode = curMode
		target.Strictness = curStr
		target.AttackMode = curAttack
	}
	var changed []string
	if p.Mode != nil && *p.Mode != target.Mode {
		changed = append(changed, "mode")
		target.Mode = *p.Mode
	}
	if p.Strictness != nil && *p.Strictness != target.Strictness {
		changed = append(changed, "strictness")
		target.Strictness = *p.Strictness
	}
	if p.AttackMode != nil && *p.AttackMode != target.AttackMode {
		changed = append(changed, "attack_mode")
		target.AttackMode = *p.AttackMode
	}

	if exists && len(changed) == 0 {
		// Полный no-op: row есть, все переданные поля совпадают. updated_at
		// не трогаем — reloader не таскает пустой diff, дашборд видит
		// `changed:false`.
		if err := tx.Commit(ctx); err != nil {
			return false, nil, fmt.Errorf("commit: %w", err)
		}
		return false, nil, nil
	}

	if !exists {
		// Новый row: используем PoolDefault'ы для всех нестроковых полей + patch.
		// JSONB-массивы инициализируем эквивалентом '[]'::jsonb через
		// маршалинг пустых slice'ов (PoolDefault уже даёт []T{}).
		uaJSON, err := mustMarshal(target.UABlacklist)
		if err != nil {
			return false, nil, err
		}
		ipWLJSON, err := mustMarshal(target.IPWhitelist)
		if err != nil {
			return false, nil, err
		}
		ipBLJSON, err := mustMarshal(target.IPBlocklist)
		if err != nil {
			return false, nil, err
		}
		asnJSON, err := mustMarshal(target.ASNBlock)
		if err != nil {
			return false, nil, err
		}
		geoJSON, err := mustMarshal(target.GeoWhitelist)
		if err != nil {
			return false, nil, err
		}
		rateJSON, err := mustMarshal(target.RateRules)
		if err != nil {
			return false, nil, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO policy (host, mode, strictness, attack_mode,
				ua_blacklist, ip_whitelist, ip_blocklist,
				asn_block, geo_whitelist, rate_rules, updated_at)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, NOW())`,
			site, target.Mode, target.Strictness, target.AttackMode,
			uaJSON, ipWLJSON, ipBLJSON, asnJSON, geoJSON, rateJSON,
		); err != nil {
			return false, nil, fmt.Errorf("insert: %w", err)
		}
		// Для нового row "changed" — это весь patch (все переданные поля,
		// независимо от того, отличались ли от default'а).
		if len(changed) == 0 {
			for _, f := range []struct {
				name string
				set  bool
			}{
				{"mode", p.Mode != nil},
				{"strictness", p.Strictness != nil},
				{"attack_mode", p.AttackMode != nil},
			} {
				if f.set {
					changed = append(changed, f.name)
				}
			}
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE policy
			SET mode = $2, strictness = $3, attack_mode = $4, updated_at = NOW()
			WHERE host = $1`,
			site, target.Mode, target.Strictness, target.AttackMode,
		); err != nil {
			return false, nil, fmt.Errorf("update: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, nil, fmt.Errorf("commit: %w", err)
	}
	return true, changed, nil
}

// AppendStringArray делает идемпотентный append в JSONB-string-массив.
// Создаёт row с PoolDefault, если site нет. changed=false → значение уже было.
func (s *Store) AppendStringArray(ctx context.Context, site, field, value string) (bool, error) {
	if _, ok := allowedStringArrayFields[field]; !ok {
		return false, fmt.Errorf("unknown field: %s", field)
	}
	if err := s.ensureRow(ctx, site); err != nil {
		return false, err
	}
	// jsonb-containment: уже есть → no-op. fmt.Sprintf для имени колонки безопасен
	// после white-list проверки выше.
	q := fmt.Sprintf(
		`UPDATE policy
		 SET %[1]s = %[1]s || to_jsonb($2::text), updated_at = NOW()
		 WHERE host = $1 AND NOT (%[1]s @> to_jsonb($2::text))`, field)
	tag, err := s.pool.Exec(ctx, q, site, value)
	if err != nil {
		return false, fmt.Errorf("append %s: %w", field, err)
	}
	return tag.RowsAffected() == 1, nil
}

// RemoveStringArray удаляет элемент. existed=false → элемента не было,
// handler возвращает 404 (отделяем «не было» от «было и удалили»).
func (s *Store) RemoveStringArray(ctx context.Context, site, field, value string) (bool, error) {
	if _, ok := allowedStringArrayFields[field]; !ok {
		return false, fmt.Errorf("unknown field: %s", field)
	}
	q := fmt.Sprintf(
		`UPDATE policy
		 SET %[1]s = %[1]s - $2, updated_at = NOW()
		 WHERE host = $1 AND (%[1]s @> to_jsonb($2::text))`, field)
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
		  SET asn_block = asn_block || to_jsonb($2::bigint), updated_at = NOW()
		  WHERE host = $1 AND NOT (asn_block @> to_jsonb($2::bigint))`
	tag, err := s.pool.Exec(ctx, q, site, int64(asn))
	if err != nil {
		return false, fmt.Errorf("append asn_block: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) RemoveASN(ctx context.Context, site string, asn uint32) (bool, error) {
	// Минус-оператор по числу из jsonb-массива: WHERE-фильтр + перестройка
	// массива через jsonb_array_elements. Простой `arr - 'val'` работает только
	// на text-членах; для чисел нужно вытащить и пересобрать.
	q := `WITH cur AS (
		SELECT host, asn_block FROM policy WHERE host = $1
	  ), rebuilt AS (
		SELECT host, COALESCE(jsonb_agg(elem), '[]'::jsonb) AS new_arr
		FROM cur, LATERAL jsonb_array_elements(asn_block) AS elem
		WHERE (elem)::bigint <> $2
		GROUP BY host
	  ), empty_case AS (
		SELECT host, '[]'::jsonb AS new_arr FROM cur
		WHERE NOT EXISTS (SELECT 1 FROM rebuilt WHERE rebuilt.host = cur.host)
	  ), final AS (
		SELECT host, new_arr FROM rebuilt
		UNION ALL
		SELECT host, new_arr FROM empty_case
	  )
	  UPDATE policy
	  SET asn_block = final.new_arr, updated_at = NOW()
	  FROM final
	  WHERE policy.host = final.host AND policy.asn_block @> to_jsonb($2::bigint)`
	tag, err := s.pool.Exec(ctx, q, site, int64(asn))
	if err != nil {
		return false, fmt.Errorf("remove asn_block: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ensureRow создаёт row с PoolDefault если site нет. Идемпотентно через
// ON CONFLICT DO NOTHING — не перетирает существующие значения.
func (s *Store) ensureRow(ctx context.Context, site string) error {
	def := catalog.PoolDefault()
	uaJSON, err := mustMarshal(def.UABlacklist)
	if err != nil {
		return err
	}
	ipWLJSON, err := mustMarshal(def.IPWhitelist)
	if err != nil {
		return err
	}
	ipBLJSON, err := mustMarshal(def.IPBlocklist)
	if err != nil {
		return err
	}
	asnJSON, err := mustMarshal(def.ASNBlock)
	if err != nil {
		return err
	}
	geoJSON, err := mustMarshal(def.GeoWhitelist)
	if err != nil {
		return err
	}
	rateJSON, err := mustMarshal(def.RateRules)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO policy (host, mode, strictness, attack_mode,
			ua_blacklist, ip_whitelist, ip_blocklist,
			asn_block, geo_whitelist, rate_rules)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb)
		ON CONFLICT (host) DO NOTHING`,
		site, def.Mode, def.Strictness, def.AttackMode,
		uaJSON, ipWLJSON, ipBLJSON, asnJSON, geoJSON, rateJSON,
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

// mustMarshal — обёртка над json.Marshal для типов, которые точно
// сериализуются (slice/map простых типов из catalog.PoolDefault). Возвращает
// ошибку наверх (а не паникует), чтобы errchkjson не ругался и чтобы
// hypothetic future-тип, который ломает Marshal, валил handler корректно.
func mustMarshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	return b, nil
}
