// The write side of the policy API. Every mutation is one short transaction:
// SELECT current → no-op detection → an UPSERT with PoolDefault for new hosts.
// updated_at = NOW() is written explicitly in the UPDATE (no database trigger — one write path).
package antibotapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/catalog"
)

// ErrNotFound — there is no row for the site (on GET; for an array DELETE, the element did not exist).
var ErrNotFound = errors.New("not found")

// The field name is interpolated into SQL, so this whitelist is the only thing
// standing between a URL path segment and an injection.
var allowedStringArrayFields = map[string]struct{}{
	"ua_blacklist":  {},
	"ip_blocklist":  {},
	"ip_whitelist":  {},
	"geo_whitelist": {},
}

// allowedASNField — the only JSONB field holding numbers.
const allowedASNField = "asn_block"

// Marshalled once at startup rather than per insert. Going through the same
// typed defaults as everything else, instead of a SQL literal, is what keeps a
// new row identical to what the reloader and the dashboard expect.
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
		// json.Marshal does not fail on our fixed types; if it ever
		// does, we catch it at process start rather than in a request handler.
		panic(fmt.Sprintf("antibotapi: marshal PoolDefault: %v", err))
	}
	return b
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// PolicyPatch — a partial update of the scalar fields. A nil pointer means "do not touch".
type PolicyPatch struct {
	Mode       *string
	Strictness *string
	AttackMode *bool
	OriginIP   *string
}

// IsEmpty — every pointer is nil. The handler answers 400 on an empty PATCH (a meaningless request).
func (p PolicyPatch) IsEmpty() bool {
	return p.Mode == nil && p.Strictness == nil && p.AttackMode == nil && p.OriginIP == nil
}

// PatchScalars applies a patch and reports whether anything changed; a patch
// matching the current values leaves updated_at alone.
//
// The self-assignment in the conflict clause looks pointless but is what takes
// the row lock, so concurrent patches to different fields serialise instead of
// clobbering each other. `xmax = 0` then distinguishes a real insert from the
// update branch.
//
// The cost is a dead tuple per patch, no-ops included — worth revisiting if
// idempotent patches ever become frequent.
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
		curOrigin       string
	)
	if err := tx.QueryRow(ctx, `
		INSERT INTO policy (host, mode, strictness, attack_mode,
			ua_blacklist, ip_whitelist, ip_blocklist,
			asn_block, geo_whitelist, rate_rules)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb)
		ON CONFLICT (host) DO UPDATE SET host = EXCLUDED.host
		RETURNING (xmax = 0) AS inserted, mode, strictness, attack_mode, origin_ip`,
		site, def.Mode, def.Strictness, def.AttackMode,
		poolDefaultUAJSON, poolDefaultIPWLJSON, poolDefaultIPBLJSON,
		poolDefaultASNJSON, poolDefaultGeoJSON, poolDefaultRateJSON,
	).Scan(&inserted, &curMode, &curStr, &curAttack, &curOrigin); err != nil {
		return false, nil, fmt.Errorf("upsert-lock: %w", err)
	}

	targetMode, targetStr, targetAttack, targetOrigin := curMode, curStr, curAttack, curOrigin
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
	if p.OriginIP != nil && *p.OriginIP != targetOrigin {
		changed = append(changed, "origin_ip")
		targetOrigin = *p.OriginIP
	}

	// An UPDATE only when at least one field differs. Under the row lock from the UPSERT
	// above — a concurrent PATCH waits on our lock, then sees the already-new
	// state and computes its diff correctly.
	if len(changed) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE policy
			SET mode = $2, strictness = $3, attack_mode = $4, origin_ip = $5, updated_at = NOW()
			WHERE host = $1`,
			site, targetMode, targetStr, targetAttack, targetOrigin,
		); err != nil {
			return false, nil, fmt.Errorf("update: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, nil, fmt.Errorf("commit: %w", err)
	}

	switch {
	case inserted:
		// A new row: changed=true (the site got settings for the first time). The diff is
		// every EXPLICITLY passed field, so that the dashboard can see exactly what from
		// its PATCH landed. updated_at is the schema default NOW() on INSERT.
		return true, patchFields(p), nil
	case len(changed) > 0:
		return true, changed, nil
	default:
		// An existing row where every passed field matched → a no-op, and
		// updated_at is preserved.
		return false, nil, nil
	}
}

// patchFields — the list of field names explicitly passed in the patch (for the diff of a
// new row, where comparing with current is meaningless).
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
	if p.OriginIP != nil {
		out = append(out, "origin_ip")
	}
	return out
}

// AppendStringArray is an idempotent append, creating the row if needed.
//
// The COALESCE guards a JSONB null, where concatenation would silently do
// nothing. Creation and update share a transaction, or a concurrent site delete
// between them would lose the append.
func (s *Store) AppendStringArray(ctx context.Context, site, field, value string) (bool, error) {
	if _, ok := allowedStringArrayFields[field]; !ok {
		return false, fmt.Errorf("unknown field: %s", field)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.ensureRowTx(ctx, tx, site); err != nil {
		return false, err
	}
	// fmt.Sprintf for the column name is safe after the whitelist check above.
	q := fmt.Sprintf(
		`UPDATE policy
		 SET %[1]s = COALESCE(%[1]s, '[]'::jsonb) || to_jsonb($2::text), updated_at = NOW()
		 WHERE host = $1 AND NOT (COALESCE(%[1]s, '[]'::jsonb) @> to_jsonb($2::text))`, field)
	tag, err := tx.Exec(ctx, q, site, value)
	if err != nil {
		return false, fmt.Errorf("append %s: %w", field, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RemoveStringArray deletes an element, reporting whether it was there so the
// handler can answer 404. A single statement is atomic on its own, and deleting
// from a site that does not exist is correctly a 404.
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

// AppendASN — symmetric with AppendStringArray, but for the numeric asn_block.
// JSONB containment works on scalar values, so the semantics are the same.
// The tx wrapper is identical to AppendStringArray (see the audit note there).
func (s *Store) AppendASN(ctx context.Context, site string, asn uint32) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.ensureRowTx(ctx, tx, site); err != nil {
		return false, err
	}
	q := `UPDATE policy
		  SET asn_block = COALESCE(asn_block, '[]'::jsonb) || to_jsonb($2::bigint), updated_at = NOW()
		  WHERE host = $1 AND NOT (COALESCE(asn_block, '[]'::jsonb) @> to_jsonb($2::bigint))`
	tag, err := tx.Exec(ctx, q, site, int64(asn))
	if err != nil {
		return false, fmt.Errorf("append asn_block: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RemoveASN removes an ASN from the array.
//
// The new array is computed in a subquery inside the SET, so it runs after the
// row lock against current state. Computing it in a CTE would silently clobber a
// concurrent append: Read Committed re-locks the row but does not re-evaluate
// the CTE.
//
// The type filter keeps numbers only: the schema does not constrain the element
// types, and a string left by manual SQL would make every delete for that site
// fail until the database was fixed by hand.
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

// ensureRowTx creates the row with PoolDefault when the site is absent, inside the passed tx,
// AND takes a row lock on the conflicting row through `DO UPDATE SET
// host = EXCLUDED.host` (a self-assignment, as in PatchScalars).
//
// The lock is mandatory rather than cosmetic: `DO NOTHING` does NOT lock the
// existing row on a conflict, so a concurrent DeletePolicy could
// commit its DELETE between ensureRow (a no-op) and the subsequent UPDATE in
// AppendStringArray/AppendASN — that UPDATE would see RowsAffected=0 and return
// 200 changed:false, silently losing the append (the row was deleted and the value never written).
// Wrapping ensure+UPDATE in one tx did NOT by itself
// close it — the lock is what is needed. `DO UPDATE` takes a ROW SHARE+EXCLUSIVE lock,
// so a concurrent DELETE waits on it; the append commits a real record
// (changed:true), and only then does the DELETE remove the host — with no silent no-op.
//
// The trade-off: every append now writes a dead tuple on the ensure branch even when
// the row already exists (there is no SET-to-same-value short circuit) — the same churn
// documented in PatchScalars; acceptable at the frequency of appends.
//
// PatchScalars does its own UPSERT-with-lock (the xmax=0 trick), so
// ensureRowTx is not wired in there.
func (s *Store) ensureRowTx(ctx context.Context, tx pgx.Tx, site string) error {
	def := catalog.PoolDefault()
	_, err := tx.Exec(ctx, `
		INSERT INTO policy (host, mode, strictness, attack_mode,
			ua_blacklist, ip_whitelist, ip_blocklist,
			asn_block, geo_whitelist, rate_rules)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb)
		ON CONFLICT (host) DO UPDATE SET host = EXCLUDED.host`,
		site, def.Mode, def.Strictness, def.AttackMode,
		poolDefaultUAJSON, poolDefaultIPWLJSON, poolDefaultIPBLJSON,
		poolDefaultASNJSON, poolDefaultGeoJSON, poolDefaultRateJSON,
	)
	if err != nil {
		return fmt.Errorf("ensure row: %w", err)
	}
	return nil
}

// GetPolicy returns the full Policy for a site. ErrNotFound when there is no row —
// the handler separates "configured to the default" from "not configured" (the latter → 404).
func (s *Store) GetPolicy(ctx context.Context, site string) (catalog.Policy, error) {
	var (
		p                                                      catalog.Policy
		uaJSON, ipWLJSON, ipBLJSON, asnJSON, geoJSON, rateJSON []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT mode, strictness, attack_mode, origin_ip,
		       ua_blacklist, ip_whitelist, ip_blocklist,
		       asn_block, geo_whitelist, rate_rules
		FROM policy WHERE host = $1`, site,
	).Scan(&p.Mode, &p.Strictness, &p.AttackMode, &p.OriginIP,
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
	// nil → []T{} for JSON stability (as in catalog.normalize).
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

// DeletePolicy removes a host's policy row entirely. existed=false means the row
// was absent and the handler returns 404 (like the array DELETE — separating "it was not there"
// from "it was there and we deleted it"). A single-statement DELETE is atomic; ensureRow is unnecessary.
//
// After the COMMIT the host disappears from the table. The reloader does a full LoadRuntime plus
// Store.Replace, so a deleted host simply does not appear in the next snapshot,
// and buildPolicy serves PoolDefault() (mode=shadow, observe-only) — deletion
// through Channel C is handled by full-reload semantics rather than by an upsert.
func (s *Store) DeletePolicy(ctx context.Context, site string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM policy WHERE host = $1`, site)
	if err != nil {
		return false, fmt.Errorf("delete policy: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// GetStringArray returns one JSONB array field. A missing row means []
// (not ErrNotFound: from the dashboard's point of view "the customer has nothing yet").
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

// GetASN — symmetric with GetStringArray, but for the numeric asn_block.
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
