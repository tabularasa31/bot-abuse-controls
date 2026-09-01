// Package dbloader reads the catalogs' runtime layer from PostgreSQL.
//
// The database holds only what changes on its own: the verified-bot verdicts
// written by the rDNS worker, and the per-host policy written by the dashboard.
// The product-curated catalogs live in git and are loaded elsewhere.
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

// An arbitrary constant: isolation comes from the value being random, not from
// any derivation scheme.
const migrateAdvisoryLockKey int64 = 0x616E7469626F7402 // "antibo\x02"

// Migrate applies the embedded SQL files in order. They are written to be
// idempotent, so reapplying them is safe.
//
// Both replicas of the HA pair start at once, so an advisory lock serialises
// them: the second waits and then finds the work already done. Without it the
// first non-idempotent statement would crash-loop one of them.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	// The lock is session-scoped, so it lives on this one connection and is
	// released even if the migration fails.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn for migrate: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateAdvisoryLockKey); err != nil {
		return fmt.Errorf("pg_advisory_lock: %w", err)
	}
	defer func() {
		// Its own context: on a cancelled parent the unlock would return an error
		// without ever sending the statement, leaving the lock held on a
		// connection that goes back into the pool alive — and the other replica
		// blocked until that connection eventually expires.
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
		// One Exec for the whole file — pgx handles multi-statement strings.
		// If the operator breaks a file (a syntax error) we fail at startup
		// rather than making the backend live with a partially applied schema.
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("apply %s: %w", e.Name(), err)
		}
	}
	return nil
}

// LoadRuntime reads only the runtime tables (verified_bot_ips, policy)
// in a single read-only transaction. The slow-catalog layer now lives in
// files (see internal/filesource) and is merged into *catalog.Data in the reloader.
//
// The catalog version (for X-Catalog-Version) comes from the
// catalogs/version file rather than the database — the `catalog_version` table was dropped in
// migration 0004.
//
// Regex and CIDR validation for the per-host policy remains: an operator can
// write a broken policy.ua_blacklist through antibotapi, and without the check at
// this step the combined regex would take the UA stage down across the edge pool.
// Store.Replace is not called when LoadRuntime returns an error — the edge
// keeps working from the previous good snapshot (fail-stale).
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

	// verified_bot_ips: the rDNS worker ([B7]) writes BOTH outcomes — verified and rejected
	// (vision §Stage 2.2 plus entities-reference.md bot_verification_status). The edge
	// tells them apart by the value — hence the payload carries "<status>:<family>"
	// rather than just the family. expires_at > NOW() cuts expired records at the
	// database level: the edge sees "no key" and takes the provisional fastpath rather
	// than an out-of-date verdict. Deleting expired rows is the worker's job
	// (the GC tick); the filter here is defence in depth, so that correctness does not
	// depend on whether the GC kept up. Migration 0002 introduced status/expires_at.
	if err := loadKVString(ctx, tx, &r.VerifiedBotIPs,
		`SELECT ip, status || ':' || bot_name FROM verified_bot_ips
		 WHERE expires_at > NOW() ORDER BY ip`); err != nil {
		return nil, err
	}
	if err := loadPolicy(ctx, tx, r); err != nil {
		return nil, err
	}

	// Per-host policy regexes and CIDRs are validated right away: before Store.Replace
	// nobody sees this payload. The slow-catalog layer arrives from
	// filesource (validated there); the final merge in the
	// reloader also runs catalog.Validate as defence in depth.
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

// loadPolicy reads the `policy` rows and unpacks the JSONB fields into slices.
// Each JSONB field is decoded separately — which allows fields to be added in
// future without a migration (carefully: a new field must be
// optional and have a default).
func loadPolicy(ctx context.Context, tx pgx.Tx, r *catalog.RuntimeData) error {
	rows, err := tx.Query(ctx, `
		SELECT host, mode, strictness, attack_mode, origin_ip,
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
			&host, &p.Mode, &p.Strictness, &p.AttackMode, &p.OriginIP,
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
		// asn_block: a defensive decode through []*int64 plus per-element
		// filtering. A direct Unmarshal into []uint32 failed on any
		// -1 / >2^32 value in one row and took the whole catalog tick down →
		// Store.Replace was never called → the edge failed stale for ALL customers.
		// A write through the admin API is already caught by `antibotapi.ValidateASN`, but
		// legacy or manual SQL and imports can leave an out-of-range value or a null —
		// they are skipped silently (see the doc comment on decodeASNBlock).
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

// decodeASNBlock decodes a JSONB array of ASNs into []uint32 with per-element
// filtering. It returns an error only when the JSON itself is broken (not an array,
// not numbers).
//
// Skipped WITHOUT an error (the loader does not fail the whole tick because of one broken
// row — otherwise one out-of-range ASN takes the edge down for the whole pool):
//   - elements with n < 0 or n > 2^32-1 (out of uint32 range)
//   - JSON null (json.Unmarshal maps null → a zero int64 of 0, which once it
//     reaches out looks like a valid ASN 0; the legitimate admin API
//     path accepts 0, but phantom 0s from null elements are definitely an artefact of
//     legacy or manual SQL, and we do not add a symmetric 0 filter — let the operator
//     insert [0] explicitly if they really want ASN 0).
//
// The skip is silent — the operator sees the discrepancy through the dashboard or analytics
// rather than through the backend logs. Keeping the host plus the raw value for a warn
// would mean threading the host deep down, and slog would spam the same thing on every
// 5-second reloader tick — better to fix it at the source.
func decodeASNBlock(b []byte, dst *[]uint32) error {
	if len(b) == 0 {
		// Empty bytes mean "the field did not arrive" (a NULL column from the database). The contract:
		// dst stays nil. We zero it explicitly in case the caller
		// reuses the slice (decode_asn_test checks this).
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
			// A JSON null — discarded (not defaulted to 0).
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
