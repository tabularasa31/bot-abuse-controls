// The rDNS write side on top of pgxpool. Kept separate from worker.go so that tests
// do not pull in pgx (the DB interface in worker.go covers the write contract).
package rdns

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PgxWriter implements DB on top of *pgxpool.Pool. The constructor takes the pool,
// to reuse the connection already opened in app.New.
type PgxWriter struct {
	pool *pgxpool.Pool
}

func NewPgxWriter(pool *pgxpool.Pool) *PgxWriter {
	return &PgxWriter{pool: pool}
}

// UpsertVerifiedBot — INSERT … ON CONFLICT (ip). Writing a verdict for an IP
// overwrites any previous one: an rDNS check is idempotent by
// construction, and the latest check is authoritative.
//
// verified_at is left at its default (NOW()), so that an operator reading the table
// can see "when we decided this". expires_at comes explicitly from the worker, so that
// tests can substitute the clock and check the TTL.
func (w *PgxWriter) UpsertVerifiedBot(ctx context.Context, ip, family, status string, expiresAt time.Time) error {
	_, err := w.pool.Exec(ctx, `
		INSERT INTO verified_bot_ips (ip, bot_name, status, expires_at, verified_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (ip) DO UPDATE SET
			bot_name = EXCLUDED.bot_name,
			status = EXCLUDED.status,
			expires_at = EXCLUDED.expires_at,
			verified_at = NOW()
	`, ip, family, status, expiresAt)
	if err != nil {
		return fmt.Errorf("upsert verified_bot_ips: %w", err)
	}
	return nil
}

// DeleteExpired removes rows with expires_at <= NOW(). dbloader.Load
// already filters them on read (see dbloader.go), and the DELETE here only
// keeps the table from bloating. It returns the number deleted for a metric.
func (w *PgxWriter) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := w.pool.Exec(ctx, `DELETE FROM verified_bot_ips WHERE expires_at <= NOW()`)
	if err != nil {
		return 0, fmt.Errorf("delete expired verified_bot_ips: %w", err)
	}
	return tag.RowsAffected(), nil
}
