// Package db opens the pgxpool connection used by all backend modules.
//
// Skeleton level: the pool is either open (when POSTGRES_DSN is set) or nil.
// Real SQL queries arrive in B3 (catalog) / B6/B9 (logs) / B7 (rDNS), and
// the migrations in B4/B15. Only the pool and a ping live here.
package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}
