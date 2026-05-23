// Package db opens the pgxpool connection used by all backend modules.
//
// Skeleton-уровень: пул либо открыт (если задан POSTGRES_DSN), либо nil.
// Реальные SQL-запросы появятся в B3 (catalog) / B6/B9 (логи) / B7 (rDNS) +
// миграции — в B4/B15. Здесь только pool и ping.
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
