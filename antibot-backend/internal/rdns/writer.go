// rDNS write-сторона поверх pgxpool. Отдельно от worker.go, чтобы тесты
// не тянули pgx (DB-интерфейс в worker.go покрывает write-контракт).
package rdns

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PgxWriter реализует DB поверх *pgxpool.Pool. Конструктор берёт пул,
// чтобы переиспользовать уже открытое соединение из app.New.
type PgxWriter struct {
	pool *pgxpool.Pool
}

func NewPgxWriter(pool *pgxpool.Pool) *PgxWriter {
	return &PgxWriter{pool: pool}
}

// UpsertVerifiedBot — INSERT … ON CONFLICT (ip). Запись verdict'а для IP
// перезатирает любой предыдущий: rDNS-проверка идемпотентна по
// постановке, последняя проверка — авторитетная.
//
// verified_at оставляем дефолтным (NOW()), чтобы оператор по таблице
// видел «когда мы это решили». expires_at — явно от воркера, чтобы
// тесты могли подменить часы и проверить TTL.
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

// DeleteExpired удаляет строки с expires_at <= NOW(). dbloader.Load
// уже фильтрует их при чтении (см. dbloader.go), DELETE здесь — только
// чтобы таблица не пухла. Возвращает число удалённых для метрики.
func (w *PgxWriter) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := w.pool.Exec(ctx, `DELETE FROM verified_bot_ips WHERE expires_at <= NOW()`)
	if err != nil {
		return 0, fmt.Errorf("delete expired verified_bot_ips: %w", err)
	}
	return tag.RowsAffected(), nil
}
