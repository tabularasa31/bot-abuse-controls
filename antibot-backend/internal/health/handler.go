// Package health serves the /health endpoint the B1 LB round-robins on.
//
// Контракт совместим с прошлым плейсхолдером (200 + JSON c "instance"), но
// теперь honest readiness: если задан pinger (pgxpool) и БД не отвечает за
// pingTimeout — возвращаем 503 c reason. LB сам выкинет инстанс из ротации,
// не дожидаясь TCP-уровневых таймаутов.
//
// Liveness/readiness split на скелете не делаем: один эндпоинт, B1-substrate
// и так держит depends_on=service_healthy перед стартом backend.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Pinger — минимальный интерфейс, под который подходит *pgxpool.Pool,
// чтобы пакет health не тащил pgx в зависимости.
type Pinger interface {
	Ping(ctx context.Context) error
}

const pingTimeout = 100 * time.Millisecond

type response struct {
	Status   string `json:"status"`
	Instance string `json:"instance"`
	Role     string `json:"role"`
	DB       string `json:"db,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Handler возвращает обработчик /health. pinger=nil — skeleton-режим без БД,
// /health всегда 200 (используется в smoke-тестах без POSTGRES_DSN).
func Handler(instance string, pinger Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := response{
			Status:   "ok",
			Instance: instance,
			Role:     "antibot-backend",
		}
		status := http.StatusOK
		if pinger != nil {
			ctx, cancel := context.WithTimeout(r.Context(), pingTimeout)
			defer cancel()
			if err := pinger.Ping(ctx); err != nil {
				body.Status = "degraded"
				body.DB = "down"
				body.Error = err.Error()
				status = http.StatusServiceUnavailable
			} else {
				body.DB = "up"
			}
		}
		data, err := json.Marshal(body)
		if err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend", instance)
		w.WriteHeader(status)
		_, _ = w.Write(data)
	}
}
