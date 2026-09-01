// Package health serves the /health endpoint the load balancer round-robins on.
//
// The contract is compatible with the previous placeholder (200 plus JSON with "instance"), but
// it now does honest readiness: when a pinger (pgxpool) is set and the database does not answer within
// pingTimeout, we return 503 with a reason. The LB removes the instance from rotation itself,
// without waiting for TCP-level timeouts.
//
// We do not split liveness from readiness: one endpoint, and the B1 substrate
// already holds depends_on=service_healthy before the backend starts.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Pinger — the minimal interface *pgxpool.Pool satisfies,
// so that the health package does not drag pgx into its dependencies.
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

// Handler returns the /health handler. pinger=nil means skeleton mode with no database, and
// /health always returns 200 (used in smoke tests without POSTGRES_DSN).
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
