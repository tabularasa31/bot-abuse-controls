// Package health serves the /health endpoint the B1 LB round-robins on.
//
// Контракт совместим с infra/demo-backend/nginx/backend.conf (плейсхолдер):
// 200 + JSON c полем "instance" — verify.sh шаг 3 ловит ≥2 разных instance,
// доказывая HA. role меняется на "antibot-backend", чтобы ops видели, что в
// топологии уже не плейсхолдер.
package health

import (
	"encoding/json"
	"net/http"
)

type response struct {
	Status   string `json:"status"`
	Instance string `json:"instance"`
	Role     string `json:"role"`
}

func Handler(instance string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend", instance)
		_ = json.NewEncoder(w).Encode(response{
			Status:   "ok",
			Instance: instance,
			Role:     "antibot-backend",
		})
	}
}
