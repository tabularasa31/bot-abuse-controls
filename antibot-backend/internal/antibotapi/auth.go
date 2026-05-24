// Bearer-token middleware для policy API. Один shared M2M secret между
// dashboard-backend и antibot-backend; единственный потребитель этих
// endpoint'ов — dashboard-backend, per-tenant авторизация делается ВНУТРИ
// дашборда.
//
// Constant-time compare (crypto/subtle) — стандартная защита от timing
// side-channel'ов при поиске валидного токена.
package antibotapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Authenticator проверяет bearer-token. Сконфигурирован одним allowed-токеном;
// больше нужно — заводим slice (per-tenant — v2).
//
// Compare-стратегия: sha256(token) → 32 байта → ConstantTimeCompare фиксированной
// длины. Прямой ConstantTimeCompare([]byte(got), token) short-circuit'ит когда
// len(got) != len(token), что технически leak'ает длину сконфигурированного
// токена через timing (PR-58 security audit #8). Хеширование выравнивает
// длину compare-операндов независимо от длины входа.
type Authenticator struct {
	tokenHash     [32]byte               // sha256 of configured token
	authFailures  *prometheus.CounterVec // {reason}: missing | malformed | bad_token
	authSucceeded prometheus.Counter
}

// NewAuthenticator валидирует токен на старте: пустая строка = nil, вызывающий
// должен решить «не регистрировать handler'ы». Зарегистрирует метрики на
// переданном registerer (обычно общий *prometheus.Registry).
func NewAuthenticator(token string, reg prometheus.Registerer) *Authenticator {
	if token == "" {
		return nil
	}
	a := &Authenticator{
		tokenHash: sha256.Sum256([]byte(token)),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "antibot_backend_api_auth_failures_total",
			Help: "policy API: bearer-token auth failures, by reason.",
		}, []string{"reason"}),
		authSucceeded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_api_auth_success_total",
			Help: "policy API: bearer-token auth successes.",
		}),
	}
	reg.MustRegister(a.authFailures, a.authSucceeded)
	return a
}

// Middleware обёртывает handler bearer-auth'ом. На fail — 401 + JSON-тело,
// next не вызывается.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h == "" {
			a.fail(w, "missing")
			return
		}
		// Принимаем только "Bearer <tok>" (case-insensitive scheme).
		const prefix = "bearer "
		if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
			a.fail(w, "malformed")
			return
		}
		got := strings.TrimSpace(h[len(prefix):])
		gotHash := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(gotHash[:], a.tokenHash[:]) != 1 {
			a.fail(w, "bad_token")
			return
		}
		a.authSucceeded.Inc()
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) fail(w http.ResponseWriter, reason string) {
	a.authFailures.WithLabelValues(reason).Inc()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="antibot-backend"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
