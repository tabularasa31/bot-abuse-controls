// Bearer-token middleware for the policy API. One shared M2M secret between the
// dashboard backend and antibot-backend; the only consumer of these
// endpoints is the dashboard backend, and per-tenant authorisation happens INSIDE
// the dashboard.
//
// A constant-time compare (crypto/subtle) — the standard protection from timing
// side channels while searching for a valid token.
package antibotapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Authenticator verifies the bearer token. It is configured with one allowed token;
// if more are ever needed we add a slice (per tenant — v2).
//
// The compare strategy: sha256(token) → 32 bytes → a fixed-length ConstantTimeCompare.
// A direct ConstantTimeCompare([]byte(got), token) short-circuits when
// len(got) != len(token), which technically leaks the length of the configured
// token through timing. Hashing equalises the
// length of the compare operands regardless of the input length.
type Authenticator struct {
	tokenHash     [32]byte               // sha256 of configured token
	authFailures  *prometheus.CounterVec // {reason}: missing | malformed | bad_token
	authSucceeded prometheus.Counter
}

// NewAuthenticator validates the token at startup: an empty string means nil, and the caller
// must decide "do not register the handlers". It registers metrics on the
// passed registerer (usually the shared *prometheus.Registry).
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

// Middleware wraps a handler in bearer auth. On failure it returns 401 plus a JSON body and
// next is not called.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h == "" {
			a.fail(w, "missing")
			return
		}
		// We accept only "Bearer <tok>" (with a case-insensitive scheme).
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
