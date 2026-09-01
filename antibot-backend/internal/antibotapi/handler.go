// Package antibotapi is the write side of the policy, called only by the
// dashboard backend.
//
// Authenticating the end user is the dashboard's job; this is a
// server-to-server contract with bearer auth and validation before any
// transaction opens. Every mutation writes an slog record, which is the audit
// trail — there is a single machine actor here, so a table would add nothing.
package antibotapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// maxBodyBytes — the bound on one request body. A PATCH payload is small; this protects
// against an accidental gigantic write from a buggy dashboard client.
const maxBodyBytes = 64 * 1024

// Server holds the API's dependencies and metrics. New returns nil when auth
// is not configured — main warns and does not register the routes.
type Server struct {
	store *Store
	auth  *Authenticator
	log   *slog.Logger

	mutations *prometheus.CounterVec // {action,result}: ok|noop|bad_request|not_found|db_error
	latency   *prometheus.HistogramVec
}

func New(pool *pgxpool.Pool, auth *Authenticator, log *slog.Logger, reg prometheus.Registerer) *Server {
	if auth == nil || pool == nil {
		return nil
	}
	s := &Server{
		store: NewStore(pool),
		auth:  auth,
		log:   log.With("component", "antibotapi"),
		mutations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "antibot_backend_api_mutations_total",
			Help: "policy API: handler outcomes by action and result.",
		}, []string{"action", "result"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "antibot_backend_api_request_duration_seconds",
			Help:    "policy API: request handler duration by action.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"action"}),
	}
	reg.MustRegister(s.mutations, s.latency)
	return s
}

// Register mounts the routes under a shared bearer-auth middleware. Go 1.22+
// method+path routing: other methods → 405 without entering the handler.
func (s *Server) Register(mux *http.ServeMux) {
	api := http.NewServeMux()
	api.HandleFunc("GET /antibot/v1/policy/{site}", s.timed("get_policy", s.handleGetPolicy))
	api.HandleFunc("PATCH /antibot/v1/policy/{site}", s.timed("patch_policy", s.handlePatchPolicy))
	api.HandleFunc("DELETE /antibot/v1/policy/{site}", s.timed("delete_policy", s.handleDeletePolicy))

	for field := range allowedStringArrayFields {
		f := field
		api.HandleFunc(fmt.Sprintf("GET /antibot/v1/policy/{site}/%s", f),
			s.timed("get_"+f, s.makeStringGet(f)))
		api.HandleFunc(fmt.Sprintf("POST /antibot/v1/policy/{site}/%s", f),
			s.timed("append_"+f, s.makeStringAppend(f)))
		api.HandleFunc(fmt.Sprintf("DELETE /antibot/v1/policy/{site}/%s", f),
			s.timed("delete_"+f, s.makeStringDelete(f)))
	}
	api.HandleFunc(fmt.Sprintf("GET /antibot/v1/policy/{site}/%s", allowedASNField),
		s.timed("get_"+allowedASNField, s.handleGetASN))
	api.HandleFunc(fmt.Sprintf("POST /antibot/v1/policy/{site}/%s", allowedASNField),
		s.timed("append_"+allowedASNField, s.handleAppendASN))
	api.HandleFunc(fmt.Sprintf("DELETE /antibot/v1/policy/{site}/%s", allowedASNField),
		s.timed("delete_"+allowedASNField, s.handleDeleteASN))

	mux.Handle("/antibot/v1/", s.auth.Middleware(api))
}

// timed — a wrapper: it measures latency and validates the site from the path. The handler works
// in an already-authenticated context, with the site extracted and checked.
func (s *Server) timed(action string, h func(action, site string, w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			s.latency.WithLabelValues(action).Observe(time.Since(start).Seconds())
		}()
		site := r.PathValue("site")
		if err := ValidateSite(site); err != nil {
			s.bad(w, action, "bad_site", err.Error())
			return
		}
		h(action, site, w, r)
	}
}

// requestAttrs collects the forensic fields for the audit record. Without a
// source address and request id, a leaked token would leave no way to separate
// legitimate mutations from an attacker's.
func requestAttrs(r *http.Request) []any {
	src := r.Header.Get("X-Forwarded-For")
	if src == "" {
		src = r.RemoteAddr
	}
	return []any{"src", src, "request_id", r.Header.Get("X-Request-Id")}
}

// --- GET / PATCH policy ----------------------------------------------------

func (s *Server) handleGetPolicy(action, site string, w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetPolicy(r.Context(), site)
	if errors.Is(err, ErrNotFound) {
		s.writeErr(w, http.StatusNotFound, "not_found", "")
		s.mutations.WithLabelValues(action, "not_found").Inc()
		return
	}
	if err != nil {
		s.dbErr(w, action, err)
		return
	}
	s.writeJSON(w, p)
	s.mutations.WithLabelValues(action, "ok").Inc()
}

// patchBody accepts only scalar fields; unknown keys are rejected by the
// strict decoder (DisallowUnknownFields), so that a typo from the dashboard is not
// silently ignored.
type patchBody struct {
	Mode       *string `json:"mode,omitempty"`
	Strictness *string `json:"strictness,omitempty"`
	AttackMode *bool   `json:"attack_mode,omitempty"`
	OriginIP   *string `json:"origin_ip,omitempty"`
}

func (s *Server) handlePatchPolicy(action, site string, w http.ResponseWriter, r *http.Request) {
	var pb patchBody
	if err := decodeJSON(r, &pb); err != nil {
		s.handleDecodeErr(w, action, err)
		return
	}
	patch := PolicyPatch{Mode: pb.Mode, Strictness: pb.Strictness, AttackMode: pb.AttackMode, OriginIP: pb.OriginIP}
	if patch.IsEmpty() {
		s.bad(w, action, "empty_patch", "PATCH body must include at least one of mode, strictness, attack_mode, origin_ip")
		return
	}
	if patch.Mode != nil {
		if err := ValidateMode(*patch.Mode); err != nil {
			s.bad(w, action, "bad_mode", err.Error())
			return
		}
	}
	if patch.Strictness != nil {
		if err := ValidateStrictness(*patch.Strictness); err != nil {
			s.bad(w, action, "bad_strictness", err.Error())
			return
		}
	}
	if patch.OriginIP != nil {
		if err := ValidateOriginIP(*patch.OriginIP); err != nil {
			s.bad(w, action, "bad_origin_ip", err.Error())
			return
		}
	}
	changed, fields, err := s.store.PatchScalars(r.Context(), site, patch)
	if err != nil {
		s.dbErr(w, action, err)
		return
	}
	s.log.Info("policy mutation",
		append([]any{"actor", "dashboard", "action", action, "site", site, "was_noop", !changed, "fields", fields},
			requestAttrs(r)...)...)
	if changed {
		s.mutations.WithLabelValues(action, "ok").Inc()
	} else {
		s.mutations.WithLabelValues(action, "noop").Inc()
	}
	s.writeJSON(w, map[string]any{"changed": changed, "diff": orEmpty(fields)})
}

// handleDeletePolicy removes a host's policy entirely; the edge falls back to
// the pool default on its next pull.
func (s *Server) handleDeletePolicy(action, site string, w http.ResponseWriter, r *http.Request) {
	existed, err := s.store.DeletePolicy(r.Context(), site)
	if err != nil {
		s.dbErr(w, action, err)
		return
	}
	if !existed {
		s.writeErr(w, http.StatusNotFound, "not_found", "")
		s.mutations.WithLabelValues(action, "not_found").Inc()
		return
	}
	s.log.Info("policy mutation",
		append([]any{"actor", "dashboard", "action", action, "site", site, "was_noop", false},
			requestAttrs(r)...)...)
	s.mutations.WithLabelValues(action, "ok").Inc()
	s.writeJSON(w, map[string]any{"changed": true})
}

// --- string-array handlers (ua/ip/geo) ------------------------------------

func (s *Server) makeStringGet(field string) func(action, site string, w http.ResponseWriter, r *http.Request) {
	return func(action, site string, w http.ResponseWriter, r *http.Request) {
		arr, err := s.store.GetStringArray(r.Context(), site, field)
		if err != nil {
			s.dbErr(w, action, err)
			return
		}
		s.writeJSON(w, map[string]any{itemsKey(field): arr})
		s.mutations.WithLabelValues(action, "ok").Inc()
	}
}

type stringArrayBody struct {
	Pattern string `json:"pattern,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	Geo     string `json:"geo,omitempty"`
}

// valueForField extracts the value from the body per the field's semantics and
// validates it. It returns (value, errCode, errMsg).
func valueForField(field string, b stringArrayBody) (string, string, string) {
	switch field {
	case "ua_blacklist":
		if err := ValidateUARegex(b.Pattern); err != nil {
			return "", "bad_pattern", err.Error()
		}
		return b.Pattern, "", ""
	case "ip_blocklist", "ip_whitelist":
		if err := ValidateCIDR(b.CIDR); err != nil {
			return "", "bad_cidr", err.Error()
		}
		return b.CIDR, "", ""
	case "geo_whitelist":
		if err := ValidateGeoCode(b.Geo); err != nil {
			return "", "bad_geo", err.Error()
		}
		return b.Geo, "", ""
	default:
		return "", "internal", "unknown field"
	}
}

func (s *Server) makeStringAppend(field string) func(action, site string, w http.ResponseWriter, r *http.Request) {
	return func(action, site string, w http.ResponseWriter, r *http.Request) {
		var b stringArrayBody
		if err := decodeJSON(r, &b); err != nil {
			s.handleDecodeErr(w, action, err)
			return
		}
		val, errCode, errMsg := valueForField(field, b)
		if errCode != "" {
			s.bad(w, action, errCode, errMsg)
			return
		}
		changed, err := s.store.AppendStringArray(r.Context(), site, field, val)
		if err != nil {
			s.dbErr(w, action, err)
			return
		}
		s.log.Info("policy mutation",
			append([]any{"actor", "dashboard", "action", action, "site", site, "was_noop", !changed},
				requestAttrs(r)...)...)
		if changed {
			s.mutations.WithLabelValues(action, "ok").Inc()
		} else {
			s.mutations.WithLabelValues(action, "noop").Inc()
		}
		s.writeJSON(w, map[string]any{"changed": changed})
	}
}

func (s *Server) makeStringDelete(field string) func(action, site string, w http.ResponseWriter, r *http.Request) {
	return func(action, site string, w http.ResponseWriter, r *http.Request) {
		var b stringArrayBody
		if err := decodeJSON(r, &b); err != nil {
			s.handleDecodeErr(w, action, err)
			return
		}
		val, errCode, errMsg := valueForField(field, b)
		if errCode != "" {
			s.bad(w, action, errCode, errMsg)
			return
		}
		existed, err := s.store.RemoveStringArray(r.Context(), site, field, val)
		if err != nil {
			s.dbErr(w, action, err)
			return
		}
		if !existed {
			s.writeErr(w, http.StatusNotFound, "not_found", "item not present")
			s.mutations.WithLabelValues(action, "not_found").Inc()
			return
		}
		s.log.Info("policy mutation",
			append([]any{"actor", "dashboard", "action", action, "site", site, "was_noop", false},
				requestAttrs(r)...)...)
		s.mutations.WithLabelValues(action, "ok").Inc()
		s.writeJSON(w, map[string]any{"changed": true})
	}
}

// --- asn_block handlers ----------------------------------------------------

func (s *Server) handleGetASN(action, site string, w http.ResponseWriter, r *http.Request) {
	arr, err := s.store.GetASN(r.Context(), site)
	if err != nil {
		s.dbErr(w, action, err)
		return
	}
	s.writeJSON(w, map[string]any{"asns": arr})
	s.mutations.WithLabelValues(action, "ok").Inc()
}

// A pointer, to tell an unset field from zero: ASN 0 is accepted, so an empty
// body would otherwise silently act on it.
type asnBody struct {
	ASN *int64 `json:"asn"`
}

// requireASN — the shared required plus range check for POST/DELETE asn_block.
func (s *Server) requireASN(w http.ResponseWriter, action string, b asnBody) (uint32, bool) {
	if b.ASN == nil {
		s.bad(w, action, "missing_asn", "field 'asn' is required")
		return 0, false
	}
	if err := ValidateASN(*b.ASN); err != nil {
		s.bad(w, action, "bad_asn", err.Error())
		return 0, false
	}
	return uint32(*b.ASN), true //nolint:gosec // G115: bounds checked by ValidateASN above
}

func (s *Server) handleAppendASN(action, site string, w http.ResponseWriter, r *http.Request) {
	var b asnBody
	if err := decodeJSON(r, &b); err != nil {
		s.handleDecodeErr(w, action, err)
		return
	}
	asn, ok := s.requireASN(w, action, b)
	if !ok {
		return
	}
	changed, err := s.store.AppendASN(r.Context(), site, asn)
	if err != nil {
		s.dbErr(w, action, err)
		return
	}
	s.log.Info("policy mutation",
		append([]any{"actor", "dashboard", "action", action, "site", site, "was_noop", !changed},
			requestAttrs(r)...)...)
	if changed {
		s.mutations.WithLabelValues(action, "ok").Inc()
	} else {
		s.mutations.WithLabelValues(action, "noop").Inc()
	}
	s.writeJSON(w, map[string]any{"changed": changed})
}

func (s *Server) handleDeleteASN(action, site string, w http.ResponseWriter, r *http.Request) {
	var b asnBody
	if err := decodeJSON(r, &b); err != nil {
		s.handleDecodeErr(w, action, err)
		return
	}
	asn, ok := s.requireASN(w, action, b)
	if !ok {
		return
	}
	existed, err := s.store.RemoveASN(r.Context(), site, asn)
	if err != nil {
		s.dbErr(w, action, err)
		return
	}
	if !existed {
		s.writeErr(w, http.StatusNotFound, "not_found", "item not present")
		s.mutations.WithLabelValues(action, "not_found").Inc()
		return
	}
	s.log.Info("policy mutation",
		append([]any{"actor", "dashboard", "action", action, "site", site, "was_noop", false},
			requestAttrs(r)...)...)
	s.mutations.WithLabelValues(action, "ok").Inc()
	s.writeJSON(w, map[string]any{"changed": true})
}

// --- helpers ---------------------------------------------------------------

// The sentinel errors of decodeJSON — handler.bad() maps them onto sanitised codes
// without leaking internal details (the names of unknown fields, JSON decoder messages,
// the MaxBytes size — from the security audit).
var (
	errBodyEmpty    = errors.New("empty body")
	errBodyTooLarge = errors.New("body too large")
	errBodyBadJSON  = errors.New("invalid json")
)

// decodeJSON reads a bounded body and parses it with a strict decoder. It returns
// one of the sentinel errors above (or nil). The json.Decoder messages themselves and
// `read body: http: request body too large` never leave the package.
func decodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errBodyTooLarge
		}
		return errBodyBadJSON
	}
	if len(buf) == 0 {
		return errBodyEmpty
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errBodyBadJSON
	}
	if dec.More() {
		return errBodyBadJSON
	}
	return nil
}

// handleDecodeErr maps decodeJSON's sentinel errors onto the correct HTTP status
// plus a static JSON code without revealing details. 413 for an oversize is the standard
// (RFC 7231 §6.5.11); we do not lump everything into a 400.
func (s *Server) handleDecodeErr(w http.ResponseWriter, action string, err error) {
	switch {
	case errors.Is(err, errBodyTooLarge):
		s.writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "")
		s.mutations.WithLabelValues(action, "bad_request").Inc()
	case errors.Is(err, errBodyEmpty):
		s.bad(w, action, "empty_body", "")
	default:
		s.bad(w, action, "invalid_json", "")
	}
}

// itemsKey returns the key name in the JSON response of a GET array endpoint.
// It matches the table in the B10 plan: ua → "patterns", ip_* → "cidrs",
// geo → "geos". It makes the output self-documenting ("patterns": [...]).
func itemsKey(field string) string {
	switch field {
	case "ua_blacklist":
		return "patterns"
	case "ip_blocklist", "ip_whitelist":
		return "cidrs"
	case "geo_whitelist":
		return "geos"
	}
	return "items"
}

// orEmpty guarantees a non-nil slice in the JSON response ("diff": [] instead of null).
func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

type errBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// writeJSON always answers 200 OK — a handler's successful response. For errors
// we use writeErr with an explicit status.
func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Impossible for our types, but errchkjson requires handling it.
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) writeErr(w http.ResponseWriter, status int, code, detail string) {
	body, err := json.Marshal(errBody{Error: code, Detail: detail})
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) bad(w http.ResponseWriter, action, code, detail string) {
	s.writeErr(w, http.StatusBadRequest, code, detail)
	s.mutations.WithLabelValues(action, "bad_request").Inc()
}

func (s *Server) dbErr(w http.ResponseWriter, action string, err error) {
	s.log.Error("policy api db error", "action", action, "err", err)
	s.writeErr(w, http.StatusInternalServerError, "db_error", "")
	s.mutations.WithLabelValues(action, "db_error").Inc()
}
