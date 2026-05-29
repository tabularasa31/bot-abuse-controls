// Package antibotapi — HTTP-эндпоинты policy API ([B10]).
//
// Контракт server-to-server: единственный потребитель — dashboard-backend.
// Аутентификация конечного клиента — забота дашборда; здесь только bearer-auth
// между двумя сервисами и валидация payload'ов до открытия транзакции.
//
// Маршруты — под `/antibot/v1/policy/{site}` (`{site}` — host клиента,
// валидируется ≤253 байта). Каждый mutation handler пишет slog с полями
// actor=dashboard, action, site, was_noop — единая точка для агрегатора
// логов когда он появится. Audit-таблицу в БД не вводим (обоснование — в
// плане B10).
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

// maxBodyBytes — bound на одно тело запроса. PATCH-payload маленький; защита
// от случайного гигантского write от багнутого dashboard-клиента.
const maxBodyBytes = 64 * 1024

// Server держит зависимости и метрики API. New возвращает nil, если auth
// не сконфигурирован — main делает warn и не регистрирует роуты.
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

// Register монтирует роуты под общим bearer-auth-middleware. Go 1.22+
// method+path-маршрутизация: чужие методы → 405 без захода в handler.
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

// timed — обёртка: измеряет latency, валидирует site из path. handler работает
// в уже-аутентифицированном контексте; site вытащен и проверен.
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

// requestAttrs собирает forensic-поля для slog'а на каждую mutation
// (PR-58 security audit #3): при leak'е токена audit-log без source IP /
// request_id не позволял отличить легитимные мутации от атакующих.
// Источник IP — X-Forwarded-For (наш LB — nginx — его выставляет; см.
// infra/demo-backend/nginx/lb.conf), fallback на r.RemoteAddr. Request-id —
// заголовок X-Request-Id (если dashboard-backend его проставляет), пустая
// строка иначе.
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

// patchBody принимает только скалярные поля; unknown ключи валятся
// strict-декодером (DisallowUnknownFields), чтобы опечатки от dashboard'а не
// тихо игнорировались.
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

// handleDeletePolicy удаляет policy-запись host'а целиком. Тела нет (DELETE
// идентифицирует ресурс через path). Отсутствие записи → 404, идемпотентно
// как у array DELETE. После удаления эдж через Channel C ≤30с возвращается к
// pool default (mode=shadow, observe-only).
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

// valueForField извлекает значение из body согласно семантике поля и
// валидирует его. Возвращает (value, errCode, errMsg).
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

// asnBody — ASN как *int64 чтобы отличить «не задано» от «0». ValidateASN(0)
// принимает (RFC 6793 — 0 reserved, но не блокируем как явный выбор оператора),
// поэтому без *-указателя пустой body `{}` молча мутировал бы ASN 0
// (PR-58 review #4).
type asnBody struct {
	ASN *int64 `json:"asn"`
}

// requireASN — общая проверка required + range для POST/DELETE asn_block.
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

// Sentinel-ошибки decodeJSON — handler.bad() мапит их на санитарные коды
// без leak'a внутренних деталей (имена unknown полей, JSON-decoder сообщения,
// размер MaxBytes — PR-58 security audit #5/#7).
var (
	errBodyEmpty    = errors.New("empty body")
	errBodyTooLarge = errors.New("body too large")
	errBodyBadJSON  = errors.New("invalid json")
)

// decodeJSON читает bounded body и парсит strict-декодером. Возвращает
// одну из sentinel-ошибок выше (или nil). Сами json.Decoder-сообщения и
// `read body: http: request body too large` НЕ выходят за пределы пакета.
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

// handleDecodeErr мапит sentinel-ошибки decodeJSON на корректный HTTP-статус
// + статичный JSON-код без раскрытия деталей. 413 для oversize — стандарт
// (RFC 7231 §6.5.11), не лепим всё в 400.
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

// itemsKey возвращает имя ключа в JSON-ответе для GET array-endpoint'а.
// Соответствует таблице в плане B10: ua → "patterns", ip_* → "cidrs",
// geo → "geos". Делает выдачу самодокументируемой («patterns»: [...]).
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

// orEmpty гарантирует не-nil slice в JSON-ответе («diff»: [] вместо null).
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

// writeJSON всегда отвечает 200 OK — успешный ответ handler'а. Для ошибок
// используется writeErr с явным status.
func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Невозможно для наших типов; но errchkjson требует обработки.
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
