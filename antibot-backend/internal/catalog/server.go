// Package catalog is the Channel C catalog server (one of the three antibot-
// backend functions per ADR-005 / config-distribution.md).
//
// Skeleton scope ([B2]): монтируем /catalog/* и отвечаем 501 Not Implemented
// для всех известных каталогов из config-distribution §"The 'catalog' concept".
// Реальные ETag/If-None-Match, тела каталогов и схема в PostgreSQL — задача
// [B3] (HTTP-контракт) поверх [B4] (схема). Здесь только маршруты и форма
// ответа, чтобы edge-клиент ([B5]) и тесты контракта ([B13]) могли биндиться
// к стабильной поверхности.
package catalog

import (
	"encoding/json"
	"net/http"
	"strings"
)

// knownCatalogs — список из config-distribution.md §"The 'catalog' concept".
// Держим в одном месте, чтобы B3 просто заменил handler-у на реальный.
var knownCatalogs = map[string]struct{}{
	"fp_blocklist":     {},
	"ua_blacklist":     {},
	"ip_blocklist":     {},
	"ip_whitelist":     {},
	"asn_datacenters":  {},
	"verified_bot_ips": {},
	"policy":           {},
	"attack_mode":      {},
}

type Server struct{}

func New() *Server { return &Server{} }

// Register монтирует /catalog/{name}. Один обработчик на все каталоги —
// разводить по отдельным путям в скелете нет смысла, B3 либо оставит так,
// либо разнесёт.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/catalog/", s.handle)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/catalog/")
	if name == "" || strings.Contains(name, "/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if _, ok := knownCatalogs[name]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":   "unknown_catalog",
			"catalog": name,
		})
		return
	}
	// Контракт ETag/If-None-Match и тело — задача B3.
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":   "not_implemented",
		"catalog": name,
		"note":    "Channel C catalog body lands in B3 (HTTP+ETag) over B4 (schema)",
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
