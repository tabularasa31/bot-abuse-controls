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

// Register монтирует GET /catalog/{name}. Метод и парсинг сегмента — на
// уровне ServeMux (Go 1.22+ routing); один обработчик на все каталоги — в
// скелете разводить по отдельным путям нет смысла, B3 либо оставит так,
// либо разнесёт.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /catalog/{name}", s.handle)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := knownCatalogs[name]; !ok {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "unknown_catalog", Catalog: name})
		return
	}
	// Контракт ETag/If-None-Match и тело — задача B3.
	writeJSON(w, http.StatusNotImplemented, errorBody{
		Error:   "not_implemented",
		Catalog: name,
		Note:    "Channel C catalog body lands in B3 (HTTP+ETag) over B4 (schema)",
	})
}

// errorBody — типизированное тело, чтобы json.Encode не получал `any`
// (errchkjson по делу: канал/функция в any падает в рантайме).
type errorBody struct {
	Error   string `json:"error"`
	Catalog string `json:"catalog,omitempty"`
	Note    string `json:"note,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body errorBody) {
	// json.Marshal на errorBody (только строки) не может вернуть ошибку,
	// но errchkjson хочет явной проверки — пусть будет.
	data, err := json.Marshal(body)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
