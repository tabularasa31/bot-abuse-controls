// Package catalog — HTTP-сервер Channel C ([B3]).
//
// Контракт по docs/architecture/config-distribution.md §"The 'catalog' concept"
// + §"Channel C — antibot-backend HTTP pull (runtime data)":
//
//   - GET /catalog/{name}            — снимок каталога.
//   - ?site=<host>                   — per-tenant фильтрация (combined UA regex,
//     per-resource ip_*, policy/attack_mode).
//   - If-None-Match: "<etag>"        — 304 без тела, если payload не менялся.
//   - X-Catalog-Version: <semver>    — версия схемы payload (RFC §В1).
//   - ETag: "<sha256-hex>"           — strong, content-hash.
//
// Хранилище — *Store (in-memory, atomic-swap). Реальный YAML/Postgres
// загрузчик подаётся снаружи: B3 ставит in-memory + YAML, B4 заменит на pgx
// без изменения интерфейса.
package catalog

import (
	"encoding/json"
	"net/http"
)

// knownCatalogs — восемь каталогов из config-distribution.md §"The 'catalog'
// concept". Держим в одном месте, чтобы регистрация роутов и handle.handle
// смотрели на тот же список.
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

// Server — HTTP-обёртка над Store. Один Store на процесс; Server-объектов
// может быть несколько (например, тестовый и продовый mux'ы), они шарят данные.
type Server struct {
	store *Store
}

func New() *Server { return &Server{store: NewStore()} }

// NewWithStore — для тестов и для main(), который грузит данные сам и хочет
// передать готовый Store.
func NewWithStore(s *Store) *Server {
	if s == nil {
		s = NewStore()
	}
	return &Server{store: s}
}

// Store — доступ к данным, чтобы main мог вызывать Replace из YAML-reloader'a
// без знания внутренностей пакета.
func (s *Server) Store() *Store { return s.store }

// Register монтирует GET /catalog/{name}. Метод фиксируется на ServeMux
// (Go 1.22+); чужие методы получают 405 без захода в handler.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /catalog/{name}", s.handle)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := knownCatalogs[name]; !ok {
		writeErr(w, http.StatusNotFound, "unknown_catalog", name)
		return
	}

	// site — опционален. Пустой = глобальный payload. Валидация: только
	// длина (защита от случайного гигантского ?site=) — формат host'a
	// проверять смысла нет, неизвестный host для policy/attack_mode
	// штатно отдаёт дефолт.
	site := r.URL.Query().Get("site")
	if len(site) > 253 {
		// RFC 1035 §2.3.4: максимальная длина doman name — 253 октета.
		writeErr(w, http.StatusBadRequest, "site_too_long", "")
		return
	}

	snap, ok := s.store.Snapshot(name, site)
	if !ok {
		// Не должно случиться (имя уже в knownCatalogs), но defense-in-depth:
		// если кто-то добавит каталог в knownCatalogs и забудет в Store —
		// 500 заметнее в логах эджа, чем 200 с пустым телом.
		writeErr(w, http.StatusInternalServerError, "catalog_not_built", name)
		return
	}

	// Контракт §В1: X-Catalog-Version всегда, ETag всегда, тело — только
	// если If-None-Match не совпал.
	h := w.Header()
	if snap.Version != "" {
		h.Set("X-Catalog-Version", snap.Version)
	}
	h.Set("ETag", snap.ETag)
	// Cache-Control: эдж сам решает (timer.every(30s)), но запрещаем
	// промежуточным прокси кэшировать — иначе at-most-once-per-edge
	// сломается.
	h.Set("Cache-Control", "no-store")

	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, snap.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(snap.Body)
}

// etagMatches реализует совпадение по RFC 7232 §3.1: If-None-Match может
// содержать список через запятую и "*". Слабые валидаторы (W/"...") в наших
// ответах не используются, но в запросе допустимы — для not-modified strong
// и weak-сравнение совпадают.
func etagMatches(header, etag string) bool {
	header = trimSpace(header)
	if header == "*" {
		return true
	}
	for len(header) > 0 {
		var token string
		if idx := indexByte(header, ','); idx >= 0 {
			token = trimSpace(header[:idx])
			header = header[idx+1:]
		} else {
			token = trimSpace(header)
			header = ""
		}
		// strip W/ prefix — weak/strong сравнение для not-modified эквивалентно.
		if len(token) >= 2 && token[0] == 'W' && token[1] == '/' {
			token = token[2:]
		}
		if token == etag {
			return true
		}
	}
	return false
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// errorBody — типизированное тело, чтобы json.Marshal не получал `any`
// (errchkjson: any может скрыть unencodable-тип).
type errorBody struct {
	Error   string `json:"error"`
	Catalog string `json:"catalog,omitempty"`
}

func writeErr(w http.ResponseWriter, status int, code, catalog string) {
	data, err := json.Marshal(errorBody{Error: code, Catalog: catalog})
	if err != nil {
		// Невозможно для errorBody (только строки), но errchkjson требует.
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
