// Package catalog — HTTP-сервер Channel C ([B3]).
//
// Контракт по docs/architecture/config-distribution.md §"The 'catalog' concept"
// + §"Channel C — antibot-backend HTTP pull (runtime data)":
//
//   - GET /catalog/{name}            — снимок каталога.
//   - ?site=<host>                   — per-tenant фильтрация (combined UA regex,
//     per-resource ip_*, policy/attack_mode).
//   - If-None-Match: "<etag>"        — 304 без тела, если payload не менялся.
//   - X-Catalog-Version: <semver>    — версия схемы payload (RFC §C1).
//   - ETag: "<sha256-hex>"           — strong, content-hash.
//   - 503 Service Unavailable        — Store пуст (никто не вызвал Replace);
//     fail-closed, чтобы эдж не "успешно" принимал пустые катаолги.
//
// Хранилище — *Store (in-memory, atomic-swap). Реальный YAML/Postgres
// загрузчик подаётся снаружи: B3 ставит in-memory + YAML, B4 заменит на pgx
// без изменения интерфейса.
package catalog

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// knownCatalogs — восемь каталогов из config-distribution.md §"The 'catalog'
// concept". Держим в одном месте, чтобы регистрация роутов и handle.handle
// смотрели на тот же список.
var knownCatalogs = map[string]struct{}{
	"tls_fp_blocklist":        {},
	"ua_blacklist":            {},
	"ip_blocklist":            {},
	"ip_whitelist":            {},
	"asn_datacenters":         {},
	"tls_fp_catalog":          {},
	"tls_fp_browser_profiles": {},
	"verified_bot_ips":        {},
	"policy":                  {},
	"attack_mode":             {},
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
		// RFC 1035 §2.3.4: максимальная длина domain name — 253 октета.
		writeErr(w, http.StatusBadRequest, "site_too_long", "")
		return
	}

	snap, err := s.store.Snapshot(name, site)
	if err != nil {
		var unk errUnknownCatalog
		if errors.As(err, &unk) {
			// Не должно случиться (имя уже в knownCatalogs), но defense-in-depth:
			// если кто-то добавит каталог в knownCatalogs и забудет в Store —
			// 500 заметнее в логах эджа, чем 200 с пустым телом.
			writeErr(w, http.StatusInternalServerError, "catalog_not_built", name)
			return
		}
		// json.Marshal на нашей форме не должен падать; если упал — лучше
		// явный 500, чем процессовая паника (PR #42 review).
		writeErr(w, http.StatusInternalServerError, "serialize_failed", name)
		return
	}

	// Fail-closed: Store ни разу не звался Replace'ом → 503 Service Unavailable.
	// Эдж по логике fail-stale (docs/architecture/config-distribution.md
	// §"Channel C / Failure mode") держит последний хороший каталог, а не
	// перезаписывает его нашим "успешным" пустым ответом (codex review).
	// Проверка через флаг Store.IsLoaded, а не по сравнению Version с
	// defaultVersion — иначе оператор, поставивший в YAML `version: "0.0.0"`,
	// видел бы 503 на легитимном payload'е.
	if !s.store.IsLoaded() {
		w.Header().Set("X-Catalog-Version", snap.Version)
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "catalog_not_loaded", name)
		return
	}

	// Контракт §C1: X-Catalog-Version всегда, ETag всегда, тело — только
	// если If-None-Match не совпал.
	h := w.Header()
	h.Set("X-Catalog-Version", snap.Version)
	h.Set("ETag", snap.ETag)
	// Cache-Control: эдж сам решает (timer.every(30s)), но запрещаем
	// промежуточным прокси кэшировать — иначе at-most-once-per-edge сломается.
	h.Set("Cache-Control", "no-store")

	if anyETagMatches(r.Header.Values("If-None-Match"), snap.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(snap.Body)
}

// anyETagMatches проверяет совпадение по RFC 7232 §3.2 поверх ВСЕХ значений
// If-None-Match. Клиент имеет право прислать заголовок несколько раз
// (http.Header.Values вернёт их раздельно) или один раз со списком через
// запятую — поддерживаем оба случая.
func anyETagMatches(headers []string, etag string) bool {
	for _, h := range headers {
		if etagMatches(h, etag) {
			return true
		}
	}
	return false
}

// etagMatches парсит один If-None-Match по RFC 7232 §3.2: список через
// запятую, "*", опциональный prefix `W/`. Принципиально: запятая ВНУТРИ
// quoted-string не разделяет токены — ETag `"foo,bar"` валидный. Поэтому
// токенайзер ведёт state-машину по DQUOTE, а не slice'ит по indexByte
// (PR #42 review).
func etagMatches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "*" {
		return true
	}
	for _, token := range splitETagList(header) {
		// strip W/ prefix — weak/strong сравнение для not-modified эквивалентно.
		token = strings.TrimPrefix(token, "W/")
		if token == "" {
			continue
		}
		if token == etag {
			return true
		}
	}
	return false
}

// splitETagList разбивает значение If-None-Match на токены, уважая
// quoted-string по RFC 7230 §3.2.6 (quoted-pair `\X` внутри тоже
// поглощается). Пустые токены отбрасываются.
func splitETagList(s string) []string {
	var out []string
	inQuotes := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuotes = !inQuotes
		case c == '\\' && inQuotes && i+1 < len(s):
			// quoted-pair: пропускаем следующий байт целиком, чтобы `\"`
			// не закрывал quoted-string.
			i++
		case c == ',' && !inQuotes:
			if tok := strings.TrimSpace(s[start:i]); tok != "" {
				out = append(out, tok)
			}
			start = i + 1
		}
	}
	if tok := strings.TrimSpace(s[start:]); tok != "" {
		out = append(out, tok)
	}
	return out
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
