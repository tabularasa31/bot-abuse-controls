// Package catalog serves the catalogs to the edges.
//
//   - GET /catalog/{name}  — the catalog snapshot, optionally filtered by ?site.
//   - ETag / If-None-Match — a strong content hash, answering 304 unchanged.
//   - X-Catalog-Version    — the payload schema version.
//   - 503                  — nothing loaded yet; fail closed, so the edge never
//     mistakes an empty catalog for a successful one.
package catalog

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// knownCatalogs — the eight catalogs from config-distribution.md §"The 'catalog'
// concept". Kept in one place, so that route registration and handle.handle
// look at the same list.
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

// Server — the HTTP wrapper over Store. One Store per process; there can be
// several Server objects (a test mux and a production one, say) sharing the data.
type Server struct {
	store *Store
}

func New() *Server { return &Server{store: NewStore()} }

// NewWithStore — for tests and for main(), which loads the data itself and wants to
// pass a ready Store.
func NewWithStore(s *Store) *Server {
	if s == nil {
		s = NewStore()
	}
	return &Server{store: s}
}

// Store — access to the data, so that main can call Replace from the YAML reloader
// without knowing the package internals.
func (s *Server) Store() *Store { return s.store }

// Register mounts GET /catalog/{name}. The method is pinned at the ServeMux
// (Go 1.22+); other methods get a 405 without entering the handler.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /catalog/{name}", s.handle)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := knownCatalogs[name]; !ok {
		writeErr(w, http.StatusNotFound, "unknown_catalog", name)
		return
	}

	// Only the length is validated: an unknown host legitimately returns the
	// default, so the format does not matter.
	site := r.URL.Query().Get("site")
	if len(site) > 253 {
		// RFC 1035 §2.3.4: the maximum length of a domain name is 253 octets.
		writeErr(w, http.StatusBadRequest, "site_too_long", "")
		return
	}

	snap, err := s.store.Snapshot(name, site)
	if err != nil {
		var unk errUnknownCatalog
		if errors.As(err, &unk) {
			// Should not happen (the name is already in knownCatalogs), but defence in depth:
			// if somebody adds a catalog to knownCatalogs and forgets the Store,
			// a 500 is more visible in the edge logs than a 200 with an empty body.
			writeErr(w, http.StatusInternalServerError, "catalog_not_built", name)
			return
		}
		// json.Marshal must not fail on our shape; if it does, an explicit
		// 500 is better than a process panic (from review).
		writeErr(w, http.StatusInternalServerError, "serialize_failed", name)
		return
	}

	// Nothing loaded yet: answer 503 so the edge keeps its last good catalog
	// instead of replacing it with a successful-looking empty one.
	if !s.store.IsLoaded() {
		w.Header().Set("X-Catalog-Version", snap.Version)
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "catalog_not_loaded", name)
		return
	}

	// The §C1 contract: X-Catalog-Version always, an ETag always, and a body only
	// when If-None-Match did not match.
	h := w.Header()
	h.Set("X-Catalog-Version", snap.Version)
	h.Set("ETag", snap.ETag)
	// Cache-Control: the edge decides for itself (timer.every(30s)), but we forbid
	// intermediate proxies to cache — otherwise at-most-once-per-edge breaks.
	h.Set("Cache-Control", "no-store")

	if anyETagMatches(r.Header.Values("If-None-Match"), snap.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(snap.Body)
}

// anyETagMatches handles both forms a client may use: the header repeated, or
// one header carrying a comma-separated list.
func anyETagMatches(headers []string, etag string) bool {
	for _, h := range headers {
		if etagMatches(h, etag) {
			return true
		}
	}
	return false
}

// etagMatches parses one header value per RFC 7232 §3.2. A comma inside a
// quoted string does not separate tokens, so this walks the quotes rather than
// splitting on commas.
func etagMatches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "*" {
		return true
	}
	for _, token := range splitETagList(header) {
		// strip the W/ prefix — weak and strong comparison are equivalent for not-modified.
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

// splitETagList splits an If-None-Match value into tokens, respecting
// quoted-string per RFC 7230 §3.2.6 (a quoted-pair `\X` inside is also
// consumed). Empty tokens are discarded.
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
			// A quoted-pair: we skip the next byte entirely, so that `\"`
			// does not close the quoted-string.
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

// errorBody — a typed body, so that json.Marshal never receives an `any`
// (errchkjson: an any can hide an unencodable type).
type errorBody struct {
	Error   string `json:"error"`
	Catalog string `json:"catalog,omitempty"`
}

func writeErr(w http.ResponseWriter, status int, code, catalog string) {
	data, err := json.Marshal(errorBody{Error: code, Catalog: catalog})
	if err != nil {
		// Impossible for errorBody (strings only), but errchkjson requires it.
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
