// Валидация payload'ов admin API ДО открытия транзакции. Любая запись,
// прошедшая эти проверки, обязана пройти catalog.Validate на следующем тике
// dbloader.Reloader — иначе reloader станет fail-stale и edge зависнет на
// старом каталоге.
package antibotapi

import (
	"fmt"
	"regexp"

	"golang.org/x/net/publicsuffix"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
)

// maxSiteLen — RFC 1035 §2.3.4 (максимум 253 октета для domain name).
const maxSiteLen = 253

// siteRE — допустимое hostname по RFC 1123 §2.1: LDH-label'ы (буквы, цифры,
// дефис), разделённые точкой, label ≤63 байт, не начинается/заканчивается
// дефисом. Регистр сохраняем как есть (Postgres host PK is case-sensitive),
// но фактически hostname'ы lowercase у дашборда.
//
// PR-58 security audit #2: до этого проверка была только len ≤253, что
// пропускало `..`, NUL, control-chars, percent-encoded slash (после
// ServeMux URL-decode становится '/'), unicode. Не SQLi (parameterized),
// но мусор в `host` PK + сломанная корреляция по `site` в SIEM-логах.
var siteRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// ValidateSite — синтаксическая проверка hostname'a из URL-path.
// LDH + dots + length ≤253. Single-label hosts разрешены (например, internal
// `staging`). IDN не поддерживаем — дашборд обязан подавать ASCII (Punycode
// при необходимости).
func ValidateSite(s string) error {
	if s == "" {
		return fmt.Errorf("site: empty")
	}
	if len(s) > maxSiteLen {
		return fmt.Errorf("site: longer than %d bytes (RFC 1035)", maxSiteLen)
	}
	if !siteRE.MatchString(s) {
		return fmt.Errorf("site: must be a valid LDH hostname (RFC 1123)")
	}
	// Reject registering a public suffix itself (`com`, `co.uk`, `xn--p1ai`=рф):
	// the edge applies a parent-domain policy fallback (86exrefdz) — a row for a
	// public suffix would then be inherited by every unrelated child host that
	// merely points DNS at the edge, breaking unknown-host isolation (codex P1
	// on PR #100). icann-only: internal single-label names (`staging`) return
	// icann=false and stay allowed.
	if suffix, icann := publicsuffix.PublicSuffix(s); icann && suffix == s {
		return fmt.Errorf("site: must not be a public suffix (%q)", s)
	}
	return nil
}

var (
	validModes        = map[string]struct{}{"shadow": {}, "active": {}}
	validStrictnesses = map[string]struct{}{"standard": {}, "permissive": {}}
)

func ValidateMode(s string) error {
	if _, ok := validModes[s]; !ok {
		return fmt.Errorf("mode: must be 'shadow' or 'active', got %q", s)
	}
	return nil
}

func ValidateStrictness(s string) error {
	if _, ok := validStrictnesses[s]; !ok {
		return fmt.Errorf("strictness: must be 'standard' or 'permissive', got %q", s)
	}
	return nil
}

// ValidateUARegex — RE2-валидация. Та же грамматика, что и catalog.Validate
// на стороне reloader'a: если здесь пропустили, там тоже пропустит.
func ValidateUARegex(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern: empty")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("pattern: invalid regex: %w", err)
	}
	return nil
}

// ValidateCIDR делегирует catalog.ValidateCIDR — симметрично reloader'у и
// lua-resty-ipmatcher на edge (принимает IP без /N как host-route).
func ValidateCIDR(s string) error {
	if s == "" {
		return fmt.Errorf("cidr: empty")
	}
	return catalog.ValidateCIDR(s)
}

// ValidateOriginIP делегирует catalog.ValidateOriginIP — тот же предикат,
// что reloader применяет в catalog.Validate. Пустая строка допустима
// (снять origin_ip / тенант не проксируется); иначе одиночный bare-адрес
// IPv4/IPv6, без префикса.
func ValidateOriginIP(s string) error {
	return catalog.ValidateOriginIP(s)
}

// ValidateASN — RFC 6793 32-bit ASN. Допускаем диапазон uint32 (≤4_294_967_295).
// 0 — зарезервирован, но не блокируем (operator-discretion); ловим в БД при
// необходимости.
func ValidateASN(n int64) error {
	if n < 0 || n > 0xFFFFFFFF {
		return fmt.Errorf("asn: out of uint32 range, got %d", n)
	}
	return nil
}

// geoCodeRE — две заглавные ASCII-буквы. ISO 3166-1 alpha-2 без проверки
// against реального списка стран (это не наша забота, geoip-база может быть
// обновлённее нашего hard-coded списка).
var geoCodeRE = regexp.MustCompile(`^[A-Z]{2}$`)

func ValidateGeoCode(s string) error {
	if !geoCodeRE.MatchString(s) {
		return fmt.Errorf("geo: must be ISO 3166-1 alpha-2 uppercase, got %q", s)
	}
	return nil
}
