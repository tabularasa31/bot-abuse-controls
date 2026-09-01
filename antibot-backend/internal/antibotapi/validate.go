// Validation of the admin API payloads BEFORE a transaction is opened. Any record
// that passes these checks must also pass catalog.Validate on the next tick of
// dbloader.Reloader — otherwise the reloader goes fail-stale and the edge is stuck on the
// old catalog.
package antibotapi

import (
	"fmt"
	"regexp"

	"golang.org/x/net/publicsuffix"

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/catalog"
)

// maxSiteLen — RFC 1035 §2.3.4 (a maximum of 253 octets for a domain name).
const maxSiteLen = 253

// siteRE — a permissible hostname per RFC 1123 §2.1: LDH labels (letters, digits,
// hyphens) separated by dots, each label ≤63 bytes, not starting or ending with a
// hyphen. We preserve the case as given (the Postgres host PK is case-sensitive),
// though in practice the dashboard sends lowercase hostnames.
//
// previously the check was only len ≤253, which
// let through `..`, NUL, control characters, a percent-encoded slash (which after
// the ServeMux URL decode becomes '/') and unicode. Not SQLi (the queries are parameterized),
// but junk in the `host` PK plus broken correlation by `site` in SIEM logs.
var siteRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// ValidateSite — a syntactic check of the hostname from the URL path.
// LDH plus dots plus a length ≤253. Single-label hosts are allowed (an internal
// `staging`, say). IDN is not supported — the dashboard must send ASCII (Punycode
// where needed).
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
	// the edge applies a parent-domain policy fallback — a row for a
	// public suffix would then be inherited by every unrelated child host that
	// merely points DNS at the edge, breaking unknown-host isolation. icann-only: internal single-label names (`staging`) return
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

// ValidateUARegex — RE2 validation. The same grammar as catalog.Validate
// on the reloader side: if it passes here, it passes there too.
func ValidateUARegex(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern: empty")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("pattern: invalid regex: %w", err)
	}
	return nil
}

// ValidateCIDR delegates to catalog.ValidateCIDR — symmetrically with the reloader and
// lua-resty-ipmatcher on the edge (an IP with no /N is accepted as a host route).
func ValidateCIDR(s string) error {
	if s == "" {
		return fmt.Errorf("cidr: empty")
	}
	return catalog.ValidateCIDR(s)
}

// ValidateOriginIP delegates to catalog.ValidateOriginIP — the same predicate
// the reloader applies in catalog.Validate. An empty string is permitted
// (clearing origin_ip / a non-proxied tenant); otherwise a single bare
// IPv4/IPv6 address with no prefix.
func ValidateOriginIP(s string) error {
	return catalog.ValidateOriginIP(s)
}

// ValidateASN — an RFC 6793 32-bit ASN. We allow the uint32 range (≤4_294_967_295).
// 0 is reserved, but we do not block it (operator discretion); catch it in the database if
// needed.
func ValidateASN(n int64) error {
	if n < 0 || n > 0xFFFFFFFF {
		return fmt.Errorf("asn: out of uint32 range, got %d", n)
	}
	return nil
}

// geoCodeRE — two uppercase ASCII letters. ISO 3166-1 alpha-2 without checking
// against a real country list (that is not our concern; the geoip database may be
// more up to date than any list we hardcode).
var geoCodeRE = regexp.MustCompile(`^[A-Z]{2}$`)

func ValidateGeoCode(s string) error {
	if !geoCodeRE.MatchString(s) {
		return fmt.Errorf("geo: must be ISO 3166-1 alpha-2 uppercase, got %q", s)
	}
	return nil
}
