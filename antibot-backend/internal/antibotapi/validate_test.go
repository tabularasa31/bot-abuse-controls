package antibotapi_test

import (
	"strings"
	"testing"

	"github.com/tabularasa31/antibot-backend/internal/antibotapi"
)

func TestValidateSite(t *testing.T) {
	cases := []struct {
		in  string
		bad bool
	}{
		{"", true},
		{"foo.example", false},
		{"a.b.c.example.com", false},
		{"single", false},                // a single-label internal hostname is allowed
		{"foo-bar.example.com", false},   // a hyphen inside a label
		{strings.Repeat("a", 63), false}, // max label len
		{strings.Repeat("a", 64), true},  // > 63 in a label
		{strings.Repeat("a.", 100) + "z", false},
		{strings.Repeat("a", 254), true}, // > 253 total
		// Junk that used to pass the len-only check:
		{"../etc/passwd", true},
		{"foo/bar", true},
		{"foo bar", true},
		{"-foo.example", true}, // label leading hyphen
		{"foo-.example", true}, // label trailing hyphen
		{".foo.example", true}, // leading dot
		{"foo.example.", true}, // trailing dot
		{"foo..bar", true},     // empty label
		{"foo.例え.jp", true},    // non-ASCII (IDN is not supported)
		{"foo\x00bar", true},   // NUL
		{"foo\nbar", true},     // newline (header injection guard)
		// Public suffixes rejected — the edge parent-domain fallback would
		// otherwise let any child host inherit them (codex P1 on PR #100).
		{"com", true},                    // bare gTLD
		{"org", true},                    // bare gTLD
		{"co.uk", true},                  // multi-label ccTLD suffix
		{"xn--p1ai", true},               // the .рф TLD (punycode)
		{"example.com", false},           // registrable domain — allowed
		{"xn--e1afmkfd.xn--p1ai", false}, // пример.рф — registrable, allowed
	}
	for _, tc := range cases {
		err := antibotapi.ValidateSite(tc.in)
		if (err != nil) != tc.bad {
			t.Errorf("ValidateSite(%q): err=%v, bad=%v", tc.in, err, tc.bad)
		}
	}
}

func TestValidateMode(t *testing.T) {
	for _, ok := range []string{"shadow", "active"} {
		if err := antibotapi.ValidateMode(ok); err != nil {
			t.Errorf("ValidateMode(%q): unexpected err %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Active", "off", "block"} {
		if err := antibotapi.ValidateMode(bad); err == nil {
			t.Errorf("ValidateMode(%q): expected error", bad)
		}
	}
}

func TestValidateStrictness(t *testing.T) {
	for _, ok := range []string{"standard", "permissive"} {
		if err := antibotapi.ValidateStrictness(ok); err != nil {
			t.Errorf("ValidateStrictness(%q): unexpected err %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Standard", "strict"} {
		if err := antibotapi.ValidateStrictness(bad); err == nil {
			t.Errorf("ValidateStrictness(%q): expected error", bad)
		}
	}
}

func TestValidateUARegex(t *testing.T) {
	if err := antibotapi.ValidateUARegex("curl/[0-9]"); err != nil {
		t.Errorf("valid regex rejected: %v", err)
	}
	if err := antibotapi.ValidateUARegex(""); err == nil {
		t.Error("empty regex accepted")
	}
	if err := antibotapi.ValidateUARegex("bot[a-z"); err == nil {
		t.Error("invalid regex accepted")
	}
}

func TestValidateCIDR(t *testing.T) {
	for _, ok := range []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::1", "2001:db8::/64"} {
		if err := antibotapi.ValidateCIDR(ok); err != nil {
			t.Errorf("CIDR %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "not-a-cidr", "999.999.999.999", "10.0.0.0/99"} {
		if err := antibotapi.ValidateCIDR(bad); err == nil {
			t.Errorf("CIDR %q accepted", bad)
		}
	}
}

func TestValidateOriginIP(t *testing.T) {
	// Empty = unset/clear; bare IPv4/IPv6 accepted; prefixes & garbage rejected.
	for _, ok := range []string{"", "203.0.113.9", "2001:db8::1"} {
		if err := antibotapi.ValidateOriginIP(ok); err != nil {
			t.Errorf("origin_ip %q rejected: %v", ok, err)
		}
	}
	// Private/global unicast are valid tenant backends.
	for _, ok := range []string{"10.0.0.5", "192.168.1.10", "172.16.0.1", "fd00::1"} {
		if err := antibotapi.ValidateOriginIP(ok); err != nil {
			t.Errorf("origin_ip %q (private unicast) rejected: %v", ok, err)
		}
	}
	// Prefixes, garbage, zoned IPv6, and non-routable / metadata addresses rejected.
	for _, bad := range []string{
		"10.0.0.0/8", "2001:db8::/64", "not-an-ip", "999.999.999.999", "host.example",
		"fe80::1%eth0",  // zoned
		"0.0.0.0", "::", // unspecified
		"127.0.0.1", "::1", // loopback
		"169.254.169.254", "fe80::1", // link-local incl. cloud metadata
		"224.0.0.1", "ff02::1", // multicast
	} {
		if err := antibotapi.ValidateOriginIP(bad); err == nil {
			t.Errorf("origin_ip %q accepted", bad)
		}
	}
}

func TestValidateASN(t *testing.T) {
	for _, ok := range []int64{0, 1, 65535, 4_294_967_295} {
		if err := antibotapi.ValidateASN(ok); err != nil {
			t.Errorf("ASN %d rejected: %v", ok, err)
		}
	}
	for _, bad := range []int64{-1, 4_294_967_296} {
		if err := antibotapi.ValidateASN(bad); err == nil {
			t.Errorf("ASN %d accepted", bad)
		}
	}
}

func TestValidateGeoCode(t *testing.T) {
	for _, ok := range []string{"US", "RU", "DE"} {
		if err := antibotapi.ValidateGeoCode(ok); err != nil {
			t.Errorf("geo %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "us", "USA", "U1", "ru"} {
		if err := antibotapi.ValidateGeoCode(bad); err == nil {
			t.Errorf("geo %q accepted", bad)
		}
	}
}
