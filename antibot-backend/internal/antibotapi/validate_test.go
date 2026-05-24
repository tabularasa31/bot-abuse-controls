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
		{strings.Repeat("a", 253), false},
		{strings.Repeat("a", 254), true},
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
