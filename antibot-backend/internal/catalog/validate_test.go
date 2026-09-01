package catalog

import "testing"

// A review follow-up: Validate must accept exactly the same
// subset as the edge's lua-resty-ipmatcher — not the strict
// netip.ParsePrefix. See validateCIDR.
func TestValidate_CIDRAcceptsSameSetAsIpmatcher(t *testing.T) {
	good := []string{
		"203.0.113.0/24", // a canonical IPv4 prefix
		"198.51.100.5",   // a bare IPv4 — ipmatcher treats it as /32
		"10.0.0.5/8",     // host bits are set — ipmatcher masks them
		"2001:db8::/32",  // a canonical IPv6 prefix
		"2001:db8::1",    // a bare IPv6 — ipmatcher treats it as /128
	}
	bad := []string{
		"999.0.0.0/33",
		"not-a-cidr",
		"203.0.113.0/abc",
		"",
	}

	for _, c := range good {
		d := &Data{IPBlocklist: map[string]string{c: "block"}}
		if err := Validate(d); err != nil {
			t.Errorf("Validate rejected the valid CIDR/IP %q: %v", c, err)
		}
	}
	for _, c := range bad {
		d := &Data{IPBlocklist: map[string]string{c: "block"}}
		if err := Validate(d); err == nil {
			t.Errorf("Validate accepted the junk %q without an error", c)
		}
	}
}

// Policy.OriginIP — empty (a non-proxied tenant) or a single
// bare address. Prefixes and junk must fail before Store.Replace, otherwise the
// reloader goes fail-stale on the next tick (symmetric with ValidateOriginIP in
// antibotapi).
func TestValidate_PolicyOriginIP(t *testing.T) {
	for _, ip := range []string{"", "203.0.113.9", "2001:db8::1"} {
		d := &Data{Policy: map[string]Policy{"clientx.com": {
			Mode: "shadow", Strictness: "standard", OriginIP: ip,
		}}}
		if err := Validate(d); err != nil {
			t.Errorf("Validate rejected valid origin_ip %q: %v", ip, err)
		}
	}
	for _, ip := range []string{"203.0.113.0/24", "not-an-ip", "host.example", "fe80::1%eth0"} {
		d := &Data{Policy: map[string]Policy{"clientx.com": {
			Mode: "shadow", Strictness: "standard", OriginIP: ip,
		}}}
		if err := Validate(d); err == nil {
			t.Errorf("Validate accepted bad origin_ip %q", ip)
		}
	}
}

// From review: normalize must coerce the system slices
// nil → []T{}, not only the per-host policy. Otherwise json.Marshal emits
// `null` on an empty database and the ETag drifts.
func TestNormalize_SystemSlicesNotNilAfterEmpty(t *testing.T) {
	d := &Data{} // every slice is nil
	normalize(d)
	if d.UABlacklist == nil {
		t.Errorf("UABlacklist stayed nil after normalize")
	}
	if d.IPWhitelist == nil {
		t.Errorf("IPWhitelist stayed nil after normalize")
	}
	if d.ASNDatacenters == nil {
		t.Errorf("ASNDatacenters stayed nil after normalize")
	}
}
