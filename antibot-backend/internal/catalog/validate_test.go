package catalog

import "testing"

// PR #43 review follow-up: Validate должна принимать ровно то же
// подмножество, что edge'овый lua-resty-ipmatcher — а не строгий
// netip.ParsePrefix. См. validateCIDR.
func TestValidate_CIDRAcceptsSameSetAsIpmatcher(t *testing.T) {
	good := []string{
		"203.0.113.0/24", // канонический IPv4 prefix
		"198.51.100.5",   // bare IPv4 — ipmatcher трактует как /32
		"10.0.0.5/8",     // host-биты заданы — ipmatcher маскирует
		"2001:db8::/32",  // канонический IPv6 prefix
		"2001:db8::1",    // bare IPv6 — ipmatcher трактует как /128
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
			t.Errorf("Validate отвергла валидный CIDR/IP %q: %v", c, err)
		}
	}
	for _, c := range bad {
		d := &Data{IPBlocklist: map[string]string{c: "block"}}
		if err := Validate(d); err == nil {
			t.Errorf("Validate приняла мусор %q без ошибки", c)
		}
	}
}

// 86exrefdz: Policy.OriginIP — пусто (тенант не проксируется) или одиночный
// bare-адрес. Префиксы/мусор должны валиться до Store.Replace, иначе
// reloader fail-stale на следующем тике (симметрия с ValidateOriginIP в
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
	for _, ip := range []string{"203.0.113.0/24", "not-an-ip", "host.example"} {
		d := &Data{Policy: map[string]Policy{"clientx.com": {
			Mode: "shadow", Strictness: "standard", OriginIP: ip,
		}}}
		if err := Validate(d); err == nil {
			t.Errorf("Validate accepted bad origin_ip %q", ip)
		}
	}
}

// PR #43 review (Angle A): normalize должен coerce-нить системные срезы
// nil → []T{}, не только per-host policy. Иначе json.Marshal эмитит
// `null` на пустой БД, ETag дрейфит.
func TestNormalize_SystemSlicesNotNilAfterEmpty(t *testing.T) {
	d := &Data{} // все срезы nil
	normalize(d)
	if d.UABlacklist == nil {
		t.Errorf("UABlacklist остался nil после normalize")
	}
	if d.IPWhitelist == nil {
		t.Errorf("IPWhitelist остался nil после normalize")
	}
	if d.ASNDatacenters == nil {
		t.Errorf("ASNDatacenters остался nil после normalize")
	}
}
