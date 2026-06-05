-- Unit tests for tls_autossl.allow_domain (the on-demand-TLS gate).
-- Pure logic with injected deps — the auto-ssl/ACME wiring itself can only be
-- verified on a deployed edge, but the allow/deny decision is testable here.

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local autossl = require "tls_autossl"

local passed, failed = 0, 0
local function eq(actual, want, name)
    if actual == want then
        passed = passed + 1
    else
        failed = failed + 1
        io.write(string.format("FAIL %s: got %s, want %s\n",
            name, tostring(actual), tostring(want)))
    end
end

-- Tenant set (host -> origin_ip), as policy.origin_ip would return.
local TENANTS = {
    ["clientx.com"]              = "203.0.113.9",
    ["dashboard.example.com"] = "<TENANT_ORIGIN_IP>", -- tenant, but under base domain
    ["observed.example"]         = "",             -- policy row, no origin_ip
}
local function origin_ip(h) return TENANTS[h] end
local opts = { base_domain = "example.com", origin_ip = origin_ip }

-- Custom-domain tenant → ACME allowed.
eq(autossl.allow_domain("clientx.com", opts), true, "custom-domain tenant → allow")
eq(autossl.allow_domain("ClientX.COM", opts), true, "case-insensitive → allow")

-- Under the stand base domain → static fallback cert, never ACME (even if tenant).
eq(autossl.allow_domain("dashboard.example.com", opts), false,
   "tenant under base domain → deny (served by static cert)")
eq(autossl.allow_domain("example.com", opts), false, "base apex → deny")
eq(autossl.allow_domain("bac.example.com", opts), false, "bac under base → deny")

-- Not a tenant → deny (anti-abuse: random/scanner SNI can't trigger issuance).
eq(autossl.allow_domain("evil.example", opts), false, "non-tenant → deny")
eq(autossl.allow_domain("observed.example", opts), false, "policy row, empty origin_ip → deny")
eq(autossl.allow_domain("clientx.com.evil.example", opts), false, "suffix-attack → deny")

-- Suffix-match must be on a dot boundary, not substring.
TENANTS["notexample.com"] = "203.0.113.50"
eq(autossl.allow_domain("notexample.com", opts), true,
   "host ending in base-domain string but not a subdomain → still evaluated as tenant")

-- nil / empty host.
eq(autossl.allow_domain(nil, opts), false, "nil host → deny")
eq(autossl.allow_domain("", opts), false, "empty host → deny")

-- Empty base domain (disabled) → tenant gate only.
local opts_nobase = { base_domain = "", origin_ip = origin_ip }
eq(autossl.allow_domain("dashboard.example.com", opts_nobase), true,
   "no base domain → tenant under it now ACME-eligible")

-- Cached DEFAULT_BASE_DOMAIN path: when opts has no base_domain, allow_domain
-- uses the module-level cache (loaded from STAND_BASE_DOMAIN at require / via
-- _reset_cache). Default (env unset in test) is example.com.
local opts_nobasekey = { origin_ip = origin_ip } -- no base_domain key → cached default
eq(autossl.allow_domain("clientx.com", opts_nobasekey), true,
   "cached default base: custom-domain tenant → allow")
eq(autossl.allow_domain("dashboard.example.com", opts_nobasekey), false,
   "cached default base: under example.com → deny")

-- _reset_cache picks up a changed STAND_BASE_DOMAIN (stub os.getenv).
do
    local real_getenv = os.getenv
    os.getenv = function(n) if n == "STAND_BASE_DOMAIN" then return "example.com" end return real_getenv(n) end
    autossl._reset_cache()
    eq(autossl.allow_domain("dashboard.example.com", opts_nobasekey), true,
       "after _reset_cache to example.com: example host no longer base → tenant gate (allow)")
    eq(autossl.allow_domain("foo.example.com", { origin_ip = function() return "203.0.113.99" end }), false,
       "after _reset_cache to example.com: *.example.com is base → deny")
    os.getenv = real_getenv
    autossl._reset_cache() -- restore default for any later cases
end

-- sni_known (edge self-protection step 2) — "serve this SNI at all?", the
-- complement of allow_domain ("ACME this SNI?"). The KEY difference is the base
-- domain: allow_domain=false (static cert, no ACME) but sni_known=true (it is a
-- name we legitimately serve and must NOT reject at the handshake).
eq(autossl.sni_known("dashboard.example.com", opts), true,
   "sni_known: base-domain host → known (served by static cert)")
eq(autossl.sni_known("example.com", opts), true, "sni_known: base apex → known")
eq(autossl.sni_known("bac.example.com", opts), true, "sni_known: bac under base → known")
-- Tenant (custom domain) → known.
eq(autossl.sni_known("clientx.com", opts), true, "sni_known: custom-domain tenant → known")
eq(autossl.sni_known("ClientX.COM", opts), true, "sni_known: case-insensitive → known")
-- Non-tenant / scanner SNI → unknown (handshake would be rejected).
eq(autossl.sni_known("evil.example", opts), false, "sni_known: non-tenant → unknown")
eq(autossl.sni_known("observed.example", opts), false,
   "sni_known: policy row, empty origin_ip → unknown")
eq(autossl.sni_known("clientx.com.evil.example", opts), false,
   "sni_known: suffix-attack → unknown")
-- nil / empty SNI → unknown (but reject_unknown_sni only acts on a PRESENT SNI;
-- no-SNI handshakes are left to the HTTP-layer 444).
eq(autossl.sni_known(nil, opts), false, "sni_known: nil SNI → unknown")
eq(autossl.sni_known("", opts), false, "sni_known: empty SNI → unknown")
-- Empty base domain (disabled) → tenant gate only; base host falls through to
-- the tenant lookup (here a tenant, so known).
eq(autossl.sni_known("dashboard.example.com", opts_nobase), true,
   "sni_known: no base domain → tenant under it still known via origin_ip")

io.write(string.format("tls_autossl_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
