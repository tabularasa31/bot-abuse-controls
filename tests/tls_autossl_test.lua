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

io.write(string.format("tls_autossl_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
