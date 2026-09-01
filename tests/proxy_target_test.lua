-- Unit tests for infra/demo-stand/lua/proxy_target.lua.
-- Policy-driven routing (ClickUp 86exrefdz). Pure function — no ngx, no
-- shared_dict, no I/O: the tenant set is injected via the test-only
-- policy_override argument ({host -> origin_ip}), so we never touch the
-- real policy module / Channel C harness.

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

local proxy_target = require "proxy_target"

local passed, failed = 0, 0
local function eq(actual, want, name)
    if actual == want then
        passed = passed + 1
    else
        failed = failed + 1
        io.write(string.format("FAIL %s: got %q, want %q\n",
            name, tostring(actual), tostring(want)))
    end
end

-- backend(host, override) returns two values (origin_ip, loop_host); call it
-- through this helper so the multi-return isn't truncated by being mid-arglist.
local function eq_backend(host, override, want_ip, want_host, name)
    local ip, lh = proxy_target.backend(host, override)
    if ip == want_ip and lh == want_host then
        passed = passed + 1
    else
        failed = failed + 1
        io.write(string.format("FAIL %s: got (%q,%q), want (%q,%q)\n",
            name, tostring(ip), tostring(lh), tostring(want_ip), tostring(want_host)))
    end
end

-- Tenant set: host -> origin_ip (mirrors policy.get(host).origin_ip).
-- A v4 tenant, a v6 tenant, and a host present-but-not-a-tenant (policy
-- row with empty origin_ip).
local TENANTS = {
    ["clientx.com"]              = "203.0.113.9",
    ["dashboard.example.com"] = "203.0.113.15",
    ["v6.example"]               = "2001:db8::1",
    ["observed.example"]         = "",          -- policy row, no origin_ip
}

-- ====================================================================
-- Tenant → https://<host>; backend() → (origin_ip, host).
-- ====================================================================
eq(proxy_target.origin("clientx.com", TENANTS),
   "https://clientx.com",
   "v4 tenant → https://<host>")
eq_backend("clientx.com", TENANTS,
    "203.0.113.9", "clientx.com",
    "v4 tenant backend() → (origin_ip, host)")

eq(proxy_target.origin("dashboard.example.com", TENANTS),
   "https://dashboard.example.com",
   "dashboard tenant (seeded) → https://<host>")
eq_backend("dashboard.example.com", TENANTS,
    "203.0.113.15", "dashboard.example.com",
    "dashboard tenant backend()")

-- IPv6 origin_ip passes through verbatim; origin_resolve.resolve() does the
-- bracketing when it builds the proxy URL (covered in origin_resolve_test).
eq_backend("v6.example", TENANTS,
    "2001:db8::1", "v6.example",
    "IPv6 tenant backend() → (v6 ip, host)")

-- ====================================================================
-- Case-insensitivity: nginx lowercases ngx.var.host, but origin()/backend()
-- normalise defensively so a mixed-case Host still matches a lowercase
-- tenant key.
-- ====================================================================
eq(proxy_target.origin("ClientX.COM", TENANTS),
   "https://clientx.com",
   "mixed-case Host → matches lowercase tenant, lowercased in output")

-- ====================================================================
-- Non-tenant → BAC (""). backend() → ("", "").
-- ====================================================================
eq(proxy_target.origin("observed.example", TENANTS),
   "",
   "policy row with empty origin_ip → not a tenant → BAC")
eq_backend("observed.example", TENANTS,
    "", "",
    "empty origin_ip backend() → ('','')")

eq(proxy_target.origin("bac.example.com", TENANTS),
   "",
   "bac.example.com (no policy row) → BAC")
eq(proxy_target.origin("example.com", TENANTS),
   "",
   "random Host → BAC")
eq(proxy_target.origin("203.0.113.117", TENANTS),
   "",
   "IP-literal Host (scanner) → BAC (loop-safe)")
eq(proxy_target.origin("localhost", TENANTS),
   "",
   "Host: localhost → BAC")
eq(proxy_target.origin("clientx.com.evil.com", TENANTS),
   "",
   "suffix-attack hostname → BAC")
eq(proxy_target.origin("sub.clientx.com", TENANTS),
   "",
   "subdomain of a tenant not auto-included → BAC")

-- ====================================================================
-- Empty / nil host — fail safe to BAC.
-- ====================================================================
eq(proxy_target.origin(nil, TENANTS), "", "nil host → BAC")
eq(proxy_target.origin("", TENANTS), "", "empty host (HTTP/1.0 no Host) → BAC")
eq_backend(nil, TENANTS, "", "", "nil host backend() → ('','')")
eq_backend("", TENANTS, "", "", "empty host backend() → ('','')")

-- ====================================================================
-- policy_override as a function (host -> origin_ip) — same contract as the
-- table form, exercising the function branch of origin_ip_for().
-- ====================================================================
local fn = function(host)
    if host == "fn.example" then return "198.51.100.7" end
    return nil
end
eq(proxy_target.origin("fn.example", fn),
   "https://fn.example",
   "function policy_override: tenant → https://<host>")
eq_backend("fn.example", fn,
    "198.51.100.7", "fn.example",
    "function policy_override: backend()")
eq(proxy_target.origin("nope.example", fn),
   "",
   "function policy_override: non-tenant → BAC")

-- ====================================================================
-- Summary
-- ====================================================================
io.write(string.format("proxy_target_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
