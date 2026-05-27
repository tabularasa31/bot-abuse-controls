-- Unit tests for infra/demo-stand/lua/origin_resolve.lua.
-- Pure function — no ngx, no shared_dict, no I/O.

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

local origin_resolve = require "origin_resolve"

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

-- ====================================================================
-- Happy path: scheme + hostname → IP substitution preserves everything else.
-- ====================================================================
eq(origin_resolve.resolve("https://dashboard.example.com", "<TENANT_ORIGIN_IP>"),
   "https://<TENANT_ORIGIN_IP>",
   "https hostname only → ip")

eq(origin_resolve.resolve("http://dashboard.example.com", "<TENANT_ORIGIN_IP>"),
   "http://<TENANT_ORIGIN_IP>",
   "http scheme preserved")

eq(origin_resolve.resolve("https://dashboard.example.com/path/to/thing", "<TENANT_ORIGIN_IP>"),
   "https://<TENANT_ORIGIN_IP>/path/to/thing",
   "path preserved after substitution")

eq(origin_resolve.resolve("https://dashboard.example.com:8443", "<TENANT_ORIGIN_IP>"),
   "https://<TENANT_ORIGIN_IP>:8443",
   "port preserved after substitution")

eq(origin_resolve.resolve("https://dashboard.example.com:8443/api", "<TENANT_ORIGIN_IP>"),
   "https://<TENANT_ORIGIN_IP>:8443/api",
   "port + path preserved")

-- ====================================================================
-- The actual bug fix: substitution is INDEPENDENT of any incoming Host.
-- resolve() doesn't take a Host argument — it only rewrites the origin URL.
-- ====================================================================
-- (Encoded as a comment, not a test — there's no Host parameter to vary.
-- The point of factoring out resolve() is that the inline $origin_resolve
-- in nginx.demo.conf no longer gates substitution on `Host == "…"`.)

-- ====================================================================
-- Pass-throughs when there's nothing to substitute.
-- ====================================================================
eq(origin_resolve.resolve("", "<TENANT_ORIGIN_IP>"),
   "",
   "empty origin → empty (bac.example.com landing path)")

eq(origin_resolve.resolve(nil, "<TENANT_ORIGIN_IP>"),
   nil,
   "nil origin → nil")

eq(origin_resolve.resolve("https://dashboard.example.com", ""),
   "https://dashboard.example.com",
   "empty origin_ip → original origin (no DASHBOARD_BACKEND_IP configured)")

eq(origin_resolve.resolve("https://dashboard.example.com", nil),
   "https://dashboard.example.com",
   "nil origin_ip → original origin")

-- ====================================================================
-- Origin URLs that don't fit `scheme://host` are returned as-is, not mangled.
-- ====================================================================
eq(origin_resolve.resolve("dashboard.example.com", "<TENANT_ORIGIN_IP>"),
   "dashboard.example.com",
   "bare hostname (no scheme) → unchanged")

eq(origin_resolve.resolve("ftp://example.com", "<TENANT_ORIGIN_IP>"),
   "ftp://example.com",
   "non-http(s) scheme → unchanged")

-- ====================================================================
-- IPv4 in ORIGIN_URL — operator already configured an IP, substitute anyway
-- (consistent behaviour; no special-case needed). The new ip replaces the old.
-- ====================================================================
eq(origin_resolve.resolve("https://192.0.2.10", "<TENANT_ORIGIN_IP>"),
   "https://<TENANT_ORIGIN_IP>",
   "IPv4 in origin → replaced by configured origin_ip")

eq(origin_resolve.resolve("https://192.0.2.10:8443/x", "<TENANT_ORIGIN_IP>"),
   "https://<TENANT_ORIGIN_IP>:8443/x",
   "IPv4 + port + path → host replaced, rest preserved")

-- ====================================================================
-- Summary
-- ====================================================================
io.write(string.format("origin_resolve_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
