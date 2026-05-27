-- Unit tests for infra/demo-stand/lua/proxy_target.lua.
-- Pure function — no ngx, no shared_dict, no I/O.

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

local function env(proxied_host, origin_url)
    return { proxied_host = proxied_host, origin_url = origin_url }
end

local DASH = "dashboard.example.com"
local URL  = "https://dashboard.example.com"

-- ====================================================================
-- Happy path: registered proxied client → ORIGIN_URL.
-- ====================================================================
eq(proxy_target.origin(DASH, env(DASH, URL)),
   URL,
   "registered host → ORIGIN_URL")

-- ====================================================================
-- Catch-all to BAC: everything else returns "" so location / falls
-- through to /__landing.
-- ====================================================================
eq(proxy_target.origin("bac.example.com", env(DASH, URL)),
   "",
   "bac.example.com → BAC ('')")

eq(proxy_target.origin("example.com", env(DASH, URL)),
   "",
   "random Host: example.com → BAC")

eq(proxy_target.origin("<EDGE_VM_IP>", env(DASH, URL)),
   "",
   "IP literal in Host → BAC")

eq(proxy_target.origin("localhost", env(DASH, URL)),
   "",
   "Host: localhost (README quickstart) → BAC")

eq(proxy_target.origin("dashboard.example.com", env(DASH, URL)),
   "",
   "case-sensitive: uppercase variant → BAC (Host is normalized lowercase by ngx.var.host;\
    if someone sneaks an uppercase comparison should fail safe)")

eq(proxy_target.origin("subdomain.dashboard.example.com", env(DASH, URL)),
   "",
   "subdomain of dashboard not auto-included → BAC")

eq(proxy_target.origin("dashboard.example.com.evil.com", env(DASH, URL)),
   "",
   "suffix-attack hostname → BAC")

-- ====================================================================
-- Empty / nil inputs — fail safe to BAC ("").
-- ====================================================================
eq(proxy_target.origin(nil, env(DASH, URL)),
   "",
   "nil host → BAC")

eq(proxy_target.origin("", env(DASH, URL)),
   "",
   "empty host (HTTP/1.0 without Host header) → BAC")

eq(proxy_target.origin(DASH, env("", URL)),
   "",
   "no proxied_host configured → BAC")

eq(proxy_target.origin(DASH, env(DASH, "")),
   "",
   "no ORIGIN_URL configured → BAC (operator hasn't set upstream)")

eq(proxy_target.origin(DASH, env(nil, URL)),
   "",
   "nil proxied_host → BAC")

eq(proxy_target.origin(DASH, env(DASH, nil)),
   "",
   "nil origin_url → BAC")

eq(proxy_target.origin(DASH, nil),
   "",
   "nil env → BAC")

eq(proxy_target.origin(DASH, {}),
   "",
   "empty env → BAC")

-- ====================================================================
-- Summary
-- ====================================================================
io.write(string.format("proxy_target_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
