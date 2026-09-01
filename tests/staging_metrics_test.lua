-- Unit tests for infra/demo-stand/lua/staging_metrics.lua (A11, ).
-- Pure logic over a mocked `ngx.shared.metrics`; runs under bare luajit.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

-- Mock just enough of ngx.shared.metrics (safe_add / get / delete).
local function new_metrics()
    local s, d = {}, {}
    function d:safe_add(k, v) if s[k] ~= nil then return nil, "exists" end s[k] = v; return true end
    function d:incr(k, delta, init) s[k] = (s[k] or init or 0) + delta; return s[k] end
    function d:get(k) return s[k] end
    function d:set(k, v) s[k] = v; return true end
    function d:delete(k) s[k] = nil end
    return d, s
end

local metrics, store = new_metrics()
_G.ngx = { shared = { metrics = metrics } }

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local sm = require "staging_metrics"

local failed, passed = 0, 0
local function check(actual, expected, label)
    if actual == expected then
        passed = passed + 1
    else
        failed = failed + 1
        io.stderr:write(string.format("FAIL  %s\n      expected: %s\n      actual:   %s\n",
            label, tostring(expected), tostring(actual)))
    end
end

-- prime: new ids get a zero counter; prefix is "staging:<catalog>:".
sm.reconcile("ua_blacklist", {}, { "curl", "wget" })
check(store["staging:ua_blacklist:curl"], 0, "prime new id curl -> 0")
check(store["staging:ua_blacklist:wget"], 0, "prime new id wget -> 0")

-- existing counter with accumulated matches must NOT be reset by a re-prime.
store["staging:ua_blacklist:curl"] = 5
sm.reconcile("ua_blacklist", { "curl", "wget" }, { "curl", "wget" })
check(store["staging:ua_blacklist:curl"], 5, "re-prime keeps accumulated count")

-- id leaves staging with ZERO count -> counter deleted (phantom cleanup).
sm.reconcile("ua_blacklist", { "curl", "wget" }, { "curl" })
check(store["staging:ua_blacklist:wget"], nil, "stale zero-count id deleted")

-- id leaves staging with NON-ZERO count -> counter kept (history preserved).
sm.reconcile("ua_blacklist", { "curl" }, {})
check(store["staging:ua_blacklist:curl"], 5, "stale non-zero id kept (zombie)")

-- catalog name is namespaced into the key; nil prev/new tolerated.
sm.reconcile("ip_blocklist", nil, { "203.0.113.0/24" })
check(store["staging:ip_blocklist:203.0.113.0/24"], 0, "ip_blocklist prefix + nil prev")
sm.reconcile("ip_blocklist", { "203.0.113.0/24" }, nil)
check(store["staging:ip_blocklist:203.0.113.0/24"], nil, "nil new drops zero-count id")

-- missing metrics dict -> silent noop (no crash).
_G.ngx.shared.metrics = nil
local ok = pcall(sm.reconcile, "ua_blacklist", {}, { "x" })
check(ok, true, "missing metrics dict -> noop, no error")
_G.ngx.shared.metrics = metrics

if failed > 0 then
    io.stderr:write(string.format("\n%d passed, %d FAILED\n", passed, failed))
    os.exit(1)
end
print(string.format("staging_metrics: %d passed", passed))
