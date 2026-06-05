-- Unit tests for infra/demo-stand/lua/policy_view.lua — the read-only effective-
-- policy view on the :9090 mgmt plane (extracted from an inline nginx block so
-- it's testable). Covers pick_host (the ?host= override fallback); encode()'s
-- empty-array wire contract needs real cjson (absent from the bare-luajit
-- runner) and is exercised end-to-end by tests/integration/cases/01-latency.sh.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

local policy_view = require "policy_view"

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

-- pick_host: explicit ?host= override wins; else the request Host.
eq(policy_view.pick_host("override.example", "req.example"), "override.example",
   "pick_host: arg_host override wins")
eq(policy_view.pick_host(nil, "req.example"), "req.example",
   "pick_host: nil arg → request host")
eq(policy_view.pick_host("", "req.example"), "req.example",
   "pick_host: empty arg → request host")
eq(policy_view.pick_host("only.example", nil), "only.example",
   "pick_host: arg present, no request host → arg")
eq(policy_view.pick_host(nil, nil), nil,
   "pick_host: both nil → nil")

io.write(string.format("\npolicy_view_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
