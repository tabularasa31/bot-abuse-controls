-- Unit tests for infra/demo-stand/lua/hygiene.lua + header_sanity.lua.
-- Pure Lua; runs under any luajit / lua 5.1+ with no openresty deps — the
-- ngx-touching parts (hygiene.run) are exercised on the stand, the pure
-- compile/decision helpers are covered here.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;./infra/demo-stand/lua/?.lua;" .. package.path
local hygiene = require "hygiene"
local header_sanity = require "header_sanity"

local failed, passed = 0, 0

local function check(actual, expected, label)
    if actual == expected then
        passed = passed + 1
    else
        failed = failed + 1
        io.stderr:write(string.format(
            "FAIL  %s\n      expected: %s\n      actual:   %s\n",
            label, tostring(expected), tostring(actual)))
    end
end

-- ===========================================================================
-- hygiene.build_combined() — combined regex of ACTIVE patterns
-- ===========================================================================

check(hygiene.build_combined(nil), nil, "build_combined nil -> nil")
check(hygiene.build_combined({}), nil, "build_combined empty -> nil (shadow)")

check(
    hygiene.build_combined({ { value = "curl", attrs = {} } }),
    "(curl)",
    "build_combined single")

check(
    hygiene.build_combined({
        { value = "curl", attrs = {} },
        { value = "python-requests", attrs = { status = "active" } },
    }),
    "(curl)|(python-requests)",
    "build_combined two active")

-- Staged patterns are excluded from the active regex (staging is task A11).
check(
    hygiene.build_combined({
        { value = "curl", attrs = { status = "active" } },
        { value = "AhrefsBot", attrs = { status = "staging" } },
    }),
    "(curl)",
    "build_combined excludes staging")

check(
    hygiene.build_combined({ { value = "AhrefsBot", attrs = { status = "staging" } } }),
    nil,
    "build_combined only-staging -> nil")

-- ===========================================================================
-- hygiene.method_lookup()
-- ===========================================================================

local mset = hygiene.method_lookup({ "GET", "HEAD", "POST", "OPTIONS" })
check(mset.GET, true,    "method_lookup GET allowed")
check(mset.OPTIONS, true, "method_lookup OPTIONS allowed")
check(mset.TRACE, nil,   "method_lookup TRACE not listed")
check(hygiene.method_lookup("GET").GET, true, "method_lookup single string")

-- ===========================================================================
-- header_sanity.check() — RFC §A2
-- ===========================================================================

check(header_sanity.check("HTTP/2.0", nil, nil), "http2_no_accept",
    "header_sanity HTTP/2 no Accept -> block")
check(header_sanity.check("HTTP/2.0", "text/html", nil), nil,
    "header_sanity HTTP/2 with Accept -> pass")
check(header_sanity.check("HTTP/1.1", nil, nil), nil,
    "header_sanity HTTP/1.1 no Accept -> pass (rule not applied)")
check(header_sanity.check("HTTP/1.1", nil, "en-US"), nil,
    "header_sanity HTTP/1.1 with Accept-Language -> pass")

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
