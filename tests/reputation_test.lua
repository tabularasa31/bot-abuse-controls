-- Unit tests for infra/demo-stand/lua/reputation.lua.
-- Pure Lua; runs under any luajit / lua 5.1+ with no openresty deps — only
-- the pure helper active_values() is covered here. The ipmatcher build and
-- the ngx-touching run() path are exercised on the live stand (the require of
-- resty.ipmatcher is lazy, inside build()/run(), so this file loads cleanly).
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local reputation = require "reputation"

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

-- Compare an array-of-strings result against an expected array, order-sensitive
-- (active_values preserves input order). Joined with "|" so a mismatch prints
-- both sequences.
local function check_arr(actual, expected, label)
    check(table.concat(actual, "|"), table.concat(expected, "|"), label)
end

-- ===========================================================================
-- reputation.active_values() — non-staging `value` strings from a parsed list
-- ===========================================================================

check_arr(reputation.active_values(nil), {}, "active_values nil -> {}")
check_arr(reputation.active_values({}), {}, "active_values empty -> {}")

check_arr(
    reputation.active_values({ { value = "10.0.0.0/8", attrs = {} } }),
    { "10.0.0.0/8" },
    "active_values single (no status)")

check_arr(
    reputation.active_values({
        { value = "10.0.1.0/24", attrs = { status = "active" } },
        { value = "10.0.2.5",    attrs = {} },
    }),
    { "10.0.1.0/24", "10.0.2.5" },
    "active_values two active, order preserved")

-- Staged entries are excluded from the active set (staging promotion is A11).
check_arr(
    reputation.active_values({
        { value = "203.0.113.42",    attrs = { status = "active" } },
        { value = "198.51.100.0/24", attrs = { status = "staging" } },
    }),
    { "203.0.113.42" },
    "active_values excludes staging")

check_arr(
    reputation.active_values({
        { value = "198.51.100.0/24", attrs = { status = "staging" } },
    }),
    {},
    "active_values only-staging -> {}")

-- Empty/blank values are dropped (defensive against malformed lines).
check_arr(
    reputation.active_values({
        { value = "", attrs = {} },
        { value = "2001:db8::/32", attrs = {} },
    }),
    { "2001:db8::/32" },
    "active_values drops empty value, keeps ipv6 cidr")

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
