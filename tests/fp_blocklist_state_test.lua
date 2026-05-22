-- Unit tests for infra/demo-stand/lua/fp_blocklist_state.lua.
-- Pure Lua; runs under any luajit / lua 5.1+ with no openresty deps — the
-- module is just a per-worker generation cursor plus a pure key builder.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local fp_state = require "fp_blocklist_state"

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
-- key() — the `fp .. ":" .. gen` format shared by the §A1 read and the seed.
-- ===========================================================================

check(fp_state.key("t13d1516h2_8daaf6152771_b186095e22b6", 0),
    "t13d1516h2_8daaf6152771_b186095e22b6:0",
    "key() appends :0 for the static seed generation")

check(fp_state.key("abc", 7), "abc:7", "key() appends arbitrary generation")

-- The read side (verdict.lua) and the write side (init.lua / catalog pull)
-- must build the exact same string for the same (fp, gen).
check(fp_state.key("xy", 3) == fp_state.key("xy", 3), true,
    "key() is deterministic for equal inputs")

-- ===========================================================================
-- sync() — advances the per-worker cursor and returns the generation to use.
-- ===========================================================================

check(fp_state.gen, 0, "cursor starts at generation 0")

check(fp_state.sync(0), 0, "sync(0) returns 0 (no pull yet — stand steady state)")
check(fp_state.gen, 0, "cursor stays 0 when generation is unchanged")

check(fp_state.sync(5), 5, "sync() returns the new generation")
check(fp_state.gen, 5, "cursor advances to the pulled generation")

check(fp_state.sync(5), 5, "sync() is idempotent on a repeated generation")
check(fp_state.gen, 5, "cursor unchanged on a repeated generation")

-- A reader that pinned gen 5 must look up under gen 5, not the new one — but a
-- fresh sync moves the worker forward.
check(fp_state.sync(6), 6, "sync() advances again on the next bump")
check(fp_state.key("abc", fp_state.gen), "abc:6",
    "key() uses the advanced cursor after sync()")

-- ===========================================================================

if failed > 0 then
    io.stderr:write(string.format("\n%d passed, %d FAILED\n", passed, failed))
    os.exit(1)
end
print(string.format("fp_blocklist_state: %d passed", passed))
