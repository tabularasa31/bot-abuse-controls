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
-- match() — inverse of key(): bare fp when the key is in `gen`, else nil.
-- ===========================================================================

check(fp_state.match("abc:0", 0), "abc", "match() strips the suffix in-gen")
check(fp_state.match(fp_state.key("t13d:weird", 3), 3), "t13d:weird",
    "match() round-trips a fp that itself contains a colon")
check(fp_state.match("abc:0", 1), nil, "match() returns nil for a stale gen")
check(fp_state.match("abc:10", 1), nil,
    "match() is not fooled by a gen prefix (10 vs 1)")

-- ===========================================================================
-- META_GEN_KEY — the meta shared_dict key, shared by every reader/writer.
-- ===========================================================================

check(fp_state.META_GEN_KEY, "fp_blocklist_gen", "META_GEN_KEY is stable")

-- ===========================================================================

if failed > 0 then
    io.stderr:write(string.format("\n%d passed, %d FAILED\n", passed, failed))
    os.exit(1)
end
print(string.format("fp_blocklist_state: %d passed", passed))
