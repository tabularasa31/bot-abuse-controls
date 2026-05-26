-- Unit tests for infra/demo-stand/lua/policy_matchers.lua.
-- Pure-helper coverage: to_set / compile_ua. The lrucache + ipmatcher
-- bundle live behind ngx-touching get(host) and are exercised on the
-- stand; this file stubs the module-level requires so the pure helpers
-- can be reached under bare luajit.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

-- Stubs for the module's three module-top requires. The pure helpers
-- (to_set, compile_ua) never invoke any of them; the real ipmatcher /
-- lrucache come from openresty and aren't on the host luajit path.
package.loaded["resty.lrucache"]  = { new = function() return { get = function() end, set = function() end } end }
package.loaded["resty.ipmatcher"] = { new = function() return nil, "stub: not exercised" end }
package.loaded["policy"]          = {
    get            = function() return {} end,
    canonical_host = function(h) return h end,
}

-- ngx stub — module-load reaches `ngx.log` only if lrucache.new errors
-- (it doesn't with our stub). Keep a minimal table for defence.
_G.ngx = _G.ngx or {
    log = function() end,
    ERR = "err", WARN = "warn",
    shared = {},
}

local pm = require "policy_matchers"

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
-- to_set — array → lookup table
-- ===========================================================================

check(pm._to_set(nil), nil, "to_set nil -> nil (no entries)")
check(pm._to_set({}),  nil, "to_set empty -> nil (no entries)")

do
    local s = pm._to_set({ "13335", "16509" })
    check(s and s["13335"] or false, true,  "to_set strings: 13335 present")
    check(s and s["16509"] or false, true,  "to_set strings: 16509 present")
    check(s and s["99999"] or false, false, "to_set strings: absent key is nil")
end

-- Numbers (cjson decodes JSON numbers as Lua numbers) must be tostring'd
-- so they match the geoip.lookup return shape (asn = tostring(value)).
do
    local s = pm._to_set({ 13335, 16509 })
    check(s and s["13335"] or false, true, "to_set numbers: stringified key 13335")
    check(s and s[13335]   or false, false, "to_set numbers: numeric key NOT set")
end

-- Blanks / nils are skipped silently — they are valid in JSON (empty
-- string) and shouldn't shadow a real entry.
do
    local s = pm._to_set({ "", "13335", "" })
    local count = 0
    for _ in pairs(s or {}) do count = count + 1 end
    check(count, 1, "to_set skips blanks: count==1")
    check(s["13335"], true, "to_set skips blanks: real key kept")
end

do
    -- All-blank input should collapse to nil (caller can `if set then ... end`).
    local s = pm._to_set({ "", "" })
    check(s, nil, "to_set all-blank -> nil")
end

-- ===========================================================================
-- compile_ua — array of regex strings → combined alternation
-- ===========================================================================

check(pm._compile_ua(nil), nil, "compile_ua nil -> nil")
check(pm._compile_ua({}),  nil, "compile_ua empty -> nil")
check(pm._compile_ua({ "curl" }), "(curl)", "compile_ua single")
check(
    pm._compile_ua({ "curl", "python-requests" }),
    "(curl)|(python-requests)",
    "compile_ua two patterns wrapped + joined")

-- Empties dropped so an accidental "" doesn't degenerate the combined
-- regex to `()|(real)` which matches the empty string and 403s every UA.
check(pm._compile_ua({ "", "curl", "" }), "(curl)", "compile_ua skips blank entries")
check(pm._compile_ua({ "", "" }),         nil,      "compile_ua all-blank -> nil")

-- ===========================================================================
-- EMPTY sentinel shape — readers must be able to field-test without nil deref.
-- ===========================================================================

check(pm.EMPTY.whitelist,        nil, "EMPTY.whitelist is nil")
check(pm.EMPTY.blocklist,        nil, "EMPTY.blocklist is nil")
check(pm.EMPTY.asn_block,        nil, "EMPTY.asn_block is nil")
check(pm.EMPTY.geo_whitelist,    nil, "EMPTY.geo_whitelist is nil")
check(pm.EMPTY.ua_blacklist_re,  nil, "EMPTY.ua_blacklist_re is nil")

-- ===========================================================================
-- Summary
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
