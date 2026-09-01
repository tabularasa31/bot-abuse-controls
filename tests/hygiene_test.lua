-- Unit tests for infra/demo-stand/lua/hygiene.lua.
-- Pure Lua; runs under any luajit / lua 5.1+ with no openresty deps — the
-- ngx-touching parts (hygiene.run) are exercised on the stand, the pure
-- compile helpers are covered here.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

-- Stub the `policy` module so `require "hygiene"` resolves under bare
-- luajit. hygiene requires policy at module-top (B11 / ), and
-- the real policy.lua pulls in cjson.safe which isn't shipped with the
-- host luajit used by `make test-host`. The pure helpers covered here
-- never invoke hygiene.run(), so the stub's bodies don't run — only its
-- shape matters (same approach catalog_pull_test takes for cjson.safe).
package.loaded["policy"] = {
    enforce        = function() end,
    get            = function() return { mode = "shadow", strictness = "standard" } end,
    canonical_host = function(h) return h end,
}

-- policy_matchers pulls in resty.lrucache + resty.ipmatcher + cjson via
-- policy.lua. Same stub strategy — pure helpers don't exercise the
-- request-time matcher path.
package.loaded["policy_matchers"] = {
    get   = function() return { whitelist = nil, blocklist = nil, asn_block = nil,
                                geo_whitelist = nil, ua_blacklist_re = nil } end,
    EMPTY = { whitelist = nil, blocklist = nil, asn_block = nil,
              geo_whitelist = nil, ua_blacklist_re = nil },
}

local hygiene = require "hygiene"

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
-- hygiene.build_staging() — combined regex + pattern list of STAGING patterns
-- (A11, ). Mirror image of build_combined: keeps only status=staging.
-- ===========================================================================

do
    local re, pats = hygiene.build_staging(nil)
    check(re, nil, "build_staging nil -> nil re")
    check(#pats, 0, "build_staging nil -> empty patterns")
end
do
    -- active patterns are dropped; only staging kept (in input order).
    local re, pats = hygiene.build_staging({
        { value = "curl",      attrs = { status = "active" } },
        { value = "AhrefsBot", attrs = { status = "staging" } },
        { value = "scrapy",    attrs = { status = "staging" } },
    })
    check(re, "(AhrefsBot)|(scrapy)", "build_staging combined keeps only staging")
    check(table.concat(pats, "|"), "AhrefsBot|scrapy", "build_staging patterns list")
end
do
    local re, pats = hygiene.build_staging({
        { value = "curl", attrs = { status = "active" } },
    })
    check(re, nil, "build_staging only-active -> nil re")
    check(#pats, 0, "build_staging only-active -> empty patterns")
end

-- combine_patterns — wrap a plain array (used by refresh from the Channel C
-- staging list) into a combined alternation.
check(hygiene.combine_patterns(nil), nil, "combine_patterns nil -> nil")
check(hygiene.combine_patterns({}), nil, "combine_patterns empty -> nil")
check(hygiene.combine_patterns({ "a" }), "(a)", "combine_patterns single")
check(hygiene.combine_patterns({ "a", "b" }), "(a)|(b)", "combine_patterns two")

-- ===========================================================================
-- hygiene.method_lookup()
-- ===========================================================================

local mset = hygiene.method_lookup({ "GET", "HEAD", "POST", "OPTIONS" })
check(mset.GET, true,    "method_lookup GET allowed")
check(mset.OPTIONS, true, "method_lookup OPTIONS allowed")
check(mset.TRACE, nil,   "method_lookup TRACE not listed")
check(hygiene.method_lookup("GET").GET, true, "method_lookup single string")

-- ===========================================================================
-- hygiene.header_anomaly() — informational tag heuristic (vision.md T0)
-- ===========================================================================

check(hygiene.header_anomaly("HTTP/2.0", nil), true,
    "header_anomaly HTTP/2 no Accept -> true")
check(hygiene.header_anomaly("HTTP/2.0", "text/html"), false,
    "header_anomaly HTTP/2 with Accept -> false")
check(hygiene.header_anomaly("HTTP/1.1", nil), false,
    "header_anomaly HTTP/1.1 no Accept -> false (not applied)")

-- ===========================================================================
-- refresh() — rebuild active_re / staging from the Channel C ua_blacklist
-- snapshot (A11, ). Mock ngx.shared (meta + antibot_ua_blacklist +
-- metrics) and a cjson.safe.decode stub; assert a gen flip swaps the matcher.
-- ===========================================================================

do
    local function new_dict()
        local s, d = {}, {}
        function d:get(k) return s[k] end
        function d:set(k, v) s[k] = v; return true end
        function d:safe_add(k, v) if s[k] ~= nil then return nil, "exists" end s[k] = v; return true end
        function d:delete(k) s[k] = nil end
        return d
    end

    local saved_ngx  = _G.ngx
    local saved_cjson = package.loaded["cjson.safe"]
    local meta, ua, metrics = new_dict(), new_dict(), new_dict()
    _G.ngx = { shared = { meta = meta, antibot_ua_blacklist = ua, metrics = metrics },
               log = function() end, ERR = "ERR", WARN = "WARN" }
    -- decode stub: map the exact stored string back to a Lua array.
    package.loaded["cjson.safe"] = {
        decode = function(str)
            if str == '["scrapy","ahrefs"]' then return { "scrapy", "ahrefs" } end
            return {}
        end,
    }

    hygiene.ua_blacklist_enabled = true
    hygiene._cached_gen_ua = nil

    -- gen 1 snapshot.
    ua:set("active:1", "(curl)|(wget)")
    ua:set("staging:1", '["scrapy","ahrefs"]')
    meta:set("ua_blacklist_gen", 1)
    hygiene.refresh()
    check(hygiene.active_re, "(curl)|(wget)", "refresh sets active_re from snapshot")
    check(hygiene.staging_re, "(scrapy)|(ahrefs)", "refresh builds staging_re from list")
    check(table.concat(hygiene.staging_patterns, "|"), "scrapy|ahrefs", "refresh staging patterns")

    -- gen 2: empty active, no staging.
    ua:set("active:2", "")
    ua:set("staging:2", "[]")
    meta:set("ua_blacklist_gen", 2)
    package.loaded["cjson.safe"].decode = function() return {} end
    hygiene.refresh()
    check(hygiene.active_re, nil, "refresh empty active -> nil")
    check(hygiene.staging_re, nil, "refresh empty staging -> nil")

    -- kill-switch: disabled → active/staging cleared regardless of snapshot.
    hygiene.ua_blacklist_enabled = false
    ua:set("active:3", "(curl)")
    meta:set("ua_blacklist_gen", 3)
    hygiene.refresh()
    check(hygiene.active_re, nil, "refresh respects kill-switch (active nil)")

    hygiene._cached_gen_ua = nil
    package.loaded["cjson.safe"] = saved_cjson
    _G.ngx = saved_ngx
end

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
