-- Unit tests for infra/demo-stand/lua/reputation.lua.
-- Pure Lua; runs under any luajit / lua 5.1+ with no openresty deps — the pure
-- helpers active_values() / to_set() / country_blocked() are covered here. The
-- ipmatcher build, the GeoLite2 lookup (geoip.lua) and the ngx-touching run()
-- path are exercised on the live stand (the requires of resty.ipmatcher and
-- geoip are lazy, inside build()/run(), so this file loads cleanly).
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

-- Stub the `policy` module so `require "reputation"` resolves under
-- bare luajit. reputation requires policy at module-top (B11 /
-- ), and the real policy.lua pulls in cjson.safe which isn't
-- shipped with the host luajit used by `make test-host`. The pure
-- helpers covered here never invoke reputation.run(), so the stub's
-- bodies don't run — only its shape matters (same pattern hygiene_test
-- uses).
package.loaded["policy"] = {
    enforce        = function() end,
    get            = function() return { mode = "shadow", strictness = "standard" } end,
    canonical_host = function(h) return h end,
}

-- policy_matchers — same stub rationale: tests cover pure
-- helpers that never reach the per-host matcher path. EMPTY sentinel
-- shape mirrors the real module.
package.loaded["policy_matchers"] = {
    get   = function() return { whitelist = nil, blocklist = nil, asn_block = nil,
                                geo_whitelist = nil, ua_blacklist_re = nil } end,
    EMPTY = { whitelist = nil, blocklist = nil, asn_block = nil,
              geo_whitelist = nil, ua_blacklist_re = nil },
}

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
-- reputation.staging_values() — mirror image of active_values: keeps only
-- status=staging CIDRs (A11, ), drops active/blank. Order preserved.
-- ===========================================================================
check_arr(reputation.staging_values(nil), {}, "staging_values nil -> {}")
check_arr(
    reputation.staging_values({
        { value = "203.0.113.0/24", attrs = { status = "active" } },
        { value = "198.51.100.42",  attrs = { status = "staging" } },
        { value = "2001:db8::/48",  attrs = { status = "staging" } },
    }),
    { "198.51.100.42", "2001:db8::/48" },
    "staging_values keeps only staging, order preserved")
check_arr(
    reputation.staging_values({
        { value = "203.0.113.0/24", attrs = { status = "active" } },
    }),
    {},
    "staging_values only-active -> {}")
check_arr(
    reputation.staging_values({
        { value = "", attrs = { status = "staging" } },
        { value = "10.0.0.1", attrs = { status = "staging" } },
    }),
    { "10.0.0.1" },
    "staging_values drops empty value")

-- ===========================================================================
-- reputation.to_set() — array -> membership set (asn_datacenters lookup)
-- ===========================================================================

local function has(set, k) return set[k] == true end

do
    local s = reputation.to_set({ "24940", "16276", "14061" })
    check(has(s, "24940"), true,  "to_set contains 24940")
    check(has(s, "16276"), true,  "to_set contains 16276")
    check(s["99999"],      nil,   "to_set absent key -> nil")
end

check(next(reputation.to_set(nil)) == nil, true, "to_set nil -> empty")
check(next(reputation.to_set({})) == nil,  true, "to_set empty -> empty")
check(reputation.to_set({ "", "8075" })[""], nil, "to_set drops empty string")

-- ===========================================================================
-- reputation.country_blocked(allow, cc) — geo_blocklist inverted-whitelist
-- logic (rules-reference #9). Block iff a whitelist is set AND cc is known AND
-- cc is not in it. The Phase 1 stand reality is an empty whitelist (no
-- per-resource policy source yet) -> never blocks (dormant).
-- ===========================================================================

check(reputation.country_blocked({ RU = true }, "CN"), true,
    "country_blocked: CN not in {RU} -> block")
check(reputation.country_blocked({ RU = true, CN = true }, "CN"), false,
    "country_blocked: CN in whitelist -> pass")
check(reputation.country_blocked({}, "CN"), false,
    "country_blocked: empty whitelist -> pass (dormant)")
check(reputation.country_blocked(nil, "CN"), false,
    "country_blocked: nil whitelist -> pass (dormant)")
check(reputation.country_blocked({ RU = true }, nil), false,
    "country_blocked: unknown country -> pass")
check(reputation.country_blocked({ RU = true }, ""), false,
    "country_blocked: blank country -> pass")

-- ===========================================================================
-- reputation.refresh_whitelist() / refresh_asn() — gen-cached rebuild from the
-- Channel C snapshot (B12, ). Mock ngx.shared (meta + the two catalog
-- dicts) and a fake resty.ipmatcher; assert a gen flip swaps the matcher/set.
-- ===========================================================================

do
    local function new_dict()
        local s, d = {}, {}
        function d:get(k) return s[k] end
        function d:set(k, v) s[k] = v; return true end
        function d:delete(k) s[k] = nil end
        function d:get_keys(_) local out = {} for k in pairs(s) do out[#out+1] = k end return out end
        return d
    end

    local saved_ngx       = _G.ngx
    local saved_ipmatcher = package.loaded["resty.ipmatcher"]
    local meta, wl, asn   = new_dict(), new_dict(), new_dict()
    _G.ngx = { shared = { meta = meta, antibot_ip_whitelist = wl,
                          antibot_asn_datacenters = asn },
               log = function() end, ERR = "ERR", WARN = "WARN" }

    -- Fake ipmatcher: capture the CIDR set passed to new() so we can assert the
    -- matcher was rebuilt from exactly the snapshot's gen.
    local captured
    package.loaded["resty.ipmatcher"] = {
        new = function(values) captured = values; return { match = function() return true end } end,
    }

    -- ---- ip_whitelist refresh ------------------------------------------------
    reputation.ip_whitelist_enabled = true
    reputation._cached_gen_wl = nil

    wl:set("203.0.113.7:1", "1")
    wl:set("2001:db8::/48:1", "1")
    wl:set("198.51.100.0/24:0", "1") -- stale gen-0 key, must be ignored at gen 1
    meta:set("ip_whitelist_gen", 1)
    reputation.refresh_whitelist()
    table.sort(captured)
    check_arr(captured, { "2001:db8::/48", "203.0.113.7" },
        "refresh_whitelist rebuilds matcher from current gen only")
    check(reputation.whitelist ~= nil, true, "refresh_whitelist sets matcher")

    -- gen 2: empty snapshot → nil matcher (rule becomes a no-op).
    meta:set("ip_whitelist_gen", 2)
    reputation.refresh_whitelist()
    check(reputation.whitelist, nil, "refresh_whitelist empty gen -> nil matcher")

    -- kill-switch: disabled → matcher cleared regardless of snapshot.
    reputation.ip_whitelist_enabled = false
    wl:set("10.0.0.1:3", "1")
    meta:set("ip_whitelist_gen", 3)
    reputation.refresh_whitelist()
    check(reputation.whitelist, nil, "refresh_whitelist respects kill-switch")

    -- ---- asn_datacenters refresh --------------------------------------------
    reputation._cached_gen_asn = nil
    asn:set("24940:1", "1")
    asn:set("16276:1", "1")
    asn:set("14061:0", "1") -- stale gen-0, ignored at gen 1
    meta:set("asn_datacenters_gen", 1)
    reputation.refresh_asn()
    check(reputation.asn_dc_set["24940"], true, "refresh_asn set contains 24940")
    check(reputation.asn_dc_set["16276"], true, "refresh_asn set contains 16276")
    check(reputation.asn_dc_set["14061"], nil,  "refresh_asn ignores stale gen-0 key")
    check(reputation.asn_dc_set["99999"], nil,  "refresh_asn absent asn -> nil")

    -- gen 2: empty snapshot → empty set (tag never fires).
    meta:set("asn_datacenters_gen", 2)
    reputation.refresh_asn()
    check(next(reputation.asn_dc_set), nil, "refresh_asn empty gen -> empty set")

    -- gen-cache: a second call without a gen flip is a no-op (no rescan).
    asn:set("8075:2", "1")
    reputation.refresh_asn()
    check(reputation.asn_dc_set["8075"], nil, "refresh_asn gen-cached: no rescan without flip")

    package.loaded["resty.ipmatcher"] = saved_ipmatcher
    _G.ngx = saved_ngx
end

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
