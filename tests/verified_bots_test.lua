-- Unit tests for infra/demo-stand/lua/verified_bots.lua (B8).
--
-- Covers the pure helpers (split_ua_pattern / looks_like_bot / parse_entry)
-- under bare luajit, plus the ngx-touching classify() + run() paths with
-- minimal stubs (ngx.shared, package.loaded["bac_log"]).
--
-- Six scenarios from the B8 acceptance:
--   1. verified IP + searchbot UA → "verified", verdict bot_verified
--   2. rejected → "rejected", NO verdict (cascade continues)
--   3. absent → "pending", verdict bot_verified_pending (SEO-safe)
--   4. non-searchbot UA → nil (rule does not fire)
--   5. disabled rule → nil even on a verified hit
--   6. provisional_pending=false → nil on absent (no verdict)
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

-- ===========================================================================
-- Stubs: ngx, ngx.shared, bac_log
-- ===========================================================================

local set_calls = {}    -- array of { stage, verdict, rule } in call order
local function reset_calls() set_calls = {} end

package.loaded["bac_log"] = {
    set_verdict = function(stage, verdict, rule)
        set_calls[#set_calls + 1] = { stage = stage, verdict = verdict, rule = rule }
    end,
}

local function new_dict()
    local d = { _store = {} }
    -- get returns (value, err); err is set by tests that simulate a real
    -- shared_dict failure (rare — covered by the "meta:get error" case).
    function d:get(k) return self._store[k], self._err end
    function d:set(k, v) self._store[k] = v; return true end
    -- add inserts only if the key is missing; returns true on insert, false
    -- otherwise — mirrors ngx.shared.DICT:add's "first-wins" contract that
    -- classify uses to dedupe its WARN/ERR logs.
    function d:add(k, v)
        if self._store[k] ~= nil then return false, "exists" end
        self._store[k] = v
        return true
    end
    function d:incr(k, delta, init)
        self._store[k] = (self._store[k] or init or 0) + delta
        return self._store[k]
    end
    return d
end

local logged = {}
local function reset_log() logged = {} end

_G.ngx = _G.ngx or {}
ngx.WARN, ngx.ERR, ngx.NOTICE = "WARN", "ERR", "NOTICE"
ngx.log = function(level, ...)
    local parts = { ... }
    for i, p in ipairs(parts) do parts[i] = tostring(p) end
    logged[#logged + 1] = level .. " " .. table.concat(parts)
end
local function log_contains(needle)
    for _, line in ipairs(logged) do
        if line:find(needle, 1, true) then return true end
    end
    return false
end
ngx.shared = {
    verified_bots = new_dict(),
    meta          = new_dict(),
    metrics       = new_dict(),
}

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local vb = require "verified_bots"

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

local function check_arr(actual, expected, label)
    check(table.concat(actual, "|"), table.concat(expected, "|"), label)
end

-- ===========================================================================
-- split_ua_pattern — `|`-alternation parser
-- ===========================================================================

check_arr(vb.split_ua_pattern(""), {}, "split: empty -> {}")
check_arr(vb.split_ua_pattern(nil), {}, "split: nil -> {}")
check_arr(vb.split_ua_pattern("Googlebot"), { "Googlebot" }, "split: single")
check_arr(
    vb.split_ua_pattern("Googlebot|bingbot|YandexBot|DuckDuckBot"),
    { "Googlebot", "bingbot", "YandexBot", "DuckDuckBot" },
    "split: four families (defaults.conf shape)")
check_arr(
    vb.split_ua_pattern(" Googlebot | bingbot "),
    { "Googlebot", "bingbot" },
    "split: trims whitespace")
check_arr(vb.split_ua_pattern("||"), {}, "split: only separators -> {}")

-- ===========================================================================
-- looks_like_bot — plain-substring alternation
-- ===========================================================================

local alts = { "Googlebot", "bingbot", "YandexBot", "DuckDuckBot" }

check(vb.looks_like_bot(nil, alts), false, "looks: nil ua -> false")
check(vb.looks_like_bot("", alts), false, "looks: empty ua -> false")
check(vb.looks_like_bot("curl/8", alts), false, "looks: curl -> false")
check(vb.looks_like_bot("Mozilla/5.0 (compatible; Googlebot/2.1)", alts), true,
    "looks: real Googlebot UA")
check(vb.looks_like_bot("Mozilla/5.0 (compatible; bingbot/2.0)", alts), true,
    "looks: bingbot")
check(vb.looks_like_bot("YandexBot/3.0", alts), true, "looks: YandexBot")
check(vb.looks_like_bot("DuckDuckBot/1.0", alts), true, "looks: DuckDuckBot")
check(vb.looks_like_bot("anything", {}), false, "looks: empty alts -> false")
check(vb.looks_like_bot("anything", nil), false, "looks: nil alts -> false")

-- ===========================================================================
-- parse_entry — "<status>:<family>" -> (status, family)
-- ===========================================================================

local function check_parse(input, e_status, e_family, label)
    local s, f = vb.parse_entry(input)
    check(s, e_status, label .. " status")
    check(f, e_family, label .. " family")
end

check_parse("verified:google", "verified", "google", "parse: verified:google")
check_parse("rejected:bing",   "rejected", "bing",   "parse: rejected:bing")
check_parse("verified:duckduckbot/1.0", "verified", "duckduckbot/1.0",
    "parse: family may contain non-colon chars")
check_parse(nil,                 nil, nil, "parse: nil")
check_parse("",                  nil, nil, "parse: empty")
check_parse("verified",          nil, nil, "parse: no colon -> nil")
check_parse("unknown:google",    nil, nil, "parse: unknown status -> nil")
check_parse("provisional:google",nil, nil, "parse: provisional is NOT a status")
check_parse(42,                  nil, nil, "parse: non-string -> nil")

-- ===========================================================================
-- build() — reads defaults.allow.bot_verified
-- ===========================================================================

local _, n_default = vb.build({
    defaults = {
        allow = { bot_verified = {
            ua_pattern = "Googlebot|bingbot|YandexBot|DuckDuckBot",
            provisional_pending = true,
        }},
    },
})
check(n_default, 4, "build: four UA alts compiled")
check(vb.enabled, true, "build: enabled defaults true")
check(vb.provisional, true, "build: provisional_pending=true")

vb.build({ defaults = { allow = { bot_verified = {
    enabled = false, ua_pattern = "Googlebot",
}}}})
check(vb.enabled, false, "build: enabled=false honoured")

vb.build({ defaults = { allow = { bot_verified = {
    ua_pattern = "Googlebot", provisional_pending = false,
}}}})
check(vb.provisional, false, "build: provisional_pending=false honoured")

vb.build({ defaults = {} })
check_arr(vb.ua_alts, {}, "build: missing rule -> empty alts (dormant)")
check(vb.enabled, true, "build: missing rule -> enabled defaults true")

-- ===========================================================================
-- classify() — reads ngx.shared.verified_bots keyed by `<ip>:<gen>`
-- ===========================================================================

ngx.shared.verified_bots = new_dict()
ngx.shared.meta = new_dict()
ngx.shared.meta:set("verified_bots_gen", 0)
ngx.shared.verified_bots:set("66.249.66.1:0", "verified:google")
ngx.shared.verified_bots:set("203.0.113.5:0", "rejected:google")

do
    local s, f = vb.classify("66.249.66.1")
    check(s, "verified", "classify: verified status")
    check(f, "google",   "classify: verified family")
end
do
    local s, f = vb.classify("203.0.113.5")
    check(s, "rejected", "classify: rejected status")
    check(f, "google",   "classify: rejected family")
end
do
    local s, f = vb.classify("198.51.100.1")
    check(s, "absent", "classify: missing IP -> absent")
    check(f, nil,      "classify: absent has no family")
end
do
    local s = vb.classify("")
    check(s, "absent", "classify: empty IP -> absent")
end

-- After a (simulated) gen bump, the gen-0 entries become unreachable
-- without code changes — the reader follows the meta gen.
ngx.shared.meta:set("verified_bots_gen", 1)
do
    local s = vb.classify("66.249.66.1")
    check(s, "absent", "classify: old-gen entry unreachable after gen bump")
end
ngx.shared.meta:set("verified_bots_gen", 0)

-- ===========================================================================
-- run() — full 3-state behaviour (acceptance criteria)
-- ===========================================================================

vb.build({ defaults = { allow = { bot_verified = {
    ua_pattern = "Googlebot|bingbot|YandexBot|DuckDuckBot",
    provisional_pending = true,
}}}})

local function last_call() return set_calls[#set_calls] end

-- (1) verified
reset_calls()
check(vb.run("66.249.66.1", "Mozilla/5.0 (Googlebot/2.1)"), "verified",
    "run: verified -> verified")
do
    local c = last_call()
    check(c and c.stage,   "reputation", "run: verified set_verdict stage")
    check(c and c.verdict, "allow",      "run: verified set_verdict verdict")
    check(c and c.rule,    "bot_verified", "run: verified set_verdict rule")
end

-- (2) rejected — NO verdict written, cascade must continue
reset_calls()
check(vb.run("203.0.113.5", "Googlebot/2.1"), "rejected",
    "run: rejected -> rejected")
check(#set_calls, 0, "run: rejected writes NO verdict (cascade continues)")

-- (3) absent → provisional fastpath
reset_calls()
check(vb.run("198.51.100.1", "Googlebot/2.1"), "pending",
    "run: absent -> pending")
do
    local c = last_call()
    check(c and c.rule, "bot_verified_pending", "run: absent set_verdict rule")
end

-- (4) non-searchbot UA — rule dormant
reset_calls()
check(vb.run("198.51.100.1", "Mozilla/5.0"), nil,
    "run: non-bot UA -> nil (rule does not fire)")
check(#set_calls, 0, "run: non-bot UA writes NO verdict")

-- (5) disabled
vb.enabled = false
reset_calls()
check(vb.run("66.249.66.1", "Googlebot/2.1"), nil,
    "run: disabled -> nil even for verified")
check(#set_calls, 0, "run: disabled writes NO verdict")
vb.enabled = true

-- (6) provisional disabled
vb.provisional = false
reset_calls()
check(vb.run("198.51.100.1", "Googlebot/2.1"), nil,
    "run: provisional=false + absent -> nil")
check(#set_calls, 0, "run: provisional=false writes NO verdict on absent")
vb.provisional = true

-- ===========================================================================
-- classify() WARN on malformed catalog value (PR #55 review #2)
-- ===========================================================================

-- Fresh state: gen=0 seeded, insert a malformed entry, expect WARN once and
-- "absent" return (SEO-safe demotion). Second classify on the same (ip,val)
-- must NOT re-log — dedup via meta:add.
ngx.shared.verified_bots = new_dict()
ngx.shared.meta = new_dict()
ngx.shared.metrics = new_dict()
ngx.shared.meta:set("verified_bots_gen", 0)
ngx.shared.verified_bots:set("203.0.113.99:0", "verified:")  -- empty family
reset_log()

do
    local s = vb.classify("203.0.113.99")
    check(s, "absent", "classify: malformed val demotes to absent")
    check(log_contains("malformed entry for ip=203.0.113.99"), true,
        "classify: WARN logged on first malformed encounter")
    check(ngx.shared.metrics:get("verified_bots_malformed_total"), 1,
        "classify: malformed counter incremented")
end

reset_log()
do
    local s = vb.classify("203.0.113.99")
    check(s, "absent", "classify: malformed val still absent on second call")
    check(log_contains("malformed entry"), false,
        "classify: WARN deduped on second call (same ip+val)")
end

-- ===========================================================================
-- classify() WARN on missing gen key (PR #55 review #4)
-- ===========================================================================

-- Wipe meta entirely — simulates an ordering bug where init.lua did not run
-- (or a future hot-reload that cleared meta). classify must log WARN once
-- and treat gen as 0 (fail-open into provisional).
ngx.shared.meta = new_dict()
ngx.shared.verified_bots = new_dict()
reset_log()

do
    local s = vb.classify("66.249.66.1")
    check(s, "absent", "classify: missing gen key → absent (fail-open)")
    check(log_contains("verified_bots_gen missing"), true,
        "classify: WARN on missing gen key")
end

reset_log()
do
    local s = vb.classify("66.249.66.1")
    check(s, "absent", "classify: still absent on second call")
    check(log_contains("verified_bots_gen missing"), false,
        "classify: WARN deduped (per-worker)")
end

-- ===========================================================================
-- SHORT_CIRCUIT set (PR #55 review #3) — reputation.lua single source of truth
-- ===========================================================================

check(vb.SHORT_CIRCUIT["verified"], true,  "SHORT_CIRCUIT contains verified")
check(vb.SHORT_CIRCUIT["pending"],  true,  "SHORT_CIRCUIT contains pending")
check(vb.SHORT_CIRCUIT["rejected"], nil,
    "SHORT_CIRCUIT does NOT contain rejected (cascade must continue)")
check(vb.SHORT_CIRCUIT[nil],        nil,
    "SHORT_CIRCUIT[nil] is nil (non-bot UA falls through)")

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
