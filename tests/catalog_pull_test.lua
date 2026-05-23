-- Unit tests for infra/demo-stand/lua/catalog_pull.lua (B5).
-- Pure Lua; the HTTP transport is exercised on the stand, the pure
-- response-handling logic — gen flip, 304 short-circuit, fail-stale skip,
-- decode + type guard, version gate — is covered here.
--
-- The module requires `cjson.safe` and the global `ngx`. We stub both
-- before `require "catalog_pull"` so this file runs under bare luajit
-- (no openresty deps) and the test cases drive handle_response with
-- pre-baked res tables, dodging the HTTP layer entirely.
--
-- Six cases from the B5 acceptance:
--   1. normal pull (200 → entries in shared dict, gen bumped, old swept)
--   2. 304 → entries not touched, generation not lost (regression
--      from RFC §В1 round-3 review)
--   3. timeout / connection error → log + skip, no dict mutation
--   4. malformed JSON → log + skip
--   5. decode returns string/number → log + skip
--   6. X-Catalog-Version mismatch → keep previous, bump metric
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

-- ===========================================================================
-- Stubs: cjson.safe, ngx, ngx.shared.*
-- ===========================================================================

local decode_table = {}    -- body-string → decoded table
local decode_err   = {}    -- body-string → error to return as (nil, err)

package.loaded["cjson.safe"] = {
    decode = function(s)
        if decode_err[s] then return nil, decode_err[s] end
        local v = decode_table[s]
        if v == nil then return nil, "no decode stub registered for " .. tostring(s) end
        return v
    end,
}

local logged = {}
local function reset_log() logged = {} end
local function log_contains(needle)
    for _, line in ipairs(logged) do
        if line:find(needle, 1, true) then return true end
    end
    return false
end

local function new_dict()
    local d = { _store = {} }
    function d:get(k) return self._store[k] end
    function d:set(k, v) self._store[k] = v; return true end
    function d:delete(k) self._store[k] = nil; return true end
    function d:incr(k, delta, init)
        self._store[k] = (self._store[k] or init or 0) + delta
        return self._store[k]
    end
    function d:get_keys(_max)
        local out = {}
        for k in pairs(self._store) do out[#out + 1] = k end
        return out
    end
    return d
end

_G.ngx = _G.ngx or {}
ngx.ERR    = "ERR"
ngx.WARN   = "WARN"
ngx.NOTICE = "NOTICE"
ngx.log = function(_level, ...)
    local parts = { ... }
    for i, p in ipairs(parts) do parts[i] = tostring(p) end
    logged[#logged + 1] = table.concat(parts)
end
ngx.time = function() return 1234567 end
ngx.shared = {
    fp_blocklist = new_dict(),
    meta         = new_dict(),
    metrics      = new_dict(),
}

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local cp       = require "catalog_pull"
local fp_state = require "fp_blocklist_state"

local cat = cp.catalogs.fp_blocklist
assert(cat, "fp_blocklist descriptor must be registered")

-- ===========================================================================
-- Test harness
-- ===========================================================================

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

local function check_true(cond, label)  check(cond and true or false, true,  label) end
local function check_false(cond, label) check(cond and true or false, false, label) end

-- Re-seed dicts + log to the "static gen 0 with one entry" state init.lua
-- leaves behind. Every test starts from this state so coverage is
-- independent.
local function reset_state()
    ngx.shared.fp_blocklist = new_dict()
    ngx.shared.meta         = new_dict()
    ngx.shared.metrics      = new_dict()
    -- static seed: one fp under gen 0, like init.lua's `fp_dict:set(key(fp, 0), "block")`.
    ngx.shared.fp_blocklist:set(fp_state.key("seed_fp", 0), "block")
    ngx.shared.meta:set(fp_state.META_GEN_KEY, 0)
    ngx.shared.meta:set("fp_blocklist_etag", "seed-etag")
    reset_log()
    decode_table = {}
    decode_err   = {}
end

-- ===========================================================================
-- 1. Normal 200 pull
-- ===========================================================================

do
    reset_state()
    local body = '{"fp_a":"block","fp_b":"block"}'
    decode_table[body] = { fp_a = "block", fp_b = "block" }
    local res = {
        status  = 200,
        body    = body,
        headers = { ETag = "\"new-etag\"", ["X-Catalog-Version"] = "1.0.0" },
    }
    local outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "ok", "200: returns ok")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1,
        "200: gen flipped from 0 to 1")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_a", 1)), "block",
        "200: new entry written under new gen")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_b", 1)), "block",
        "200: second entry written under new gen")
    check(ngx.shared.fp_blocklist:get(fp_state.key("seed_fp", 0)), nil,
        "200: old gen entry swept after flip")
    check(ngx.shared.meta:get("fp_blocklist_etag"), "\"new-etag\"",
        "200: etag stored in meta")
    check(ngx.shared.meta:get("fp_blocklist_version"), "1.0.0",
        "200: version stored in meta")
    check(ngx.shared.metrics:get("catalog_last_pull_ts:fp_blocklist"), 1234567,
        "200: last_pull_ts stamped for staleness gauge")
end

-- ===========================================================================
-- 2. 304 Not Modified
-- Regression from round-3 review: 304 must NOT touch dict / gen / etag.
-- ===========================================================================

do
    reset_state()
    -- live state: gen=5 with two live entries (simulate a steady-state edge
    -- that has been pulling for a while). 304 must preserve all of it.
    ngx.shared.meta:set(fp_state.META_GEN_KEY, 5)
    ngx.shared.fp_blocklist:set(fp_state.key("live_a", 5), "block")
    ngx.shared.fp_blocklist:set(fp_state.key("live_b", 5), "block")
    ngx.shared.meta:set("fp_blocklist_etag", "\"live-etag\"")

    local res = { status = 304, body = "", headers = {} }
    local outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "not_modified", "304: returns not_modified")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 5,
        "304: generation unchanged")
    check(ngx.shared.fp_blocklist:get(fp_state.key("live_a", 5)), "block",
        "304: live entry a preserved (regression guard)")
    check(ngx.shared.fp_blocklist:get(fp_state.key("live_b", 5)), "block",
        "304: live entry b preserved (regression guard)")
    check(ngx.shared.meta:get("fp_blocklist_etag"), "\"live-etag\"",
        "304: etag unchanged")
    check(ngx.shared.metrics:get("catalog_last_pull_ts:fp_blocklist"), nil,
        "304: last_pull_ts NOT bumped (304 is not a successful refresh of data)")
end

-- ===========================================================================
-- 3. Transport error (res=nil)
-- ===========================================================================

do
    reset_state()
    local outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, nil, "timeout")
    check(outcome, "skip", "transport error: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "transport error: gen unchanged")
    check(ngx.shared.fp_blocklist:get(fp_state.key("seed_fp", 0)), "block",
        "transport error: seed entry preserved")
    check_true(log_contains("fetch failed: timeout"),
        "transport error: ngx.log includes the err string")
end

-- ===========================================================================
-- 4. Malformed JSON
-- ===========================================================================

do
    reset_state()
    local body = "not-json"
    decode_err[body] = "expected value but found invalid token"
    local res = {
        status  = 200,
        body    = body,
        headers = { ETag = "\"x\"", ["X-Catalog-Version"] = "1.0.0" },
    }
    local outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "skip", "malformed JSON: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "malformed JSON: gen unchanged")
    check(ngx.shared.fp_blocklist:get(fp_state.key("seed_fp", 0)), "block",
        "malformed JSON: seed entry preserved")
    check_true(log_contains("decode failed"),
        "malformed JSON: ngx.log mentions decode failure")
end

-- ===========================================================================
-- 5. Decode returns a string / number (valid JSON, wrong shape).
-- pairs() on a non-table would crash; handle_response must skip cleanly.
-- ===========================================================================

do
    reset_state()
    local body = '"just-a-string"'
    decode_table[body] = "just-a-string"   -- decoder returns a string
    local res = {
        status  = 200,
        body    = body,
        headers = { ETag = "\"y\"", ["X-Catalog-Version"] = "1.0.0" },
    }
    local outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "skip", "wrong type (string): returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "wrong type (string): gen unchanged")
    check_true(log_contains("decoded value is string"),
        "wrong type (string): log identifies the wrong type")

    -- Same with a number — cjson is happy to return a top-level number.
    reset_state()
    body = "42"
    decode_table[body] = 42
    res = { status = 200, body = body, headers = { ["X-Catalog-Version"] = "1.0.0" } }
    outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "skip", "wrong type (number): returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "wrong type (number): gen unchanged")
end

-- ===========================================================================
-- 6. Version mismatch → keep previous gen, bump metric.
-- ===========================================================================

do
    reset_state()
    local body = '{"fp_a":"block"}'
    decode_table[body] = { fp_a = "block" }
    local res = {
        status  = 200,
        body    = body,
        headers = { ETag = "\"z\"", ["X-Catalog-Version"] = "2.0.0" },  -- major 2
    }
    local outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "skip", "version mismatch: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "version mismatch: gen unchanged")
    check(ngx.shared.fp_blocklist:get(fp_state.key("seed_fp", 0)), "block",
        "version mismatch: seed entry preserved")
    check(ngx.shared.metrics:get("edge_sidecar_version_mismatch_total:fp_blocklist"), 1,
        "version mismatch: metric bumped")
    check_true(log_contains("version mismatch"),
        "version mismatch: ngx.log identifies the mismatch")
end

-- ===========================================================================
-- version_compatible — the pure helper used by the gate above.
-- ===========================================================================

check_true(cp.version_compatible("1"),       "version_compatible: bare major 1")
check_true(cp.version_compatible("1.2.3"),   "version_compatible: semver 1.2.3")
check_true(cp.version_compatible("1.0"),     "version_compatible: 1.0")
check_false(cp.version_compatible("2.0.0"),  "version_compatible: rejects major 2")
check_false(cp.version_compatible("0.9.0"),  "version_compatible: rejects major 0")
check_false(cp.version_compatible("garbage"),"version_compatible: rejects non-numeric")
check_true(cp.version_compatible(nil),       "version_compatible: nil is compatible")
check_true(cp.version_compatible(""),        "version_compatible: empty is compatible")

-- ===========================================================================
-- Non-200 / non-304 status (e.g. 500) → skip, no mutation.
-- ===========================================================================

do
    reset_state()
    local res = { status = 500, body = "", headers = {} }
    local outcome = cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "skip", "HTTP 500: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "HTTP 500: gen unchanged")
    check_true(log_contains("HTTP 500"), "HTTP 500: log mentions status code")
end

-- ===========================================================================
-- Multi-tick steady state: 200 → 304 → 304 → 200, gen progression and
-- entry retention over time (the soak-test miniature).
-- ===========================================================================

do
    reset_state()
    -- Tick 1: 200 lands fp_a, fp_b at gen=1; seed swept.
    local b1 = "tick1"
    decode_table[b1] = { fp_a = "block", fp_b = "block" }
    cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta,
        { status = 200, body = b1, headers = { ["X-Catalog-Version"] = "1.0" } }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1, "soak: gen=1 after first 200")

    -- Tick 2: 304 — entries and gen stable.
    cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta,
        { status = 304, body = "", headers = {} }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1, "soak: gen still 1 after 304")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_a", 1)), "block",
        "soak: fp_a still present after 304")

    -- Tick 3: 304 again — still stable.
    cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta,
        { status = 304, body = "", headers = {} }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1, "soak: gen still 1 after second 304")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_a", 1)), "block",
        "soak: fp_a still present after second 304")

    -- Tick 4: 200 with a new set (fp_a kept, fp_c added, fp_b dropped) → gen=2.
    local b4 = "tick4"
    decode_table[b4] = { fp_a = "block", fp_c = "block" }
    cp.handle_response(cat, ngx.shared.fp_blocklist, ngx.shared.meta,
        { status = 200, body = b4, headers = { ["X-Catalog-Version"] = "1.0" } }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 2, "soak: gen=2 after second 200")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_a", 2)), "block",
        "soak: fp_a present under gen 2")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_c", 2)), "block",
        "soak: fp_c present under gen 2")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_b", 1)), nil,
        "soak: fp_b from old gen swept")
    check(ngx.shared.fp_blocklist:get(fp_state.key("fp_a", 1)), nil,
        "soak: old-gen fp_a swept (gen 2 has its own copy)")
end

-- ===========================================================================

if failed > 0 then
    io.stderr:write(string.format("\n%d passed, %d FAILED\n", passed, failed))
    os.exit(1)
end
print(string.format("catalog_pull: %d passed", passed))
