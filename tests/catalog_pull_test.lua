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
--      from RFC §C1 round-3 review)
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
    -- Minimal encode for the ua_blacklist apply test: arrays → a stable
    -- "[a,b]" string. Sufficient to assert the staging key was written.
    encode = function(v)
        if type(v) == "table" then
            return "[" .. table.concat(v, ",") .. "]"
        end
        return tostring(v)
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
    tls_fp_blocklist = new_dict(),
    meta         = new_dict(),
    metrics      = new_dict(),
    antibot_ua_blacklist = new_dict(),
    antibot_ip_blocklist = new_dict(),
    antibot_ip_whitelist = new_dict(),
    antibot_asn_datacenters = new_dict(),
}

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local cp       = require "catalog_pull"
local fp_state = require "tls_fp_blocklist_state"

local cat = cp.catalogs.tls_fp_blocklist
assert(cat, "tls_fp_blocklist descriptor must be registered")

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
    ngx.shared.tls_fp_blocklist = new_dict()
    ngx.shared.meta         = new_dict()
    ngx.shared.metrics      = new_dict()
    -- static seed: one fp under gen 0, like init.lua's `fp_dict:set(key(fp, 0), "block")`.
    ngx.shared.tls_fp_blocklist:set(fp_state.key("seed_fp", 0), "block")
    ngx.shared.meta:set(fp_state.META_GEN_KEY, 0)
    ngx.shared.meta:set("tls_fp_blocklist_etag", "seed-etag")
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
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "ok", "200: returns ok")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1,
        "200: gen flipped from 0 to 1")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_a", 1)), "block",
        "200: new entry written under new gen")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_b", 1)), "block",
        "200: second entry written under new gen")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("seed_fp", 0)), nil,
        "200: old gen entry swept after flip")
    check(ngx.shared.meta:get("tls_fp_blocklist_etag"), "\"new-etag\"",
        "200: etag stored in meta")
    check(ngx.shared.meta:get("tls_fp_blocklist_version"), "1.0.0",
        "200: version stored in meta")
    check(ngx.shared.metrics:get("catalog_last_pull_ts:tls_fp_blocklist"), 1234567,
        "200: last_pull_ts stamped for staleness gauge")
end

-- ===========================================================================
-- 2. 304 Not Modified
-- Regression from round-3 review: 304 must NOT touch dict / gen / etag.
-- Staleness gauge contract: 304 IS a successful contact, so last_pull_ts
-- gets bumped (alert fires on dead channel, not on stale-but-correct data).
-- ===========================================================================

do
    reset_state()
    -- live state: gen=5 with two live entries (simulate a steady-state edge
    -- that has been pulling for a while). 304 must preserve all of it.
    ngx.shared.meta:set(fp_state.META_GEN_KEY, 5)
    ngx.shared.tls_fp_blocklist:set(fp_state.key("live_a", 5), "block")
    ngx.shared.tls_fp_blocklist:set(fp_state.key("live_b", 5), "block")
    ngx.shared.meta:set("tls_fp_blocklist_etag", "\"live-etag\"")

    local res = { status = 304, body = "", headers = {} }
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "not_modified", "304: returns not_modified")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 5,
        "304: generation unchanged")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("live_a", 5)), "block",
        "304: live entry a preserved (regression guard)")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("live_b", 5)), "block",
        "304: live entry b preserved (regression guard)")
    check(ngx.shared.meta:get("tls_fp_blocklist_etag"), "\"live-etag\"",
        "304: etag unchanged")
    check(ngx.shared.metrics:get("catalog_last_pull_ts:tls_fp_blocklist"), 1234567,
        "304: last_pull_ts bumped (304 = successful contact, staleness is a liveness signal)")
end

-- ===========================================================================
-- 3. Transport error (res=nil)
-- ===========================================================================

do
    reset_state()
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, nil, "timeout")
    check(outcome, "skip", "transport error: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "transport error: gen unchanged")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("seed_fp", 0)), "block",
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
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "skip", "malformed JSON: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "malformed JSON: gen unchanged")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("seed_fp", 0)), "block",
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
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res, nil)
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
    outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res, nil)
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
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res, nil)
    check(outcome, "skip", "version mismatch: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "version mismatch: gen unchanged")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("seed_fp", 0)), "block",
        "version mismatch: seed entry preserved")
    check(ngx.shared.metrics:get("edge_sidecar_version_mismatch_total:tls_fp_blocklist"), 1,
        "version mismatch: metric bumped")
    check_true(log_contains("version mismatch"),
        "version mismatch: ngx.log identifies the mismatch")
end

-- ===========================================================================
-- Metrics key naming contract (PR #55 review P1). bump_last_pull_ts and
-- the version-mismatch bump must key by CATALOG NAME (descriptor key —
-- what metrics.lua iterates), NOT by dict_name. The bug was invisible for
-- tls_fp_blocklist (name == dict_name) and surfaced only on verified_bot_ips
-- (dict_name=verified_bots) where /metrics returned -1 staleness forever.
-- Use a synthetic descriptor here so the assertion holds even if both
-- shipped descriptors are renamed in lockstep.
-- ===========================================================================

do
    reset_state()
    local synth = {
        name        = "synth_cat",
        endpoint    = "/catalog/synth_cat",
        dict_name   = "tls_fp_blocklist",  -- reuse tls_fp_blocklist dict for the harness
        gen_key     = fp_state.META_GEN_KEY,
        etag_key    = "synth_etag",
        version_key = "synth_version",
        apply = function() return true, 0 end,
        sweep = function() return 0 end,
    }
    -- 304 path → bumps last_pull_ts only
    local res304 = { status = 304, headers = {} }
    local outcome = cp.handle_response(synth, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res304, nil)
    check(outcome, "not_modified", "metrics key: 304 returns not_modified")
    check(ngx.shared.metrics:get("catalog_last_pull_ts:synth_cat"), 1234567,
        "metrics key: catalog_last_pull_ts keyed by NAME, not dict_name")
    check(ngx.shared.metrics:get("catalog_last_pull_ts:tls_fp_blocklist"), nil,
        "metrics key: NOT keyed by dict_name (regression guard PR #55 P1)")

    -- version mismatch → bumps the mismatch counter
    local res_vmis = { status = 200, body = "{}", headers = { ["X-Catalog-Version"] = "2.0.0" } }
    cp.handle_response(synth, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res_vmis, nil)
    check(ngx.shared.metrics:get("edge_sidecar_version_mismatch_total:synth_cat"), 1,
        "metrics key: version mismatch keyed by NAME, not dict_name")
    check(ngx.shared.metrics:get("edge_sidecar_version_mismatch_total:tls_fp_blocklist"), nil,
        "metrics key: vmis NOT keyed by dict_name (regression guard PR #55 P1)")
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
-- apply() failure mid-batch (no memory / oversized key) → no gen flip,
-- partially-written new gen is rolled back, old gen stays intact.
-- Regression guard for the gemini/codex review: violation of fail-stale
-- when dict:set returns nil, "no memory".
-- ===========================================================================

do
    reset_state()
    -- Make the tls_fp_blocklist dict refuse the SECOND set with a fake "no memory".
    local fp_dict = ngx.shared.tls_fp_blocklist
    local calls = 0
    local real_set = fp_dict.set
    fp_dict.set = function(self, k, v)
        calls = calls + 1
        if calls == 2 then return nil, "no memory" end
        return real_set(self, k, v)
    end

    local body = '{"fp_a":"block","fp_b":"block","fp_c":"block"}'
    decode_table[body] = { fp_a = "block", fp_b = "block", fp_c = "block" }
    local res = {
        status  = 200,
        body    = body,
        headers = { ETag = "\"x\"", ["X-Catalog-Version"] = "1.0" },
    }
    local outcome = cp.handle_response(cat, fp_dict, ngx.shared.meta, res, nil)
    check(outcome, "skip", "apply failure: returns skip")
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 0,
        "apply failure: gen NOT flipped (still 0)")
    check(fp_dict:get(fp_state.key("seed_fp", 0)), "block",
        "apply failure: old-gen seed entry preserved")
    -- The first set went through (calls==1) — verify the partial new-gen
    -- write was swept on rollback so the dict isn't carrying dead entries
    -- until the next pull.
    local any_new_gen = false
    for _, k in ipairs(fp_dict:get_keys(0)) do
        if k:sub(-2) == ":1" then any_new_gen = true end
    end
    check_false(any_new_gen, "apply failure: partial new-gen entries swept on rollback")
    check_true(log_contains("apply failed"), "apply failure: log mentions apply failure")
    fp_dict.set = real_set
end

-- ===========================================================================
-- meta:set(gen_key) failure → roll back, old gen kept (defense-in-depth;
-- a 1m meta dict with a single int practically can't fail, but if it did
-- we'd activate a catalog readers can't see).
-- ===========================================================================

do
    reset_state()
    local meta = ngx.shared.meta
    local real_meta_set = meta.set
    meta.set = function(self, k, v)
        if k == fp_state.META_GEN_KEY and v == 1 then
            return nil, "no memory"
        end
        return real_meta_set(self, k, v)
    end

    local body = '{"fp_x":"block"}'
    decode_table[body] = { fp_x = "block" }
    local res = { status = 200, body = body, headers = { ["X-Catalog-Version"] = "1.0" } }
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, meta, res, nil)
    check(outcome, "skip", "meta:set failure: returns skip")
    check(meta:get(fp_state.META_GEN_KEY), 0,
        "meta:set failure: gen unchanged")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("seed_fp", 0)), "block",
        "meta:set failure: seed preserved")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_x", 1)), nil,
        "meta:set failure: failed new-gen entry swept on rollback")
    check_true(log_contains("gen flip failed"),
        "meta:set failure: log mentions gen flip failure")
    meta.set = real_meta_set
end

-- ===========================================================================
-- Non-200 / non-304 status (e.g. 500) → skip, no mutation.
-- ===========================================================================

do
    reset_state()
    local res = { status = 500, body = "", headers = {} }
    local outcome = cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta, res, nil)
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
    cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta,
        { status = 200, body = b1, headers = { ["X-Catalog-Version"] = "1.0" } }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1, "soak: gen=1 after first 200")

    -- Tick 2: 304 — entries and gen stable.
    cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta,
        { status = 304, body = "", headers = {} }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1, "soak: gen still 1 after 304")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_a", 1)), "block",
        "soak: fp_a still present after 304")

    -- Tick 3: 304 again — still stable.
    cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta,
        { status = 304, body = "", headers = {} }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 1, "soak: gen still 1 after second 304")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_a", 1)), "block",
        "soak: fp_a still present after second 304")

    -- Tick 4: 200 with a new set (fp_a kept, fp_c added, fp_b dropped) → gen=2.
    local b4 = "tick4"
    decode_table[b4] = { fp_a = "block", fp_c = "block" }
    cp.handle_response(cat, ngx.shared.tls_fp_blocklist, ngx.shared.meta,
        { status = 200, body = b4, headers = { ["X-Catalog-Version"] = "1.0" } }, nil)
    check(ngx.shared.meta:get(fp_state.META_GEN_KEY), 2, "soak: gen=2 after second 200")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_a", 2)), "block",
        "soak: fp_a present under gen 2")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_c", 2)), "block",
        "soak: fp_c present under gen 2")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_b", 1)), nil,
        "soak: fp_b from old gen swept")
    check(ngx.shared.tls_fp_blocklist:get(fp_state.key("fp_a", 1)), nil,
        "soak: old-gen fp_a swept (gen 2 has its own copy)")
end

-- ===========================================================================
-- In-flight guard: concurrent fetch() calls for the same catalog must skip
-- (rather than interleave apply/flip/sweep with a stale tick). Regression
-- from review finding: slow backend can let ngx.timer.every fire while a
-- previous tick is still inside httpc:request_uri.
-- ===========================================================================

do
    reset_state()
    -- Stub the http module: capture the in-flight state at the moment the
    -- "request" starts. We don't actually return — we let the call NOT be
    -- made by setting in_flight from a nested fetch attempt and verifying
    -- it short-circuits.
    local httpc_stub = {}
    function httpc_stub:set_timeout(_) end
    function httpc_stub:request_uri(_, _)
        -- While the "first" tick is still in flight, attempt a second tick
        -- for the SAME catalog. It must short-circuit at the in_flight guard
        -- without making a real call.
        local outcomes_before = #logged
        cp.fetch("tls_fp_blocklist")
        local outcomes_after = #logged
        check_true(outcomes_after > outcomes_before,
            "in-flight guard: nested fetch logs the skip")
        check_true(log_contains("still in flight"),
            "in-flight guard: log mentions 'still in flight'")
        return { status = 304, body = "", headers = {} }, nil
    end
    cp.http_module = { new = function() return httpc_stub end }
    cp.backend_url = "http://stub:0"
    cp.timeout_ms  = 1000
    cp.ssl_verify  = false

    -- Outer tick: this one makes the "real" call (via the stub), and from
    -- inside the stub we recursively try fetch() again to model overlap.
    cp.fetch("tls_fp_blocklist")

    -- After the outer fetch returns, in_flight must be cleared so the next
    -- tick can proceed normally.
    httpc_stub.request_uri = function(_, _, _)
        return { status = 304, body = "", headers = {} }, nil
    end
    local before = #logged
    cp.fetch("tls_fp_blocklist")  -- this one must NOT short-circuit
    check_false(log_contains("still in flight") and #logged > before
                and logged[#logged]:find("still in flight", 1, true),
        "in-flight guard: cleared after outer tick returns")

    cp.http_module = nil  -- restore for other tests
end

-- ===========================================================================
-- [B6] mTLS: preload_mtls + load_mtls_material + fetch() ssl_client_cert
-- passthrough. Code-review F4: the original PR added these without coverage,
-- so a typo in field names would still pass `make test`.
-- ===========================================================================

do
    -- Stub ngx.ssl with sentinel parsers — capture the PEM bytes that get
    -- passed in, and return distinguishable cdata-like sentinels so we can
    -- assert they round-trip into req_opts.
    local seen_cert_pem, seen_key_pem
    local CERT_SENTINEL = { _kind = "parsed_cert" }
    local KEY_SENTINEL  = { _kind = "parsed_key"  }
    package.loaded["ngx.ssl"] = {
        parse_pem_cert = function(pem)
            seen_cert_pem = pem
            return CERT_SENTINEL
        end,
        parse_pem_priv_key = function(pem)
            seen_key_pem = pem
            return KEY_SENTINEL
        end,
    }

    -- Write two temp PEM files. Content is opaque to the stubbed parser;
    -- load_mtls_material reads the bytes and hands them to parse_pem_*.
    local function write_tmp(content)
        local path = os.tmpname()
        local f = assert(io.open(path, "wb"))
        f:write(content); f:close()
        return path
    end
    local cert_path = write_tmp("-----CERT PEM BODY-----")
    local key_path  = write_tmp("-----KEY  PEM BODY-----")

    -- Reset the module-level mTLS state so a previous test (or load order)
    -- doesn't make preload short-circuit.
    cp.parsed_cert = nil
    cp.parsed_key  = nil

    cp.preload_mtls(cert_path, key_path)
    check(cp.parsed_cert, CERT_SENTINEL, "preload_mtls: parsed_cert is sentinel")
    check(cp.parsed_key,  KEY_SENTINEL,  "preload_mtls: parsed_key is sentinel")
    check(seen_cert_pem, "-----CERT PEM BODY-----",
        "preload_mtls: cert PEM bytes handed to ngx.ssl.parse_pem_cert")
    check(seen_key_pem,  "-----KEY  PEM BODY-----",
        "preload_mtls: key PEM bytes handed to ngx.ssl.parse_pem_priv_key")

    -- Idempotency: second call must not re-parse.
    seen_cert_pem = nil
    cp.preload_mtls(cert_path, key_path)
    check(seen_cert_pem, nil, "preload_mtls: idempotent on second call")

    -- fetch() must thread the parsed cdata into req_opts.ssl_client_cert /
    -- ssl_client_priv_key. Stub httpc to capture req_opts and skip the rest.
    reset_state()
    local captured_opts
    local httpc_stub = {}
    function httpc_stub:set_timeout(_) end
    function httpc_stub:request_uri(_, opts)
        captured_opts = opts
        return { status = 304, body = "", headers = {} }, nil
    end
    cp.http_module = { new = function() return httpc_stub end }
    cp.backend_url = "https://stub:0"
    cp.timeout_ms  = 1000
    cp.ssl_verify  = true
    cp.fetch("tls_fp_blocklist")
    check(captured_opts and captured_opts.ssl_client_cert, CERT_SENTINEL,
        "fetch: req_opts.ssl_client_cert is parsed cert")
    check(captured_opts and captured_opts.ssl_client_priv_key, KEY_SENTINEL,
        "fetch: req_opts.ssl_client_priv_key is parsed key")
    cp.http_module = nil

    -- Negative: if parsed_cert is nil (no mTLS configured), fetch must NOT
    -- attach the keys to req_opts.
    cp.parsed_cert = nil
    cp.parsed_key  = nil
    captured_opts = nil
    cp.http_module = { new = function() return httpc_stub end }
    cp.fetch("tls_fp_blocklist")
    check(captured_opts and captured_opts.ssl_client_cert, nil,
        "fetch: no ssl_client_cert when mTLS not configured")
    check(captured_opts and captured_opts.ssl_client_priv_key, nil,
        "fetch: no ssl_client_priv_key when mTLS not configured")
    cp.http_module = nil

    -- Missing/empty paths: load_mtls_material returns nil,nil silently
    -- (used by init.lua when env vars unset).
    local pc, pk = cp.load_mtls_material(nil, nil)
    check(pc, nil, "load_mtls_material(nil,nil): cert nil")
    check(pk, nil, "load_mtls_material(nil,nil): key nil")
    pc, pk = cp.load_mtls_material("", "")
    check(pc, nil, "load_mtls_material('',''): cert nil")
    check(pk, nil, "load_mtls_material('',''): key nil")

    -- File-missing path: log + nil return, no crash.
    pc, pk = cp.load_mtls_material("/nonexistent/cert.pem", "/nonexistent/key.pem")
    check(pc, nil, "load_mtls_material(missing): cert nil")
    check(pk, nil, "load_mtls_material(missing): key nil")
    check_true(log_contains("read client cert"),
        "load_mtls_material(missing): logs the read failure")

    os.remove(cert_path)
    os.remove(key_path)
    package.loaded["ngx.ssl"] = nil
end

-- ===========================================================================
-- start() env knobs: empty string treated as unset (compose's `${VAR:-}`
-- emits empty strings, which are truthy in Lua and would otherwise produce
-- "bad uri" on every tick), and ANTIBOT_BACKEND_SSL_VERIFY env override.
-- ===========================================================================

do
    -- Save / restore the real os.getenv around the test.
    local real_getenv = os.getenv
    local env_stub = {}
    os.getenv = function(k) return env_stub[k] end

    -- Stub the http module so start() doesn't actually try to require resty.http
    -- and doesn't wire ngx.timer.
    local fake_http = {}
    cp.http_module = fake_http

    -- Empty string from compose default: not the "antibot-backend:8080" hard
    -- fallback either — empty must be treated as nil so the fallback URL kicks
    -- in (or, when nginx.demo.conf gates on it, the timer is skipped). The
    -- contract here is just that backend_url is NOT "" after start().
    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = { ANTIBOT_BACKEND_URL = "" }
    cp.start({ catalogs = {} })
    check_false(cp.backend_url == "",
        "start: empty ANTIBOT_BACKEND_URL → not literally empty string")
    check(cp.backend_url, "http://antibot-backend:8080",
        "start: empty ANTIBOT_BACKEND_URL → hard fallback used")

    -- Empty string host header: treated as nil so the Host header isn't
    -- emitted at all (was silently emitting `Host: ` before the nonempty fix).
    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = { ANTIBOT_BACKEND_HOST = "" }
    cp.start({ catalogs = {} })
    check(cp.backend_host_header, nil,
        "start: empty ANTIBOT_BACKEND_HOST → backend_host_header nil")

    -- ssl_verify defaults to true.
    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = {}
    cp.start({ catalogs = {} })
    check(cp.ssl_verify, true, "start: ssl_verify default = true")

    -- Various falsy ANTIBOT_BACKEND_SSL_VERIFY values.
    for _, v in ipairs({ "false", "FALSE", "0", "no", "off" }) do
        cp.parsed_cert = nil; cp.parsed_key = nil
        env_stub = { ANTIBOT_BACKEND_SSL_VERIFY = v }
        cp.start({ catalogs = {} })
        check(cp.ssl_verify, false,
            "start: ANTIBOT_BACKEND_SSL_VERIFY=" .. v .. " → ssl_verify false")
    end

    -- Empty env string keeps default (true).
    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = { ANTIBOT_BACKEND_SSL_VERIFY = "" }
    cp.start({ catalogs = {} })
    check(cp.ssl_verify, true,
        "start: empty ANTIBOT_BACKEND_SSL_VERIFY → ssl_verify default true")

    -- opts.ssl_verify overrides env (callers still authoritative).
    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = { ANTIBOT_BACKEND_SSL_VERIFY = "false" }
    cp.start({ catalogs = {}, ssl_verify = true })
    check(cp.ssl_verify, true,
        "start: opts.ssl_verify=true overrides env false")

    -- Empty-string opts: same treatment as empty-string envs (gemini-review).
    -- A caller plumbing `os.getenv("…")` straight into `start({ backend_url = … })`
    -- without normalising would otherwise pin an empty URL.
    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = { ANTIBOT_BACKEND_URL = "https://from-env.example" }
    cp.start({ catalogs = {}, backend_url = "" })
    check(cp.backend_url, "https://from-env.example",
        "start: empty opts.backend_url falls through to env")

    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = { ANTIBOT_BACKEND_HOST = "from.env" }
    cp.start({ catalogs = {}, backend_host_header = "" })
    check(cp.backend_host_header, "from.env",
        "start: empty opts.backend_host_header falls through to env")

    cp.parsed_cert = nil; cp.parsed_key = nil
    env_stub = { ANTIBOT_BACKEND_URL = "", ANTIBOT_BACKEND_HOST = "" }
    cp.start({ catalogs = {}, backend_url = "", backend_host_header = "" })
    check(cp.backend_url, "http://antibot-backend:8080",
        "start: both opts+env empty for URL → hard fallback")
    check(cp.backend_host_header, nil,
        "start: both opts+env empty for host header → nil (no Host override)")

    os.getenv = real_getenv
    cp.http_module = nil
end

-- ===========================================================================
-- A11: ua_blacklist + ip_blocklist descriptors.
-- ===========================================================================

-- ua_blacklist: object payload {active=string, staging=array}. apply writes
-- two keys per gen; sweep deletes the old gen's two keys.
do
    local uacat = cp.catalogs.ua_blacklist
    check_true(uacat ~= nil, "ua_blacklist descriptor registered")
    local d = ngx.shared.antibot_ua_blacklist
    d._store = {}
    local ok, n = uacat.apply(d, { active = "(curl)|(wget)", staging = { "scrapy", "ahrefs" } }, 3)
    check_true(ok, "ua_blacklist apply ok")
    check(n, 2, "ua_blacklist apply wrote 2 keys")
    check(d:get("active:3"), "(curl)|(wget)", "ua_blacklist active:3 stored combined regex")
    check(d:get("staging:3"), "[scrapy,ahrefs]", "ua_blacklist staging:3 stored encoded list")
    -- seed an old gen to prove sweep removes exactly the old gen's two keys.
    d:set("active:2", "(old)"); d:set("staging:2", "[old]")
    local swept = uacat.sweep(d, 2)
    check(swept, 2, "ua_blacklist sweep removed 2 old-gen keys")
    check(d:get("active:2"), nil, "ua_blacklist sweep deleted active:2")
    check(d:get("active:3"), "(curl)|(wget)", "ua_blacklist sweep kept current gen")
end

-- ip_blocklist: per-key map payload {cidr → "<status>:block"}. apply writes
-- `<cidr>:<gen>`; sweep removes the old gen by suffix.
do
    local ipcat = cp.catalogs.ip_blocklist
    check_true(ipcat ~= nil, "ip_blocklist descriptor registered")
    local d = ngx.shared.antibot_ip_blocklist
    d._store = {}
    local ok, n = ipcat.apply(d, {
        ["203.0.113.0/24"] = "active:block",
        ["2001:db8::/48"]  = "staging:block",
    }, 5)
    check_true(ok, "ip_blocklist apply ok")
    check(n, 2, "ip_blocklist apply wrote 2 keys")
    check(d:get("203.0.113.0/24:5"), "active:block", "ip_blocklist active cidr stored")
    check(d:get("2001:db8::/48:5"), "staging:block", "ip_blocklist staging ipv6 cidr stored")
    -- old-gen ghost + current; sweep(4) removes only the `:4` key.
    d:set("198.51.100.0/24:4", "active:block")
    local swept = ipcat.sweep(d, 4)
    check(swept, 1, "ip_blocklist sweep removed 1 old-gen key")
    check(d:get("198.51.100.0/24:4"), nil, "ip_blocklist sweep deleted old gen")
    check(d:get("203.0.113.0/24:5"), "active:block", "ip_blocklist sweep kept current gen")
end

-- ===========================================================================
-- B12: ip_whitelist + asn_datacenters descriptors.
-- ===========================================================================

-- ip_whitelist: flat ARRAY payload [cidr, …]. apply writes `<cidr>:<gen>` → "1";
-- sweep removes the old gen by suffix. No status (flat allow list).
do
    local wlcat = cp.catalogs.ip_whitelist
    check_true(wlcat ~= nil, "ip_whitelist descriptor registered")
    local d = ngx.shared.antibot_ip_whitelist
    d._store = {}
    local ok, n = wlcat.apply(d, { "203.0.113.7", "2001:db8::/48", "" }, 5)
    check_true(ok, "ip_whitelist apply ok")
    check(n, 2, "ip_whitelist apply wrote 2 keys (empty entry skipped)")
    check(d:get("203.0.113.7:5"), "1", "ip_whitelist cidr stored")
    check(d:get("2001:db8::/48:5"), "1", "ip_whitelist ipv6 cidr stored")
    -- old-gen ghost + current; sweep(4) removes only the `:4` key.
    d:set("198.51.100.0/24:4", "1")
    local swept = wlcat.sweep(d, 4)
    check(swept, 1, "ip_whitelist sweep removed 1 old-gen key")
    check(d:get("198.51.100.0/24:4"), nil, "ip_whitelist sweep deleted old gen")
    check(d:get("203.0.113.7:5"), "1", "ip_whitelist sweep kept current gen")
end

-- asn_datacenters: OBJECT payload {asn → 1}. apply writes `<asn>:<gen>` → "1";
-- sweep removes the old gen by suffix. No status (flat list).
do
    local asncat = cp.catalogs.asn_datacenters
    check_true(asncat ~= nil, "asn_datacenters descriptor registered")
    local d = ngx.shared.antibot_asn_datacenters
    d._store = {}
    local ok, n = asncat.apply(d, { ["24940"] = 1, ["16276"] = 1 }, 3)
    check_true(ok, "asn_datacenters apply ok")
    check(n, 2, "asn_datacenters apply wrote 2 keys")
    check(d:get("24940:3"), "1", "asn_datacenters asn stored")
    check(d:get("16276:3"), "1", "asn_datacenters second asn stored")
    -- old-gen ghost + current; sweep(2) removes only the `:2` key.
    d:set("14061:2", "1")
    local swept = asncat.sweep(d, 2)
    check(swept, 1, "asn_datacenters sweep removed 1 old-gen key")
    check(d:get("14061:2"), nil, "asn_datacenters sweep deleted old gen")
    check(d:get("24940:3"), "1", "asn_datacenters sweep kept current gen")
end

-- ===========================================================================

if failed > 0 then
    io.stderr:write(string.format("\n%d passed, %d FAILED\n", passed, failed))
    os.exit(1)
end
print(string.format("catalog_pull: %d passed", passed))
