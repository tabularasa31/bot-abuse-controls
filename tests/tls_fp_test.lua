-- Unit tests for infra/demo-stand/lua/tls_fp.lua (A9).
-- Pure Lua; runs under any luajit / lua 5.1+ with no openresty deps — the
-- ngx-touching part (tls_fp.run) is exercised on the stand, the pure decision
-- helpers are covered here.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local tls_fp = require "tls_fp"

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
-- classify_ua — 6 UAs from the Phase 1/2 catalog (acceptance) + edge cases
-- ===========================================================================

local CHROME  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
local FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
local SAFARI  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
local EDGE    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"
local CURL    = "curl/8.4.0"
local PYREQ   = "python-requests/2.31.0"

check(tls_fp.classify_ua(CHROME),  "chrome",  "classify_ua chrome")
check(tls_fp.classify_ua(FIREFOX), "firefox", "classify_ua firefox")
check(tls_fp.classify_ua(SAFARI),  "safari",  "classify_ua safari")
check(tls_fp.classify_ua(EDGE),    "edge",    "classify_ua edge (Chrome+Safari+Edg → edge)")
check(tls_fp.classify_ua(CURL),    "other",   "classify_ua curl → other")
check(tls_fp.classify_ua(PYREQ),   "other",   "classify_ua python-requests → other")
check(tls_fp.classify_ua(""),      "other",   "classify_ua empty → other")
check(tls_fp.classify_ua(nil),     "other",   "classify_ua nil → other")
-- Case-insensitive: a spoof that lowercases the tokens must not slip to "other".
check(tls_fp.classify_ua("mozilla/5.0 chrome/148.0.0.0 safari/537.36"), "chrome",
    "classify_ua lowercased Chrome spoof → chrome (no evasion)")

-- ===========================================================================
-- is_automation_ua — tls_fp:automation_ua tag heuristic
-- ===========================================================================

check(tls_fp.is_automation_ua(CURL),  true,  "automation_ua curl → true")
check(tls_fp.is_automation_ua(PYREQ), true,  "automation_ua python-requests → true")
check(tls_fp.is_automation_ua("Go-http-client/2.0"), true, "automation_ua Go → true")
check(tls_fp.is_automation_ua("okhttp/4.9.3"), true, "automation_ua okhttp → true")
check(tls_fp.is_automation_ua(CHROME), false, "automation_ua Chrome → false")
check(tls_fp.is_automation_ua(""),     false, "automation_ua empty → false")

-- ===========================================================================
-- hash_b / cipher_count — fp parsing
-- ===========================================================================

local FP = "L13d15h2_a8b9c0d1e2f3_4d5e6f7a8b9c"
check(tls_fp.hash_b(FP),       "a8b9c0d1e2f3", "hash_b extracts middle segment")
check(tls_fp.hash_b("garbage"), nil,           "hash_b malformed → nil")
check(tls_fp.hash_b("L13d15h2_a8b9c0d1e2f3_c_d_e"), "a8b9c0d1e2f3",
    "hash_b tolerates extra trailing segments")
check(tls_fp.hash_b(nil),       nil,           "hash_b nil → nil")
check(tls_fp.cipher_count(FP),  15,            "cipher_count from prefix")
check(tls_fp.cipher_count("L13d11h2_x_y"), 11, "cipher_count 11")
check(tls_fp.cipher_count("nope"), nil,        "cipher_count malformed → nil")

-- ===========================================================================
-- build_catalog / build_profiles — parse Channel C wire format
-- "<status>:<value>" into (active, staging) tables. After PR2 (ADR-006)
-- this is the only build path; on-disk INI source removed.
-- ===========================================================================

local cat_active, cat_staging = tls_fp.build_catalog({
    ["1ed0482b9b4c"] = "active:python-requests",
    ["a1b2c3d4e5f6"] = "staging:curl",
    ["dead00000000"] = "active:",            -- empty family → skipped
    ["bad-status"]   = "unknown:something",  -- an unknown status → skip
    ["malformed"]    = "no-colon-here",      -- a broken wire format → skip
})
check(cat_active["1ed0482b9b4c"],  "python-requests", "build_catalog active")
check(cat_active["a1b2c3d4e5f6"],  nil,               "build_catalog active drops staging")
check(cat_staging["a1b2c3d4e5f6"], "curl",            "build_catalog staging")
check(cat_active["dead00000000"],  nil,               "build_catalog drops empty family")
check(cat_active["bad-status"],    nil,               "build_catalog drops unknown status")
check(cat_active["malformed"],     nil,               "build_catalog drops malformed wire")
local empty_a, empty_s = tls_fp.build_catalog(nil)
check(next(empty_a), nil, "build_catalog nil active → empty")
check(next(empty_s), nil, "build_catalog nil staging → empty")

local prof_active, prof_staging = tls_fp.build_profiles({
    chrome  = "active:15",
    firefox = "active:16",
    safari  = "active:20",
    edge    = "active:15",
    beta    = "staging:18",
    bad     = "active:notanumber",  -- non-numeric → skipped
    zero    = "active:0",            -- non-positive → skipped (defence; the backend Validate catches it too)
})
check(prof_active.chrome,  15,  "build_profiles chrome=15")
check(prof_active.firefox, 16,  "build_profiles firefox=16")
check(prof_active.safari,  20,  "build_profiles safari=20")
check(prof_active.edge,    15,  "build_profiles edge=15")
check(prof_active.beta,    nil, "build_profiles active drops staging")
check(prof_staging.beta,   18,  "build_profiles staging beta=18")
check(prof_active.bad,     nil, "build_profiles drops non-numeric")
check(prof_active.zero,    nil, "build_profiles drops zero cipher_cnt")

-- ===========================================================================
-- build_blocklist — parse Channel C wire map { [fp] = "<status>:block" } into
-- the staging fp set (A11, ). Only status=staging fps are kept; active
-- ones block directly in verdict.lua off the same dict, legacy bare "block" is
-- active.
-- ===========================================================================

local bl_staging = tls_fp.build_blocklist({
    ["L13i1900_aaa_bbb"] = "active:block",   -- active → not in staging set
    ["L12i1400_ccc_ddd"] = "staging:block",  -- staged → kept
    ["L13i1300_eee_fff"] = "block",          -- legacy bare → active → skipped
    ["L13i1300_ggg_hhh"] = "unknown:block",  -- unknown status → skipped
})
check(bl_staging["L12i1400_ccc_ddd"], true, "build_blocklist keeps staging fp")
check(bl_staging["L13i1900_aaa_bbb"], nil,  "build_blocklist drops active fp")
check(bl_staging["L13i1300_eee_fff"], nil,  "build_blocklist treats bare 'block' as active")
check(bl_staging["L13i1300_ggg_hhh"], nil,  "build_blocklist drops unknown status")
check(next(tls_fp.build_blocklist(nil)), nil, "build_blocklist nil → empty")

-- Local aliases for the rest of the file's tests — they expected a single-table
-- shape, whereas build_* now returns (active, staging).
local cat  = cat_active
local prof = prof_active

-- ===========================================================================
-- is_impersonator — UA browser + fp hash_b is a known automation signature
-- ===========================================================================

check(tls_fp.is_impersonator("chrome", "1ed0482b9b4c", cat), true,
    "impersonator: Chrome UA + python-requests fp → true")
check(tls_fp.is_impersonator("edge", "1ed0482b9b4c", cat), true,
    "impersonator: Edge UA + automation fp → true")
check(tls_fp.is_impersonator("chrome", "ffffffffffff", cat), false,
    "impersonator: Chrome UA + unknown fp → false")
check(tls_fp.is_impersonator("other", "1ed0482b9b4c", cat), false,
    "impersonator: automation UA + matching automation fp → false (honest)")
check(tls_fp.is_impersonator("chrome", nil, cat), false,
    "impersonator: nil hash_b → false")

-- ===========================================================================
-- is_suspicious_ciphers — browser UA + cipher_count off its profile
-- ===========================================================================

check(tls_fp.is_suspicious_ciphers("chrome", 11, prof), true,
    "suspicious: Chrome UA + cipher_count 11 (≠15) → true")
check(tls_fp.is_suspicious_ciphers("chrome", 15, prof), false,
    "suspicious: Chrome UA + cipher_count 15 (=15) → false")
check(tls_fp.is_suspicious_ciphers("firefox", 16, prof), false,
    "suspicious: Firefox UA + cipher_count 16 (=16) → false")
check(tls_fp.is_suspicious_ciphers("other", 11, prof), false,
    "suspicious: non-browser UA → false (no profile)")
check(tls_fp.is_suspicious_ciphers("chrome", nil, prof), false,
    "suspicious: nil cipher_count → false")

-- ===========================================================================
-- fp_looks_like_browser / has_tag — dc_browser cross-layer helpers
-- ===========================================================================

check(tls_fp.fp_looks_like_browser(15, prof), true,
    "fp_looks_like_browser: cipher_count matches a profile → true")
check(tls_fp.fp_looks_like_browser(11, prof), false,
    "fp_looks_like_browser: cipher_count off every profile → false")
check(tls_fp.fp_looks_like_browser(nil, prof), false,
    "fp_looks_like_browser: nil → false")

check(tls_fp.has_tag({ "reputation:asn_dc", "hygiene:header_anomaly" }, "reputation:asn_dc"),
    true, "has_tag finds present tag")
check(tls_fp.has_tag({ "hygiene:header_anomaly" }, "reputation:asn_dc"),
    false, "has_tag missing tag → false")
check(tls_fp.has_tag(nil, "reputation:asn_dc"), false, "has_tag nil tags → false")

-- ===========================================================================
-- Cold-start fallback semantics (PR-62 re-review + round-6 staging-gate)
-- ===========================================================================
-- Signature: is_suspicious_ciphers(ua_family, cc, profiles, allow_fallback)
-- allow_fallback=true → the active call (cold-start coverage before the first pull).
-- allow_fallback=false/nil → the staging call (no phantom matches).
tls_fp._cached_gen_profiles = nil
local empty = {}

-- Active-call (allow_fallback=true): cold start → fallback chrome=15.
check(tls_fp.is_suspicious_ciphers("chrome", 11, empty, true), true,
    "active cold start: chrome UA + cipher=11 vs fallback chrome=15 → suspicious")
check(tls_fp.is_suspicious_ciphers("chrome", 15, empty, true), false,
    "active cold start: chrome UA + cipher=15 matches fallback → ok")

-- The STAGING call (allow_fallback=false): an empty table → NO fallback and
-- no phantom staging_match. That is the fix from review.
check(tls_fp.is_suspicious_ciphers("chrome", 11, empty, false), false,
    "staging cold start: empty profiles_staging → NO fallback → no phantom match")
check(tls_fp.is_suspicious_ciphers("chrome", 15, empty, false), false,
    "staging cold start: empty staging table → no match regardless of cipher")

-- fp_looks_like_browser has one call site (active) and always applies the fallback on a cold start.
check(tls_fp.fp_looks_like_browser(15, empty), true,
    "cold start: cipher=15 matches fallback chrome/edge → browser-shaped")
check(tls_fp.fp_looks_like_browser(99, empty), false,
    "cold start: cipher=99 off every fallback → not browser")

-- After first successful pull (gen >= 1): Channel C is authoritative.
-- Fallback MUST NOT mask backend decisions (e.g. backend dropped chrome,
-- moved cipher_cnt to 16, etc.). Empty dynamic table = «no profiles known»,
-- the rule simply doesn't fire — the fallback does not override that decision.
tls_fp._cached_gen_profiles = 1
check(tls_fp.is_suspicious_ciphers("chrome", 11, empty, true), false,
    "post-pull active: backend dropped chrome → no profile → no verdict (fallback off after landed)")
check(tls_fp.is_suspicious_ciphers("chrome", 11, empty, false), false,
    "post-pull staging: empty table → no match (fallback never applies to staging anyway)")
check(tls_fp.fp_looks_like_browser(15, empty), false,
    "post-pull: empty profiles, cipher=15 NOT browser-shaped (fallback off)")
-- And if the backend moved chrome to 16, the old 15 no longer counts as chrome:
local moved = { chrome = 16 }
check(tls_fp.is_suspicious_ciphers("chrome", 15, moved, true), true,
    "post-pull active: backend moved chrome to 16, observed cipher=15 → suspicious vs new value")
check(tls_fp.is_suspicious_ciphers("chrome", 16, moved, true), false,
    "post-pull active: chrome matches updated profile → ok")
-- A reset for the tests that follow (should any be added below).
tls_fp._cached_gen_profiles = nil

-- ===========================================================================
-- refresh() blocklist staging from the Channel C snapshot (A11, ).
-- Mock ngx.shared (meta + tls_fp_blocklist + metrics) and assert refresh()
-- rebuilds tls_fp.blocklist_staging to exactly the status=staging fps in the
-- dict at the published generation — verdict.lua blocks the active ones, this
-- set drives staging_match in run().
-- ===========================================================================

do
    local function new_dict()
        local store = {}
        local d = {}
        function d:get(k) return store[k] end
        function d:set(k, v) store[k] = v; return true end
        function d:safe_add(k, v)
            if store[k] ~= nil then return nil, "exists" end
            store[k] = v; return true
        end
        function d:delete(k) store[k] = nil end
        function d:get_keys(_) local ks = {} for k in pairs(store) do ks[#ks+1] = k end return ks end
        return d
    end

    local saved_ngx = _G.ngx
    local fp_state = require "tls_fp_blocklist_state"
    local bl   = new_dict()
    local meta = new_dict()
    _G.ngx = {
        shared = { meta = meta, tls_fp_blocklist = bl, metrics = new_dict() },
        log = function() end, ERR = "ERR", WARN = "WARN", NOTICE = "NOTICE",
    }

    -- gen 1 snapshot: one active, one staging fp (wire "<status>:block").
    bl:set(fp_state.key("L13i1900_active_fp", 1), "active:block")
    bl:set(fp_state.key("L12i1400_staged_fp", 1), "staging:block")
    meta:set(fp_state.META_GEN_KEY, 1)
    tls_fp._cached_gen_blocklist = nil  -- force rebuild

    tls_fp.refresh()
    check(tls_fp.blocklist_staging["L12i1400_staged_fp"], true,
        "refresh builds blocklist_staging from staging fp")
    check(tls_fp.blocklist_staging["L13i1900_active_fp"], nil,
        "refresh excludes active fp from blocklist_staging")

    -- gen 2: staged fp promoted to active → it drops out of the staging set.
    bl:delete(fp_state.key("L12i1400_staged_fp", 1))
    bl:set(fp_state.key("L12i1400_staged_fp", 2), "active:block")
    bl:set(fp_state.key("L13i1900_active_fp", 2), "active:block")
    meta:set(fp_state.META_GEN_KEY, 2)
    tls_fp.refresh()
    check(tls_fp.blocklist_staging["L12i1400_staged_fp"], nil,
        "refresh drops promoted fp from blocklist_staging on gen flip")

    tls_fp._cached_gen_blocklist = nil
    _G.ngx = saved_ngx
end

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
