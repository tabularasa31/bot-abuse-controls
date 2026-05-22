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
check(tls_fp.hash_b(nil),       nil,           "hash_b nil → nil")
check(tls_fp.cipher_count(FP),  15,            "cipher_count from prefix")
check(tls_fp.cipher_count("L13d11h2_x_y"), 11, "cipher_count 11")
check(tls_fp.cipher_count("nope"), nil,        "cipher_count malformed → nil")

-- ===========================================================================
-- build_catalog / build_profiles — active-only compilation
-- ===========================================================================

local cat = tls_fp.build_catalog({
    ["1ed0482b9b4c"] = { family = "python-requests", status = "active" },
    ["a1b2c3d4e5f6"] = { family = "curl",            status = "staging" },
    ["dead00000000"] = { status = "active" },  -- no family → skipped
})
check(cat["1ed0482b9b4c"], "python-requests", "build_catalog keeps active")
check(cat["a1b2c3d4e5f6"], nil,               "build_catalog drops staging")
check(cat["dead00000000"], nil,               "build_catalog drops family-less")
check(next(tls_fp.build_catalog(nil)), nil,   "build_catalog nil → empty")

local prof = tls_fp.build_profiles({
    chrome  = { expected_cipher_cnt = 15, status = "active" },
    firefox = { expected_cipher_cnt = 16, status = "active" },
    safari  = { expected_cipher_cnt = 20, status = "active" },
    edge    = { expected_cipher_cnt = 15, status = "active" },
    beta    = { expected_cipher_cnt = 18, status = "staging" },  -- excluded
    bad     = { status = "active" },                              -- no cnt → skip
})
check(prof.chrome,  15,  "build_profiles chrome=15")
check(prof.firefox, 16,  "build_profiles firefox=16")
check(prof.safari,  20,  "build_profiles safari=20")
check(prof.edge,    15,  "build_profiles edge=15")
check(prof.beta,    nil, "build_profiles drops staging")
check(prof.bad,     nil, "build_profiles drops cnt-less")

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
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
