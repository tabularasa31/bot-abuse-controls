-- Unit tests for infra/demo-stand/lua/rate_limit.lua.
-- Pure Lua; runs under any luajit / lua 5.1+ with no openresty deps — the pure
-- helpers gcra() / windows() / glob_match() / is_api_path() / uri_bucket() are
-- covered here. The shared-dict TAT storage and the ngx-touching run() path are
-- exercised on the live stand (the ngx.* uses are inside run(), so this file
-- loads cleanly under bare luajit).
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local rl = require "rate_limit"

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
-- windows() — threshold pair -> per-window {limit, interval, burst}
-- ===========================================================================

do
    local w = rl.windows(100, 600)
    check(w.w10.limit, 100, "windows: w10 limit")
    check(w.w60.limit, 600, "windows: w60 limit")
    check(w.w10.seconds, 10, "windows: w10 seconds")
    check(w.w60.seconds, 60, "windows: w60 seconds")
    check(w.w10.interval, 10 / 100, "windows: w10 interval = window/limit")
    -- burst = (limit-1)*interval so exactly `limit` pass before the next trips.
    check(w.w10.burst, 99 * (10 / 100), "windows: w10 burst = (limit-1)*interval")
end

check(rl.windows(nil, nil), nil, "windows: both nil -> nil (inert)")
check(rl.windows(0, 0),   nil, "windows: non-positive -> nil (inert)")
do
    local w = rl.windows(nil, 300)
    check(w.w10, nil, "windows: only 60s configured -> w10 nil")
    check(w.w60.limit, 300, "windows: only 60s configured -> w60 set")
end

-- ===========================================================================
-- gcra() — one window. Simulate N requests at a fixed instant and count how
-- many conform. This is the acceptance shape at the pure level: under the limit
-- pass, over the limit are rejected.
-- ===========================================================================

-- Drive `n` requests all at time `now` through a single window; return how many
-- were allowed (advancing the TAT cell only on allow, exactly like run()).
local function allowed_at_once(win, n, now)
    now = now or 0
    local tat, allowed = nil, 0
    for _ = 1, n do
        local ok, new_tat = rl.gcra(now, tat, win.interval, win.burst)
        if ok then allowed = allowed + 1; tat = new_tat end
    end
    return allowed
end

do
    local w = rl.windows(50, 300)  -- the rate_api thresholds
    check(allowed_at_once(w.w10, 49), 49, "gcra: 49 < 50 all pass (under limit)")
    check(allowed_at_once(w.w10, 50), 50, "gcra: exactly 50 pass at the limit")
    -- The 51st is the first rejected: a burst of 200 yields only 50 allowed.
    check(allowed_at_once(w.w10, 200), 50, "gcra: burst of 200 -> 50 pass, rest rejected")
end

-- Rejected request reports a positive retry-after and does NOT advance the TAT.
do
    local w = rl.windows(1, nil).w10        -- limit 1 in 10s
    local ok1, tat1 = rl.gcra(0, nil, w.interval, w.burst)
    check(ok1, true, "gcra: first request under limit-1 allowed")
    local ok2, tat2, retry = rl.gcra(0, tat1, w.interval, w.burst)
    check(ok2, false, "gcra: second request over limit-1 rejected")
    check(tat2, tat1, "gcra: rejected request leaves TAT unchanged")
    check(retry > 0, true, "gcra: rejected request reports positive retry-after")
end

-- The window refills over time: after the window elapses a fresh request passes.
do
    local w = rl.windows(3, nil).w10
    local tat
    for _ = 1, 3 do _, tat = rl.gcra(0, tat, w.interval, w.burst) end  -- exhaust
    local blocked = rl.gcra(0, tat, w.interval, w.burst)
    check(blocked, false, "gcra: 4th at t=0 rejected")
    local refilled = rl.gcra(10, tat, w.interval, w.burst)
    check(refilled, true, "gcra: request after the window elapses passes again")
end

-- ===========================================================================
-- glob_match() / is_api_path() — API path detection (gates rate_api)
-- ===========================================================================

check(rl.glob_match("/api/users", "/api/*"), true,  "glob: /api/* matches /api/users")
check(rl.glob_match("/api",       "/api/*"), false, "glob: /api/* does not match bare /api")
check(rl.glob_match("/graphql",   "/graphql"), true, "glob: exact match")
check(rl.glob_match("/graphql/x", "/graphql"), false, "glob: exact pattern is not a prefix")
check(rl.glob_match("/static/a",  "/api/*"), false, "glob: unrelated path no match")

do
    local pats = { "/api/*", "/graphql" }
    check(rl.is_api_path("/api/v1/x", pats), true,  "is_api_path: /api/v1/x")
    check(rl.is_api_path("/graphql",  pats), true,  "is_api_path: /graphql")
    check(rl.is_api_path("/static/x", pats), false, "is_api_path: /static/x not api")
    check(rl.is_api_path("/",         pats), false, "is_api_path: / not api")
    check(rl.is_api_path("/x", nil),         false, "is_api_path: nil patterns -> false")
end

-- ===========================================================================
-- uri_bucket() — coarse normalised label (bounded metric/key cardinality)
-- ===========================================================================

do
    local pats = { "/api/*", "/graphql" }
    check(rl.uri_bucket("/api/v1/x", pats), "api",    "uri_bucket: api path")
    check(rl.uri_bucket("/static/a", pats), "static", "uri_bucket: static path")
    check(rl.uri_bucket("/",         pats), "root",   "uri_bucket: root")
    check(rl.uri_bucket("/anything", pats), "root",   "uri_bucket: other -> root")
end

-- ===========================================================================
-- "Different paths do not interfere" at the pure level: an API-path request
-- counts toward rate_api, a /static request does not (is_api_path gates it), so
-- traffic to one bucket cannot exhaust the other's budget. (The per-key TAT
-- separation in run() is exercised live; here we prove the gating predicate.)
-- ===========================================================================

do
    local pats = { "/api/*" }
    check(rl.is_api_path("/api/x", pats),    true,  "non-interference: /api/x is counted by rate_api")
    check(rl.is_api_path("/static/x", pats), false, "non-interference: /static/x is NOT counted by rate_api")
end

-- ===========================================================================
-- fp_usable() — graceful-skip predicate for rate_tls_fp. A real fp (cipher_count
-- > 0) is usable; a degenerate "no handshake" fp (cipher_count 0), an
-- absent/empty/malformed fp is not, so rate_tls_fp is skipped on an fp-cache
-- miss (phase2-spec §"Влияние на этап rate_limits").
-- ===========================================================================

check(rl.fp_usable("L13d15h2_0a1b2c3d4e5f_aabbccddeeff"), true,
    "fp_usable: real fp with cipher_count 15 is usable")
check(rl.fp_usable("L12d01h1_0a1b2c3d4e5f_aabbccddeeff"), true,
    "fp_usable: cipher_count 01 (>0) is usable")
check(rl.fp_usable("L00i00_000000000000_000000000000"), false,
    "fp_usable: degenerate no-handshake fp (cipher_count 0) is NOT usable")
check(rl.fp_usable(nil),  false, "fp_usable: nil fp -> not usable")
check(rl.fp_usable(""),   false, "fp_usable: empty fp -> not usable")
check(rl.fp_usable("garbage"), false, "fp_usable: unparseable fp -> not usable")
check(rl.fp_usable(123),  false, "fp_usable: non-string fp -> not usable")

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
