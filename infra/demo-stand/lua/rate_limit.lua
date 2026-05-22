-- L4 rate_limits stage (rules-reference L4, phase1-spec "rate_limits"; RFC §A3).
--
-- Phase 1 system profiles, in order (first match wins within the stage):
--   1. rate_ip       — per source IP            (10s>100  || 60s>600)
--   2. rate_ip_ua    — per source IP + UA pair  (10s>100  || 60s>600)
--   3. rate_api      — per IP, API paths only   (10s>50   || 60s>300)
--   4. rate_scan_urls— per IP, UNIQUE URLs      (10s>50   || 60s>200)
-- (rate_tls_fp is Phase 2 and is intentionally NOT built here.)
-- Each profile has two windows (10s and 60s); the profile fires if EITHER is
-- exceeded. Thresholds come from defaults.conf [blocking.rate_*] via the config
-- module (window_10s / window_60s), so admins retune without code changes.
--
-- Algorithm — GCRA (phase1-spec §"Семантика sliding window"): one float TAT
-- cell per (profile, window, key) in the `rate_limit` shared_dict, updated with
-- one arithmetic op. No timestamp lists, so it scales to many keys. We roll our
-- own over shared_dict (the spec explicitly allows this in lieu of
-- lua-resty-limit-req, which the stand does not vendor). The read-modify-write
-- is not locked; under contention a few extra requests can slip a window
-- boundary — acceptable for an observe-only stand, and lua-resty-limit-req's
-- locking is the productionize step, not Phase 1.
--
-- Phase 1 is OBSERVE-ONLY, exactly like hygiene.lua / reputation.lua: run()
-- records the would-be verdict via bac_log but NEVER ngx.exit(429), NEVER
-- ngx.sleep (fair queueing), and NEVER short-circuits the cascade. phase1-spec
-- is explicit: "физически с запросом ничего не происходит — он всегда доходит
-- до origin". The 429 + Retry-After and the delay/fair-queueing behaviour the
-- RFC describes are the future per-rule-enforce task (synchronous with the
-- per-resource business mode), not Phase 1. The GCRA cell already computes the
-- retry-after gap; we just don't act on it yet.
--
-- Cascade order is hygiene → reputation → tls_fp → rate_limits → verification,
-- so run() is called LAST in verdict.lua (after the tls_fp allow fall-through).
-- bac_log is last-writer-wins, so a rate_limits block overwrites an earlier
-- observe-only hygiene/reputation verdict — matching the "финальное сработавшее
-- правило" logging contract (phase1-spec). Metrics: a fired profile is counted
-- automatically by log_event.lua as antibot_rule_total{stage="rate_limits",
-- rule="rate_ip"|...} — the stand's per-rule counter model. (The dedicated
-- lua-resty-prometheus histograms are cascade task В3.)

local _M = {
    enabled  = true,
    profiles = {},   -- ordered array of compiled rate profiles (build())
    api      = {},   -- api_path_patterns globs for rate_api / uri_bucket
}

-- pure: GCRA conformance test for one window. `interval` = seconds between two
-- conforming requests (= window/limit); `burst` = burst tolerance in seconds.
-- With burst = (limit-1)*interval = window-interval (see windows()), a fresh key
-- emits exactly `limit` requests instantaneously and the (limit+1)th is the
-- first rejected — matching the rules-reference ">N" threshold (block the
-- request that pushes the count past N). Returns (allowed, new_tat, retry_after):
--   * allowed false  → request is over the limit; new_tat unchanged; retry_after
--                      = seconds until it would conform again.
--   * allowed true   → new_tat is the updated cell to persist; retry_after 0.
-- No ngx dependency — unit-tested in tests/rate_limit_test.lua.
function _M.gcra(now, tat, interval, burst)
    tat = tat or 0
    local allow_at = tat - burst
    if now < allow_at then
        return false, tat, allow_at - now
    end
    local base = (now > tat) and now or tat   -- max(now, tat)
    return true, base + interval, 0
end

-- pure: glob match for an api_path pattern. "/api/*" matches any URI under the
-- "/api/" prefix; a pattern without a trailing "*" matches the URI exactly.
-- Mirrors how config-templates.md describes api_path_patterns. No ngx dep.
function _M.glob_match(uri, pattern)
    if not uri or not pattern or pattern == "" then return false end
    if pattern:sub(-1) == "*" then
        local prefix = pattern:sub(1, -2)
        return uri:sub(1, #prefix) == prefix
    end
    return uri == pattern
end

-- pure: is this URI an API endpoint per the configured patterns? Used to gate
-- rate_api (it only counts requests on API paths). No ngx dep.
function _M.is_api_path(uri, patterns)
    for _, p in ipairs(patterns or {}) do
        if _M.glob_match(uri, p) then return true end
    end
    return false
end

-- pure: coarse URI bucket label for metrics / debugging. Normalises a URI to a
-- small fixed set so the label cardinality stays bounded (the composite-key
-- shape RFC §A3 sketches). api patterns win; "/static/" is recognised as a
-- common second class; everything else collapses to "/". No ngx dep.
function _M.uri_bucket(uri, api_patterns)
    if _M.is_api_path(uri, api_patterns) then return "api" end
    if uri and uri:sub(1, 8) == "/static/" then return "static" end
    return "root"
end

-- pure: derive the two windows of a profile from its threshold pair. Each
-- window carries both the raw `limit` (used by the scan-urls unique counter)
-- and the GCRA params interval=window/limit, burst=(limit-1)*interval (used by
-- the rate cells; burst sized so exactly `limit` requests pass before the
-- (limit+1)th trips). Returns { w10, w60 } or nil when neither threshold is a
-- positive number (profile inert). No ngx dep.
function _M.windows(window_10s, window_60s)
    local function win(seconds, limit)
        if type(limit) ~= "number" or limit <= 0 then return nil end
        local interval = seconds / limit
        return { seconds = seconds, limit = limit,
                 interval = interval, burst = (limit - 1) * interval }
    end
    local w10, w60 = win(10, window_10s), win(60, window_60s)
    if not w10 and not w60 then return nil end
    return { w10 = w10, w60 = w60 }
end

-- Called once in init_by_lua, after config.load(). Compiles the defaults.conf
-- thresholds into the ordered profile list the request path reads. Done in the
-- master so workers inherit it on fork (no shared dict for config; the shared
-- dict holds only per-key TAT state). Returns _M and the count of active
-- profiles for the startup log.
function _M.build(config)
    local defaults = config.defaults or {}
    local blocking = defaults.blocking or {}
    local hygiene  = defaults.hygiene  or {}

    -- api_path_patterns may be a single string or a comma-split list (coerce()).
    local api = hygiene.api_path_patterns
    if type(api) == "string" then api = { api } end
    _M.api = api or {}

    -- Profile order is the rules-reference order minus the Phase 2 rate_tls_fp.
    -- rate_scan_urls counts UNIQUE URLs, not request rate (kind="scan"); the
    -- others are plain GCRA request-rate cells (kind="rate"). rate_api is a
    -- rate cell that only applies on API paths (api_only=true).
    local specs = {
        { rule = "rate_ip",        kind = "rate", key = "ip" },
        { rule = "rate_ip_ua",     kind = "rate", key = "ip_ua" },
        { rule = "rate_api",       kind = "rate", key = "ip",  api_only = true },
        { rule = "rate_scan_urls", kind = "scan", key = "ip" },
    }

    _M.profiles = {}
    for _, spec in ipairs(specs) do
        local cfg = blocking[spec.rule] or {}
        if cfg.enabled ~= false then
            local wins = _M.windows(cfg.window_10s, cfg.window_60s)
            if wins then
                _M.profiles[#_M.profiles + 1] = {
                    rule     = spec.rule,
                    kind     = spec.kind,
                    key      = spec.key,
                    api_only = spec.api_only,
                    w10      = wins.w10,
                    w60      = wins.w60,
                }
            end
        end
    end

    -- Stage off when the global kill-switch or the per-stage rate_limits switch
    -- is set (config-templates.md kill_switch; defaults.conf [kill_switch.*]).
    local ks = defaults.kill_switch or {}
    _M.enabled = not ((ks.global or {}).enabled == true
                      or (ks.per_stage or {}).rate_limits == true)

    return _M, #_M.profiles
end

-- One GCRA window against the shared dict. `dict_key` identifies the cell;
-- `win` is a {interval,burst,seconds} window (or nil → not configured, never
-- blocks). Returns true when this window is exceeded. The cell TTL is 2× the
-- window so idle keys evict and the dict stays bounded.
local function window_exceeded(dict, dict_key, win)
    if not win then return false end
    local now = ngx.now()
    local tat = dict:get(dict_key)
    local ok, new_tat = _M.gcra(now, tat, win.interval, win.burst)
    if ok then
        dict:set(dict_key, new_tat, win.seconds * 2)
        return false
    end
    return true
end

-- rate_scan_urls: count UNIQUE URLs per IP per window. GCRA models request rate,
-- not set cardinality, so this is a fixed-window unique counter instead: a
-- per-(window,ip,uri) marker added with the window TTL fires :add() only the
-- first time that URL is seen in the window, and each first-sight bumps a
-- per-(window,ip) counter. Exceeded when the counter passes the threshold.
-- Fixed-window (not sliding) is acceptable for the observe-only stand.
local function scan_window_exceeded(dict, ip, uri, win)
    if not win then return false end
    local seen_key = "su:" .. win.seconds .. ":" .. ip .. ":" .. (uri or "")
    -- :add succeeds only if the marker is absent → first sight of this URL.
    local added = dict:add(seen_key, true, win.seconds)
    if not added then return false end
    local cnt_key = "sc:" .. win.seconds .. ":" .. ip
    local n = dict:incr(cnt_key, 1, 0, win.seconds)
    return (n or 0) > win.limit
end

-- Called per request from verdict.lua, LAST in the cascade. Observe-only:
-- records the would-be verdict via bac_log on the first profile that trips,
-- then returns (first-match-wins). Never blocks, never sleeps, never stops the
-- cascade; the boolean return is informational only.
function _M.run()
    if not _M.enabled then return false end
    if #_M.profiles == 0 then return false end

    local dict = ngx.shared.rate_limit
    if not dict then return false end

    local ip  = ngx.var.binary_remote_addr
    if not ip then return false end
    local ua  = ngx.var.http_user_agent or ""
    local uri = ngx.var.uri or ""
    local is_api = _M.is_api_path(uri, _M.api)

    local bac_log = package.loaded["bac_log"] or require "bac_log"

    for _, p in ipairs(_M.profiles) do
        local fire = false

        if p.kind == "scan" then
            fire = scan_window_exceeded(dict, ip, uri, p.w10)
                or scan_window_exceeded(dict, ip, uri, p.w60)
        else
            -- rate_api only counts on API paths; skip it elsewhere.
            if not (p.api_only and not is_api) then
                local material = (p.key == "ip_ua") and (ip .. "\0" .. ua) or ip
                local base = p.rule .. ":" .. material
                fire = window_exceeded(dict, base .. ":10", p.w10)
                    or window_exceeded(dict, base .. ":60", p.w60)
            end
        end

        if fire then
            bac_log.set_verdict("rate_limits", "block", p.rule)
            return true
        end
    end

    return false
end

return _M
