-- L4 rate limits.
--
-- Five system profiles, first match wins: per IP, per IP+UA, per IP on API
-- paths, per TLS fingerprint, and unique-URL scanning per IP. Each has a 10 s
-- and a 60 s window and fires if either is exceeded; the thresholds live in the
-- config so they can be retuned without code changes.
--
-- rate_tls_fp keys on the fingerprint instead of the IP, which closes the
-- IP-rotation case. It skips gracefully when no fingerprint was computed, so
-- only the per-IP profiles apply rather than everything sharing one empty key.
--
-- The algorithm is GCRA: one float cell per (profile, window, key), updated
-- with a single arithmetic operation, so it scales to many keys without storing
-- timestamp lists. The read-modify-write is unlocked, so under contention a few
-- requests can slip past a window boundary.
--
-- A tripped profile is a fast 429 with Retry-After, never a delay or a hold.

local policy = require "policy"

local _M = {
    enabled  = true,
    profiles = {},   -- ordered array of compiled rate profiles (build())
    api      = {},   -- api_path_patterns globs for rate_api / uri_bucket
}

-- GCRA conformance for one window. `interval` is the spacing between conforming
-- requests and `burst` the tolerance; sized as below, a fresh key passes exactly
-- `limit` requests and rejects the next one. Returns (allowed, new_tat,
-- retry_after).
function _M.gcra(now, tat, interval, burst)
    tat = tat or 0
    local allow_at = tat - burst
    if now < allow_at then
        return false, tat, allow_at - now
    end
    local base = (now > tat) and now or tat   -- max(now, tat)
    return true, base + interval, 0
end

-- A fingerprint is usable only if it carries a real handshake: with none, the
-- cipher count degenerates to zero and every such request would share one key.
function _M.fp_usable(fp)
    if type(fp) ~= "string" or fp == "" then return false end
    local cc = fp:match("^L%d%d[di](%d%d)")
    return cc ~= nil and tonumber(cc) > 0
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

-- Derives both windows from a threshold pair, carrying the raw limit for the
-- unique-URL counter and the GCRA parameters for the rate cells. nil when
-- neither threshold is set, which leaves the profile inert. No ngx dep.
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

-- Compiles the thresholds into the ordered profile list, in the master so
-- workers inherit it. The shared dict holds only per-key state.
function _M.build(config)
    local defaults = config.defaults or {}
    local blocking = defaults.blocking or {}
    local hygiene  = defaults.hygiene  or {}

    -- api_path_patterns may be a single string or a comma-split list (coerce()).
    local api = hygiene.api_path_patterns
    if type(api) == "string" then api = { api } end
    _M.api = api or {}

    -- Order matters: first match wins. rate_scan_urls counts unique URLs
    -- rather than request rate, which is why it has its own kind.
    local specs = {
        { rule = "rate_ip",        kind = "rate", key = "ip" },
        { rule = "rate_ip_ua",     kind = "rate", key = "ip_ua" },
        { rule = "rate_api",       kind = "rate", key = "ip",     api_only = true },
        { rule = "rate_tls_fp",    kind = "rate", key = "tls_fp" },
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

    -- Stage off via the shared kill-switch helper (config-templates.md
    -- kill_switch; defaults.conf [kill_switch.*]). Required explicitly rather
    -- than read off the `config` arg so build() works with any config-shaped
    -- table, not only the config module instance.
    _M.enabled = require("config").stage_enabled(defaults, "rate_limits")

    return _M, #_M.profiles
end

-- One GCRA window against the shared dict; a nil window never blocks.
--
-- The cell is persisted only on an allowed request, and the burst caps how far
-- it can run ahead — never more than one window into the future. So the 2×
-- window TTL always outlives the cell while still letting idle keys evict.
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

-- Bound a key fragment to a safe length for lua_shared_dict keys (a long URI or
-- User-Agent must not blow the dict's key-size limit or silently fail set/add).
-- Anything over 64 bytes is replaced by its md5 hex — collisions are negligible
-- for rate accounting and the length becomes fixed.
local function bound(s)
    if #s > 64 then return ngx.md5(s) end
    return s
end

-- Unique URLs per IP per window. GCRA models a rate, not set cardinality, so
-- this is a fixed-window unique counter instead.
--
-- Both the per-URL marker and the per-IP counter carry the same bucket number,
-- giving each window its own key namespace: a marker left over from an earlier
-- bucket cannot suppress counting in the next one.
--
-- Marker writes stop once the counter is over the limit. Without that cap a
-- scraper hitting tens of thousands of URLs would fill the shared dict and
-- evict the other profiles' cells through LRU, corrupting their accounting.
local function scan_window_exceeded(dict, ip, uri, win)
    if not win then return false end
    local bucket  = math.floor(ngx.now() / win.seconds)
    local cnt_key = "sc:" .. win.seconds .. ":" .. bucket .. ":" .. ip
    local ttl     = win.seconds * 2

    local cnt = dict:get(cnt_key)
    if cnt and cnt > win.limit then return true end   -- decided; stop adding markers

    local marker = "su:" .. win.seconds .. ":" .. bucket .. ":" .. ip
                   .. ":" .. bound(uri or "")
    if not dict:add(marker, true, ttl) then return false end
    local n = dict:incr(cnt_key, 1, 0, ttl)
    return (n or 0) > win.limit
end

-- Records the first profile that trips and returns. Never sleeps. The boolean
-- return is informational.
function _M.run(fp)
    if not _M.enabled then return false end
    if #_M.profiles == 0 then return false end

    local dict = ngx.shared.rate_limit
    if not dict then return false end

    local ip  = ngx.var.binary_remote_addr
    if not ip then return false end
    local ua  = ngx.var.http_user_agent or ""
    local uri = ngx.var.uri or ""
    local is_api = _M.is_api_path(uri, _M.api)
    local fp_ok  = _M.fp_usable(fp)

    local bac_log = package.loaded["bac_log"] or require "bac_log"

    for _, p in ipairs(_M.profiles) do
        local fire = false

        -- Both windows are evaluated every request (no `or` short-circuit): each
        -- window keeps its own cell/counter and must advance independently, else
        -- tripping the 10s window would stop the 60s window from tracking.
        if p.kind == "scan" then
            local f10 = scan_window_exceeded(dict, ip, uri, p.w10)
            local f60 = scan_window_exceeded(dict, ip, uri, p.w60)
            fire = f10 or f60
        else
            -- rate_api applies only on API paths, rate_tls_fp only when the
            -- fingerprint exists; the rest always apply.
            local applies, material
            if p.key == "tls_fp" then
                applies, material = fp_ok, fp
            elseif p.api_only then
                applies, material = is_api, ip
            else
                applies = true
                material = (p.key == "ip_ua") and (ip .. "\0" .. ua) or ip
            end
            if applies then
                local base = p.rule .. ":" .. bound(material)
                local f10 = window_exceeded(dict, base .. ":10", p.w10)
                local f60 = window_exceeded(dict, base .. ":60", p.w60)
                fire = f10 or f60
            end
        end

        if fire then
            bac_log.set_verdict("rate_limits", "block", p.rule)
            -- The larger window is a safe upper bound on the recovery time:
            -- never under-advise, or the client retries straight into another
            -- 429.
            local retry = (p.w60 and p.w60.seconds)
                       or (p.w10 and p.w10.seconds)
                       or 60
            -- mode-gate: active → ngx.exit(429) + Retry-After;
            -- shadow → no-op, cascade ends naturally (rate_limit is
            -- the last stage), request reaches origin with would-be
            -- block in the log.
            policy.enforce(429, { ["Retry-After"] = retry })
            return true
        end
    end

    return false
end

return _M
