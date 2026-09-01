-- L4 rate limits: five profiles, first match wins, each with a 10 s and a 60 s
-- window that fires if either is exceeded.
--
-- rate_tls_fp keys on the fingerprint rather than the IP, which closes the
-- IP-rotation case, and skips when no fingerprint was computed so those
-- requests do not all share one empty key.
--
-- GCRA: one float cell per (profile, window, key), so it scales to many keys
-- without storing timestamps. The read-modify-write is unlocked, so under
-- contention a few requests can slip past a boundary.
--
-- A tripped profile is a fast 429, never a delay.

local policy = require "policy"

local _M = {
    enabled  = true,
    profiles = {},   -- ordered array of compiled rate profiles (build())
    api      = {},   -- api_path_patterns globs for rate_api / uri_bucket
}

-- Sized as below, a fresh key passes exactly `limit` requests and rejects the
-- next. Returns (allowed, new_tat, retry_after).
function _M.gcra(now, tat, interval, burst)
    tat = tat or 0
    local allow_at = tat - burst
    if now < allow_at then
        return false, tat, allow_at - now
    end
    local base = (now > tat) and now or tat   -- max(now, tat)
    return true, base + interval, 0
end

-- Without a real handshake the cipher count is zero and every such request
-- would share one key.
function _M.fp_usable(fp)
    if type(fp) ~= "string" or fp == "" then return false end
    local cc = fp:match("^L%d%d[di](%d%d)")
    return cc ~= nil and tonumber(cc) > 0
end

-- "/api/*" matches anything under the prefix; without the star, exactly.
function _M.glob_match(uri, pattern)
    if not uri or not pattern or pattern == "" then return false end
    if pattern:sub(-1) == "*" then
        local prefix = pattern:sub(1, -2)
        return uri:sub(1, #prefix) == prefix
    end
    return uri == pattern
end

function _M.is_api_path(uri, patterns)
    for _, p in ipairs(patterns or {}) do
        if _M.glob_match(uri, p) then return true end
    end
    return false
end

-- Normalises the URI to a small fixed set, so the label cardinality stays
-- bounded.
function _M.uri_bucket(uri, api_patterns)
    if _M.is_api_path(uri, api_patterns) then return "api" end
    if uri and uri:sub(1, 8) == "/static/" then return "static" end
    return "root"
end

-- nil when neither threshold is set, which leaves the profile inert.
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

-- Compiled in the master so workers inherit it; the dict holds only per-key
-- state.
function _M.build(config)
    local defaults = config.defaults or {}
    local blocking = defaults.blocking or {}
    local hygiene  = defaults.hygiene  or {}

    local api = hygiene.api_path_patterns
    if type(api) == "string" then api = { api } end
    _M.api = api or {}

    -- Order matters: first match wins.
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

    -- Passed explicitly, so build() works with any config-shaped table.
    _M.enabled = require("config").stage_enabled(defaults, "rate_limits")

    return _M, #_M.profiles
end

-- One GCRA window; a nil window never blocks. The cell is persisted only on an
-- allowed request and can never run more than one window ahead, so the 2× TTL
-- always outlives it while idle keys still evict.
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

-- A long URI or User-Agent would blow the dict's key-size limit, so anything
-- over 64 bytes becomes its md5 — collisions are harmless for rate accounting.
local function bound(s)
    if #s > 64 then return ngx.md5(s) end
    return s
end

-- Unique URLs per IP per window. GCRA models a rate, not set cardinality, so
-- this is a fixed-window unique counter.
--
-- Marker and counter share a bucket number, so each window has its own key
-- namespace and a stale marker cannot suppress counting in the next one.
--
-- Marker writes stop at the limit: otherwise a scraper hitting tens of
-- thousands of URLs would fill the dict and evict the other profiles' cells.
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

-- Records the first profile that trips. The boolean return is informational.
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

        -- Both windows every request: each keeps its own cell and must advance
        -- independently, or tripping the short one would freeze the long one.
        if p.kind == "scan" then
            local f10 = scan_window_exceeded(dict, ip, uri, p.w10)
            local f60 = scan_window_exceeded(dict, ip, uri, p.w60)
            fire = f10 or f60
        else
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
            -- The larger window never under-advises, so the client does not
            -- retry straight into another 429.
            local retry = (p.w60 and p.w60.seconds)
                       or (p.w10 and p.w10.seconds)
                       or 60
            policy.enforce(429, { ["Retry-After"] = retry })
            return true
        end
    end

    return false
end

return _M
