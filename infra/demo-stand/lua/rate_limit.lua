-- L4 rate_limits stage (rules-reference L4, phase1-spec "rate_limits",
-- phase2-spec "Влияние на этап rate_limits"; RFC §A3).
--
-- System profiles, in rules-reference order (first match wins within the stage):
--   1. rate_ip       — per source IP            (10s>100  || 60s>600)
--   2. rate_ip_ua    — per source IP + UA pair  (10s>100  || 60s>600)
--   3. rate_api      — per IP, API paths only   (10s>50   || 60s>300)
--   4. rate_tls_fp   — per TLS fingerprint      (10s>50   || 60s>300)  [Phase 2]
--   5. rate_scan_urls— per IP, UNIQUE URLs      (10s>50   || 60s>200)
-- Each profile has two windows (10s and 60s); the profile fires if EITHER is
-- exceeded. Thresholds come from defaults.conf [blocking.rate_*] via the config
-- module (window_10s / window_60s), so admins retune without code changes.
--
-- rate_tls_fp (Phase 2, phase2-spec §"Влияние на этап rate_limits") keys the
-- GCRA cell on the TLS fingerprint instead of the IP, closing the IP-rotation /
-- single-TLS-stack class. It is GRACEFUL-SKIP on an fp-cache miss: if the fp was
-- not computed for this request (no TLS handshake captured ⇒ cipher_count 0, or
-- an absent/malformed fp), the profile is skipped entirely (no key, no cell, no
-- verdict) and only the per-IP / per-IP+UA limits apply — exactly as the spec
-- requires ("Если tls_fp_cache промахнулся ... правило rate_tls_fp не
-- срабатывает"). The fp is computed once in verdict.lua and passed into run().
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
-- Mode-gated enforcement (86exr0627). When a profile fires, run() records
-- the would-be verdict via bac_log and then calls policy.enforce(429,
-- {Retry-After=...}). For a host with policy.mode=active that means
-- ngx.exit(429) right inside run with a Retry-After header (the larger
-- of the profile's windows, typically 60s — phase1-spec §"429 с
-- Retry-After"). For mode=shadow (pool default) enforce is a no-op:
-- run returns true, the cascade ends (rate_limit is already last), and
-- the request continues to origin. The GCRA cell's exact retry-after
-- gap is still not surfaced — using the window size is a safe upper
-- bound and avoids leaking the cell's internal state; refining to the
-- precise gap is a future optimization, not a correctness gap.
--
-- Fair-queueing / ngx.sleep delaying is explicitly NOT done: a block
-- is a fast 429, not a hold. Spec mentions delay/fair-queue as
-- possible future behaviour; current scope is plain 429.
--
-- Cascade order is hygiene → reputation → tls_fp → rate_limits → verification,
-- so run() is called LAST in verdict.lua (after the tls_fp allow fall-through).
-- bac_log is last-writer-wins, so a rate_limits block overwrites an earlier
-- observe-only hygiene/reputation verdict — matching the "финальное сработавшее
-- правило" logging contract (phase1-spec). Metrics: a fired profile is counted
-- automatically by log_event.lua as antibot_rule_total{stage="rate_limits",
-- rule="rate_ip"|...} — the stand's per-rule counter model. (The dedicated
-- lua-resty-prometheus histograms are cascade task C3.)

local policy = require "policy"

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

-- pure: is the fp usable as a rate_tls_fp key? True only when fp is a non-empty
-- string carrying a real handshake — cipher_count > 0. The fp prefix is always
-- "L<ver:2d><sni:d|i><cipher_cnt:2d>…" (ja4_compute.lua), and a request with no
-- TLS handshake degenerates to cipher_count 0 ("L00i00…"). A 0 count (or a
-- prefix that does not parse) means "fp not computed" → graceful skip. Same
-- parse as tls_fp.cipher_count; inlined to keep this module free of a tls_fp dep.
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

    -- Profile order is the rules-reference order: rate_ip → rate_ip_ua →
    -- rate_api → rate_tls_fp → rate_scan_urls. rate_scan_urls counts UNIQUE URLs,
    -- not request rate (kind="scan"); the others are plain GCRA request-rate
    -- cells (kind="rate"). rate_api is a rate cell that only applies on API paths
    -- (api_only=true). rate_tls_fp (Phase 2) keys on the TLS fp and is skipped
    -- when the fp is not usable (graceful skip — see run()).
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

-- One GCRA window against the shared dict. `dict_key` identifies the cell;
-- `win` is a {interval,burst,seconds} window (or nil → not configured, never
-- blocks). Returns true when this window is exceeded.
--
-- We only persist the cell on an ALLOWED request, and burst = window - interval
-- caps how far the TAT can run ahead: a request only conforms while
-- now >= tat - burst, so the stored new_tat = max(now,tat) + interval is at most
-- now + burst + interval = now + window. The 2× window TTL therefore always
-- outlives the cell's own TAT (the cell never points more than one window into
-- the future) while still letting idle keys evict so the dict stays bounded.
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

-- rate_scan_urls: count UNIQUE URLs per IP per window. GCRA models request rate,
-- not set cardinality, so this is a fixed-window unique counter instead.
--
-- Keys are bucketed by floor(now/window): both the per-URL marker and the
-- per-IP counter carry the same bucket number, so each window generation has a
-- distinct key namespace. That is what keeps the marker and counter lifetimes
-- consistent — a marker lingering from an earlier bucket cannot suppress
-- counting in the next one (its key no longer matches), and within a bucket the
-- counter is created on the first unique URL and lives 2× the window, well
-- beyond every marker added in that same bucket. The marker fires :add() only
-- the first time a URL is seen in the bucket; each first-sight bumps the
-- counter. Exceeded when the counter passes the threshold. Fixed-window (not
-- sliding) with the usual boundary doubling is acceptable for the observe-only
-- stand.
--
-- Marker writes are CAPPED at the threshold: once the counter is over the limit
-- the verdict is already decided, so we stop recording new URL markers. Without
-- this a scraper hitting tens of thousands of distinct URLs would flood the
-- shared `rate_limit` dict and, via LRU, evict the GCRA TAT cells of the OTHER
-- profiles — corrupting their accounting too. The cap bounds markers to ~limit
-- per (ip, bucket) (a few hundred), so scan traffic can no longer starve the
-- rest of the stage.
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

-- Called per request from verdict.lua, LAST in the cascade. Observe-only:
-- records the would-be verdict via bac_log on the first profile that trips,
-- then returns (first-match-wins). Never blocks, never sleeps, never stops the
-- cascade; the boolean return is informational only. `fp` is the TLS
-- fingerprint computed once in verdict.lua, used to key rate_tls_fp; when it is
-- not usable that profile is skipped (graceful skip).
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
            -- Per-profile applicability:
            --   * rate_api  — only on API paths (api_only).
            --   * rate_tls_fp — only when the fp was computed (graceful skip on
            --     an fp-cache miss; phase2-spec). Its key material is the fp.
            --   * everything else always applies, keyed on ip / ip+ua.
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
            -- Retry-After in seconds. Use the larger of the profile's
            -- two windows (typically 60s) as a safe upper bound on the
            -- recovery time — the GCRA cell's exact gap isn't surfaced
            -- here, but the window size is always ≥ the gap, so we
            -- never under-advise the client (which would cause an
            -- immediate retry that 429s again). Fall back to 60 if
            -- neither window has a `.seconds` field, defensive only.
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
