-- Aggregate stats pushed to stdout once per interval, which promtail already
-- tails alongside the request log. Aggregate rather than per-request, so it
-- stays safe under a flood and exposes no endpoint to scan.
--
-- The whole metrics dict is enumerated rather than an allowlist: a curated list
-- had already dropped the security counters, and this way a new counter ships
-- without editing here.
--
-- Staged patterns with zero traffic matter: nothing else can reconstruct them
-- for the promotion decision.

local _M = { interval = 30 }

-- Second precision is accepted by promtail's RFC3339Nano parsing.
function _M.iso8601(epoch)
    return os.date("!%Y-%m-%dT%H:%M:%S", math.floor(epoch or 0)) .. "Z"
end

function _M.snapshot(map, now, start_time, edge_id)
    local s = {
        type     = "edge_stats",
        edge_id  = edge_id or "",
        rules    = {},
        flags    = {},
        tags     = {},
        staging  = {},
        version_mismatch = {},
    }
    for k, v in pairs(map or {}) do
        local rule = k:match("^rule:(.+)$")
        local flag = k:match("^flag:(.+)$")
        local tag  = k:match("^tag:(.+)$")
        local stg  = k:match("^staging:(.+)$")
        local vmis = k:match("^edge_sidecar_version_mismatch_total:(.+)$")
        -- Internal keys: they drive the gauges below and are not dumped raw.
        local internal = (k == "start_time") or (k:find("^catalog_last_pull_ts:") ~= nil)
        if rule then s.rules[rule] = v
        elseif flag then s.flags[flag] = v
        elseif tag then s.tags[tag] = v
        elseif stg then s.staging[stg] = v
        elseif vmis then s.version_mismatch[vmis] = v
        elseif not internal then s[k] = v   -- plain scalar counter / gauge
        end
    end
    local hit  = s.cache_hit_total or 0
    local miss = s.cache_miss_total or 0
    s.cache_hit_ratio = (hit + miss) > 0 and (hit / (hit + miss)) or 0
    s.uptime_seconds = (now and start_time) and (now - start_time) or 0
    s.timestamp = _M.iso8601(now)
    return s
end

-- Straight to stdout: ngx.log would wrap the line and break the promtail regex.
-- The file wins over the env var, since it survives a hot reload.
local cached_revision
local function revision()
    if cached_revision then return cached_revision end
    local f = io.open("/etc/nginx/lua/.revision", "r")
    if f then
        local rev = f:read("*l")
        f:close()
        if rev and rev ~= "" then cached_revision = rev; return rev end
    end
    cached_revision = os.getenv("REVISION") or "unknown"
    return cached_revision
end

-- Shared by the stdout push and the /__stats handler, so both agree.
function _M.collect()
    local m = ngx.shared.metrics
    if not m then return nil end
    -- One lock-pass over the whole dict, once per tick.
    local map = {}
    for _, k in ipairs(m:get_keys(0)) do
        map[k] = m:get(k)
    end
    local snap = _M.snapshot(
        map,
        ngx.now(),
        m:get("start_time"),
        os.getenv("EDGE_ID") or "stand-bac")

    -- Lets an operator confirm what is deployed from the log alone. Static for
    -- a worker's life; the `false` sentinel separates "resolved to nil" from
    -- "not yet resolved".
    snap.commit = revision()
    if _M._cached_cascade_version == nil then
        local ok_cv, cv = pcall(function() return require("challenge").template_version() end)
        _M._cached_cascade_version = (ok_cv and cv) or false
    end
    snap.cascade_version = _M._cached_cascade_version or nil
    if _M._cached_secret_fp == nil then
        local ok_fp, fp = pcall(function() return require("challenge_secret").fingerprint() end)
        _M._cached_secret_fp = (ok_fp and fp) or false
    end
    snap.challenge_secret_fp = _M._cached_secret_fp or nil

    -- Seconds since the last successful pull, -1 if never. The alert signal for
    -- a dead channel: the warnings go to the error log, which promtail drops.
    local ok_st, stale = pcall(function()
        local cp = require "catalog_pull"
        local now = ngx.time()
        local out = {}
        -- Resolve from key or value, so an array form would work too.
        for k, v in pairs(cp.catalogs or {}) do
            local name = (type(k) == "string") and k or v
            if type(name) == "string" then
                local ts = m:get("catalog_last_pull_ts:" .. name)
                out[name] = ts and (now - ts) or -1
            end
        end
        return out
    end)
    snap.catalog_staleness_seconds = ok_st and stale or nil

    return snap
end

function _M.emit()
    local snap = _M.collect()
    if not snap then return end
    local line = require("cjson.safe").encode(snap)
    if not line then return end
    io.stdout:write("EDGE_STATS ", line, "\n")
    io.stdout:flush()
end

-- Worker 0 only, so an N-worker pool emits one line per interval; the metrics
-- dict is shared, so any worker sees the global totals.
function _M.start(opts)
    opts = opts or {}
    local interval = tonumber(opts.interval) or _M.interval
    if ngx.worker.id() ~= 0 then return end
    local ok, err = ngx.timer.every(interval, function(premature)
        -- `premature` is true when the timer is cancelled on a worker reload or
        -- shutdown; skip that final fire so nothing is emitted mid-teardown.
        if premature then return end
        local pok, perr = pcall(_M.emit)
        if not pok then
            ngx.log(ngx.ERR, "edge_stats: emit failed: ", tostring(perr))
        end
    end)
    if not ok then
        ngx.log(ngx.ERR, "edge_stats: timer.every failed: ", tostring(err))
    end
end

return _M
