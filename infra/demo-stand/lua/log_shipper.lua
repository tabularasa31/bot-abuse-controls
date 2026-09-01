-- Ships the request log to the backend receiver: emit appends to a per-worker
-- queue, and a background timer drains it as a batch over mTLS.
--
-- One queue and timer per worker — a shared queue would put contention on the
-- hot path of every request.
--
-- Fail-stale: an unreachable backend drops the batch and counts it. The buffer
-- is in memory and does not survive a reload.

local _M = {}

-- Disabled when backend_url is unset: enqueue becomes a no-op.
local DEFAULTS = {
    flush_interval = 1,        -- seconds between flush ticks
    batch_max      = 1000,     -- the maximum lines in one POST
    queue_max      = 10000,    -- the per-worker queue capacity (drop-newest on overflow)
    timeout_ms     = 5000,     -- httpc timeout (connect + read)
    path           = "/v1/logs",
}

-- An array plus a write index. Deliberately not a shared_dict, whose locking
-- would land on the hot path of every request.
local queue = {}
local in_flight = false  -- a guard so that ticks do not overlap

-- Overflow and disabled are counted separately: identical in a total, and
-- completely different to an operator. The loaded gauge distinguishes "failed to
-- load" from "loaded and idle".
local M_ENQUEUED          = "bac_log_enqueued_total"
local M_DROPPED_OVERFLOW  = "bac_log_dropped_overflow_total"
local M_DROPPED_DISABLED  = "bac_log_dropped_disabled_total"
local M_SHIPPED           = "bac_log_shipped_total"
local M_FAILED            = "bac_log_ship_failed_total"
local M_BATCHES_OK        = "bac_log_batches_ok_total"
local M_SHIPPER_LOADED    = "bac_log_shipper_loaded"

local function metric_incr(key, by)
    local m = ngx.shared.metrics
    if m then m:incr(key, by or 1, 0) end
end

local function nonempty(s)
    if s == nil or s == "" then return nil end
    return s
end

local function truthy_env(s, default)
    s = nonempty(s)
    if s == nil then return default end
    s = s:lower()
    if s == "false" or s == "0" or s == "no" or s == "off" then return false end
    return true
end

-- The hot path. Never blocks; returns false when the line was dropped.
function _M.enqueue(line)
    if not line then return false end
    if line == "" then
        -- Only reachable through a producer bug.
        ngx.log(ngx.WARN, "log_shipper: enqueue('') — empty line, upstream bug?")
        return false
    end
    if not _M.backend_url then
        metric_incr(M_DROPPED_DISABLED)
        return false
    end
    if #queue >= _M.queue_max then
        -- Drop-newest: the older lines may already have been useful.
        metric_incr(M_DROPPED_OVERFLOW)
        return false
    end
    queue[#queue + 1] = line
    metric_incr(M_ENQUEUED)
    return true
end

function _M.queue_size() return #queue end

-- Copy plus a tail shift — microseconds at these sizes, once a second.
local function drain_batch(n)
    if n > #queue then n = #queue end
    local batch = {}
    for i = 1, n do batch[i] = queue[i] end
    local len = #queue
    for i = 1, len - n do queue[i] = queue[i + n] end
    for i = len - n + 1, len do queue[i] = nil end
    return batch
end

-- Deliberately absent: requeueing on a send error would spin forever.

local function ship(batch)
    local httpc_mod = _M.http_module
    if not httpc_mod then return false, "http module not configured" end
    local httpc = httpc_mod.new()
    httpc:set_timeout(_M.timeout_ms)

    -- One JSON object per line, which is what the receiver's scanner expects.
    local body = table.concat(batch, "\n")

    local headers = { ["Content-Type"] = "application/x-ndjson" }
    if _M.backend_host_header then headers["Host"] = _M.backend_host_header end

    local req_opts = {
        method     = "POST",
        body       = body,
        headers    = headers,
        ssl_verify = _M.ssl_verify,
    }
    if _M.parsed_cert and _M.parsed_key then
        req_opts.ssl_client_cert     = _M.parsed_cert
        req_opts.ssl_client_priv_key = _M.parsed_key
    end

    -- A trailing slash would produce a double slash, which nginx may route to a
    -- different location.
    local base = _M.backend_url:gsub("/+$", "")
    local res, err = httpc:request_uri(base .. _M.path, req_opts)
    if not res then return false, "transport: " .. tostring(err) end
    -- Only 202 is success. A 4xx means the batch is partly broken and is lost;
    -- a 5xx means there is nowhere to retry.
    if res.status ~= 202 then
        return false, "status=" .. tostring(res.status)
    end
    return true, nil
end

-- Guarded by a pcall in start(): a raise would kill the timer through
-- ngx.timer.every's rate limiter.
local function tick(premature)
    if premature then return end
    if in_flight then
        -- The previous tick is still in HTTP; multiplying connections would not
        -- help.
        return
    end
    if #queue == 0 then return end
    in_flight = true

    local batch = drain_batch(_M.batch_max)
    local ok, err = ship(batch)
    in_flight = false

    if ok then
        metric_incr(M_SHIPPED, #batch)
        metric_incr(M_BATCHES_OK)
    else
        metric_incr(M_FAILED)
        ngx.log(ngx.WARN, "log_shipper: ship failed (", err,
            "), batch=", #batch, " dropped")
    end
end

-- For tests. Without the pcall a raise would leave in_flight set forever.
function _M.flush_now()
    if #queue == 0 then return true, nil end
    if in_flight then return false, "in_flight" end
    in_flight = true
    local batch = drain_batch(_M.batch_max)
    local pok, ok, err = pcall(ship, batch)
    in_flight = false
    if not pok then
        metric_incr(M_FAILED)
        return false, "ship raised: " .. tostring(ok)
    end
    if ok then
        metric_incr(M_SHIPPED, #batch)
        metric_incr(M_BATCHES_OK)
    else
        metric_incr(M_FAILED)
    end
    return ok, err
end

-- Runs in every worker, unlike the catalog pull. The loaded gauge is set only
-- where setup completed, so an error path leaves it at zero.
local function mark_loaded()
    if ngx.shared.metrics then ngx.shared.metrics:set(M_SHIPPER_LOADED, 1) end
end

function _M.start(opts)
    opts = opts or {}
    _M.backend_url = nonempty(opts.backend_url)
                     or nonempty(os.getenv("ANTIBOT_BACKEND_URL"))
    if not _M.backend_url then
        ngx.log(ngx.NOTICE, "log_shipper: ANTIBOT_BACKEND_URL not set — shipper disabled (dropped_disabled will increment per request)")
        mark_loaded()
        return
    end
    _M.backend_host_header = nonempty(opts.backend_host_header)
                             or nonempty(os.getenv("ANTIBOT_BACKEND_HOST"))
    _M.flush_interval = opts.flush_interval or DEFAULTS.flush_interval
    _M.batch_max      = opts.batch_max      or DEFAULTS.batch_max
    _M.queue_max      = opts.queue_max      or DEFAULTS.queue_max
    _M.timeout_ms     = opts.timeout_ms     or DEFAULTS.timeout_ms
    _M.path           = opts.path           or DEFAULTS.path
    if opts.ssl_verify ~= nil then
        _M.ssl_verify = opts.ssl_verify
    else
        _M.ssl_verify = truthy_env(os.getenv("ANTIBOT_BACKEND_SSL_VERIFY"), true)
    end

    -- Shares the certificate parsed in the master. With none, the backend
    -- refuses the handshake and it surfaces as a transport error.
    local cp = require "catalog_pull"
    _M.parsed_cert = cp.parsed_cert
    _M.parsed_key  = cp.parsed_key

    -- One warning at startup beats hunting the cause through rate logs later.
    if _M.backend_url:sub(1, 8) == "https://"
        and not (_M.parsed_cert and _M.parsed_key)
    then
        ngx.log(ngx.WARN,
            "log_shipper: backend_url is https:// but mTLS material is absent — ",
            "set ANTIBOT_BACKEND_CLIENT_CERT/KEY or expect handshake failures (",
            "ship_failed_total will grow).")
    end

    if not _M.http_module then
        local ok, mod = pcall(require, "resty.http")
        if not ok then
            ngx.log(ngx.ERR, "log_shipper: resty.http not available: ", tostring(mod))
            return
        end
        _M.http_module = mod
    end

    local function safe_tick(premature)
        local ok, e = pcall(tick, premature)
        if not ok then
            ngx.log(ngx.ERR, "log_shipper: tick raised: ", tostring(e))
            in_flight = false
        end
    end

    local ok, err = ngx.timer.every(_M.flush_interval, safe_tick)
    if not ok then
        ngx.log(ngx.ERR, "log_shipper: ngx.timer.every failed: ", err)
        return
    end
    ngx.log(ngx.NOTICE, "log_shipper: started — backend=", _M.backend_url,
        " flush=", _M.flush_interval, "s batch_max=", _M.batch_max,
        " queue_max=", _M.queue_max,
        _M.parsed_cert and " mTLS=on" or " mTLS=off")
    mark_loaded()
end

return _M
