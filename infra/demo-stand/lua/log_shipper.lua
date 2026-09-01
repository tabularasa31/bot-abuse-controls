-- Ships the request log from the edge to the backend receiver.
--
-- bac_log.emit appends a JSON line to a per-worker queue, and a background timer
-- drains it as a batch over mTLS, reusing the certificate the catalog pull
-- already parsed.
--
-- Every worker keeps its own queue and its own timer: several parallel POSTs
-- are fine for the load balancer, whereas a shared queue would put contention
-- on the hot path of every request and make a single worker a bottleneck.
--
-- Fail-stale. If the backend is unreachable the batch is dropped, a counter
-- increments, and the edge keeps serving. The buffer is in memory and does not
-- survive a reload — the hot path takes priority over the logs.

local _M = {}

-- The defaults follow the same spirit as catalog_pull.start: nonempty(opts) →
-- nonempty(env) → a hard fallback. The shipper is DISABLED when backend_url is unset
-- (see start() — with no url, enqueue becomes a no-op and the queue does not grow).
local DEFAULTS = {
    flush_interval = 1,        -- seconds between flush ticks
    batch_max      = 1000,     -- the maximum lines in one POST
    queue_max      = 10000,    -- the per-worker queue capacity (drop-newest on overflow)
    timeout_ms     = 5000,     -- httpc timeout (connect + read)
    path           = "/v1/logs",
}

-- An array plus a write index: appending is O(1) and draining is a single pass.
-- Deliberately not a shared_dict, whose locking would land on the hot path of
-- every request.
local queue = {}
local in_flight = false  -- a guard so that ticks do not overlap

-- Drops are split in two: overflow means the backend cannot keep up, disabled
-- means the shipper was never configured. They look identical in a total and
-- mean completely different things to an operator.
--
-- shipper_loaded exists so that "the module failed to load" is distinguishable
-- from "the module works and the counters are simply zero".
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

-- enqueue — the hot path, the log_by_lua phase. It returns true if the
-- line made it into the queue, false if it was dropped (overflow / the shipper
-- is not initialised). It never blocks and allocates nothing heavy.
function _M.enqueue(line)
    if not line then return false end
    if line == "" then
        -- Only reachable through a producer bug. Skip the line rather than
        -- taking the worker down.
        ngx.log(ngx.WARN, "log_shipper: enqueue('') — empty line, upstream bug?")
        return false
    end
    if not _M.backend_url then
        -- start() was never called or backend_url is empty — the shipper is off.
        -- We increment dropped_disabled (separately from dropped_overflow),
        -- so that the dashboard tells "the shipper is off" from "the queue is full".
        metric_incr(M_DROPPED_DISABLED)
        return false
    end
    if #queue >= _M.queue_max then
        -- Drop-newest: simpler and more honest than drop-oldest (the older logs
        -- may already have been useful to the rDNS worker, the newer ones not yet).
        metric_incr(M_DROPPED_OVERFLOW)
        return false
    end
    queue[#queue + 1] = line
    metric_incr(M_ENQUEUED)
    return true
end

function _M.queue_size() return #queue end

-- drain_batch — cuts the first N lines out of the queue into a new array.
-- O(N) to copy plus O(M-N) to shift the tail — for batch_max=1000
-- and queue_max=10000 that is microseconds, once a second.
local function drain_batch(n)
    if n > #queue then n = #queue end
    local batch = {}
    for i = 1, n do batch[i] = queue[i] end
    -- shifting the tail: queue[i] := queue[i+n] for i ∈ [1, #queue - n]
    local len = #queue
    for i = 1, len - n do queue[i] = queue[i + n] end
    for i = len - n + 1, len do queue[i] = nil end
    return batch
end

-- Deliberately absent: requeueing on a send error would spin into an endless
-- retry loop, so a failed batch is dropped.

-- ship — one POST with a batch. It returns (ok, err) for logging.
local function ship(batch)
    local httpc_mod = _M.http_module
    if not httpc_mod then return false, "http module not configured" end
    local httpc = httpc_mod.new()
    httpc:set_timeout(_M.timeout_ms)

    -- The body is N JSON lines separated by \n. It matches what
    -- backend.logs.Receiver parses through bufio.Scanner: one JSON
    -- per line, and the last line may lack a \n. table.concat
    -- is faster than string.format or `..` for large N.
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

    -- We normalise a trailing `/` in backend_url: otherwise a URL of "https://h/"
    -- plus the path "/v1/logs" gives "https://h//v1/logs", which nginx sometimes
    -- routes to a different location.
    local base = _M.backend_url:gsub("/+$", "")
    local res, err = httpc:request_uri(base .. _M.path, req_opts)
    if not res then return false, "transport: " .. tostring(err) end
    -- A backend 202 is the only success code. 413/400 mean "the batch is
    -- partly broken" — in v1 we lose it entirely (the backend increments its own
    -- parseErr metrics and the operator sees them). A 5xx means the backend is down and there is
    -- nowhere to retry.
    if res.status ~= 202 then
        return false, "status=" .. tostring(res.status)
    end
    return true, nil
end

-- tick — one iteration of the background flush. It is protected by a pcall from
-- start(); reaching here with a raise is only possible through the ngx.* API (unlikely),
-- but the guard is mandatory — otherwise a lost tick kills the timer
-- through ngx.timer.every's rate limiter.
local function tick(premature)
    if premature then return end
    if in_flight then
        -- The previous tick is still in HTTP — we skip. lua-resty-http
        -- has no pool of its own and we call new() every time; parallel
        -- requests are possible, but there is no point multiplying TCP connections.
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

-- For tests. The pcall matters: without it a raise would leave in_flight set
-- and every later flush would refuse to run.
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

-- Runs in every worker, unlike the catalog pull: each has its own queue.
--
-- The loaded gauge is set only where setup actually completed — either
-- deliberately disabled, or fully wired. An error path leaves it at zero, which
-- is what tells the operator the failure was silent.
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

    -- Reuses the certificate parsed in the master, so both routines share the
    -- same objects after the fork. With none, the backend refuses the handshake
    -- and that surfaces as an ordinary transport error.
    local cp = require "catalog_pull"
    _M.parsed_cert = cp.parsed_cert
    _M.parsed_key  = cp.parsed_key

    -- A loud signal for an https:// url with missing cert/key: a backend under
    -- AUTH_MODE=mtls will reject the handshake, every batch will fly into ship_failed,
    -- and the operator will hunt for the cause on the backend. Better one WARN at startup
    -- than a search through rate logs.
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
