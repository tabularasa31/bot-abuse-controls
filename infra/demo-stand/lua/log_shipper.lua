-- BAC_LOG shipper (edge → antibot-backend /v1/logs).
--
-- The Phase 1 receiver on the backend (antibot-backend [B6/B7]) already accepts
-- POST /v1/logs, validates the JSON lines and (B7) triggers the rDNS worker
-- for IPs with a search engine UA. This module closes the edge side of the chain:
-- bac_log.emit() in log_by_lua appends a JSON line to a per-worker
-- queue, and a background ngx.timer.every pulls it as a batch and POSTs it to the
-- backend over mTLS (the same certificate catalog_pull uses for
-- Channel C — we reuse the pre-parsed _M.parsed_{cert,key}).
--
-- Topology: every nginx worker keeps ITS OWN queue and its own timer.
-- Several parallel POSTs to the backend are fine for an HA load balancer;
-- a cross-worker shared_dict queue would add serialisation on the
-- hot path of bac_log.emit() plus a single point of failure in a single-worker shipper.
--
-- Fail-stale: with the backend offline / a handshake error / a 5xx, the batch is lost, the
-- `bac_log_ship_failed_total` metric increments, and the edge keeps
-- handling requests. A persistent disk queue to guarantee "logs are never
-- lost" is a separate backend task [B9]; on the edge, v1 keeps the buffer
-- in memory and it disappears on an nginx reload. That is a deliberate trade-off from
-- vision §"Log delivery" (the hot path takes priority over logs).
--
-- API:
--   _M.enqueue(line)    — add a JSON line to the queue (the hot path!)
--   _M.start(opts)      — wire timer.every from init_worker_by_lua_block
--   _M.flush_now()      — a synchronous flush for tests / a drain on shutdown
--   _M.queue_size()     — the current queue length (for the metric)

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

-- Per-worker state. A simple array plus a write index for the tail: an append is
-- O(1), and the drain is `for i=1,#q` plus a table.clear() equivalent. We do not use a
-- shared_dict — this is per worker, because:
--   1. bac_log.emit() is on the hot path, and regular shared_dict lpush/rpush
--      would add spinlock contention as traffic grows;
--   2. one queue per worker means N parallel POSTs into the load balancer, which for the
--      demo stand (4 workers × ~100 RPS) is a non-issue.
local queue = {}
local in_flight = false  -- a guard so that ticks do not overlap

-- Metrics. The names follow the shared antibot_edge_* style, so that a /metrics scrape
-- sees them as ordinary prometheus counters. The metrics shared_dict is already
-- declared in nginx.demo.conf (1m) and loaded by init.lua (see below —
-- primed through safe_add(0)).
-- Metrics. dropped is split into TWO counters so that the dashboard can distinguish:
--   _overflow — the queue is full and the backend cannot keep up (real load)
--   _disabled — the shipper is off (ANTIBOT_BACKEND_URL is empty);
--               for an operator that signals "traffic is flowing but we are not
--               delivering it", which is conceptually a different error.
-- shipper_loaded — a 0/1 gauge; init.lua primes it with zero and start() sets 1.
-- Without it, "the module did not load because of a syntax bug in log_shipper.lua"
-- is indistinguishable from "the module works, the counters are simply at zero".
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
        -- An empty string from bac_log.emit is possible only on a
        -- cjson.encode regression (which is checked above — emit returns
        -- early on an encode failure). Here == "" means a bug
        -- in the producer; we WARN but do not fail — better to skip
        -- one line than to take the worker down. From review.
        ngx.log(ngx.WARN, "log_shipper: enqueue('') — empty line, upstream bug?")
        return false
    end
    if not _M.backend_url then
        -- start() was never called or backend_url is empty — the shipper is off.
        -- We increment dropped_disabled (separately from dropped_overflow),
        -- so that the dashboard tells "the shipper is off" from "the queue is full".
        -- PR #54 codex+self review.
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

-- requeue_front — on a shutdown drain it would be nice to return the unprocessed
-- tail, but on a POST error that would create an endless retry loop
-- (the same reason the backend has no sink retry — that is B9). So
-- on a send error the batch is lost. A v1 trade-off; the backend disk queue
-- will close it when it appears.

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
    -- routes to a different location. From review.
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

-- A synchronous flush for draining from tests. We never call it in production —
-- timer.every gives an asynchronous pipeline.
-- It uses a pcall around ship() symmetrically with the tick — if ship raises
-- (resty.http throwing on a broken URL, table.concat on a non-string and so on),
-- in_flight is still reset, otherwise the next flush_now would return
-- "in_flight" forever. From review.
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

-- start — wire the background timer.every from init_worker_by_lua_block.
-- It is not pinned to worker 0 (unlike catalog_pull): a per-worker
-- shipper is by design — every worker has its own queue. It is invoked
-- through the same path from nginx.demo.conf, see init_worker_by_lua_block.
-- mark_loaded — we set the gauge ONLY on paths where start() really
-- completed its setup successfully: either "backend_url is empty and we deliberately
-- started nothing" (intentionally disabled — the module works and
-- enqueue correctly counts dropped_disabled), or "the timer plus the http
-- module plus the mTLS snapshot are ready" (the full happy path). The error paths
-- (a resty.http require failure, an ngx.timer.every failure) do NOT set the
-- gauge — the operator sees loaded=0 and is alerted to the silent failure.
-- From self-review (setting the gauge before the setup was a bug — the contract in
-- metrics.lua says "the module plus its dependencies are OK").
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

    -- mTLS: we reuse the pre-parsed cert/key from catalog_pull —
    -- init.lua already called preload_mtls() in the master phase, and both routines
    -- see the same cdata objects after the fork. If there are no certificates
    -- (the cert paths are unset or parsing failed) we ship plain HTTPS
    -- and get a handshake error from the backend, which ship() catches
    -- as a transport error → a metric, with no crash.
    local cp = require "catalog_pull"
    _M.parsed_cert = cp.parsed_cert
    _M.parsed_key  = cp.parsed_key

    -- A loud signal for an https:// url with missing cert/key: a backend under
    -- AUTH_MODE=mtls will reject the handshake, every batch will fly into ship_failed,
    -- and the operator will hunt for the cause on the backend. Better one WARN at startup
    -- than a search through rate logs. From review.
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
