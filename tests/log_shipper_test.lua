-- Unit tests for infra/demo-stand/lua/log_shipper.lua (B6 edge-side).
-- Pure Lua; the HTTP transport is mocked through _M.http_module injection, and
-- ngx through a thin stub (as in catalog_pull_test.lua).
--
-- The cases:
--   1. enqueue before start() — a drop plus a metric, the queue does not grow
--   2. enqueue after start() — it lands in the queue, the metric increments
--   3. queue overflow (queue_max=2) — the third line is dropped
--   4. flush_now: a successful POST → shipped/batches_ok metrics, an empty queue
--   5. flush_now: a non-202 from the backend → the failed metric, an empty queue (the batch is lost)
--   6. flush_now: a transport error → the failed metric
--   7. drain_batch with batch_max=2 at #queue=5 — it cuts the first 2, leaving 3
--   8. enqueue("") — a drop with no metric (an empty string is not counted as a drop)

local cjson_stub = { decode = function(s) return nil, "unused" end, encode = function() return "" end }
package.loaded["cjson.safe"] = cjson_stub

-- ngx stub: shared.metrics (incr/get), ngx.log (silent), ngx.timer (noop),
-- ngx.now (for consistency).
local metrics_store = {}
local ngx_logged = {}
local function reset_state()
    metrics_store = {}
    ngx_logged = {}
end
local shared_dict = {
    incr = function(self, k, by, init)
        metrics_store[k] = (metrics_store[k] or (init or 0)) + by
        return metrics_store[k]
    end,
    get = function(_, k) return metrics_store[k] end,
    set = function(_, k, v) metrics_store[k] = v end,
}
_G.ngx = {
    log = function(_, ...) ngx_logged[#ngx_logged + 1] = table.concat({ ... }, "") end,
    NOTICE = "N", WARN = "W", ERR = "E",
    now = function() return 0 end,
    shared = { metrics = shared_dict },
    timer = { every = function() return true end },
}

-- catalog_pull stub — log_shipper requires it for parsed_cert/key.
package.loaded["catalog_pull"] = { parsed_cert = nil, parsed_key = nil }

-- The httpc mock — driven by the test-controlled `last_response`.
local httpc_response = {}
local last_request = nil
local httpc_mock = {
    new = function()
        return {
            set_timeout = function() end,
            request_uri = function(_, _, opts)
                last_request = opts
                if httpc_response.err then return nil, httpc_response.err end
                return { status = httpc_response.status or 202 }, nil
            end,
        }
    end,
}

-- We load the shipper only after the stubs. We reload it between tests
-- through package.loaded[] = nil, otherwise _M.queue / _M.backend_url
-- would carry state between cases.
local function load_shipper()
    package.loaded["log_shipper"] = nil
    local s = require "log_shipper"
    s.http_module = httpc_mock  -- inject the mock BEFORE start()
    return s
end

local passed, failed = 0, 0
local function expect(cond, name)
    if cond then passed = passed + 1
    else failed = failed + 1; print("FAIL: " .. name) end
end
local function reset_for_test()
    reset_state()
    httpc_response = {}
    last_request = nil
end

-- 1. enqueue before start() — a drop plus a metric (the shipper is off, which is
-- real data loss; the dashboard must tell "no traffic"
-- from "there is traffic but it is not leaving"; from review).
do
    reset_for_test()
    local s = load_shipper()
    local ok = s.enqueue('{"ip":"1.2.3.4"}')
    expect(ok == false, "1: enqueue without start returns false")
    expect(s.queue_size() == 0, "1: the queue is empty")
    expect(metrics_store.bac_log_enqueued_total == nil, "1: enqueued did not move")
    expect(metrics_store.bac_log_dropped_disabled_total == 1, "1: dropped_disabled incremented")
    expect(metrics_store.bac_log_dropped_overflow_total == nil, "1: overflow did not move (this is not the overflow path)")
end

-- 2. enqueue after start() — it lands in the queue
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    local ok = s.enqueue('{"ip":"1.1.1.1"}')
    expect(ok == true, "2: enqueue after start returned true")
    expect(s.queue_size() == 1, "2: queue_size == 1")
    expect(metrics_store.bac_log_enqueued_total == 1, "2: enqueued_total == 1")
end

-- 3. queue overflow — the third line is dropped at queue_max=2
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test", queue_max = 2 })
    expect(s.enqueue("a") == true, "3: the first was accepted")
    expect(s.enqueue("b") == true, "3: the second was accepted")
    expect(s.enqueue("c") == false, "3: the third was dropped")
    expect(s.queue_size() == 2, "3: the queue does not exceed 2")
    expect(metrics_store.bac_log_dropped_overflow_total == 1, "3: dropped_total == 1")
end

-- 4. flush_now: a successful POST → shipped/batches_ok metrics, an empty queue
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    s.enqueue("line1")
    s.enqueue("line2")
    httpc_response.status = 202
    local ok, err = s.flush_now()
    expect(ok == true, "4: flush_now ok")
    expect(err == nil, "4: err nil")
    expect(s.queue_size() == 0, "4: the queue is empty after the flush")
    expect(metrics_store.bac_log_shipped_total == 2, "4: shipped == 2 lines")
    expect(metrics_store.bac_log_batches_ok_total == 1, "4: batches_ok == 1")
    expect(last_request.method == "POST", "4: the method is POST")
    expect(last_request.body == "line1\nline2", "4: the body is \\n-joined")
end

-- 5. flush_now: non-202 → failed
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    s.enqueue("x")
    httpc_response.status = 500
    local ok, err = s.flush_now()
    expect(ok == false, "5: flush_now returned false on a 500")
    expect(err and err:find("status=500"), "5: err describes the 500")
    expect(metrics_store.bac_log_ship_failed_total == 1, "5: failed_total == 1")
    expect(metrics_store.bac_log_shipped_total == nil, "5: shipped did not move")
    expect(s.queue_size() == 0, "5: the batch was NOT returned to the queue (in v1 we lose it)")
end

-- 6. flush_now: transport error
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    s.enqueue("y")
    httpc_response.err = "connection refused"
    local ok, err = s.flush_now()
    expect(ok == false, "6: flush_now returned false on a transport error")
    expect(err and err:find("connection refused"), "6: err carries the transport error")
    expect(metrics_store.bac_log_ship_failed_total == 1, "6: failed_total == 1")
end

-- 7. batch_max cuts the queue
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test", batch_max = 2 })
    s.enqueue("a") s.enqueue("b") s.enqueue("c") s.enqueue("d") s.enqueue("e")
    httpc_response.status = 202
    s.flush_now()
    expect(s.queue_size() == 3, "7: after a batch of 2, three remain in the queue")
    expect(last_request.body == "a\nb", "7: the body is the first two lines")
    expect(metrics_store.bac_log_shipped_total == 2, "7: shipped == batch_max")
end

-- 8a. The shipper_loaded gauge is set to 1 in start() only once the setup
--     completed — either intentionally disabled (an empty URL) or the happy path
--     (the timer plus http_module are ready). The error paths (resty.http missing, a timer
--     failure) leave gauge=0 — the alert catches the silent failure. From review.
do
    reset_for_test()
    local s = load_shipper()
    expect(metrics_store.bac_log_shipper_loaded == nil, "8a: before start the gauge is unset")
    s.start({})  -- with no backend_url — intentionally disabled, the setup completed
    expect(metrics_store.bac_log_shipper_loaded == 1, "8a: intentional disabled → gauge==1")
end

-- 8b. shipper_loaded is NOT set on the error path: resty.http is unavailable and
--     start() returns before timer.every — the gauge stays 0/nil.
do
    reset_for_test()
    -- We do NOT inject httpc_mock through s.http_module — log_shipper.start()
    -- will try pcall(require, "resty.http"). We make the require
    -- fail through a stub package.loaded["resty.http"]=nil and
    -- package.preload["resty.http"]=fail-loader.
    package.loaded["resty.http"] = nil
    package.preload["resty.http"] = function() error("simulated load failure") end
    local s
    do
        package.loaded["log_shipper"] = nil
        s = require "log_shipper"
        -- We do NOT assign s.http_module — let start() take the error path
    end
    s.start({ backend_url = "https://backend/test" })
    expect(metrics_store.bac_log_shipper_loaded == nil
           or metrics_store.bac_log_shipper_loaded == 0,
           "8b: the error path (resty.http missing) does NOT set the gauge")
    package.preload["resty.http"] = nil
end

-- 8. enqueue("") — a drop with no metric (an empty input)
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    local ok = s.enqueue("")
    expect(ok == false, "8: enqueue('') returned false")
    expect(s.queue_size() == 0, "8: the queue does not grow")
    expect(metrics_store.bac_log_dropped_overflow_total == nil, "8: dropped did not move (an empty string is not a drop)")
end

print(string.format("log_shipper: %d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
