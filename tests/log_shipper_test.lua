-- Unit tests for infra/demo-stand/lua/log_shipper.lua (B6 edge-side).
-- Pure Lua; HTTP transport замокан через _M.http_module-инжекцию,
-- ngx — через тонкий stub (как в catalog_pull_test.lua).
--
-- Кейсы:
--   1. enqueue до start() — drop + метрика, очередь не растёт
--   2. enqueue после start() — попадает в очередь, метрика инкрементится
--   3. queue overflow (queue_max=2) — третья строка дропается
--   4. flush_now: успешный POST → shipped/batches_ok метрики, queue пустой
--   5. flush_now: backend non-202 → failed метрика, queue пустой (батч потерян)
--   6. flush_now: transport error → failed метрика
--   7. drain_batch с batch_max=2 при #queue=5 — режет первые 2, остаётся 3
--   8. enqueue("") — drop без метрики (пустая строка — не drop'ается)

local cjson_stub = { decode = function(s) return nil, "unused" end, encode = function() return "" end }
package.loaded["cjson.safe"] = cjson_stub

-- ngx stub: shared.metrics (incr/get), ngx.log (silent), ngx.timer (noop),
-- ngx.now (для consistency).
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

-- httpc mock — управляется через test-controlled `last_response`.
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

-- Загружаем shipper только после стабов. Перезагружаем между тестами
-- через package.loaded[] = nil, иначе _M.queue / _M.backend_url
-- сохранят состояние между кейсами.
local function load_shipper()
    package.loaded["log_shipper"] = nil
    local s = require "log_shipper"
    s.http_module = httpc_mock  -- инжектим мок ДО start()
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

-- 1. enqueue до start() — drop + метрика (shipper выключен — это
-- реальная потеря данных, дашборд должен отличать «нет трафика»
-- от «трафик есть, но не уезжает»; PR #54 codex review).
do
    reset_for_test()
    local s = load_shipper()
    local ok = s.enqueue('{"ip":"1.2.3.4"}')
    expect(ok == false, "1: enqueue без start возвращает false")
    expect(s.queue_size() == 0, "1: очередь пустая")
    expect(metrics_store.bac_log_enqueued_total == nil, "1: enqueued не двинулся")
    expect(metrics_store.bac_log_dropped_total == 1, "1: dropped инкрементирован")
end

-- 2. enqueue после start() — попадает в очередь
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    local ok = s.enqueue('{"ip":"1.1.1.1"}')
    expect(ok == true, "2: enqueue после start вернул true")
    expect(s.queue_size() == 1, "2: queue_size == 1")
    expect(metrics_store.bac_log_enqueued_total == 1, "2: enqueued_total == 1")
end

-- 3. queue overflow — третья строка дропается при queue_max=2
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test", queue_max = 2 })
    expect(s.enqueue("a") == true, "3: первая принята")
    expect(s.enqueue("b") == true, "3: вторая принята")
    expect(s.enqueue("c") == false, "3: третья дропнута")
    expect(s.queue_size() == 2, "3: queue не превышает 2")
    expect(metrics_store.bac_log_dropped_total == 1, "3: dropped_total == 1")
end

-- 4. flush_now: успешный POST → shipped/batches_ok метрики, queue пустой
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
    expect(s.queue_size() == 0, "4: очередь пустая после flush")
    expect(metrics_store.bac_log_shipped_total == 2, "4: shipped == 2 строки")
    expect(metrics_store.bac_log_batches_ok_total == 1, "4: batches_ok == 1")
    expect(last_request.method == "POST", "4: метод POST")
    expect(last_request.body == "line1\nline2", "4: тело — \\n-joined")
end

-- 5. flush_now: non-202 → failed
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    s.enqueue("x")
    httpc_response.status = 500
    local ok, err = s.flush_now()
    expect(ok == false, "5: flush_now вернул false на 500")
    expect(err and err:find("status=500"), "5: err описывает 500")
    expect(metrics_store.bac_log_ship_failed_total == 1, "5: failed_total == 1")
    expect(metrics_store.bac_log_shipped_total == nil, "5: shipped не двинулся")
    expect(s.queue_size() == 0, "5: батч НЕ возвращён в очередь (v1 теряем)")
end

-- 6. flush_now: transport error
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    s.enqueue("y")
    httpc_response.err = "connection refused"
    local ok, err = s.flush_now()
    expect(ok == false, "6: flush_now вернул false на transport err")
    expect(err and err:find("connection refused"), "6: err содержит транспортную ошибку")
    expect(metrics_store.bac_log_ship_failed_total == 1, "6: failed_total == 1")
end

-- 7. batch_max режет очередь
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test", batch_max = 2 })
    s.enqueue("a") s.enqueue("b") s.enqueue("c") s.enqueue("d") s.enqueue("e")
    httpc_response.status = 202
    s.flush_now()
    expect(s.queue_size() == 3, "7: после батча на 2 в очереди осталось 3")
    expect(last_request.body == "a\nb", "7: тело — первые две строки")
    expect(metrics_store.bac_log_shipped_total == 2, "7: shipped == batch_max")
end

-- 8. enqueue("") — drop без метрики (пустая входная)
do
    reset_for_test()
    local s = load_shipper()
    s.start({ backend_url = "https://backend/test" })
    local ok = s.enqueue("")
    expect(ok == false, "8: enqueue('') вернул false")
    expect(s.queue_size() == 0, "8: очередь не растёт")
    expect(metrics_store.bac_log_dropped_total == nil, "8: dropped не двинулся (пустая строка — не drop)")
end

print(string.format("log_shipper: %d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
