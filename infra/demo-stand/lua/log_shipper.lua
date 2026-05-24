-- BAC_LOG shipper (edge → antibot-backend /v1/logs).
--
-- Phase 1 receiver на backend (antibot-backend [B6/B7]) уже принимает
-- POST /v1/logs, валидирует JSON-строки и (B7) триггерит rDNS-воркер
-- по IP с поисковым UA. Этот модуль закрывает edge-сторону цепочки:
-- bac_log.emit() в log_by_lua дописывает JSON-строку в per-worker
-- очередь, фоновый ngx.timer.every пулит её батчем и POST'ит на
-- backend через mTLS (тот же cert, что catalog_pull использует для
-- Channel C — переиспользуем pre-parsed _M.parsed_{cert,key}).
--
-- Топология: каждый nginx-worker держит СВОЮ очередь и свой timer.
-- Несколько параллельных POST'ов на backend — нормально для HA-LB;
-- кросс-воркерная shared_dict-очередь добавила бы сериализацию на
-- хот-пасе bac_log.emit() и SPOF на single-worker-shipper'е.
--
-- Fail-stale: backend offline / handshake error / 5xx → батч теряется,
-- метрика `bac_log_ship_failed_total` инкрементируется, edge продолжает
-- обрабатывать запросы. Persistent disk-queue для гарантии «логи не
-- теряются» — отдельная задача [B9] на backend; на edge'е v1 буфер
-- in-memory и при reload nginx пропадает. Это сознательный trade-off
-- vision §"Доставка логов" (приоритет hot-path над логами).
--
-- API:
--   _M.enqueue(line)    — добавить JSON-строку в очередь (горячий путь!)
--   _M.start(opts)      — wire timer.every из init_worker_by_lua_block
--   _M.flush_now()      — синхронный flush для тестов / drain на shutdown
--   _M.queue_size()     — текущая длина очереди (для метрики)

local _M = {}

-- Дефолты — те же по духу, что в catalog_pull.start: nonempty(opts) →
-- nonempty(env) → hard fallback. Шиппер ВЫКЛЮЧЕН, если backend_url не задан
-- (см. start() — без url enqueue превращается в no-op, очередь не растёт).
local DEFAULTS = {
    flush_interval = 1,        -- секунд между tick'ами flush'а
    batch_max      = 1000,     -- максимум строк в одном POST'е
    queue_max      = 10000,    -- ёмкость per-worker очереди (drop-newest на overflow)
    timeout_ms     = 5000,     -- httpc timeout (connect + read)
    path           = "/v1/logs",
}

-- Per-worker состояние. Простой массив + write-index хвоста: append =
-- O(1), drain через `for i=1,#q` + table.clear() аналог. Не используем
-- shared_dict — это per-worker, потому что:
--   1. bac_log.emit() на хот-пасе, регулярные shared_dict.lpush/rpush
--      добавили бы spinlock contention при росте трафика;
--   2. одна очередь на воркера = N POST'ов параллельно в LB, что для
--      демо-стенда (4 worker'a × ~100 RPS) — ноль проблем.
local queue = {}
local in_flight = false  -- guard, чтобы tick'и не пересекались

-- Метрики. Имена — общий стиль antibot_edge_*, чтобы /metrics scrape
-- видел их как обычные prometheus-counter'ы. metrics shared_dict уже
-- объявлен в nginx.demo.conf (1m) и нагружен init.lua (см. ниже —
-- prime через safe_add(0)).
-- Метрики. dropped разнесён на ДВА счётчика, чтобы дашборд различал:
--   _overflow — очередь полная, бэкенд не успевает (реальная нагрузка)
--   _disabled — shipper выключен (ANTIBOT_BACKEND_URL пустой);
--               для оператора это сигнал «трафик идёт, но мы его не
--               доставляем», что концептуально другая ошибка.
-- shipper_loaded — gauge 0/1; init.lua прайнит нулём, start() ставит 1.
-- Без него «module не загрузился из-за syntax-bug в log_shipper.lua»
-- неотличимо от «модуль работает, просто счётчики на нуле».
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

-- enqueue — горячий путь, log_by_lua phase. Возвращает true если
-- строка попала в очередь, false если дропнули (overflow / shipper
-- не инициализирован). Никогда не блокирует, не аллоцирует heavy.
function _M.enqueue(line)
    if not line then return false end
    if line == "" then
        -- Пустая строка из bac_log.emit'a возможна только при
        -- регрессии cjson.encode (она проверяется выше — emit делает
        -- ранний return при encode-fail). Здесь == "" означает баг
        -- в продюсере; WARN'аем, но не падаем — лучше пропустить
        -- одну строку, чем уронить worker'a. PR #54 review.
        ngx.log(ngx.WARN, "log_shipper: enqueue('') — empty line, upstream bug?")
        return false
    end
    if not _M.backend_url then
        -- start() не позвали или backend_url пустой — шиппер выключен.
        -- Инкрементим dropped_disabled (отдельно от dropped_overflow),
        -- чтобы дашборд отличал «shipper выключен» от «очередь полная».
        -- PR #54 codex+self review.
        metric_incr(M_DROPPED_DISABLED)
        return false
    end
    if #queue >= _M.queue_max then
        -- Drop-newest: проще и честнее, чем drop-oldest (старые логи
        -- уже могли быть полезны rDNS-воркеру, более новые — нет ещё).
        metric_incr(M_DROPPED_OVERFLOW)
        return false
    end
    queue[#queue + 1] = line
    metric_incr(M_ENQUEUED)
    return true
end

function _M.queue_size() return #queue end

-- drain_batch — отрезает первые N строк из очереди в новый массив.
-- O(N) на копирование, O(M-N) на смещение хвоста — для batch_max=1000
-- и queue_max=10000 это микросекунды и происходит раз в секунду.
local function drain_batch(n)
    if n > #queue then n = #queue end
    local batch = {}
    for i = 1, n do batch[i] = queue[i] end
    -- shift хвоста: queue[i] := queue[i+n] для i ∈ [1, #queue - n]
    local len = #queue
    for i = 1, len - n do queue[i] = queue[i + n] end
    for i = len - n + 1, len do queue[i] = nil end
    return batch
end

-- requeue_front — на shutdown-drain хотелось бы вернуть необработанный
-- хвост, но при ошибке POST'а это создало бы бесконечный retry-loop
-- (та же причина, по которой backend нет sink-retry — это B9). Поэтому
-- на ошибке отправки батч теряется. v1 trade-off; backend disk-queue
-- закроет его, когда appear.

-- ship — один POST с батчем. Возвращает (ok, err) для логирования.
local function ship(batch)
    local httpc_mod = _M.http_module
    if not httpc_mod then return false, "http module not configured" end
    local httpc = httpc_mod.new()
    httpc:set_timeout(_M.timeout_ms)

    -- Тело — N JSON-строк, разделённые \n. Совпадает с тем, что
    -- backend.logs.Receiver парсит через bufio.Scanner: один JSON
    -- per line, последний line может быть без \n. table.concat
    -- быстрее string.format/`..` для больших N.
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

    -- Нормализуем хвостовой `/` в backend_url: иначе при URL'е "https://h/"
    -- + path "/v1/logs" получим "https://h//v1/logs", который nginx иногда
    -- роутит в другой location. PR #54 gemini review.
    local base = _M.backend_url:gsub("/+$", "")
    local res, err = httpc:request_uri(base .. _M.path, req_opts)
    if not res then return false, "transport: " .. tostring(err) end
    -- backend 202 — единственный успешный код. 413/400 значат «батч
    -- частично битый» — на v1 теряем целиком (backend инкрементит свои
    -- parseErr-метрики, оператор увидит). 5xx — backend упал, ретраить
    -- негде.
    if res.status ~= 202 then
        return false, "status=" .. tostring(res.status)
    end
    return true, nil
end

-- tick — одна итерация фонового flush'а. Защищена pcall'ом из
-- start(); сюда попасть с raise может только через ngx.* API (мало
-- вероятно), но guard обязателен — иначе пропавший тик роняет timer
-- через ngx.timer.every'шный rate-limiter.
local function tick(premature)
    if premature then return end
    if in_flight then
        -- Предыдущий tick ещё в HTTP'е — пропускаем. lua-resty-http
        -- сам не имеет пула, мы создаём new() каждый раз; параллельные
        -- запросы возможны, но смысла плодить TCP'ы нет.
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

-- Синхронный flush для drain'а из тестов. На проде не вызываем —
-- timer.every даёт асинхронный пайплайн.
-- Использует pcall вокруг ship() симметрично tick'у — если ship raise'нет
-- (resty.http throw на битом URL, table.concat на non-string и т.д.),
-- in_flight всё равно сбросится, иначе следующий flush_now вернёт
-- "in_flight" навсегда. PR #54 review.
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

-- start — wire фоновый timer.every из init_worker_by_lua_block.
-- Не привязан к worker 0 (в отличие от catalog_pull): per-worker
-- shipper это by design — у каждого воркера своя очередь. Дёргается
-- одним и тем же путём из nginx.demo.conf, см. init_worker_by_lua_block.
function _M.start(opts)
    opts = opts or {}
    -- shipper_loaded=1 безусловно: gauge показывает, что модуль прошёл
    -- require + start, даже если конфиг ниже выключит трафик. Это
    -- ловит другую ошибку: «log_shipper.lua syntax broken / dep missing»
    -- → init_worker логирует ERR один раз, gauge остаётся 0, метрика
    -- видна оператору без хождения по worker-логам. PR #54 review.
    if ngx.shared.metrics then ngx.shared.metrics:set(M_SHIPPER_LOADED, 1) end

    _M.backend_url = nonempty(opts.backend_url)
                     or nonempty(os.getenv("ANTIBOT_BACKEND_URL"))
    if not _M.backend_url then
        ngx.log(ngx.NOTICE, "log_shipper: ANTIBOT_BACKEND_URL not set — shipper disabled (dropped_disabled будет инкрементить per request)")
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

    -- mTLS: переиспользуем pre-parsed cert/key из catalog_pull —
    -- init.lua уже сделал preload_mtls() в master-фазе, и обе горутины
    -- видят одни и те же cdata-объекты после fork'a. Если cert'ов нет
    -- (cert paths не заданы или parse провалился) — шипим plain HTTPS
    -- и получаем handshake-error от backend, который ловится в ship()
    -- как transport-error → метрика, без падения.
    local cp = require "catalog_pull"
    _M.parsed_cert = cp.parsed_cert
    _M.parsed_key  = cp.parsed_key

    -- Loud signal при https://-url + отсутствующих cert/key: backend под
    -- AUTH_MODE=mtls отвергнет handshake, каждый батч улетит в ship_failed,
    -- и оператор будет искать причину в backend'е. Лучше один WARN на старте,
    -- чем поиск по rate-логам. PR #54 review.
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
end

return _M
