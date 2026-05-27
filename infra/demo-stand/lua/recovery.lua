-- [C6] False-positive recovery loop — мутационный endpoint /__admin/recover_ip.
--
-- На демо роль «дашборд клиента» исполняет /__admin: в нём виден блок,
-- одна кнопка добавляет IP в per-resource ip_whitelist через настоящий
-- Policy API бэкенда (B10), и через ≤30с тот же запрос фастпасит на L2.3.
-- Это единственная mutating-поверхность стенда; всё остальное в /__admin —
-- read-only. На проде эту операцию делает дашборд по тому же API, эдж
-- участвует только как читатель каталога policy.
--
-- Что НЕ делаем:
--   * Не пишем в антибот-DB напрямую и не трогаем shared_dict antibot_policy.
--     Изменение проезжает: edge POST → backend Policy API → DB → reloader
--     ≤5с → /catalog/policy ETag-change → edge catalog_pull ≤30с → swap.
--   * Не валидируем IP/host «по уму» — это работа backend.ValidateCIDR.
--     Здесь только дешёвые guard'ы (длина/пустота/обязательность), чтобы
--     не звать backend на заведомо мусорном вводе.
--   * Не делаем GET — endpoint только POST.

local _M = {}

-- Инжектируется в тестах (см. catalog_pull / log_shipper паттерн). Прод-путь:
-- lazy require "resty.http" внутри _call_backend.
_M.http_module = nil

-- Бэкенд-URL читаем один раз — он не меняется в течение жизни worker'а
-- (ANTIBOT_BACKEND_URL — env, разделяется с catalog_pull / log_shipper).
local function backend_url()
    local url = os.getenv("ANTIBOT_BACKEND_URL")
    if url == nil or url == "" then return nil end
    -- nginx.demo.conf принимает URL без trailing slash; добавим путь сами.
    return (url:gsub("/+$", ""))
end

local function api_token()
    local t = os.getenv("DASHBOARD_API_TOKEN")
    if t == nil or t == "" then return nil end
    return t
end

-- Валидация host (минимальная). Бэкенд per-resource policy keyed by host,
-- так что мусорный host создаст там пустую запись — нам это не надо.
local HOST_RE = "^[%w][%w%-%.]*$"
local function validate_host(h)
    if type(h) ~= "string" or #h == 0 or #h > 253 then
        return "host must be a non-empty hostname"
    end
    if not h:match(HOST_RE) then
        return "host has invalid characters"
    end
    return nil
end

-- Валидация IP (минимальная — формат CIDR проверит backend.ValidateCIDR).
-- Отсекаем только явный мусор: пустоту, whitespace, слишком длинное.
local function validate_ip(ip)
    if type(ip) ~= "string" or #ip == 0 or #ip > 45 then
        return "ip must be non-empty (IPv4 or IPv6 literal)"
    end
    if ip:find("[%s/]") then
        return "ip must be a literal, not CIDR (suffix added server-side)"
    end
    return nil
end

-- Превращаем литерал в /32 (v4) или /128 (v6).
local function to_cidr(ip)
    if ip:find(":", 1, true) then return ip .. "/128" end
    return ip .. "/32"
end

-- Парсинг тела. cjson.safe не падает на мусоре. Только два поля: host, ip.
local function parse_body(raw)
    if not raw or raw == "" then
        return nil, nil, "empty body"
    end
    local cjson = require "cjson.safe"
    local decoded = cjson.decode(raw)
    if type(decoded) ~= "table" then
        return nil, nil, "body must be a JSON object"
    end
    return decoded.host, decoded.ip, nil
end

_M.parse_body    = parse_body
_M.validate_host = validate_host
_M.validate_ip   = validate_ip
_M.to_cidr       = to_cidr

-- POST /antibot/v1/policy/<host>/ip_whitelist с {cidr: "<ip>/32"}.
-- Возвращает (ok, info, err). info = backend JSON-ответ (раскодированный)
-- или nil при сетевой ошибке.
local function call_backend(host, cidr)
    local base = backend_url()
    if not base then
        return false, nil, "ANTIBOT_BACKEND_URL not configured"
    end
    local token = api_token()
    if not token then
        return false, nil, "DASHBOARD_API_TOKEN not configured"
    end

    if not _M.http_module then
        local ok, mod = pcall(require, "resty.http")
        if not ok then
            return false, nil, "lua-resty-http not available"
        end
        _M.http_module = mod
    end
    local httpc = _M.http_module.new()
    httpc:set_timeout(5000)  -- 5с, как в log_shipper

    local cjson = require "cjson.safe"
    local body = cjson.encode({ cidr = cidr })
    local res, err = httpc:request_uri(
        base .. "/antibot/v1/policy/" .. host .. "/ip_whitelist",
        {
            method  = "POST",
            body    = body,
            headers = {
                ["Authorization"] = "Bearer " .. token,
                ["Content-Type"]  = "application/json",
            },
            -- ssl_verify контролируется тем же флагом, что и catalog_pull —
            -- демо-бэкенд обычно self-signed на side-VM.
            ssl_verify = (os.getenv("ANTIBOT_BACKEND_SSL_VERIFY") ~= "false"),
        })
    if not res then
        return false, nil, "transport error: " .. tostring(err)
    end
    if res.status ~= 200 then
        return false, { status = res.status, body = res.body },
            "backend returned " .. tostring(res.status)
    end
    local decoded = cjson.decode(res.body or "")
    return true, decoded or {}, nil
end

_M.call_backend = call_backend

-- HTTP-handler. Подключается в nginx.demo.conf как
-- `content_by_lua_block { require("recovery").handle() }`.
function _M.handle()
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.header.cache_control = "no-store"

    if ngx.req.get_method() ~= "POST" then
        ngx.status = 405
        ngx.header["Allow"] = "POST"
        ngx.say('{"error":"method_not_allowed"}')
        return
    end

    ngx.req.read_body()
    local raw = ngx.req.get_body_data() or ""
    local host, ip, perr = parse_body(raw)
    if perr then
        ngx.status = 400
        ngx.say('{"error":"', perr, '"}')
        return
    end
    local herr = validate_host(host)
    if herr then
        ngx.status = 400
        ngx.say('{"error":"', herr, '"}')
        return
    end
    local ierr = validate_ip(ip)
    if ierr then
        ngx.status = 400
        ngx.say('{"error":"', ierr, '"}')
        return
    end

    local cidr = to_cidr(ip)
    local ok, info, err = call_backend(host, cidr)
    if not ok then
        -- 502 — мы прокси к backend; backend недоступен/ответил не-200.
        ngx.status = (info and info.status and info.status >= 400 and info.status < 500) and 400 or 502
        local cjson = require "cjson.safe"
        ngx.say(cjson.encode({
            error    = err,
            host     = host,
            cidr     = cidr,
            backend  = info,
        }))
        return
    end

    -- Лог в error.log (NOTICE) — на демо это единственный audit.
    -- На проде «кто кликнул» пишет дашборд; у нас актор — оператор за /__admin.
    ngx.log(ngx.NOTICE,
        "[C6] recovery whitelist host=", host, " cidr=", cidr,
        " changed=", tostring(info.changed))

    local cjson = require "cjson.safe"
    ngx.say(cjson.encode({
        ok       = true,
        host     = host,
        cidr     = cidr,
        changed  = info.changed,
        -- SLA окно: ≤30с (vision §5.2). Не на стороне эджа — для UI-подсказки.
        propagation_seconds = 30,
    }))
end

return _M
