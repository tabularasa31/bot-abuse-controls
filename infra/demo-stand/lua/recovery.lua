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

-- Env читаем один раз при загрузке модуля — они не меняются в жизни worker'а
-- (ANTIBOT_BACKEND_URL / DASHBOARD_API_TOKEN — env, разделяются с
-- catalog_pull / log_shipper). Тесты могут переопределить через _M (см.
-- recovery_test.lua), чтобы reset env между кейсами.
local function load_env()
    local url = os.getenv("ANTIBOT_BACKEND_URL")
    if url == nil or url == "" then
        _M.backend_url = nil
    else
        -- nginx.demo.conf принимает URL без trailing slash; добавим путь сами.
        _M.backend_url = (url:gsub("/+$", ""))
    end
    -- Strip control chars (CR/LF/tab) from token: `echo TOKEN >> .env`
    -- leaves a trailing \n, which would land directly in the Bearer
    -- header. Newer lua-resty-http rejects CRLF in header values
    -- (opaque auth failure); older versions could split headers
    -- (request-smuggling shape). Review on PR #88.
    local t = os.getenv("DASHBOARD_API_TOKEN")
    if t then t = (t:gsub("%c", "")) end
    -- Не пишем как `(t == nil or t == "") and nil or t` — это Lua-trap:
    -- `true and nil` = nil, и затем `nil or t` снова возвращает t (т.е. ""),
    -- из-за чего токен после стрипа из «\n\n» приезжал бы пустой строкой,
    -- а не nil. call_backend проверяет именно nil, так что критично.
    if t == nil or t == "" then
        _M.api_token = nil
    else
        _M.api_token = t
    end
    local s = os.getenv("ANTIBOT_BACKEND_SSL_VERIFY")
    _M.ssl_verify = (s ~= "false")
    return _M
end
_M.load_env = load_env
load_env()

-- [C6 security gate] ADMIN_ACL_CIDR — комма-разделённый список CIDR, кому
-- разрешено вызывать /__admin/recover_ip. Unset/пусто → fail-closed (403 на
-- все запросы). Это не настоящий auth, а network ACL уровня nginx-в-Lua:
-- /__admin сам сейчас публичен на демо-VM, поэтому без gate'а атакующий
-- мог бы whitelist'нуть свой IP на любой защищаемый host. Оператор VM
-- ставит свой публичный IP (или /24-блок офиса) в .env. Парсим один раз
-- при загрузке через lua-resty-ipmatcher (паттерн reputation.lua).
local function build_admin_matcher()
    local raw = os.getenv("ADMIN_ACL_CIDR") or ""
    if raw == "" then return nil end
    local cidrs = {}
    for c in raw:gmatch("[^,%s]+") do cidrs[#cidrs + 1] = c end
    if #cidrs == 0 then return nil end
    local ok, ipmatcher = pcall(require, "resty.ipmatcher")
    if not ok then return nil end
    local m, err = ipmatcher.new(cidrs)
    if not m then
        ngx.log(ngx.ERR, "[C6] ADMIN_ACL_CIDR parse failed: ", err,
            " (input=", raw, ") — recovery endpoint fail-closed")
        return nil
    end
    return m
end
_M.admin_matcher = build_admin_matcher()

local function client_allowed(remote_addr)
    if not _M.admin_matcher then return false end
    if not remote_addr or remote_addr == "" then return false end
    local ok = _M.admin_matcher:match(remote_addr)
    return ok and true or false
end
_M.client_allowed = client_allowed

-- Валидация host. Бэкенд `siteRE` (antibotapi/validate.go) — строгий
-- RFC 1123 LDH per-label валидатор; раньше HOST_RE здесь был куда laxer
-- (`%w` в Lua включает `_`, плюс пропускал `a..b` / `a.` / `a-`), и
-- backend заворачивал такие host'ы 400 → operator видел невнятное
-- «backend returned 400» вместо чёткой локальной ошибки (review on PR
-- #88). Каждый label = `[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?`,
-- разделены ровно одной точкой, no leading/trailing hyphen, no trailing
-- dot, no consecutive dots, no underscores.
--
-- NB: Lua patterns не поддерживают `?` после группы; делаем покомпонентно
-- — single-char label = `^[%w]$`, multi-char = `^[%w][%w%-]*[%w]$`.
-- `%w` включает `_`, поэтому отдельный find на `_` всё ещё нужен.
local function valid_label(label)
    local n = #label
    if n == 0 or n > 63 then return false end
    if n == 1 then return label:match("^[%w]$") ~= nil end
    return label:match("^[%w][%w%-]*[%w]$") ~= nil
end

local function validate_host(h)
    if type(h) ~= "string" or #h == 0 or #h > 253 then
        return "host must be a non-empty hostname"
    end
    -- Lua `%w` matches `_` — RFC 1123 hostnames don't allow underscore.
    if h:find("_", 1, true) then
        return "host has invalid characters"
    end
    -- Leading/trailing dot + consecutive dots отсекаем явно (gmatch скрыл бы их).
    if h:sub(1, 1) == "." or h:sub(-1) == "." or h:find("..", 1, true) then
        return "host has invalid characters"
    end
    for label in h:gmatch("[^.]+") do
        if not valid_label(label) then
            return "host has invalid characters"
        end
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
    if not _M.backend_url then
        return false, nil, "ANTIBOT_BACKEND_URL not configured"
    end
    if not _M.api_token then
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
        _M.backend_url .. "/antibot/v1/policy/" .. host .. "/ip_whitelist",
        {
            method  = "POST",
            body    = body,
            headers = {
                ["Authorization"] = "Bearer " .. _M.api_token,
                ["Content-Type"]  = "application/json",
            },
            -- ssl_verify контролируется тем же флагом, что и catalog_pull —
            -- демо-бэкенд обычно self-signed на side-VM.
            ssl_verify = _M.ssl_verify,
        })
    if not res then
        return false, nil, "transport error: " .. tostring(err)
    end
    if res.status ~= 200 then
        return false, { status = res.status, body = res.body },
            "backend returned " .. tostring(res.status)
    end
    -- cjson.decode на `null`/число/пустой ответ возвращает userdata/scalar,
    -- который truthy в Lua → `decoded or {}` пропустил бы non-table и
    -- info.changed позже крашнул бы handle() с «attempt to index userdata».
    -- Гарантируем table-результат явно (review on PR #88).
    local decoded = cjson.decode(res.body or "")
    if type(decoded) ~= "table" then decoded = {} end
    return true, decoded, nil
end

_M.call_backend = call_backend

-- HTTP-handler. Подключается в nginx.demo.conf как
-- `content_by_lua_block { require("recovery").handle() }`.
function _M.handle()
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.header.cache_control = "no-store"

    -- [C6 security gate] ACL-проверка идёт ПЕРВОЙ — перед методом, телом,
    -- env'ами. /__admin на демо публичен, без этого gate'а любой клиент
    -- мог бы POST'ом whitelist'нуть свой IP на чужой защищаемый host
    -- (codex P1 review on PR #88). Unset ADMIN_ACL_CIDR → fail-closed.
    if not client_allowed(ngx.var.remote_addr) then
        ngx.status = 403
        ngx.log(ngx.WARN, "[C6] recovery: denied ", ngx.var.remote_addr,
            " (ADMIN_ACL_CIDR ", (_M.admin_matcher and "set" or "unset"), ")")
        ngx.say('{"error":"forbidden"}')
        return
    end

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
        -- Status mapping (review on PR #88): раньше любой 4xx коллапсился в
        -- 400 — operator/monitor видели «bad request» при том, что причина
        -- была серверная (401 stale token, 403 ACL, 404 unknown route). 401
        -- /403/404/409/410 — это НЕ ошибка операторского ввода, это server
        -- /config-side, мапим в 502 («плохой ответ от upstream»). 400/422
        -- — настоящая ошибка ввода (backend ValidateCIDR/ValidateSite не
        -- пропустил), мапим в 400.
        local bs = info and info.status
        if bs == 400 or bs == 422 then
            ngx.status = 400
        else
            ngx.status = 502
        end
        local cjson = require "cjson.safe"
        ngx.say(cjson.encode({
            error    = err,
            host     = host,
            cidr     = cidr,
            backend  = info,
        }))
        return
    end

    -- Backend контракт: 200 с {"changed": bool}. Если поля нет (regression
    -- /протокол-drift), не врём UI «already whitelisted» (JS трактует null
    -- как false → ✗); сигналим явно 502 'protocol_error', чтобы оператор
    -- увидел проблему, а не молча принял на веру (review on PR #88).
    if type(info.changed) ~= "boolean" then
        ngx.status = 502
        ngx.log(ngx.ERR, "[C6] recovery: backend 200 without changed:bool ",
            "for host=", host, " cidr=", cidr, " (contract drift)")
        local cjson = require "cjson.safe"
        ngx.say(cjson.encode({
            error    = "backend_protocol_error",
            detail   = "missing or non-boolean 'changed' in 200 response",
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
