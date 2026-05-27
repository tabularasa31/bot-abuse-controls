-- Unit tests for infra/demo-stand/lua/recovery.lua (C6 FP recovery loop).
-- Pure Lua под host luajit: HTTP замокан через _M.http_module-инжекцию
-- (паттерн из log_shipper_test / catalog_pull_test); ngx — тонкий stub.
--
-- Покрытие:
--   * parse_body: пустое / не-JSON / без полей / валидное тело
--   * validate_host: пустота / длина / запрещённые символы / happy
--   * validate_ip: пустота / whitespace / CIDR-suffix / длина / happy
--   * to_cidr: IPv4 → /32, IPv6 → /128
--   * call_backend: успех / non-200 backend / отсутствие URL / отсутствие токена /
--                   transport error / правильные header'ы и path

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

-- Реальный cjson.safe из openresty в host-luajit недоступен; ставим стаб.
local function json_encode(t)
    -- Хватает для тестов: ровно те поля, что мы шлём (cidr).
    local parts = {}
    for k, v in pairs(t) do
        parts[#parts + 1] = '"' .. tostring(k) .. '":"' .. tostring(v) .. '"'
    end
    return "{" .. table.concat(parts, ",") .. "}"
end
local function json_decode(s)
    if type(s) ~= "string" or s == "" then return nil end
    if s:sub(1, 1) ~= "{" then return nil end
    local out = {}
    -- ОЧЕНЬ примитивный парсер «"k":"v"|true|false|<num>» для теста.
    -- Хватает на наши кейсы (host, ip, changed).
    for k, v in s:gmatch('"([%w_]+)"%s*:%s*"([^"]+)"') do out[k] = v end
    for k, v in s:gmatch('"([%w_]+)"%s*:%s*(true)') do out[k] = (v == "true") end
    for k, v in s:gmatch('"([%w_]+)"%s*:%s*(false)') do out[k] = (v == "true") end
    return out
end
package.loaded["cjson.safe"] = { encode = json_encode, decode = json_decode }

-- ngx stub: только то, что recovery.call_backend трогает. handle() здесь не
-- тестируем (требует ngx.req / ngx.say мок — отдельный плюс минимум смысла).
_G.ngx = {
    log = function() end,
    NOTICE = "N", WARN = "W", ERR = "E",
}

-- httpc mock с контролем ответа.
local httpc_response = {}
local last_request = nil
local httpc_mock = {
    new = function()
        return {
            set_timeout = function() end,
            request_uri = function(_, uri, opts)
                last_request = { url = uri, opts = opts }
                if httpc_response.err then return nil, httpc_response.err end
                return {
                    status = httpc_response.status or 200,
                    body   = httpc_response.body or "",
                }, nil
            end,
        }
    end,
}

-- Env override: recovery читает os.getenv ОДИН РАЗ при загрузке модуля
-- (плюс через _M.load_env по требованию), так что в тестах подменяем
-- globally + перезагружаем модуль между кейсами.
local env_override = {}
local real_getenv = os.getenv
rawset(os, "getenv", function(k)
    if env_override[k] ~= nil then return env_override[k] end
    return real_getenv(k)
end)

-- resty.ipmatcher mock — луажит без openresty не имеет нативной либы.
-- Стаб принимает только конкретный whitelisted_ip = "10.0.0.5"; всё
-- остальное → no match.
local function install_ipmatcher_stub(allow_ip)
    package.loaded["resty.ipmatcher"] = {
        new = function(...)
            local _ = ...  -- cidrs list ignored; stub matches by literal allow_ip
            return {
                match = function(_, ip)
                    return ip == allow_ip
                end,
            }, nil
        end,
    }
end

local function reset()
    httpc_response = {}
    last_request = nil
    env_override = {}
    package.loaded["recovery"] = nil
    package.loaded["resty.ipmatcher"] = nil
end
local function load_mod()
    local r = require "recovery"
    r.http_module = httpc_mock
    return r
end

local passed, failed = 0, 0
local function ok(cond, name)
    if cond then passed = passed + 1
    else failed = failed + 1; io.write("FAIL: ", name, "\n") end
end
local function eq(a, b, name)
    if a == b then passed = passed + 1
    else failed = failed + 1
        io.write(string.format("FAIL %s: got %s, want %s\n",
            name, tostring(a), tostring(b))) end
end

-- ---------------------------------------------------------------------------
-- parse_body
do
    reset(); local r = load_mod()
    local _, _, err = r.parse_body("")
    ok(err == "empty body", "parse_body empty")

    _, _, err = r.parse_body("not-json")
    ok(err == "body must be a JSON object", "parse_body non-json")

    local h, ip
    h, ip, err = r.parse_body('{"host":"a.example","ip":"1.2.3.4"}')
    eq(h, "a.example", "parse_body host")
    eq(ip, "1.2.3.4", "parse_body ip")
    ok(err == nil, "parse_body err nil on ok")
end

-- ---------------------------------------------------------------------------
-- validate_host
do
    reset(); local r = load_mod()
    ok(r.validate_host("") ~= nil, "host empty")
    ok(r.validate_host(("a"):rep(254)) ~= nil, "host too long")
    ok(r.validate_host("bad space") ~= nil, "host with space")
    ok(r.validate_host("a.example") == nil, "host happy")
    ok(r.validate_host("dashboard.example.com") == nil, "host fqdn")
end

-- ---------------------------------------------------------------------------
-- validate_ip
do
    reset(); local r = load_mod()
    ok(r.validate_ip("") ~= nil, "ip empty")
    ok(r.validate_ip("1.2.3.4/32") ~= nil, "ip rejects CIDR suffix")
    ok(r.validate_ip("1.2.3.4 evil") ~= nil, "ip rejects whitespace")
    ok(r.validate_ip(("a"):rep(46)) ~= nil, "ip too long")
    ok(r.validate_ip("1.2.3.4") == nil, "ip v4 happy")
    ok(r.validate_ip("2001:db8::1") == nil, "ip v6 happy")
end

-- ---------------------------------------------------------------------------
-- to_cidr
do
    reset(); local r = load_mod()
    eq(r.to_cidr("1.2.3.4"), "1.2.3.4/32", "to_cidr v4")
    eq(r.to_cidr("2001:db8::1"), "2001:db8::1/128", "to_cidr v6")
end

-- ---------------------------------------------------------------------------
-- call_backend: ENV не настроены → ошибка без HTTP
do
    reset()
    env_override["ANTIBOT_BACKEND_URL"] = nil
    local r = load_mod()
    local ok_, info, err = r.call_backend("a.example", "1.2.3.4/32")
    eq(ok_, false, "no backend url → not ok")
    ok(err and err:find("ANTIBOT_BACKEND_URL"), "no backend url → err msg")
    ok(last_request == nil, "no backend url → no http call")
end

do
    reset()
    env_override["ANTIBOT_BACKEND_URL"] = "http://backend:8080"
    env_override["DASHBOARD_API_TOKEN"] = nil
    local r = load_mod()
    local ok_, _, err = r.call_backend("a.example", "1.2.3.4/32")
    eq(ok_, false, "no token → not ok")
    ok(err and err:find("DASHBOARD_API_TOKEN"), "no token → err msg")
    ok(last_request == nil, "no token → no http call")
end

-- ---------------------------------------------------------------------------
-- call_backend: успех 200
do
    reset()
    env_override["ANTIBOT_BACKEND_URL"] = "http://backend:8080/"  -- trailing slash
    env_override["DASHBOARD_API_TOKEN"] = "s3cret"
    local r = load_mod()
    httpc_response.status = 200
    httpc_response.body = '{"changed":true}'
    local ok_, info, err = r.call_backend("a.example", "1.2.3.4/32")
    eq(ok_, true, "happy ok=true")
    eq(err, nil, "happy err nil")
    eq(info.changed, true, "happy changed=true echoed")
    eq(last_request.url, "http://backend:8080/antibot/v1/policy/a.example/ip_whitelist",
       "url path correct (trailing slash stripped)")
    eq(last_request.opts.method, "POST", "method POST")
    eq(last_request.opts.headers["Authorization"], "Bearer s3cret", "Bearer header")
    ok(last_request.opts.body:find('"cidr"'), "body has cidr field")
    ok(last_request.opts.body:find("1.2.3.4/32"), "body has cidr value")
end

-- ---------------------------------------------------------------------------
-- call_backend: backend ответил 4xx
do
    reset()
    env_override["ANTIBOT_BACKEND_URL"] = "http://backend:8080"
    env_override["DASHBOARD_API_TOKEN"] = "s3cret"
    local r = load_mod()
    httpc_response.status = 401
    httpc_response.body = '{"error":"unauthorized"}'
    local ok_, info, err = r.call_backend("a.example", "1.2.3.4/32")
    eq(ok_, false, "401 → not ok")
    eq(info.status, 401, "401 status echoed in info")
    ok(err and err:find("401"), "err mentions 401")
end

-- ---------------------------------------------------------------------------
-- call_backend: transport error
do
    reset()
    env_override["ANTIBOT_BACKEND_URL"] = "http://backend:8080"
    env_override["DASHBOARD_API_TOKEN"] = "s3cret"
    local r = load_mod()
    httpc_response.err = "connection refused"
    local ok_, info, err = r.call_backend("a.example", "1.2.3.4/32")
    eq(ok_, false, "transport err → not ok")
    eq(info, nil, "transport err → no info")
    ok(err and err:find("transport"), "err is transport")
end

-- ---------------------------------------------------------------------------
-- call_backend: backend вернул "null" / не-table JSON (gemini review on PR #88).
-- decoded должен стать пустым table'ом, не userdata/scalar, иначе handle()
-- крашится на info.changed.
do
    reset()
    env_override["ANTIBOT_BACKEND_URL"] = "http://backend:8080"
    env_override["DASHBOARD_API_TOKEN"] = "s3cret"
    -- json_decode-стаб возвращает nil на "null"/число/пустую строку. Через
    -- декодер пустой "" получаем nil → ветка type ~= "table" сработает.
    -- Это тот же путь, что в проде даст cjson.null / cjson.decode error.
    local r = load_mod()
    httpc_response.status = 200
    httpc_response.body = ""
    local ok_, info, err = r.call_backend("a.example", "1.2.3.4/32")
    eq(ok_, true, "empty body still ok=true (HTTP 200)")
    eq(err, nil, "empty body err nil")
    eq(type(info), "table", "empty body → info is table, not nil/userdata")
    eq(info.changed, nil, "empty body → info.changed безопасно nil")
end

-- ---------------------------------------------------------------------------
-- client_allowed: ADMIN_ACL_CIDR unset → fail-closed
do
    reset()
    env_override["ADMIN_ACL_CIDR"] = nil
    local r = load_mod()
    eq(r.admin_matcher, nil, "unset env → no matcher")
    eq(r.client_allowed("10.0.0.5"), false, "unset env → deny any IP")
    eq(r.client_allowed(""), false, "unset env → deny empty IP")
end

-- client_allowed: empty string → fail-closed
do
    reset()
    env_override["ADMIN_ACL_CIDR"] = ""
    local r = load_mod()
    eq(r.admin_matcher, nil, "empty env → no matcher")
    eq(r.client_allowed("10.0.0.5"), false, "empty env → deny")
end

-- client_allowed: установленный allowlist → match
do
    reset()
    env_override["ADMIN_ACL_CIDR"] = "10.0.0.0/8,127.0.0.1/32"
    install_ipmatcher_stub("10.0.0.5")
    local r = load_mod()
    ok(r.admin_matcher ~= nil, "set env → matcher built")
    eq(r.client_allowed("10.0.0.5"), true, "allowlisted IP → allow")
    eq(r.client_allowed("8.8.8.8"), false, "non-allowlisted IP → deny")
    eq(r.client_allowed(nil), false, "nil IP → deny")
    eq(r.client_allowed(""), false, "empty IP → deny")
end

-- ---------------------------------------------------------------------------
io.write(string.format("recovery_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
