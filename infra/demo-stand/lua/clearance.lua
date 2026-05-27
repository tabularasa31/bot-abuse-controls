-- clearance.lua — L2.1 clearance cookie verify (C3).
--
-- Phase 4, vision §5.2 / §2.1, rules-reference rule `cookie_valid`. Клиент
-- предъявляет HMAC-подписанный cookie (выписан L5 после прохождения JS
-- challenge — C5, ещё не реализовано); proxy проверяет подпись локально без
-- обращения к backend. Валидный cookie → verdict=allow, rule=cookie_valid;
-- пропуск L3 (tls_fp) и L5 (verification), но НЕ L4 (rate-limits всё равно
-- применяются — vision §2.1 и rules-reference rule 3).
--
-- РАСХОЖДЕНИЕ task ↔ docs. Формулировка C3 в ClickUp предлагает payload
-- `<site>:<fp>:<expiry_ts>` с fp-binding и метрики `wrong_fp`. Это
-- противоречит vision.md §5.2 («bearer token без привязки к fingerprint —
-- кто украл cookie в течение 24-часового TTL, тот и пользуется») и
-- edge-lua-vs-sidecar §A6 (формат `body.sig`, без fp). По правилу из
-- CLAUDE.md / комментария к задаче «при расхождении приоритет у доков»
-- реализован bearer-вариант: site и iat в payload, fp НЕ binding'ится.
-- Защита от cross-tenant утечки → атрибутами cookie (Domain=<host>,
-- vision §5.2 «Атрибуты cookie tf_clearance») + проверкой site в payload
-- (defense-in-depth, метрика wrong_site). Если продукт всё-таки потребует
-- fp-binding — это отдельный тикет, который параллельно правит vision §5.2
-- и эту реализацию (memory: «Docs vs correctness»).
--
-- Формат cookie:
--     body = b64url(<site-host>) .. ":" .. <iat> .. ":" .. <exp>
--     sig  = b64url( HMAC-SHA256(secret, body) )
--     cookie value = body .. "." .. sig
-- iat (issued_at unix seconds) кладётся «вперёд» под C7 attack_mode:
-- L2.1 под атакой не доверяет cookie, выписанным ДО начала атаки
-- (vision §«Исключение: attack_mode=on»). Сейчас iat читается только в
-- логику issue/verify не уходит — C7 добавит сравнение `iat > attack_started_at`.
--
-- Что НЕ покрывает этот модуль:
--   * issue cookie на L5 после challenge — C5 (будет переиспользовать
--     `_M.issue` отсюда же, чтобы формат жил в одном месте).
--   * attack_mode skip-fastpath — C7 (планируется как ветка в `verify`).
--   * SECRET rotation runbook — C8.

local hmac   = require "resty.openssl.hmac"
local bit    = require "bit"
local secret = require "challenge_secret"

-- Lazy config require: clearance.lua грузится в init_by_lua ПОСЛЕ
-- config.load(), но юнит-тесты bypass'ят init.lua. pcall чтобы тест без
-- настоящего config не падал на require; внутри функций перепроверяем
-- config.defaults через type(), как это делает challenge.lua.
local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

-- Default cookie name — vision §5.2 «Атрибуты cookie tf_clearance»,
-- defaults.conf [allow.cookie_valid].cookie_name. ClickUp C3 предлагает
-- `cf_clearance` — оставляем `tf_clearance` (docs win). Per-site
-- переопределение — через [allow.cookie_valid].cookie_name в defaults.conf;
-- per-host override в policy на эдже не делается (cookie name — pool-wide
-- константа, как и HMAC secret).
local DEFAULT_COOKIE_NAME = "tf_clearance"

-- Valid result codes. Совпадают с метками метрики
-- `antibot_clearance_verify_total{result=...}` (metrics.lua) и пробрасываются
-- в bac_log как rule-suffix (`cookie_valid` для valid; для остальных
-- verdict не меняется и rule не выставляется — cookie просто игнорируется).
_M.RESULT_VALID      = "valid"
_M.RESULT_INVALID    = "invalid"     -- HMAC signature mismatch / sig decode failed
_M.RESULT_EXPIRED    = "expired"     -- HMAC ok, exp <= now
_M.RESULT_MISSING    = "missing"     -- no cookie header
_M.RESULT_MALFORMED  = "malformed"   -- structure unparseable
_M.RESULT_WRONG_SITE = "wrong_site"  -- HMAC ok but payload.site ~= request host
-- no_secret — challenge_secret not loaded (operational failure: C1 file
-- missing/empty after reload). Distinct from `invalid` so an attack-shaped
-- spike in `invalid` is not masked by a secret-outage spike. Operator
-- alerts can fire on `no_secret > 0` independently. Fail-closed for
-- fastpath: cascade proceeds via the normal path (same effective behavior
-- as `invalid`); the only difference is the metric attribution.
_M.RESULT_NO_SECRET  = "no_secret"

-- valid_var_suffix — nginx variables only allow [A-Za-z0-9_]; lookups via
-- `ngx.var["cookie_" .. name]` with hyphen / dot / other chars silently
-- return nil. Without this guard, an operator override like
-- `cookie_name = cf-clearance` (such as the original ClickUp task spec
-- proposed) would make EVERY request resolve to RESULT_MISSING with no
-- error in logs. We log WARN once at first call and fall back to the
-- pool-wide default — keeps the fastpath alive on a clearly-mis-typed
-- config while leaving a loud trail for the operator.
local function valid_var_suffix(name)
    return name:match("^[%w_]+$") ~= nil
end

local warned_bad_name = false
local function get_cookie_name()
    if config and type(config.defaults) == "table" then
        local allow = config.defaults.allow
        if type(allow) == "table" and type(allow.cookie_valid) == "table" then
            local name = allow.cookie_valid.cookie_name
            if type(name) == "string" and name ~= "" then
                if valid_var_suffix(name) then
                    return name
                end
                if not warned_bad_name then
                    ngx.log(ngx.WARN, "clearance: configured cookie_name '",
                        name, "' contains chars outside [A-Za-z0-9_]; ",
                        "nginx ngx.var lookup would always be nil. Falling ",
                        "back to default '", DEFAULT_COOKIE_NAME,
                        "'. Fix [allow.cookie_valid].cookie_name in defaults.conf.")
                    warned_bad_name = true
                end
            end
        end
    end
    return DEFAULT_COOKIE_NAME
end

_M.cookie_name = get_cookie_name  -- exposed for verdict.lua / tests

local function b64url_encode(raw)
    local s = ngx.encode_base64(raw)
    return (s:gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

local function b64url_decode(s)
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    return ngx.decode_base64(s)
end

-- ct_eq — constant-time equality для HMAC compare. Lua `==` на строках
-- разной длины early-exit'ит (длину проверяет первой) — это OK, длина
-- HMAC-SHA256 фиксирована (32 байта raw). Но побайтовое сравнение должно
-- идти до конца, иначе timing-oracle позволит подобрать sig по символу.
-- bit.bxor + bit.bor накапливают разницу без ветвлений по содержимому.
local function ct_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    if #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
    end
    return diff == 0
end

local function compute_hmac(key, body)
    local h, err = hmac.new(key, "sha256")
    if not h then return nil, "hmac.new: " .. tostring(err) end
    local ok, uerr = h:update(body)
    if not ok then return nil, "hmac.update: " .. tostring(uerr) end
    local sig, ferr = h:final()
    if not sig then return nil, "hmac.final: " .. tostring(ferr) end
    return sig
end

-- issue(host, ttl_seconds, now) → (cookie_value, exp) | nil, err
--
-- Реализована здесь (не в challenge.lua) чтобы формат payload жил в
-- ОДНОМ модуле с verify — рассинхрон issue/verify обнулил бы все cookies
-- после rollout'a. C5 (cookie issue после JS challenge) будет вызывать
-- этот `_M.issue` и выставлять Set-Cookie с атрибутами per vision §5.2
-- (HttpOnly / Secure / SameSite=Lax / Domain=<host> / Path=/).
--
-- ttl_seconds: по vision §2.1 — 86400 в нормальном режиме, 3600 при
-- attack_mode=on для host'a. Выбор делает caller (C5), не этот модуль:
-- здесь нет доступа к per-host policy/attack_mode без лишнего coupling.
-- `now` — optional override для детерминированных тестов (default ngx.time()).
function _M.issue(host, ttl_seconds, now)
    if type(host) ~= "string" or host == "" then
        return nil, "host required"
    end
    local key = secret.get()
    if not key then
        return nil, "challenge_secret not loaded (see C1: challenge_secret.lua)"
    end
    local iat = now or ngx.time()
    local exp = iat + (tonumber(ttl_seconds) or 86400)
    local body = b64url_encode(host) .. ":" .. iat .. ":" .. exp
    local sig, err = compute_hmac(key, body)
    if not sig then return nil, err end
    return body .. "." .. b64url_encode(sig), exp
end

-- verify(host) → result-code (одна из _M.RESULT_*). Чистая функция: не
-- трогает ngx.ctx, не пишет метрики, не зовёт bac_log. Caller (verdict.lua)
-- интерпретирует код, обновляет verdict / ставит skip-flag / инкрементит
-- counter — это позволяет тестам гонять verify в host-luajit без полного
-- ngx.ctx stub'а.
--
-- Порядок проверок выбран так, чтобы security-важные шаги (HMAC verify)
-- не текли через ранний return на дешевых signal'ах — иначе malformed/
-- expired cookie дали бы timing-oracle для распознавания «HMAC прошёл или
-- нет». Здесь:
--   1. парсим структуру cookie (malformed → exit, безопасно: до HMAC не дошли);
--   2. считаем HMAC, ct_eq;
--   3. ПОСЛЕ verify проверяем site и exp.
-- Если HMAC битый, exp/site вообще не смотрим — payload недостоверен.
function _M.verify(host)
    local name = get_cookie_name()
    local raw  = ngx.var["cookie_" .. name]
    if not raw or raw == "" then
        return _M.RESULT_MISSING
    end

    -- Двухсегментный формат `<body>.<sig>`. Используем последний `.` как
    -- разделитель (body содержит `:` и base64url-алфавит, ни одного `.`
    -- по построению — но writer'ы будущего расширения payload могут
    -- добавить, так что match'им rightmost `.` через "^(.+)%.([^.]+)$").
    local body, sig_b64 = raw:match("^(.+)%.([^.]+)$")
    if not body or not sig_b64 then
        return _M.RESULT_MALFORMED
    end

    -- body shape: `<b64url(site)>:<iat>:<exp>`. Парсим строго — любое
    -- отклонение → malformed (не доверяем содержимому без HMAC, но
    -- structural check без HMAC безопасен — данные были бы отвергнуты
    -- HMAC'ом тоже, просто экономим crypto-вычисление на garbage cookie).
    -- iat — намеренно не используется в C3 verify, но парсится строго,
    -- чтобы (а) malformed body отсекался до HMAC compute, (б) C7
    -- attack_mode skip-fastpath читал готовое поле (сравнение
    -- `iat > attack_started_at`) без изменения формата cookie. Капчу
    -- сбрасываем в `_` чтобы luacheck не ругался на unused (см. .luacheckrc:
    -- ignore=211 не включён глобально, только для tests/).
    local site_b64, _, exp_s = body:match("^([%w%-_]+):(%d+):(%d+)$")
    if not site_b64 then
        return _M.RESULT_MALFORMED
    end

    local site = b64url_decode(site_b64)
    if not site or site == "" then
        return _M.RESULT_MALFORMED
    end

    local sig_expected = b64url_decode(sig_b64)
    if not sig_expected then
        return _M.RESULT_MALFORMED
    end

    local key = secret.get()
    if not key then
        -- Сервер-сайд проблема (C1 не загрузил секрет). Fail-closed для
        -- fastpath: cookie не доверяется, request идёт по полному каскаду.
        -- Отдельный RESULT_NO_SECRET, чтобы spike при truncate/удалении
        -- secret-файла не маскировался под attack-shaped «invalid»;
        -- operator-алерт настраивается отдельно (review on PR #85).
        ngx.log(ngx.WARN, "clearance.verify: challenge_secret not loaded; ",
            "cookie cannot be verified (RESULT_NO_SECRET)")
        return _M.RESULT_NO_SECRET
    end

    local sig_actual, err = compute_hmac(key, body)
    if not sig_actual then
        ngx.log(ngx.ERR, "clearance.verify: hmac compute failed: ", err)
        return _M.RESULT_INVALID
    end

    if not ct_eq(sig_actual, sig_expected) then
        return _M.RESULT_INVALID
    end

    -- С этого момента payload достоверен — HMAC прошёл. Expired раньше
    -- wrong_site: легитимный клиент с истекшим cookie + apex-Domain
    -- scoping (Domain=example.com, browser шлёт на api.example.com) иначе
    -- получил бы security-окрашенный wrong_site вместо bookkeeping'ового
    -- expired. wrong_site — реальный сигнал «cross-tenant попытка», его
    -- хочется видеть только когда подпись и срок валидны (review on
    -- PR #85). Trade-off: атакующий с украденным expired cookie теперь
    -- проходит как expired, а не wrong_site, если ещё и site не совпал
    -- — но cookie уже истёк, реального риска нет.
    local exp = tonumber(exp_s)
    if not exp or exp <= ngx.time() then
        return _M.RESULT_EXPIRED
    end

    if site ~= host then
        return _M.RESULT_WRONG_SITE
    end

    return _M.RESULT_VALID
end

return _M
