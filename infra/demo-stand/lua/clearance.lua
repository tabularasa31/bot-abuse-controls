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
-- iat (issued_at unix seconds) и exp дают TTL = exp-iat, по которому C7
-- attack_mode различает «выдан до атаки» vs «выдан во время атаки» (см.
-- ниже про RESULT_STALE_PRE_ATTACK и `verify(host, opts)`).
--
-- attack_mode pre-attack gate (C7, vision §2.1 «Исключение: attack_mode=on»
-- / §5.3). Под `attack_mode=on` для host'a L2.1 не доверяет clearance
-- cookie, выписанным ДО начала атаки (атакующий мог накопить их заранее).
-- Различение — по ТИПУ TTL самого cookie (vision §5.3 «механизм на стороне
-- реализации; время выписки и/или тип TTL»): cookie, выписанный в
-- нормальном режиме, несёт длинный TTL (`ttl_seconds_normal`, 24ч), а
-- cookie, выписанный уже во время атаки (после перепрохождения challenge),
-- — короткий `ttl_seconds_under_attack` (1ч). Под атакой verify фастпасит
-- только короткие (during-attack) cookie; длинные (pre-attack) → отдельный
-- RESULT_STALE_PRE_ATTACK, который caller НЕ фастпасит — запрос идёт по
-- каскаду до L5 на challenge. Это и даёт «реальный юзер проходит challenge
-- один раз за атаку»: его during-attack cookie фастпасит до конца атаки.
-- Порог берётся из opts.max_under_attack_ttl (caller читает defaults.conf),
-- чтобы verify оставалась чистой функцией без config-зависимости в решении.
-- Если под атакой порог не пришёл — fail-closed (см. сам gate ниже).
--
-- ОГРАНИЧЕНИЕ TTL-механизма. Различаем по величине TTL, а не по
-- «iat vs attack_started_at», поэтому короткий cookie, выписанный во время
-- ПРЕДЫДУЩЕЙ атаки, в течение своего 1ч TTL будет принят как during-attack
-- и в НОВОЙ атаке, начавшейся в это окно. Окно ограничено TTL (1ч), и
-- держатель только что (≤1ч назад) проходил challenge, так что риск мал;
-- vision §5.3 явно санкционирует TTL-механизм. Строгое «выписан именно в
-- эту атаку» потребовало бы attack_started_at в policy + сравнения с iat —
-- отдельный тикет, если эта дельта риска станет значимой.
--
-- Что НЕ покрывает этот модуль:
--   * issue cookie на L5 после challenge — C5 (переиспользует `_M.issue`
--     отсюда же; выбор TTL normal/under_attack — в challenge_verify.lua).
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
-- stale_pre_attack — cookie полностью валиден (HMAC ok, не истёк, site
-- совпал), но под attack_mode=on несёт длинный (normal) TTL → выписан ДО
-- начала атаки (vision §2.1/§5.3). НЕ фастпасит: caller не ставит
-- clearance_valid, запрос идёт по каскаду до L5 на challenge. Отдельный
-- код (а не invalid/expired), чтобы attack-mode «сброс доверия» был виден
-- в метрике отдельно от криптопровалов и обычных протуханий.
_M.RESULT_STALE_PRE_ATTACK = "stale_pre_attack"
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
-- Once-flag для WARN про отсутствующий max_under_attack_ttl под атакой
-- (см. attack_mode pre-attack gate в verify). Per-worker, как warned_bad_name.
local warned_missing_threshold = false
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
-- opts (optional) — attack_mode context из caller'а (verdict.lua). Поля:
--   * attack_mode          — bool, attack_mode[host]=on для этого запроса;
--   * max_under_attack_ttl — number, верхняя граница TTL «выдан во время
--                            атаки» (= ttl_seconds_under_attack из конфига).
-- Когда attack_mode=on и cookie несёт TTL больше порога → pre-attack →
-- RESULT_STALE_PRE_ATTACK (см. модульный заголовок). Чистоту функции
-- сохраняем: порог приходит аргументом, config здесь не читается.
function _M.verify(host, opts)
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
    -- iat нужен под C7 attack_mode для вычисления TTL (exp-iat) — по типу
    -- TTL различаем pre-attack vs during-attack cookie (см. модульный
    -- заголовок). Парсим строго, как и раньше, чтобы malformed body
    -- отсекался до HMAC compute.
    local site_b64, iat_s, exp_s = body:match("^([%w%-_]+):(%d+):(%d+)$")
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

    -- attack_mode pre-attack gate (C7). Cookie прошёл все проверки валидности
    -- — без атаки это RESULT_VALID. Но под attack_mode=on длинный (normal)
    -- TTL означает «выдан до атаки» (during-attack cookie несут короткий
    -- under_attack TTL) → не фастпасим. Используем `>` к порогу: ровно
    -- under_attack TTL и короче — during-attack, фастпас; длиннее (24ч
    -- normal) — pre-attack. iat/exp уже провалидированы как digits выше.
    --
    -- FAIL-CLOSED. Если под атакой порог не пришёл (config без
    -- ttl_seconds_under_attack → opts.max_under_attack_ttl=nil) или iat не
    -- распарсился — pre-attack от during-attack не различить. Под атакой
    -- безопаснее НЕ доверять (RESULT_STALE_PRE_ATTACK → запрос на L5
    -- challenge), чем распустить фастпас по нераспознанному cookie: cмысл C7
    -- — сбросить доверие к накопленным cookie, fail-open это молча отменял
    -- (code-review on PR #92). WARN однократно: это config-issue, не
    -- нагрузка, а спамить лог на каждый запрос под атакой не нужно.
    if opts and opts.attack_mode then
        local max_ttl = opts.max_under_attack_ttl
        if not max_ttl then
            if not warned_missing_threshold then
                ngx.log(ngx.WARN, "clearance.verify: attack_mode=on but ",
                    "max_under_attack_ttl missing (check [allow.cookie_valid]",
                    ".ttl_seconds_under_attack in defaults.conf); failing closed ",
                    "— clearance cookies will not fastpath under attack.")
                warned_missing_threshold = true
            end
            return _M.RESULT_STALE_PRE_ATTACK
        end
        local iat = tonumber(iat_s)
        if not iat or (exp - iat) > max_ttl then
            return _M.RESULT_STALE_PRE_ATTACK
        end
    end

    return _M.RESULT_VALID
end

return _M
