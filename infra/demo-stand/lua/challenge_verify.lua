-- challenge_verify.lua — POST /__challenge/verify endpoint (C5).
--
-- Phase 4, vision §5.2 «Ветка A». Принимает JSON-payload от JS-solver'a из
-- challenge/page.html: { nonce, token, cascade_version, not_a_robot, fp }.
-- При успехе — выписывает clearance cookie через clearance.issue (тот же
-- HMAC scheme, что и L2.1 verify, C3) и отдает 200, JS reload'ит исходный
-- URL и теперь проходит каскад фастпасом по cookie_valid.
--
-- Endpoint живёт ОТДЕЛЬНО от verdict.lua: верификация запроса с
-- неподписанной cookie уже ушла на /__challenge через ngx.exec из verdict
-- pipeline'a; этот же запрос с answer'ом приходит на новый URL вне каскада
-- (carve-out в nginx.demo.conf), иначе grey-verdict повторно бы выкинул на
-- challenge до того, как мы успели бы выписать cookie.
--
-- Контракт payload — pinned к шаблону через cascade_version. Любое
-- расхождение полей / JS_SECRET / endpoint path требует одновременного
-- bump'a CASCADE_VERSION (challenge/README.md). cascade_version в POST
-- сверяется с серверной — защита от stale-кеша браузера со старой
-- challenge-страницей (бы prокидывала старый nonce-формат после rollout'a).
--
-- Single-use nonce. Replay-защита по vision §5.2 строится на TTL (60с) +
-- single-use: первый успешный verify nonce'a кладёт его HMAC-сегмент в
-- ngx.shared.used_nonces с TTL = exp - now + slack; повторный verify того
-- же nonce'a (replay в окне expiry) отдаёт `consumed` и 403.

local cjson  = require "cjson.safe"
local hmac   = require "resty.openssl.hmac"
local sha256 = require "resty.sha256"
local str    = require "resty.string"
local bit    = require "bit"
local secret = require "challenge_secret"
local clearance = require "clearance"

local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

-- JS_SECRET — должен совпадать с константой в challenge/page.html. Это
-- «pepper», который превращает nonce-only POST в proof-of-JS-execution:
-- бот без JS-движка hash не посчитает. Криптостойкость даёт HMAC nonce'a
-- (challenge.issue_nonce), pepper — только сигнал «JS реально выполнен».
-- Ротация (новое значение pepper) обязательна одновременно с bump'ом
-- CASCADE_VERSION — иначе старый шаблон в браузерном кеше отправит token
-- от старого pepper'a, и verify будет давать `bad_token` (false-positive).
local JS_SECRET = "tf_challenge_v1_proof_of_execution"

-- Cookie TTL — vision §2.1 «86400 в нормальном режиме / 3600 при attack_mode».
-- attack_mode выбор делается в caller'е (C7); сейчас (C5 без C7) всегда
-- 86400. Когда C7 заведёт `policy.attack_mode`, переключение сделаем здесь
-- через clearance.issue(host, ttl).
local DEFAULT_COOKIE_TTL = 86400

-- Max request body — JSON-payload (~500B типично c fp). 4KiB запас на
-- разрастание fp-поля (canvas/audio fingerprints в будущем) и отсечка
-- spam-payload'ов до парсинга JSON.
local MAX_BODY_BYTES = 4096

-- Result codes — пишутся в `antibot_challenge_invalid_total{reason}`
-- метрику. Названия совпадают с phase2-spec/rules-reference терминами
-- (bad_nonce / expired / replay / bad_token / wrong_version), плюс
-- bookkeeping-исходы (body / json / shape).
_M.REASON_BAD_NONCE     = "bad_nonce"
_M.REASON_EXPIRED       = "expired"
_M.REASON_REPLAY        = "replay"
_M.REASON_BAD_TOKEN     = "bad_token"
_M.REASON_WRONG_VERSION = "wrong_version"
_M.REASON_BAD_BODY      = "bad_body"
_M.REASON_BAD_METHOD    = "bad_method"
_M.REASON_NO_SECRET     = "no_secret"

-- b64url decode mirroring challenge.lua / clearance.lua (RFC 4648 §5,
-- no padding). Вынесено как локальная функция, не shared util — три
-- разных модуля держат собственную копию для минимизации coupling
-- (см. clearance.lua и challenge.lua).
local function b64url_decode(s)
    if type(s) ~= "string" then return nil end
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    return ngx.decode_base64(s)
end

-- Constant-time compare — той же формы, что и в clearance.lua. Используется
-- ТОЛЬКО для HMAC-байтового сравнения (sig vs expected). Token (hex SHA-256
-- от nonce+JS_SECRET) тоже сравниваем через ct_eq — даже если timing-oracle
-- через JS_SECRET в нашей модели меньше критичен (pepper, не secret),
-- защищает от подбора знака по таймингу при будущей замене на per-host
-- pepper.
local function ct_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    if #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
    end
    return diff == 0
end

-- verify_nonce(nonce, host) → (payload_table, sig_b64) | nil, reason
-- HMAC-стресс-тест nonce'a: парс шаблона `<payload_b64>.<sig_b64>`, HMAC
-- recompute, ct_eq, payload decode, exp/host check. NO single-use here —
-- consume_nonce делается ПОСЛЕ token-проверки, иначе bad_token POST'ы
-- съедали бы валидный nonce и легитимный retry ломался бы.
function _M.verify_nonce(nonce, host)
    if type(nonce) ~= "string" or nonce == "" then
        return nil, _M.REASON_BAD_NONCE
    end
    local payload_b64, sig_b64 = nonce:match("^([^.]+)%.([^.]+)$")
    if not payload_b64 or not sig_b64 then
        return nil, _M.REASON_BAD_NONCE
    end

    local key = secret.get()
    if not key then
        return nil, _M.REASON_NO_SECRET
    end

    -- HMAC recompute. Mirrors challenge.issue_nonce: payload_b64 — что
    -- подписывалось (НЕ raw payload-JSON). Расхождение «что подписывали»
    -- vs «что проверяем» — основной класс багов HMAC-схем, поэтому
    -- читателю стоит держать оба места в одном глазу.
    local h, herr = hmac.new(key, "sha256")
    if not h then
        ngx.log(ngx.ERR, "challenge_verify: hmac.new: ", herr)
        return nil, _M.REASON_BAD_NONCE
    end
    local ok_upd, uerr = h:update(payload_b64)
    if not ok_upd then
        ngx.log(ngx.ERR, "challenge_verify: hmac.update: ", uerr)
        return nil, _M.REASON_BAD_NONCE
    end
    local sig_expected, ferr = h:final()
    if not sig_expected then
        ngx.log(ngx.ERR, "challenge_verify: hmac.final: ", ferr)
        return nil, _M.REASON_BAD_NONCE
    end

    local sig_actual = b64url_decode(sig_b64)
    if not sig_actual then
        return nil, _M.REASON_BAD_NONCE
    end
    if not ct_eq(sig_actual, sig_expected) then
        return nil, _M.REASON_BAD_NONCE
    end

    -- Payload достоверен — HMAC прошёл. Decode + проверка exp/host.
    local payload_json = b64url_decode(payload_b64)
    if not payload_json then
        return nil, _M.REASON_BAD_NONCE
    end
    local payload = cjson.decode(payload_json)
    if type(payload) ~= "table" then
        return nil, _M.REASON_BAD_NONCE
    end

    local exp = tonumber(payload.exp)
    if not exp or exp <= ngx.time() then
        return nil, _M.REASON_EXPIRED
    end

    -- Host-binding: nonce подписан под конкретный host. Cross-tenant
    -- replay (получил nonce на site-A, шлёт verify на site-B) даже при
    -- общем HMAC secret'е пула отвергается.
    if type(payload.h) ~= "string" or payload.h == "" or payload.h ~= host then
        return nil, _M.REASON_BAD_NONCE
    end

    return payload, sig_b64
end

-- verify_token(nonce, token) → bool. token = hex(SHA-256(nonce || JS_SECRET)).
-- Сравниваем как байтовые строки через ct_eq.
function _M.verify_token(nonce, token)
    if type(nonce) ~= "string" or type(token) ~= "string" then return false end
    if #token ~= 64 then return false end  -- hex sha256 = 64 chars
    local h = sha256:new()
    if not h then return false end
    if not h:update(nonce) then return false end
    if not h:update(JS_SECRET) then return false end
    local digest = h:final()
    if not digest then return false end
    local hex = str.to_hex(digest)
    return ct_eq(hex:lower(), token:lower())
end

-- consume_nonce(sig_b64, exp) → true on first use, false otherwise.
-- Ключом single-use берем HMAC-сегмент (а не весь nonce): он уникален
-- by construction (HMAC по payload), короче чем payload+sig, и не
-- утекает host'a в shared dict. TTL = exp - now + 5s slack — записи
-- автоматически сметаются после истечения nonce'a, не накапливаются.
--
-- `dict:add` различает два класса отказа: `err == "exists"` — реальный
-- replay (nonce уже потреблён в окне TTL), `err == "no memory"` —
-- shared_dict переполнен и LRU не нашёл что вытеснить. Без отдельного
-- ERR-лога OOM маскировался бы под replay (gemini review on PR #87) —
-- метрика `challenge_invalid_total{reason="replay"}` росла бы при OOM,
-- хотя проблема в `lua_shared_dict used_nonces` sizing'е. Логируем ERR
-- и продолжаем fail-closed (тот же 403 для клиента — лучше отказать,
-- чем выписать cookie на возможный replay).
function _M.consume_nonce(sig_b64, exp)
    local dict = ngx.shared.used_nonces
    if not dict then
        ngx.log(ngx.ERR, "challenge_verify: ngx.shared.used_nonces not declared")
        return false
    end
    local ttl = (exp - ngx.time()) + 5
    if ttl <= 0 then return false end
    local ok, err = dict:add(sig_b64, 1, ttl)
    if ok then return true end
    if err == "no memory" then
        ngx.log(ngx.ERR, "challenge_verify: used_nonces shared_dict out of memory; ",
            "bump lua_shared_dict used_nonces in nginx.conf")
    end
    return false
end

-- bump_counter — все challenge-метрики живут в ngx.shared.metrics.
-- Невыделение отдельного шорткаката (как в verdict.lua) — модуль вызывается
-- единственным content_by_lua, нет hot-path'a.
local function bump(key)
    local m = ngx.shared.metrics
    if m then m:incr(key, 1, 0) end
end

local function bump_invalid(reason)
    bump("challenge_invalid_" .. reason .. "_total")
end

-- handle() — content_by_lua entry. Не вызывается из verdict.lua (carve-out
-- в nginx config: location /__challenge/verify без access_by_lua).
function _M.handle()
    if ngx.req.get_method() ~= "POST" then
        bump_invalid(_M.REASON_BAD_METHOD)
        return ngx.exit(405)
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or body == "" then
        -- get_body_data() returns nil if body was written to disk
        -- (client_body_buffer_size overflow) — but MAX_BODY_BYTES <
        -- буфера, так что для нашего payload'a этого не случится; пустое
        -- тело реально означает «клиент не прислал ничего».
        bump_invalid(_M.REASON_BAD_BODY)
        return ngx.exit(400)
    end
    if #body > MAX_BODY_BYTES then
        bump_invalid(_M.REASON_BAD_BODY)
        return ngx.exit(413)
    end

    local payload = cjson.decode(body)
    if type(payload) ~= "table" then
        bump_invalid(_M.REASON_BAD_BODY)
        return ngx.exit(400)
    end

    -- Cascade version pin. Шаблон зашит на конкретную версию каскада
    -- (challenge/page.html `data-cascade-version` + meta). После bump'a
    -- браузер с закешированной старой страницей придёт сюда со старой
    -- `cascade_version` — отвергаем (иначе old-format payload пройдёт
    -- невалидно). Сравниваем со значением, которое challenge.preload()
    -- проверил на init и положил в template_version().
    local server_version
    local challenge_mod = require "challenge"
    server_version = challenge_mod.template_version()
    if type(payload.cascade_version) ~= "string"
        or payload.cascade_version ~= server_version then
        bump_invalid(_M.REASON_WRONG_VERSION)
        return ngx.exit(400)
    end

    local host = ngx.var.host or ""
    if host == "" then
        -- Empty host обычно значит сломанный upstream/proxy (request без
        -- Host header'a, HTTP/1.0 без него, разделено proxy_set_header).
        -- Без host'a verify_nonce упадёт на host-binding, а clearance.issue
        -- — на 'host required'. Возвращаем bad_body чтобы не пачкать
        -- no_secret/bad_nonce метрики, которые сигналят разные операционные
        -- проблемы (code-review on PR #87).
        bump_invalid(_M.REASON_BAD_BODY)
        return ngx.exit(400)
    end
    local nonce_payload, sig_or_reason = _M.verify_nonce(payload.nonce, host)
    if not nonce_payload then
        bump_invalid(sig_or_reason)
        return ngx.exit(403)
    end
    local sig_b64 = sig_or_reason

    if not _M.verify_token(payload.nonce, payload.token) then
        -- NOT consuming nonce here: legitimate retry from same page (e.g.
        -- transient subtle.digest failure → user reloads) should still
        -- be possible within the TTL window. Replay protection kicks in
        -- only on a SUCCESSFUL verify (consume_nonce ниже).
        bump_invalid(_M.REASON_BAD_TOKEN)
        return ngx.exit(403)
    end

    -- Single-use: атомарный add в shared dict. Первый — true, повторный
    -- (replay в окне TTL) — false. Делаем ПОСЛЕ token verify, чтобы
    -- неуспешный POST не сжигал валидный nonce (см. комментарий выше).
    if not _M.consume_nonce(sig_b64, nonce_payload.exp) then
        bump_invalid(_M.REASON_REPLAY)
        return ngx.exit(403)
    end

    -- Cookie TTL. defaults.conf [allow.cookie_valid] держит две точки:
    -- `ttl_seconds_normal` (vision §2.1 — 86400) и `ttl_seconds_under_attack`
    -- (vision §2.1 / §5.3 — 3600 при attack_mode=on). Выбор делает caller-
    -- ветка `attack_mode`: сейчас (C5 без C7) policy.attack_mode всегда
    -- false → normal-TTL. Когда C7 заведёт чтение per-host policy здесь,
    -- остаётся переключить ключ под p.attack_mode без изменения схемы
    -- конфига (code-review on PR #87: предыдущая версия читала
    -- несуществующий `ttl_seconds`, override был dead code).
    local ttl = DEFAULT_COOKIE_TTL
    if config and type(config.defaults) == "table" then
        local allow = config.defaults.allow
        if type(allow) == "table" and type(allow.cookie_valid) == "table" then
            local t = tonumber(allow.cookie_valid.ttl_seconds_normal)
            if t and t > 0 then ttl = t end
        end
    end

    local cookie_value, cerr = clearance.issue(host, ttl)
    if not cookie_value then
        ngx.log(ngx.ERR, "challenge_verify: clearance.issue failed: ", cerr)
        bump_invalid(_M.REASON_NO_SECRET)
        return ngx.exit(500)
    end

    -- Set-Cookie атрибуты — vision §5.2: HttpOnly, Secure, SameSite=Lax,
    -- Domain=<host> (без leading dot), Path=/.
    --
    -- Domain attr опускаем для IPv4/IPv6/localhost: per RFC 6265 §5.2.3
    -- «If the user agent receives a cookie with a Domain attribute that
    -- contains an IP address, the user agent MUST silently ignore the
    -- cookie», то же для `localhost`. Без атрибута браузер создаст
    -- host-only cookie (отправляется только на этот же хост) — это и
    -- ожидаемое поведение для демо-стенда / интеграционного харнесса,
    -- который часто бьёт по IP/`localhost` (gemini review on PR #87).
    local cookie_name = clearance.cookie_name()
    local domain_attr = ""
    local is_ipv4    = host:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
    local is_ipv6    = host:find(":", 1, true) ~= nil  -- IPv6 literal: any ':'
    local is_loopbk  = (host == "localhost")
    if not (is_ipv4 or is_ipv6 or is_loopbk) then
        domain_attr = "; Domain=" .. host
    end
    local set_cookie = string.format(
        "%s=%s; Max-Age=%d; Path=/%s; HttpOnly; Secure; SameSite=Lax",
        cookie_name, cookie_value, ttl, domain_attr)
    ngx.header["Set-Cookie"] = set_cookie
    ngx.header.cache_control = "no-store"

    bump("challenge_solved_total")

    -- BAC_LOG challenge-pass event (vision §5.2 «Сбор browser fingerprint
    -- для аналитики ... Уезжает вместе с challenge-pass-событием по тому
    -- же пути, что и обычные логи»). Endpoint вне verdict.lua, поэтому
    -- bac_log.init() здесь явный; emit() пишет в stdout + enqueue'ит в
    -- log_shipper (тот же канал, что у обычных запросов). Без этого
    -- block браузерный fingerprint, собранный JS solver'ом, никогда не
    -- доезжал бы до backend telemetry — а это явный contract из vision
    -- (codex review on PR #87).
    --
    -- verdict=allow, rule=challenge_pass — отдельный rule-код, чтобы
    -- аналитика отличала «прошел challenge» от других allow-веток
    -- (cookie_valid / bot_verified / ip_whitelist). Соответствует
    -- entities-reference Phase 4 категории challenge events.
    local bac_log = require "bac_log"
    bac_log.init()
    bac_log.set_verdict("verification", "allow", "challenge_pass")
    -- payload.fp пришёл из attacker-controlled JSON (body уже капнут
    -- MAX_BODY_BYTES, но fp как поддерево может занимать почти весь
    -- лимит и при глубокой вложенности завалить cjson.encode в
    -- bac_log.emit — emit вернётся раньше с ERR-логом, и challenge-pass
    -- запись пропадёт целиком (атакующий молча получает cookie без
    -- audit-trail; code-review on PR #87). Pre-validate: encode здесь
    -- через cjson.safe, проверяем размер, и только тогда отдаём в
    -- bac_log. На неудачу — fp=nil + WARN; cookie всё равно выписана,
    -- но bac_log.emit точно не упадёт и запись challenge_pass дойдёт.
    local FP_MAX_BYTES = 2048
    local fp_to_log
    if type(payload.fp) == "table" then
        local enc, enc_err = cjson.encode(payload.fp)
        if enc and #enc <= FP_MAX_BYTES then
            fp_to_log = payload.fp
        else
            ngx.log(ngx.WARN, "challenge_verify: dropping payload.fp ",
                "(encode err: ", tostring(enc_err),
                ", len: ", enc and #enc or "nil", ")")
        end
    end
    bac_log.set_challenge_fp(fp_to_log)
    bac_log.emit()

    -- 200 OK + пустое тело: JS на page.html делает window.location.reload(),
    -- браузер ушлёт новый GET с прикрепленным cookie, и каскад фастпасит
    -- на L2.1 (clearance.verify → RESULT_VALID).
    ngx.status = 200
    ngx.header.content_type = "text/plain; charset=utf-8"
    ngx.print("ok")
    return ngx.exit(200)
end

return _M
