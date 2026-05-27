-- challenge.lua — HTML+JS challenge page renderer + nonce issuer (C2).
--
-- Phase 4, vision §5.2 «Ветка A». Edge подставляет один self-signed nonce в
-- HTML+JS-шаблон и отдает страницу клиенту; JS вычисляет SHA-256(nonce +
-- JS_SECRET) и POST'ит токен на verify-эндпоинт. Здесь — только эмиссия
-- (render + issue_nonce); verify будет в C5, который переиспользует
-- challenge_secret.get() (C1) для HMAC и читает тот же nonce-payload.
--
-- Доставка шаблона на демо — file-mount (Channel A на демо). Подгружается
-- ровно один раз в init_by_lua (см. init.lua: `require("challenge").preload`),
-- workers наследуют закешированную строку через fork. Изменение шаблона =
-- bump `CASCADE_VERSION` + edit `page.html` + `openresty -s reload`.
--
-- Nonce-формат — двухсегментный токен `<payload-b64url>.<hmac-b64url>`:
--   payload = cjson.encode({h=<host>, ts=<issued_unix>, exp=<expiry_unix>})
--   hmac    = HMAC-SHA256(secret = challenge_secret.get(), data = payload-b64url)
-- C5 декодирует payload, проверяет HMAC, проверяет `exp > ngx.time()`,
-- проверяет совпадение `h` с request host'ом. TTL ≈ 60с (defaults.conf
-- [challenge].nonce_ttl_seconds) — это и есть «одноразовость» nonce из
-- acceptance: окно использования жестко ограничено expiry'ем, replay
-- после истечения отвергается.

local cjson  = require "cjson.safe"
local hmac   = require "resty.openssl.hmac"
local secret = require "challenge_secret"
-- Lazy `config` resolution: challenge.lua loads in init_by_lua *after*
-- config.load() runs, but unit tests bypass init.lua entirely. Require
-- here (cheap), but defensively re-check `config.defaults` in issue_nonce
-- since a test harness may inject a partial stub.
local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

-- DEFAULT_NONCE_TTL — fallback only. Source of truth is defaults.conf
-- [challenge].nonce_ttl_seconds (vision §5.2 «TTL 60с»). We keep a baked-in
-- default so issue_nonce stays operational if the config section is missing
-- (e.g., older defaults.conf during a partial rollout) — never silently
-- "no TTL" / "TTL=0", which would invalidate every nonce instantly.
local DEFAULT_NONCE_TTL = 60

-- TEMPLATE_PATH / VERSION_PATH — резолвятся через env, чтобы integration
-- harness и unit-тесты могли переопределить пути без правки defaults.conf.
-- Бои держат дефолтные пути из docker-compose mount'ов.
local TEMPLATE_PATH = os.getenv("CHALLENGE_TEMPLATE_FILE")
    or "/etc/nginx/challenge/page.html"
local VERSION_PATH  = os.getenv("CASCADE_VERSION_FILE")
    or "/etc/nginx/CASCADE_VERSION"

-- read_file — bounded read, чтобы случайный мисмаунт на большом файле
-- (`/dev/urandom`, объемный лог) не подвесил master в init_by_lua. 64KiB
-- дает ~16-кратный запас над текущим шаблоном (~3KiB) и отрезает любой
-- разумный «кто-то перепутал mount».
local MAX_TEMPLATE_BYTES = 65536

local function read_file(path, limit)
    local f, open_err = io.open(path, "r")
    if not f then return nil, open_err end
    local raw = f:read(limit + 1)
    f:close()
    if not raw then return nil, "empty read" end
    if #raw > limit then
        return nil, "file larger than " .. limit .. " bytes"
    end
    return raw
end

local function rstrip(s)
    return (s:gsub("[%s%c]+$", ""))
end

-- Module-level cache: заполняется в preload() из init_by_lua. Без preload
-- render() сработает (lazy-load), но fallback нежелателен в horячем пути —
-- preload-проверка ловит расхождение CASCADE_VERSION ↔ meta-тег еще на
-- старте, до первого запроса.
local cached_template
local cached_version

-- parse_version_from_template — единая точка извлечения версии из шаблона
-- (используется и в preload, и в render-fallback). Ищем
-- `<meta name="cascade-version" content="...">`. Это единственный
-- machine-checked маркер; HTML-комментарий `<!-- cascade-version: ... -->`
-- — для человеческого глаза в curl-выдаче и в этой функции не парсится.
local function parse_version_from_template(html)
    return html:match('<meta%s+name="cascade%-version"%s+content="([^"]+)"')
end

-- preload() — вызывается из init.lua. Читает CASCADE_VERSION и шаблон,
-- сверяет версии. Mismatch → error() — валит init_by_lua, контейнер не
-- стартует. Это и есть version-pin инвариант C2: каскад и шаблон могут
-- разъехаться только осознанно (bump в обоих местах одновременно).
function _M.preload()
    local version, ver_err = read_file(VERSION_PATH, 64)
    if not version then
        error("challenge: cannot read " .. VERSION_PATH .. ": " .. tostring(ver_err))
    end
    version = rstrip(version)
    if version == "" then
        error("challenge: " .. VERSION_PATH .. " is empty after trim")
    end

    local html, tpl_err = read_file(TEMPLATE_PATH, MAX_TEMPLATE_BYTES)
    if not html then
        error("challenge: cannot read " .. TEMPLATE_PATH .. ": " .. tostring(tpl_err))
    end

    local tpl_version = parse_version_from_template(html)
    if not tpl_version then
        error("challenge: " .. TEMPLATE_PATH ..
              ' missing <meta name="cascade-version" content="…">; ' ..
              "every challenge page must pin to a cascade version")
    end
    if tpl_version ~= version then
        error("challenge: cascade/template version mismatch — " ..
              VERSION_PATH .. "=" .. version ..
              " vs template meta=" .. tpl_version ..
              " (bump both sides together; see infra/demo-stand/challenge/README.md)")
    end

    cached_template = html
    cached_version  = version
    return version
end

function _M.template_version()
    return cached_version
end

-- base64url — без padding, RFC 4648 §5. ngx.encode_base64 дает стандартный
-- base64; конвертируем посимвольно. Compact достаточно для одного nonce на
-- запрос, hot-path не upchain.
local function b64url(raw)
    local s = ngx.encode_base64(raw)
    s = s:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
    return s
end

-- issue_nonce(host) → (nonce_string, expiry_ts) | nil, err.
--   nonce_string = b64url(payload_json) .. "." .. b64url(hmac_sha256)
-- TTL берется из defaults.conf [challenge].nonce_ttl_seconds (см.
-- config.lua); 60 — дефолт по vision §5.2.
function _M.issue_nonce(host, ttl_seconds)
    if type(host) ~= "string" or host == "" then
        return nil, "host required"
    end
    local key = secret.get()
    if not key then
        return nil, "challenge_secret not loaded (see C1: challenge_secret.lua)"
    end
    -- TTL precedence: explicit argument > config > baked-in default. The
    -- config branch reads through `config.defaults.challenge` so an empty
    -- or missing [challenge] section in defaults.conf doesn't crash —
    -- falls through to DEFAULT_NONCE_TTL. tonumber() guards a stringly-
    -- typed INI value like "60".
    local ttl = tonumber(ttl_seconds)
    if not ttl and config and type(config.defaults) == "table" then
        local ch = config.defaults.challenge
        if type(ch) == "table" then
            ttl = tonumber(ch.nonce_ttl_seconds)
        end
    end
    ttl = ttl or DEFAULT_NONCE_TTL
    local now = ngx.time()
    local exp = now + ttl

    local payload, enc_err = cjson.encode({ h = host, ts = now, exp = exp })
    if not payload then
        return nil, "payload encode: " .. tostring(enc_err)
    end
    local payload_b64 = b64url(payload)

    -- Explicit update()+final() rather than final(data). Both shapes are
    -- accepted by current lua-resty-openssl (final() calls update()
    -- internally if data is passed), but the explicit form is bug-resistant
    -- against version drift and lets the test fake mirror the real API
    -- precisely (so a future regression to `final(data)` would fail loud
    -- in unit tests, not silently sign the empty string).
    local h, hmac_err = hmac.new(key, "sha256")
    if not h then return nil, "hmac.new: " .. tostring(hmac_err) end
    local upd_ok, upd_err = h:update(payload_b64)
    if not upd_ok then return nil, "hmac.update: " .. tostring(upd_err) end
    local sig, sig_err = h:final()
    if not sig then return nil, "hmac.final: " .. tostring(sig_err) end

    return payload_b64 .. "." .. b64url(sig), exp
end

-- substitute — точечная замена плейсхолдеров. gsub plain (4-й аргумент
-- nil → pattern-mode), но плейсхолдеры в шаблоне `{{NONCE}}` /
-- `{{EXPIRY}}` / `{{CASCADE_VERSION}}` не содержат метасимволов Lua
-- pattern'a, так что fine. Замена через функцию (а не строку), чтобы
-- значения с `%` в выдаче не сломали back-reference.
local function substitute(tpl, vars)
    local function repl(name)
        return tostring(vars[name] or "")
    end
    return (tpl:gsub("{{([A-Z_]+)}}", repl))
end

-- render(host) → html_string | nil, err. Подставляет свежий nonce + expiry
-- + version в кешированный шаблон. HTTP-выдачей (status / headers /
-- ngx.say) занимается caller (C5); render — чистая функция, удобно для
-- unit-тестов и для отладочных consumer'ов.
function _M.render(host, ttl_seconds)
    if not cached_template then
        _M.preload()
    end
    local nonce, exp_or_err = _M.issue_nonce(host, ttl_seconds)
    if not nonce then
        return nil, exp_or_err
    end
    -- CASCADE_VERSION в шаблоне уже литерал (preload-инвариант: meta-тег
    -- шаблона == содержимое CASCADE_VERSION файла). Подставляем только
    -- per-request значения.
    return substitute(cached_template, {
        NONCE   = nonce,
        EXPIRY  = exp_or_err,
    })
end

return _M
