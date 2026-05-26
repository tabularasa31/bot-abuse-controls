-- Phase 4 HMAC secret для clearance cookie (vision §«HMAC secret для
-- clearance cookie», §Channel A; config-templates.md §9). Один общий для
-- всего edge-пула секрет, которым L5 подписывает cookie (issue) и self-signed
-- nonce challenge-страницы, а L2.1 проверяет cookie на fastpath. Всё —
-- локально, без обращения к backend.
--
-- Доставка. В проде — Puppet (Channel A). На демо-стенде Channel A =
-- file/mount (тот же принцип, что у kill_switch.local.conf и ./certs/*.pem):
-- редактор кладёт файл на VM, оператор делает `openresty -s reload`. Никакого
-- Puppet/Salt/container recreate.
--
-- Ротация = reload. init_by_lua перезапускается на каждом nginx -s reload и
-- перечитывает файл; secret в shared_dict переписывается. Cookie, подписанные
-- старым секретом, перестают проходить HMAC verify на L2.1 — клиент идёт через
-- каскад до L5 и проходит challenge заново (by-design, см. vision §«Ротация»:
-- «новая версия через PR + reload nginx; ротация инвалидирует все ранее
-- выданные cookie разом»).
--
-- shared_dict переживает reload (как `meta` / `tls_fp_blocklist` — см.
-- PR-62 audit round-6 в init.lua). Это важно для отказоустойчивости readers,
-- но создаёт ловушку «зомби-секрет»: если файл случайно удалили и сделали
-- reload, старое значение осталось бы в памяти. Поэтому load() в любом
-- failure-режиме явно :delete()-ит обе записи — fail-closed.

local DICT_NAME = "challenge_secret"
local KEY_SECRET = "secret"
local KEY_FP     = "fp"
-- 32 байта — минимум для HMAC-SHA256 ключа; реалистичный секрет придёт
-- через `openssl rand -base64 32` (~44 символа base64). Меньшие отвергаем,
-- чтобы случайно не подгрузить "TODO"/"changeme"/тестовую строку.
local MIN_BYTES = 32
-- Жёсткий потолок на размер файла — защита от мисмаунта (например
-- CHALLENGE_HMAC_SECRET_FILE случайно указали на /dev/urandom или на
-- большой файл): f:read('*a') блокировал бы master в init_by_lua и стенд
-- не поднимался. Реальный секрет — ~44 байта; 1024 даёт большой запас и
-- гарантированно завершается за один read. Если у кого-то когда-то появится
-- нужда в более длинных ключах — поднять этот предел осознанно.
local MAX_BYTES = 1024

local _M = {}

-- Trim trailing newline/whitespace, оставив тело base64 нетронутым.
local function rstrip(s)
    return (s:gsub("[%s%c]+$", ""))
end

-- 8-hex prefix of sha256(secret). Используется в /__version и /__admin как
-- безопасный маркер, что reload подхватил именно ожидаемый файл. Сам secret
-- наружу не выводится никогда.
local function fingerprint(secret)
    local sha256 = require "resty.sha256"
    local h = sha256:new()
    h:update(secret)
    local digest = h:final()
    -- digest — 32 raw байта; превращаем первые 4 в 8 hex.
    return (digest:sub(1, 4):gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

local function clear(dict)
    dict:delete(KEY_SECRET)
    dict:delete(KEY_FP)
end

-- load(path) — читает файл, валидирует, кладёт в shared_dict. Любой
-- failure-режим (нет файла / пустой / короче MIN_BYTES) логируется и
-- вычищает прежнее значение в dict (fail-closed: пусть consumers C3/C5
-- увидят «секрета нет» и пропустят cookie verify/issue, чем будут работать
-- со stale секретом). Вызывается из init_by_lua, поэтому ngx.log
-- доступен. Возвращает true при успехе, false иначе — для тестов.
function _M.load(path)
    if type(path) ~= "string" or path == "" then
        ngx.log(ngx.ERR, "challenge_secret: load(path) needs a non-empty string, got ",
            type(path))
        return false
    end

    local dict = ngx.shared[DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "challenge_secret: shared_dict `", DICT_NAME,
            "` not declared in nginx.conf")
        return false
    end

    local f, open_err = io.open(path, "r")
    if not f then
        ngx.log(ngx.WARN, "challenge_secret: file not found at ", path,
            " (", open_err, ") — L2.1 cookie verify and L5 cookie issue ",
            "will be skipped until the file is dropped in and nginx reloaded")
        clear(dict)
        return false
    end
    -- Bounded read: MAX_BYTES + 1, чтобы отличить «ровно по лимиту» от
    -- «больше лимита» (защита от мисмаунта на /dev/urandom или большой файл —
    -- f:read('*a') блокировал бы master в init_by_lua).
    local raw = f:read(MAX_BYTES + 1)
    f:close()
    if not raw then
        ngx.log(ngx.ERR, "challenge_secret: read failed at ", path)
        clear(dict)
        return false
    end
    if #raw > MAX_BYTES then
        ngx.log(ngx.ERR, "challenge_secret: ", path, " is larger than ",
            MAX_BYTES, " bytes — refusing to load (check the mount path; ",
            "a real HMAC secret is ~44 base64 bytes)")
        clear(dict)
        return false
    end

    local secret = rstrip(raw)
    if #secret < MIN_BYTES then
        ngx.log(ngx.ERR, "challenge_secret: ", path, " holds ", #secret,
            " bytes after trim, need >= ", MIN_BYTES,
            " — refusing to load (generate with scripts/generate-challenge-secret.sh)")
        clear(dict)
        return false
    end

    -- Set both keys, treat partial success as failure: a stored secret
    -- without its fp (or vice versa) would let /__admin and /__version
    -- report stale "null" / wrong fingerprint while get() still returns
    -- the secret. clear() wipes both on any failure (fail-closed).
    local fp = fingerprint(secret)
    local ok, set_err = dict:set(KEY_SECRET, secret)
    if ok then
        ok, set_err = dict:set(KEY_FP, fp)
    end
    if not ok then
        ngx.log(ngx.ERR, "challenge_secret: shared_dict set failed: ", set_err)
        clear(dict)
        return false
    end
    ngx.log(ngx.INFO, "challenge_secret: loaded from ", path, " (fp=", fp, ")")
    return true
end

-- get() — для C3 (verify) и C5 (issue). Возвращает (secret, fp) или nil
-- если secret не загружен. Consumers обязаны проверять nil и не пытаться
-- подписывать/проверять при его отсутствии — фастпас cookie просто пропускается.
function _M.get()
    local dict = ngx.shared[DICT_NAME]
    if not dict then return nil end
    local secret = dict:get(KEY_SECRET)
    if not secret then return nil end
    return secret, dict:get(KEY_FP)
end

-- fingerprint() — публичный 8-hex маркер для /__version и /__admin.
-- Возвращает nil если secret не загружен. Сам secret эта функция не
-- касается — read-only из dict.
function _M.fingerprint()
    local dict = ngx.shared[DICT_NAME]
    if not dict then return nil end
    return dict:get(KEY_FP)
end

return _M
