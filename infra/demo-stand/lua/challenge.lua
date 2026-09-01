-- Renders the challenge page and issues its nonce. The page computes
-- SHA-256(nonce + JS_SECRET) and POSTs the token back.
--
-- The template is loaded once at init and inherited through fork, so changing
-- it means bumping CASCADE_VERSION and reloading.
--
-- The nonce carries the host and a short expiry, which is what makes it
-- single-use.

local cjson  = require "cjson.safe"
local hmac   = require "resty.openssl.hmac"
local secret = require "challenge_secret"
-- Lazy: the unit tests bypass init.lua, so the require must not be fatal.
local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

-- Never silently zero, which would invalidate every nonce as it was issued.
local DEFAULT_NONCE_TTL = 60

-- Overridable so the tests and the harness need not edit the config.
local TEMPLATE_PATH = os.getenv("CHALLENGE_TEMPLATE_FILE")
    or "/etc/nginx/challenge/page.html"
local VERSION_PATH  = os.getenv("CASCADE_VERSION_FILE")
    or "/etc/nginx/CASCADE_VERSION"

-- Bounded, so a mis-mount onto a large file cannot hang the master.
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

-- Filled by preload at init. render() would lazily load too, but preload is
-- what catches a version divergence before the first request.
local cached_template
local cached_version

-- The meta tag is the machine-checked marker; the HTML comment is for humans.
local function parse_version_from_template(html)
    return html:match('<meta%s+name="cascade%-version"%s+content="([^"]+)"')
end

-- A mismatch fails init_by_lua and the container does not start. That is the
-- pin: template and cascade can only diverge through a deliberate bump of both.
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

-- Unpadded base64url, RFC 4648 §5.
local function b64url(raw)
    local s = ngx.encode_base64(raw)
    s = s:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
    return s
end

function _M.issue_nonce(host, ttl_seconds)
    if type(host) ~= "string" or host == "" then
        return nil, "host required"
    end
    local key = secret.get()
    if not key then
        return nil, "challenge_secret not loaded (see C1: challenge_secret.lua)"
    end
    -- Argument, then config, then default; tonumber guards the INI string.
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

    -- Explicit update() then final(): the one-call form would let a version
    -- drift silently sign the empty string.
    local h, hmac_err = hmac.new(key, "sha256")
    if not h then return nil, "hmac.new: " .. tostring(hmac_err) end
    local upd_ok, upd_err = h:update(payload_b64)
    if not upd_ok then return nil, "hmac.update: " .. tostring(upd_err) end
    local sig, sig_err = h:final()
    if not sig then return nil, "hmac.final: " .. tostring(sig_err) end

    return payload_b64 .. "." .. b64url(sig), exp
end

-- The replacement is a function so that a `%` in the value cannot be read as a
-- back-reference.
local function substitute(tpl, vars)
    local function repl(name)
        return tostring(vars[name] or "")
    end
    return (tpl:gsub("{{([A-Z_]+)}}", repl))
end

-- render(host) → html_string | nil, err. It substitutes a fresh nonce plus the expiry
-- plus the version into the cached template. The HTTP output (status / headers /
-- ngx.say) is the caller's job (C5); render is a pure function, which is convenient for
-- unit tests and for debugging consumers.
function _M.render(host, ttl_seconds)
    if not cached_template then
        _M.preload()
    end
    local nonce, exp_or_err = _M.issue_nonce(host, ttl_seconds)
    if not nonce then
        return nil, exp_or_err
    end
    -- CASCADE_VERSION is already a literal in the template (the preload invariant: the
    -- template's meta tag == the contents of the CASCADE_VERSION file). We substitute only
    -- the per-request values.
    return substitute(cached_template, {
        NONCE   = nonce,
        EXPIRY  = exp_or_err,
    })
end

return _M
