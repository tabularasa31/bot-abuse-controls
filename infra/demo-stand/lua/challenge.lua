-- challenge.lua — HTML+JS challenge page renderer + nonce issuer (C2).
--
-- Phase 4, vision §5.2 "Branch A". The edge substitutes one self-signed nonce into
-- the HTML+JS template and serves the page to the client; the JS computes SHA-256(nonce +
-- JS_SECRET) and POSTs the token to the verify endpoint. Only issuance lives here
-- (render plus issue_nonce); verify lands in C5, which reuses
-- challenge_secret.get() (C1) for the HMAC and reads the same nonce payload.
--
-- Template delivery on the demo is a file mount (Channel A on the demo). It is loaded
-- exactly once in init_by_lua (see init.lua: `require("challenge").preload`), and
-- workers inherit the cached string through fork. Changing the template means
-- bump `CASCADE_VERSION` + edit `page.html` + `openresty -s reload`.
--
-- The nonce format is a two-segment token `<payload-b64url>.<hmac-b64url>`:
--   payload = cjson.encode({h=<host>, ts=<issued_unix>, exp=<expiry_unix>})
--   hmac    = HMAC-SHA256(secret = challenge_secret.get(), data = payload-b64url)
-- C5 decodes the payload, verifies the HMAC, checks `exp > ngx.time()` and
-- checks that `h` matches the request host. The TTL is ≈60 s (defaults.conf
-- [challenge].nonce_ttl_seconds) — that is the "single use" of the nonce from the
-- acceptance criteria: the usage window is bounded hard by the expiry, and a replay
-- after it is rejected.

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
-- [challenge].nonce_ttl_seconds (vision §5.2, "TTL 60 s"). We keep a baked-in
-- default so issue_nonce stays operational if the config section is missing
-- (e.g., older defaults.conf during a partial rollout) — never silently
-- "no TTL" / "TTL=0", which would invalidate every nonce instantly.
local DEFAULT_NONCE_TTL = 60

-- TEMPLATE_PATH / VERSION_PATH are resolved through env, so that the integration
-- harness and the unit tests can override the paths without editing defaults.conf.
-- Production keeps the default paths from the docker-compose mounts.
local TEMPLATE_PATH = os.getenv("CHALLENGE_TEMPLATE_FILE")
    or "/etc/nginx/challenge/page.html"
local VERSION_PATH  = os.getenv("CASCADE_VERSION_FILE")
    or "/etc/nginx/CASCADE_VERSION"

-- read_file — a bounded read, so that an accidental mis-mount onto a large file
-- (`/dev/urandom`, a bulky log) does not hang the master in init_by_lua. 64 KiB
-- gives ~16× headroom over the current template (~3 KiB) and cuts off any
-- reasonable "somebody mixed up the mount".
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

-- A module-level cache: filled by preload() from init_by_lua. Without preload,
-- render() still works (a lazy load), but the fallback is undesirable on the hot path —
-- the preload check catches a CASCADE_VERSION ↔ meta tag divergence at
-- startup, before the first request.
local cached_template
local cached_version

-- parse_version_from_template — the single point for extracting the version from the template
-- (used both in preload and in the render fallback). We look for
-- `<meta name="cascade-version" content="...">`. That is the only
-- machine-checked marker; the HTML comment `<!-- cascade-version: ... -->`
-- is for the human eye in curl output and is not parsed by this function.
local function parse_version_from_template(html)
    return html:match('<meta%s+name="cascade%-version"%s+content="([^"]+)"')
end

-- preload() — called from init.lua. It reads CASCADE_VERSION and the template and
-- compares the versions. A mismatch → error(), which fails init_by_lua and the container does
-- not start. That is the C2 version-pin invariant: the cascade and the template can
-- only diverge deliberately (a bump in both places at once).
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

-- base64url — without padding, RFC 4648 §5. ngx.encode_base64 gives standard
-- base64; we convert character by character. Compact is enough for one nonce per
-- request, and the hot path is not upstream of this.
local function b64url(raw)
    local s = ngx.encode_base64(raw)
    s = s:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
    return s
end

-- issue_nonce(host) → (nonce_string, expiry_ts) | nil, err.
--   nonce_string = b64url(payload_json) .. "." .. b64url(hmac_sha256)
-- The TTL comes from defaults.conf [challenge].nonce_ttl_seconds (see
-- config.lua); 60 is the default per vision §5.2.
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

-- substitute — a targeted placeholder replacement. gsub is in pattern mode (the 4th
-- argument is nil), but the template placeholders `{{NONCE}}` /
-- `{{EXPIRY}}` / `{{CASCADE_VERSION}}` contain no Lua pattern
-- metacharacters, so that is fine. The replacement is a function (rather than a string), so that
-- values containing `%` in the output do not break the back-reference.
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
