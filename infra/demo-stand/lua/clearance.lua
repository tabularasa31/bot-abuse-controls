-- L2.1 clearance cookie verify.
--
-- The client presents an HMAC-signed cookie issued at L5 after solving the JS
-- challenge; the proxy verifies it locally, with no call to the backend. A
-- valid cookie allows the request and skips L3 and L5, but not L4 — the cookie
-- proves the client is not a scripted bot, not that it may abuse.
--
-- Format:
--     body = b64url(<site-host>) .. ":" .. <iat> .. ":" .. <exp>
--     sig  = b64url(HMAC-SHA256(secret, body))
--     cookie value = body .. "." .. sig
--
-- It is a bearer token: nothing binds it to a fingerprint, so whoever steals it
-- within its TTL can use it. Cross-tenant use is contained by the Domain
-- attribute plus the site check in the payload.
--
-- Under attack_mode the pre-attack gate applies: cookies issued before the
-- attack started are not trusted, because an attacker could have stockpiled
-- them. They are told apart by TTL type — a normal cookie carries 24 h, one
-- issued during the attack carries 1 h — so only the short ones fastpath. That
-- is what makes it one challenge per attack rather than one per request. The
-- threshold arrives from the caller, keeping verify a pure function.
--
-- The TTL mechanism has a known limit: a short cookie from a previous attack is
-- accepted during a new attack starting inside its 1 h window. Telling those
-- apart would need the attack start time in the policy.
local hmac   = require "resty.openssl.hmac"
local bit    = require "bit"
local secret = require "challenge_secret"

-- Lazy: the unit tests bypass init.lua, so the require must not be fatal.
local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

-- Pool-wide constant, like the HMAC secret; overridable only through the config.
local DEFAULT_COOKIE_NAME = "tf_clearance"

-- These double as the metric labels.
_M.RESULT_VALID      = "valid"
_M.RESULT_INVALID    = "invalid"     -- HMAC signature mismatch / sig decode failed
_M.RESULT_EXPIRED    = "expired"     -- HMAC ok, exp <= now
_M.RESULT_MISSING    = "missing"     -- no cookie header
_M.RESULT_MALFORMED  = "malformed"   -- structure unparseable
_M.RESULT_WRONG_SITE = "wrong_site"  -- HMAC ok but payload.site ~= request host
-- Its own code rather than invalid/expired, so the attack-mode trust reset stays
-- distinguishable from crypto failures in the metric.
_M.RESULT_STALE_PRE_ATTACK = "stale_pre_attack"
-- Distinct from `invalid` so a secret outage cannot hide behind what looks like
-- an attack, and can be alerted on separately.
_M.RESULT_NO_SECRET  = "no_secret"

-- nginx variable names allow only [A-Za-z0-9_], and `ngx.var["cookie_x-y"]`
-- silently returns nil. Without this guard a cookie name containing a hyphen
-- would make every request look cookie-less, with nothing in the log.
local function valid_var_suffix(name)
    return name:match("^[%w_]+$") ~= nil
end

local warned_bad_name = false
-- Per worker, so the WARN below fires once rather than per request.
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

-- Constant-time compare: the loop must run to the end, or the timing difference
-- lets an attacker recover the signature byte by byte.
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

-- Lives next to verify so the payload format has one owner: a divergence
-- between the two would invalidate every cookie on rollout.
--
-- The caller picks ttl_seconds, since the per-host attack state is not visible
-- from here. `now` is a test override.
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

-- Returns a RESULT_* code. Pure: the caller records the verdict and the metric,
-- which keeps this testable without an ngx stub.
--
-- Check order is deliberate. Structure is parsed, then the HMAC is verified, and
-- only then are site and expiry read — an untrusted payload is never
-- interpreted, and the cheap checks cannot become a timing oracle for whether
-- the signature matched.
--
-- `opts` carries the attack context: {attack_mode, max_under_attack_ttl}.
function _M.verify(host, opts)
    local name = get_cookie_name()
    local raw  = ngx.var["cookie_" .. name]
    if not raw or raw == "" then
        return _M.RESULT_MISSING
    end

    -- Split on the rightmost `.`, so a future payload containing one still
    -- parses.
    local body, sig_b64 = raw:match("^(.+)%.([^.]+)$")
    if not body or not sig_b64 then
        return _M.RESULT_MALFORMED
    end

    -- Structural check before the HMAC: anything malformed would fail the HMAC
    -- anyway, and this skips the crypto on a garbage cookie.
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
        -- Fail closed: with no secret nothing can be trusted, and the request
        -- takes the full cascade.
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

    -- Expiry is checked before the site so that an ordinary expired cookie under
    -- apex Domain scoping reads as expired rather than as a cross-tenant
    -- attempt. wrong_site should mean something.
    local exp = tonumber(exp_s)
    if not exp or exp <= ngx.time() then
        return _M.RESULT_EXPIRED
    end

    if site ~= host then
        return _M.RESULT_WRONG_SITE
    end

    -- The cookie is otherwise valid; under attack a long TTL means it predates
    -- the attack. Exactly the under-attack TTL still fastpaths.
    --
    -- Fail closed without a threshold: pre-attack cannot be told from
    -- during-attack, and failing open would silently cancel the trust reset
    -- that is the whole point of the gate.
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
