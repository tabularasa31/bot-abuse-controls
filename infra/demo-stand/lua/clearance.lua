-- L2.1 clearance cookie verify. The client presents an HMAC-signed cookie
-- issued after solving the challenge; the proxy verifies it locally.
--
--     body = b64url(<site-host>) .. ":" .. <iat> .. ":" .. <exp>
--     cookie = body .. "." .. b64url(HMAC-SHA256(secret, body))
--
-- A bearer token: nothing binds it to a fingerprint, so a stolen cookie works
-- until it expires. Cross-tenant use is contained by the Domain attribute and
-- the site check.
--
-- Under attack, cookies issued beforehand are not trusted — an attacker could
-- have stockpiled them. They are told apart by TTL type, which is why a user
-- solves one challenge per attack rather than one per request. A short cookie
-- from a previous attack inside its own window is accepted; separating those
-- would need the attack start time in the policy.
local hmac   = require "resty.openssl.hmac"
local bit    = require "bit"
local secret = require "challenge_secret"

-- Lazy: the unit tests bypass init.lua, so the require must not be fatal.
local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

local DEFAULT_COOKIE_NAME = "tf_clearance"

-- These double as the metric labels.
_M.RESULT_VALID      = "valid"
_M.RESULT_INVALID    = "invalid"     -- HMAC signature mismatch / sig decode failed
_M.RESULT_EXPIRED    = "expired"     -- HMAC ok, exp <= now
_M.RESULT_MISSING    = "missing"     -- no cookie header
_M.RESULT_MALFORMED  = "malformed"   -- structure unparseable
_M.RESULT_WRONG_SITE = "wrong_site"  -- HMAC ok but payload.site ~= request host
-- Its own code, so the attack-mode trust reset stays distinguishable from a
-- crypto failure.
_M.RESULT_STALE_PRE_ATTACK = "stale_pre_attack"
-- Distinct from invalid, so a secret outage cannot look like an attack.
_M.RESULT_NO_SECRET  = "no_secret"

-- nginx variable names allow only [A-Za-z0-9_], so a cookie name with a hyphen
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

-- Constant-time: the loop must run to the end, or the timing recovers the
-- signature byte by byte.
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

-- Lives next to verify so the payload format has one owner. The caller picks
-- the TTL, since the per-host attack state is not visible here.
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

-- Pure: the caller records the verdict and the metric.
--
-- Check order is deliberate — structure, then HMAC, then site and expiry. An
-- untrusted payload is never interpreted, and the cheap checks cannot become a
-- timing oracle for whether the signature matched.
function _M.verify(host, opts)
    local name = get_cookie_name()
    local raw  = ngx.var["cookie_" .. name]
    if not raw or raw == "" then
        return _M.RESULT_MISSING
    end

    -- Rightmost `.`, so a future payload containing one still parses.
    local body, sig_b64 = raw:match("^(.+)%.([^.]+)$")
    if not body or not sig_b64 then
        return _M.RESULT_MALFORMED
    end

    -- Structural check first, to skip the crypto on a garbage cookie.
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
        -- Fail closed: with no secret nothing can be trusted.
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

    -- Expiry before site, so an ordinary expired cookie under apex Domain
    -- scoping does not read as a cross-tenant attempt.
    local exp = tonumber(exp_s)
    if not exp or exp <= ngx.time() then
        return _M.RESULT_EXPIRED
    end

    if site ~= host then
        return _M.RESULT_WRONG_SITE
    end

    -- Under attack a long TTL means the cookie predates it. Fail closed with no
    -- threshold: failing open would cancel the trust reset entirely.
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
