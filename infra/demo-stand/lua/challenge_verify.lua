-- The POST /__challenge/verify endpoint: takes the solver's payload and on
-- success issues a clearance cookie.
--
-- It sits outside the cascade deliberately — the answer arrives at a new URL,
-- and running the cascade here would bounce it back to a challenge before the
-- cookie could be issued.
--
-- cascade_version pins the payload to the template, so a browser holding a page
-- cached from before a rollout cannot POST the old nonce format.
--
-- Replay protection is the short TTL plus single use.

local cjson  = require "cjson.safe"
local hmac   = require "resty.openssl.hmac"
local sha256 = require "resty.sha256"
local str    = require "resty.string"
local bit    = require "bit"
local secret = require "challenge_secret"
local clearance = require "clearance"
local policy = require "policy"

local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

-- Must match the constant in the page. A pepper, not a secret: it only proves
-- JS ran. Changing it requires a CASCADE_VERSION bump.
local JS_SECRET = "tf_challenge_v1_proof_of_execution"

-- Per host, so one customer's attack mode cannot shorten another's cookies.
-- The short TTL is itself the during-attack marker L2.1 reads.
local DEFAULT_COOKIE_TTL = 86400

-- Room for the fingerprint to grow, and it cuts spam before the JSON is parsed.
local MAX_BODY_BYTES = 4096

-- These become the reason label on the rejection metric.
_M.REASON_BAD_NONCE     = "bad_nonce"
_M.REASON_EXPIRED       = "expired"
_M.REASON_REPLAY        = "replay"
_M.REASON_BAD_TOKEN     = "bad_token"
_M.REASON_WRONG_VERSION = "wrong_version"
_M.REASON_BAD_BODY      = "bad_body"
_M.REASON_BAD_METHOD    = "bad_method"
_M.REASON_NO_SECRET     = "no_secret"

-- Each module keeps its own copy rather than sharing one, to stay decoupled.
local function b64url_decode(s)
    if type(s) ~= "string" then return nil end
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    return ngx.decode_base64(s)
end

-- Also used for the token: it would matter if the pepper became per-host.
local function ct_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    if #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
    end
    return diff == 0
end

-- Single use is deliberately not applied here: consuming before the token check
-- would let a wrong-token POST burn a valid nonce.
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

    -- What was signed is the encoded payload, not the raw JSON. A divergence
    -- between signing and verifying is the classic bug here.
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

    -- Host binding: a nonce obtained on one site cannot be verified on another,
    -- even though the secret is shared across the pool.
    if type(payload.h) ~= "string" or payload.h == "" or payload.h ~= host then
        return nil, _M.REASON_BAD_NONCE
    end

    return payload, sig_b64
end

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

-- The HMAC segment is the key: unique by construction and it keeps the host out
-- of the dict. The TTL expires with the nonce, so entries never accumulate.
--
-- "exists" is a real replay; "no memory" means the dict is undersized. Confusing
-- them would show an exhausted dict as a replay spike.
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

local function bump(key)
    local m = ngx.shared.metrics
    if m then m:incr(key, 1, 0) end
end

local function bump_invalid(reason)
    bump("challenge_invalid_" .. reason .. "_total")
end

-- handle() — the content_by_lua entry point. It is not called from verdict.lua (a carve-out
-- in the nginx config: location /__challenge/verify without access_by_lua).
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
        -- buffer, so that cannot happen for our payload; an empty
        -- body really does mean "the client sent nothing".
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

    -- After a bump, a browser holding the cached old page arrives with the old
    -- version; rejecting it stops an old-format payload from validating.
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
        -- Reported as a bad body rather than a nonce or secret failure, which
        -- signal genuinely different operational problems.
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
        -- only on a SUCCESSFUL verify (consume_nonce below).
        bump_invalid(_M.REASON_BAD_TOKEN)
        return ngx.exit(403)
    end

    -- Single use: an atomic add into the shared dict. The first is true, a repeat
    -- (a replay inside the TTL window) is false. We do it AFTER the token verify, so that
    -- an unsuccessful POST does not burn a valid nonce (see the comment above).
    if not _M.consume_nonce(sig_b64, nonce_payload.exp) then
        bump_invalid(_M.REASON_REPLAY)
        return ngx.exit(403)
    end

    -- Under attack this issues the short TTL, which is what lets L2.1 keep
    -- fastpathing the cookie for the rest of the attack.
    local ttl = DEFAULT_COOKIE_TTL
    if config and type(config.defaults) == "table" then
        local allow = config.defaults.allow
        if type(allow) == "table" and type(allow.cookie_valid) == "table" then
            local cv = allow.cookie_valid
            local p = policy.get(host)
            local ttl_key = (p and p.attack_mode)
                and "ttl_seconds_under_attack" or "ttl_seconds_normal"
            local t = tonumber(cv[ttl_key])
            if t and t > 0 then ttl = t end
        end
    end

    local cookie_value, cerr = clearance.issue(host, ttl)
    if not cookie_value then
        ngx.log(ngx.ERR, "challenge_verify: clearance.issue failed: ", cerr)
        bump_invalid(_M.REASON_NO_SECRET)
        return ngx.exit(500)
    end

    -- Domain is omitted for IP literals and localhost: RFC 6265 §5.2.3 says a
    -- user agent must silently ignore a cookie whose Domain is an IP address.
    -- Without the attribute the browser makes it host-only, which is what the
    -- stand and the integration harness need when they connect by IP.
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

    -- The endpoint is outside the cascade, so the log context is initialised
    -- here; without this the fingerprint the solver collected would never reach
    -- telemetry at all.
    --
    -- challenge_pass is its own rule code so that solving a challenge is
    -- distinguishable from the other allow paths.
    local bac_log = require "bac_log"
    bac_log.init()
    bac_log.set_verdict("verification", "allow", "challenge_pass")
    -- The solved event has to carry the TLS fingerprint, or it cannot be joined
    -- to the issued one and the solve rate reads as zero for every fingerprint —
    -- which would label solving humans as bots. The L3 stage never ran here, so
    -- it is computed explicitly; this is the same TLS client that was
    -- challenged.
    local ja4 = require "ja4_compute"
    bac_log.set_tls_fp(ja4.compute())
    -- This subtree is attacker-controlled and can be deeply nested enough to
    -- break the encode inside emit — which would drop the whole record and hand
    -- out a cookie with no audit trail. Encoding it here first means the worst
    -- case is a missing fingerprint rather than a missing event.
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

    -- 200 OK with an empty body: the JS on page.html calls window.location.reload(),
    -- the browser sends a fresh GET with the cookie attached, and the cascade fastpaths
    -- at L2.1 (clearance.verify → RESULT_VALID).
    ngx.status = 200
    ngx.header.content_type = "text/plain; charset=utf-8"
    ngx.print("ok")
    return ngx.exit(200)
end

return _M
