-- challenge_verify.lua — POST /__challenge/verify endpoint (C5).
--
-- Phase 4, vision §5.2 "Branch A". It accepts the JSON payload from the JS solver in
-- challenge/page.html: { nonce, token, cascade_version, not_a_robot, fp }.
-- On success it issues a clearance cookie through clearance.issue (the same
-- HMAC scheme as the L2.1 verify, C3) and answers 200; the JS reloads the original
-- URL and now fastpaths the cascade on cookie_valid.
--
-- The endpoint lives SEPARATELY from verdict.lua: verification of a request with
-- an unsigned cookie already went to /__challenge through ngx.exec from the verdict
-- pipeline; the same request carrying the answer arrives at a new URL outside the cascade
-- (a carve-out in nginx.demo.conf), otherwise the grey verdict would bounce it back to
-- a challenge before we managed to issue the cookie.
--
-- The payload contract is pinned to the template through cascade_version. Any
-- divergence of fields / JS_SECRET / the endpoint path requires bumping
-- CASCADE_VERSION at the same time (challenge/README.md). The cascade_version in the POST
-- is compared with the server's — protection against a stale browser cache holding an old
-- challenge page (which would send the old nonce format after a rollout).
--
-- A single-use nonce. Replay protection per vision §5.2 rests on the TTL (60 s) plus
-- single use: the first successful verify of a nonce puts its HMAC segment into
-- ngx.shared.used_nonces with TTL = exp - now + slack; a repeat verify of the same
-- nonce (a replay inside the expiry window) returns `consumed` and a 403.

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

-- JS_SECRET — must match the constant in challenge/page.html. It is the
-- "pepper" that turns a nonce-only POST into proof of JS execution: a
-- bot with no JS engine cannot compute the hash. The cryptographic strength comes from the nonce's HMAC
-- (challenge.issue_nonce); the pepper is only the signal "JS really executed".
-- Rotating it (a new pepper value) is mandatory together with a bump of
-- CASCADE_VERSION — otherwise an old template in a browser cache sends a token
-- from the old pepper and verify returns `bad_token` (a false positive).
local JS_SECRET = "tf_challenge_v1_proof_of_execution"

-- The cookie TTL — vision §2.1/§5.3, "86400 in normal mode / 3600 under
-- attack_mode=on". The choice is made per request from `policy.get(host).attack_mode`
-- for EXACTLY the host the request came to (vision §2.1: one customer enabling
-- attack_mode does not touch another's cookie TTLs — a cookie is
-- scoped Domain=<host>). The short under_attack TTL is itself the
-- "during-attack" marker for the L2.1 verify (C7): such a cookie fastpaths until the attack
-- ends, while long pre-attack cookies do not fastpath under attack (clearance.lua
-- RESULT_STALE_PRE_ATTACK). DEFAULT_COOKIE_TTL is the fallback when the config is not
-- loaded.
local DEFAULT_COOKIE_TTL = 86400

-- The max request body — the JSON payload (~500 B typically, with a fingerprint). 4 KiB leaves room for
-- the fingerprint field to grow (canvas/audio fingerprints in future) and cuts
-- spam payloads before the JSON is parsed.
local MAX_BODY_BYTES = 4096

-- The result codes — written into the `antibot_challenge_invalid_total{reason}`
-- metric. The names match the phase2-spec/rules-reference terms
-- (bad_nonce / expired / replay / bad_token / wrong_version), plus the
-- bookkeeping outcomes (body / json / shape).
_M.REASON_BAD_NONCE     = "bad_nonce"
_M.REASON_EXPIRED       = "expired"
_M.REASON_REPLAY        = "replay"
_M.REASON_BAD_TOKEN     = "bad_token"
_M.REASON_WRONG_VERSION = "wrong_version"
_M.REASON_BAD_BODY      = "bad_body"
_M.REASON_BAD_METHOD    = "bad_method"
_M.REASON_NO_SECRET     = "no_secret"

-- b64url decode mirroring challenge.lua / clearance.lua (RFC 4648 §5,
-- no padding). Kept as a local function rather than a shared util — three
-- different modules keep their own copy to minimise coupling
-- (see clearance.lua and challenge.lua).
local function b64url_decode(s)
    if type(s) ~= "string" then return nil end
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    return ngx.decode_base64(s)
end

-- A constant-time compare of the same shape as in clearance.lua. It is used
-- ONLY for the byte comparison of the HMAC (sig vs expected). The token (the hex SHA-256
-- of nonce+JS_SECRET) is also compared through ct_eq — even though a timing oracle
-- over JS_SECRET is less critical in our model (a pepper, not a secret), it
-- protects against guessing a character by timing should this later become a per-host
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
-- HMAC stress test of the nonce: parse the `<payload_b64>.<sig_b64>` template, the HMAC
-- recompute, ct_eq, payload decode, exp/host check. NO single-use here —
-- consume_nonce happens AFTER the token check, otherwise bad_token POSTs
-- would eat a valid nonce and a legitimate retry would break.
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

    -- The HMAC recompute. It mirrors challenge.issue_nonce: payload_b64 is what
    -- was signed (NOT the raw payload JSON). A divergence between "what we signed"
    -- and "what we verify" is the main class of bug in HMAC schemes, so the
    -- reader should keep both places in view at once.
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

    -- The payload is trustworthy — the HMAC passed. Decode plus the exp/host check.
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

    -- Host binding: the nonce was signed for a specific host. A cross-tenant
    -- replay (obtain a nonce on site A, send the verify to site B) is rejected even with
    -- the pool's shared HMAC secret.
    if type(payload.h) ~= "string" or payload.h == "" or payload.h ~= host then
        return nil, _M.REASON_BAD_NONCE
    end

    return payload, sig_b64
end

-- verify_token(nonce, token) → bool. token = hex(SHA-256(nonce || JS_SECRET)).
-- We compare them as byte strings through ct_eq.
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
-- We use the HMAC segment as the single-use key (rather than the whole nonce): it is unique
-- by construction (an HMAC over the payload), shorter than payload+sig, and does not
-- leak the host into the shared dict. TTL = exp - now + 5 s of slack — entries
-- are swept automatically once the nonce expires and do not accumulate.
--
-- `dict:add` distinguishes two classes of failure: `err == "exists"` is a real
-- replay (the nonce was already consumed inside the TTL window), while `err == "no memory"`
-- means the shared_dict is full and LRU found nothing to evict. Without a dedicated
-- ERR log, OOM would masquerade as a replay (from review) —
-- the `challenge_invalid_total{reason="replay"}` metric would grow under OOM
-- while the real problem is the `lua_shared_dict used_nonces` sizing. We log an ERR
-- and continue fail-closed (the same 403 for the client — better to refuse
-- than to issue a cookie on a possible replay).
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

-- bump_counter — every challenge metric lives in ngx.shared.metrics.
-- No dedicated shortcut (unlike verdict.lua) — the module is called by a
-- single content_by_lua and has no hot path.
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

    -- The cascade version pin. The template is bound to a specific cascade version
    -- (challenge/page.html `data-cascade-version` plus the meta tag). After a bump, a
    -- browser with the old page cached arrives here with the old
    -- `cascade_version` — we reject it (otherwise an old-format payload would pass
    -- invalidly). We compare against the value challenge.preload()
    -- checked at init and stored in template_version().
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
        -- An empty host usually means a broken upstream or proxy (a request with no
        -- Host header, HTTP/1.0 without one, or proxy_set_header splitting it).
        -- Without a host, verify_nonce fails on the host binding and clearance.issue
        -- fails on 'host required'. We return bad_body so as not to pollute the
        -- no_secret/bad_nonce metrics, which signal different operational
        -- problems (from code review).
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

    -- The cookie TTL (C7). defaults.conf [allow.cookie_valid] holds two points:
    -- `ttl_seconds_normal` (vision §2.1 — 86400) and `ttl_seconds_under_attack`
    -- (vision §2.1/§5.3 — 3600 under attack_mode=on). We pick the key by
    -- the attack_mode of EXACTLY this host: under attack we issue the short
    -- under_attack TTL — the during-attack marker that lets the L2.1 verify
    -- keep fastpathing the cookie until the attack ends (see clearance.lua).
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

    -- The Set-Cookie attributes — vision §5.2: HttpOnly, Secure, SameSite=Lax,
    -- Domain=<host> (with no leading dot), Path=/.
    --
    -- We omit the Domain attribute for IPv4/IPv6/localhost: per RFC 6265 §5.2.3
    -- «If the user agent receives a cookie with a Domain attribute that
    -- contains an IP address, the user agent MUST silently ignore the
    -- cookie", and the same for `localhost`. Without the attribute the browser creates a
    -- host-only cookie (sent only to that same host) — which is the
    -- expected behaviour for the demo stand and the integration harness,
    -- which often hit it by IP or `localhost` (from review).
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

    -- The BAC_LOG challenge-pass event (vision §5.2, "Collecting the browser fingerprint
    -- for analytics ... it travels with the challenge-pass event along the
    -- same path as ordinary logs"). The endpoint sits outside verdict.lua, so
    -- bac_log.init() is explicit here; emit() writes to stdout and enqueues into
    -- log_shipper (the same channel as ordinary requests). Without this
    -- block the browser fingerprint collected by the JS solver would never
    -- reach the backend telemetry — and that is an explicit contract from the vision
    -- (codex review on PR #87).
    --
    -- verdict=allow, rule=challenge_pass — a dedicated rule code, so that
    -- analytics can tell "solved the challenge" from the other allow branches
    -- (cookie_valid / bot_verified / ip_whitelist). It matches the
    -- entities-reference Phase 4 category of challenge events.
    local bac_log = require "bac_log"
    bac_log.init()
    bac_log.set_verdict("verification", "allow", "challenge_pass")
    -- [D12] Attach the client's TLS fingerprint so the solved (challenge_pass)
    -- event JOINS to the issued (verdict=challenge) events keyed by tls_fp in
    -- analyze.py. This endpoint is a carve-out (no access_by_lua), so the L3
    -- tls_fp stage never ran and ctx.tls_fp is unset — without this the record
    -- carries only challenge_fp (the browser JS fp) with tls_fp=null, and
    -- _event_from_bac_line drops it → challenge_solved stays 0 for every fp and
    -- the solve-rate signal would mislabel solving humans as bots. The verify
    -- request is the SAME TLS client that was challenged, so its computed fp
    -- matches the issued challenge's tls_fp (same compute() the cascade uses,
    -- verdict.lua:176-177).
    local ja4 = require "ja4_compute"
    bac_log.set_tls_fp(ja4.compute())
    -- payload.fp came from attacker-controlled JSON (the body is already capped at
    -- MAX_BODY_BYTES, but fp as a subtree can occupy almost the whole
    -- limit and, if deeply nested, break cjson.encode inside
    -- bac_log.emit — emit would return early with an ERR log and the challenge-pass
    -- record would vanish entirely (the attacker silently gets a cookie with no
    -- audit trail; from code review). We pre-validate: encode here
    -- through cjson.safe, check the size, and only then hand it to
    -- bac_log. On failure — fp=nil plus a WARN; the cookie is still issued,
    -- but bac_log.emit definitely will not break and the challenge_pass record arrives.
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
