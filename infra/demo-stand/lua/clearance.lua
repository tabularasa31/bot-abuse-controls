-- clearance.lua — L2.1 clearance cookie verify (C3).
--
-- Phase 4, vision §5.2 / §2.1, rules-reference rule `cookie_valid`. The client
-- presents an HMAC-signed cookie (issued at L5 after solving the JS
-- challenge — C5, not implemented yet); the proxy verifies the signature locally
-- with no call to the backend. A valid cookie → verdict=allow, rule=cookie_valid;
-- it skips L3 (tls_fp) and L5 (verification), but NOT L4 (rate limits still
-- apply — vision §2.1 and rules-reference rule 3).
--
-- A DIVERGENCE, task vs docs. The C3 wording in the tracker proposes a payload
-- of `<site>:<fp>:<expiry_ts>` with fingerprint binding and a `wrong_fp` metric.
-- That contradicts vision.md §5.2 ("a bearer token with no fingerprint binding —
-- whoever steals the cookie within its 24-hour TTL can use it") and
-- edge-lua-vs-sidecar §A6 (the `body.sig` format, with no fingerprint). Per the rule in
-- CLAUDE.md and the task comment, "on a divergence the docs win", the bearer
-- variant is implemented: site and iat in the payload, and no fingerprint binding.
-- Protection from cross-tenant leakage comes from the cookie attributes (Domain=<host>,
-- vision §5.2 "Attributes of the tf_clearance cookie") plus the site check in the payload
-- (defence in depth, the wrong_site metric). If product does end up requiring
-- fingerprint binding, that is a separate ticket which amends vision §5.2 and
-- this implementation together ("Docs vs correctness").
--
-- The cookie format:
--     body = b64url(<site-host>) .. ":" .. <iat> .. ":" .. <exp>
--     sig  = b64url( HMAC-SHA256(secret, body) )
--     cookie value = body .. "." .. sig
-- iat (issued_at, unix seconds) and exp give TTL = exp-iat, which C7
-- attack_mode uses to tell "issued before the attack" from "issued during the attack" (see
-- RESULT_STALE_PRE_ATTACK and `verify(host, opts)` below).
--
-- The attack_mode pre-attack gate (C7, vision §2.1 "The exception: attack_mode=on"
-- and §5.3). Under `attack_mode=on` for a host, L2.1 does not trust clearance
-- cookies issued BEFORE the attack started (an attacker could have stockpiled them).
-- They are told apart by the cookie's TTL TYPE (vision §5.3, "the mechanism is up to
-- the implementation; the issue time and/or the TTL type"): a cookie issued in
-- normal mode carries a long TTL (`ttl_seconds_normal`, 24 h), while a
-- cookie issued during the attack (after re-solving the challenge) carries
-- the short `ttl_seconds_under_attack` (1 h). Under attack, verify fastpaths
-- only the short (during-attack) cookies; long (pre-attack) ones give a separate
-- RESULT_STALE_PRE_ATTACK, which the caller does NOT fastpath — the request walks
-- the cascade to L5 for a challenge. That is what gives "a real user solves the challenge
-- once per attack": their during-attack cookie fastpaths until the attack ends.
-- The threshold comes from opts.max_under_attack_ttl (the caller reads defaults.conf),
-- so that verify stays a pure function with no config dependency in the decision.
-- If the threshold is missing under attack — fail-closed (see the gate itself below).
--
-- A LIMITATION OF THE TTL MECHANISM. We distinguish by TTL magnitude rather than
-- by "iat vs attack_started_at", so a short cookie issued during the PREVIOUS
-- attack will, within its 1 h TTL, be accepted as during-attack in a NEW attack
-- that starts inside that window. The window is bounded by the TTL (1 h), and the
-- holder solved a challenge only recently (≤1 h ago), so the risk is small;
-- vision §5.3 explicitly sanctions the TTL mechanism. A strict "issued during
-- exactly this attack" would need attack_started_at in the policy plus a comparison with iat —
-- a separate ticket, should that delta of risk ever become significant.
--
-- What this module does NOT cover:
--   * issuing the cookie at L5 after a challenge — C5 (it reuses `_M.issue`
--     from here; the normal/under_attack TTL choice lives in challenge_verify.lua).
--   * SECRET rotation runbook — C8.

local hmac   = require "resty.openssl.hmac"
local bit    = require "bit"
local secret = require "challenge_secret"

-- A lazy config require: clearance.lua is loaded in init_by_lua AFTER
-- config.load(), but the unit tests bypass init.lua. The pcall keeps a test without
-- a real config from failing on the require; inside the functions we re-check
-- config.defaults through type(), the way challenge.lua does.
local ok_config, config = pcall(require, "config")
if not ok_config then config = nil end

local _M = {}

-- The default cookie name — vision §5.2 "Attributes of the tf_clearance cookie",
-- defaults.conf [allow.cookie_valid].cookie_name. The C3 ticket proposes
-- `cf_clearance` — we keep `tf_clearance` (docs win). A per-site
-- override goes through [allow.cookie_valid].cookie_name in defaults.conf;
-- there is no per-host override in the policy on the edge (the cookie name is a pool-wide
-- constant, like the HMAC secret).
local DEFAULT_COOKIE_NAME = "tf_clearance"

-- The valid result codes. They match the labels of the
-- `antibot_clearance_verify_total{result=...}` metric (metrics.lua) and are passed
-- into bac_log as the rule suffix (`cookie_valid` for valid; for the rest the
-- verdict is unchanged and no rule is set — the cookie is simply ignored).
_M.RESULT_VALID      = "valid"
_M.RESULT_INVALID    = "invalid"     -- HMAC signature mismatch / sig decode failed
_M.RESULT_EXPIRED    = "expired"     -- HMAC ok, exp <= now
_M.RESULT_MISSING    = "missing"     -- no cookie header
_M.RESULT_MALFORMED  = "malformed"   -- structure unparseable
_M.RESULT_WRONG_SITE = "wrong_site"  -- HMAC ok but payload.site ~= request host
-- stale_pre_attack — the cookie is fully valid (HMAC ok, not expired, the site
-- matched), but under attack_mode=on it carries a long (normal) TTL → it was issued BEFORE
-- the attack started (vision §2.1/§5.3). It does NOT fastpath: the caller sets no
-- clearance_valid and the request walks the cascade to L5 for a challenge. A separate
-- code (rather than invalid/expired) so that attack mode's "trust reset" is visible
-- in the metric separately from crypto failures and ordinary expiries.
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
-- A once-flag for the WARN about a missing max_under_attack_ttl under attack
-- (see the attack_mode pre-attack gate in verify). Per worker, like warned_bad_name.
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

-- ct_eq — constant-time equality for the HMAC compare. Lua `==` on strings
-- of different lengths early-exits (it checks the length first) — which is fine, the length of
-- an HMAC-SHA256 is fixed (32 raw bytes). But the byte-by-byte comparison must
-- run to the end, otherwise a timing oracle lets an attacker guess the signature character by character.
-- bit.bxor plus bit.bor accumulate the difference without branching on content.
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
-- Implemented here (not in challenge.lua) so that the payload format lives in
-- ONE module with verify — an issue/verify divergence would zero every cookie
-- after a rollout. C5 (issuing the cookie after the JS challenge) will call
-- this `_M.issue` and set Set-Cookie with the attributes per vision §5.2
-- (HttpOnly / Secure / SameSite=Lax / Domain=<host> / Path=/).
--
-- ttl_seconds: per vision §2.1 — 86400 in normal mode, 3600 under
-- attack_mode=on for the host. The caller (C5) makes the choice, not this module:
-- there is no access to the per-host policy/attack_mode here without extra coupling.
-- `now` is an optional override for deterministic tests (it defaults to ngx.time()).
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

-- verify(host) → a result code (one of _M.RESULT_*). A pure function: it does not
-- touch ngx.ctx, write metrics or call bac_log. The caller (verdict.lua)
-- interprets the code, updates the verdict, sets the skip flag and increments the
-- counter — which lets tests run verify in host luajit without a full
-- ngx.ctx stub.
--
-- The order of checks is chosen so that the security-critical step (the HMAC verify)
-- does not leak through an early return on cheap signals — otherwise a malformed or
-- expired cookie would give a timing oracle for telling "the HMAC passed or
-- it did not". Here:
--   1. we parse the cookie's structure (malformed → exit, safely: we never reached the HMAC);
--   2. we compute the HMAC and ct_eq;
--   3. AFTER the verify we check the site and exp.
-- If the HMAC is broken we never look at exp/site — the payload is untrustworthy.
-- opts (optional) is the attack_mode context from the caller (verdict.lua). Its fields:
--   * attack_mode          — bool, attack_mode[host]=on for this request;
--   * max_under_attack_ttl — number, the upper bound of a TTL meaning "issued during
--                            the attack" (= ttl_seconds_under_attack from the config).
-- When attack_mode=on and the cookie carries a TTL above the threshold → pre-attack →
-- RESULT_STALE_PRE_ATTACK (see the module header). Purity is preserved:
-- the threshold arrives as an argument and no config is read here.
function _M.verify(host, opts)
    local name = get_cookie_name()
    local raw  = ngx.var["cookie_" .. name]
    if not raw or raw == "" then
        return _M.RESULT_MISSING
    end

    -- The two-segment format `<body>.<sig>`. We use the last `.` as the
    -- separator (the body contains `:` and the base64url alphabet, and no `.`
    -- by construction — but writers of a future payload extension might
    -- add one, so we match the rightmost `.` through "^(.+)%.([^.]+)$").
    local body, sig_b64 = raw:match("^(.+)%.([^.]+)$")
    if not body or not sig_b64 then
        return _M.RESULT_MALFORMED
    end

    -- The body shape: `<b64url(site)>:<iat>:<exp>`. We parse strictly — any
    -- deviation → malformed (we do not trust the content without the HMAC, but
    -- a structural check before the HMAC is safe — the data would have been rejected
    -- by the HMAC too, and this just saves the crypto work on a garbage cookie).
    -- iat is needed under C7 attack_mode to compute the TTL (exp-iat) — the TTL type
    -- tells a pre-attack cookie from a during-attack one (see the module
    -- header). We parse strictly, as before, so that a malformed body
    -- is cut before the HMAC is computed.
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
        -- A server-side problem (C1 never loaded the secret). Fail-closed for the
        -- fastpath: the cookie is not trusted and the request walks the full cascade.
        -- A separate RESULT_NO_SECRET, so that a spike caused by truncating or deleting
        -- the secret file is not masked as attack-shaped "invalid";
        -- the operator alert is configured separately (from review).
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

    -- From here the payload is trustworthy — the HMAC passed. Expired comes before
    -- wrong_site: a legitimate client with an expired cookie plus apex Domain
    -- scoping (Domain=example.com, the browser sends it to api.example.com) would otherwise
    -- get a security-flavoured wrong_site instead of a bookkeeping
    -- expired. wrong_site is a real "cross-tenant attempt" signal, and we want to
    -- see it only when the signature and the expiry are valid (from review).
    -- The trade-off: an attacker with a stolen expired cookie now
    -- comes through as expired rather than wrong_site if the site also failed to match
    -- — but the cookie has already expired, so there is no real risk.
    local exp = tonumber(exp_s)
    if not exp or exp <= ngx.time() then
        return _M.RESULT_EXPIRED
    end

    if site ~= host then
        return _M.RESULT_WRONG_SITE
    end

    -- The attack_mode pre-attack gate (C7). The cookie passed every validity check
    -- — outside an attack that is RESULT_VALID. But under attack_mode=on a long (normal)
    -- TTL means "issued before the attack" (during-attack cookies carry the short
    -- under_attack TTL) → we do not fastpath. We compare with `>`: exactly the
    -- under_attack TTL or shorter is during-attack and fastpaths; longer (the 24 h
    -- normal) is pre-attack. iat/exp were already validated as digits above.
    --
    -- FAIL-CLOSED. If the threshold did not arrive under attack (a config without
    -- ttl_seconds_under_attack → opts.max_under_attack_ttl=nil) or iat did not
    -- parse, pre-attack cannot be told from during-attack. Under attack it is
    -- safer NOT to trust (RESULT_STALE_PRE_ATTACK → the request goes to the L5
    -- challenge) than to hand out a fastpath for an unrecognised cookie: the point of C7
    -- is to reset trust in stockpiled cookies, and failing open silently cancelled that
    -- (from code review). WARN once: this is a config issue, not load,
    -- and there is no need to spam the log on every request under attack.
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
