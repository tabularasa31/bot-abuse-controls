-- L5 verification: the single point where a challenge is decided.
--
-- L3 and L4 only accumulate soft signals through bac_log.add_flag. decide()
-- turns them into a verdict, following rules-reference §"should_challenge()":
-- attack_mode forces a challenge, a customer rate rule with action=challenge
-- always wins, and a system flag is gated by Strictness — a challenge under
-- Standard, verdict=permissive (logged, passed through) under Permissive.
--
-- An existing block or allow is never overwritten: block > allow > challenge.
local _M = {}

local bac_log = require "bac_log"
local policy  = require "policy"

-- An explicit whitelist, so a customer flag cannot be mistaken for a system one
-- and bypass Permissive.
local SYSTEM_FLAGS = {
    tls_fp_impersonator       = true,
    tls_fp_suspicious_ciphers = true,
}

_M.SYSTEM_FLAGS = SYSTEM_FLAGS

-- Returns (verdict, rule), or nil when the verdict should be left alone. Pure:
-- no side effects and no ngx.*, so it is directly unit-testable.
function _M.decide(ctx, p)
    if not ctx or not p then return nil, nil end

    -- block is terminal, attack_mode included: the client is already gone with a
    -- 403, or the block is already recorded in shadow.
    if ctx.verdict == "block" then return nil, nil end

    local last_system
    for _, f in ipairs(ctx.flags or {}) do
        if SYSTEM_FLAGS[f] then last_system = f end
    end

    -- Written by a future L4 rate_custom (Phase 3+), so there is no caller yet;
    -- the type check keeps a wrong assignment from erroring on `#client`.
    local client = ctx.client_challenge_flags
    local last_client
    if type(client) == "table" and #client > 0 then
        last_client = client[#client]
    end

    -- allow still fastpaths under attack, and needs no per-rule distinction: L2
    -- has already discarded pre-attack cookies as RESULT_STALE_PRE_ATTACK, so a
    -- cookie_valid reaching L5 during an attack was issued during it. That is
    -- what makes it one challenge per attack rather than one per request.
    if p.attack_mode and ctx.verdict ~= "allow" then
        return "challenge", last_client or last_system or "attack_mode"
    end

    if ctx.verdict == "allow" then return nil, nil end

    if last_client then
        return "challenge", last_client
    end

    if last_system then
        if p.strictness == "permissive" then
            return "permissive", last_system
        end
        return "challenge", last_system
    end

    return nil, nil
end

-- Routes a challenge verdict into a branch: A serves the page, B is a
-- non-browser client, C is a browser the challenge cannot survive — a method
-- outside GET/HEAD (the redirect drops the body), a websocket upgrade, or an
-- Accept without text/html.
--
-- B is checked first because it is the more specific client property: a curl
-- POST is B, not C. Browser detection reuses tls_fp.classify_ua so L3 and L5
-- cannot disagree about what a browser is.
local tls_fp = require "tls_fp"

function _M.classify_branch(req)
    req = req or {}

    local family = tls_fp.classify_ua(req.user_agent or "")
    if family == "other" then
        return "B"
    end

    local method = req.method or ""
    if method ~= "GET" and method ~= "HEAD" then
        return "C"
    end

    local upgrade = req.upgrade
    if type(upgrade) == "string" and upgrade ~= "" then
        if upgrade:lower():find("websocket", 1, true) then
            return "C"
        end
    end

    local accept = req.accept
    -- A real browser always sends text/html on a top-level GET, so requiring it
    -- costs no false positives.
    if type(accept) ~= "string" or accept == ""
        or not accept:lower():find("text/html", 1, true) then
        return "C"
    end

    return "A"
end

-- Writes the verdict only. The physical branch dispatch stays in verdict.lua so
-- that mode gating lives in one place.
function _M.run()
    local ctx = ngx.ctx.bac
    if not ctx then return end
    local p = policy.get(ngx.var.host or "")
    local verdict, rule = _M.decide(ctx, p)
    if verdict then
        bac_log.set_verdict("verification", verdict, rule)
    end
end

return _M
