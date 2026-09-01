-- access_by_lua entry point: runs the L1-L5 cascade.
--
-- Every physical exit goes through policy.enforce, which is what makes shadow
-- mode observe-only. New enforcement points must use the same helper.

local ja4        = require "ja4_compute"
local bac_log    = require "bac_log"
local hygiene    = require "hygiene"
local reputation = require "reputation"
local tls_fp     = require "tls_fp"
local rate_limit = require "rate_limit"
local fp_state   = require "tls_fp_blocklist_state"
local config     = require "config"
local policy     = require "policy"
local clearance  = require "clearance"
local verification = require "verification"

-- Returning before bac_log.init is deliberate: a killed cascade emits no record
-- at all.
if config.global_kill(config.defaults) then
    return
end

bac_log.init()

hygiene.run()
reputation.run()

-- L2.1 clearance cookie.
if config.stage_enabled(config.defaults, "clearance") then
    local host = ngx.var.host or ""
    local opts
    local p = policy.get(host)
    if p and p.attack_mode then
        local max_ttl
        local allow = config.defaults and config.defaults.allow
        if type(allow) == "table" and type(allow.cookie_valid) == "table" then
            max_ttl = tonumber(allow.cookie_valid.ttl_seconds_under_attack)
        end
        opts = { attack_mode = true, max_under_attack_ttl = max_ttl }
    end
    local result = clearance.verify(host, opts)
    ngx.shared.metrics:incr("clearance_verify_" .. result .. "_total", 1, 0)
    if result == clearance.RESULT_VALID then
        local ctx = ngx.ctx.bac
        -- A block from L1/L2 outranks this allow, and skipping L3 would lose
        -- the soft signals for the case they exist for: a stolen cookie on a
        -- bad fingerprint.
        if ctx and ctx.verdict ~= "block" then
            ngx.ctx.clearance_valid = true
            bac_log.set_verdict("reputation", "allow", "cookie_valid")
        end
    end
end

-- L3. A valid cookie skips the decision but not the fingerprint: L4 keys on it,
-- and a cookie must not buy a free pass through the per-fingerprint limit.
local fp
if config.stage_enabled(config.defaults, "tls_fp") then
    fp = ja4.compute()
    bac_log.set_tls_fp(fp)

    if not ngx.ctx.clearance_valid then
        -- Keying by `fp:gen` makes a catalog swap atomic: old entries become
        -- unreachable instead of masking the new list until their TTL.
        local gen = ngx.shared.meta:get(fp_state.META_GEN_KEY) or 0
        local key = fp_state.key(fp, gen)

        local cache  = ngx.shared.verdict_cache
        local cached = cache:get(key)
        local cache_hit = (cached ~= nil)

        local verdict
        if cached == "block" or cached == "allow" then
            verdict = cached
        else
            -- Only an active entry blocks; a staged one falls through and is
            -- recorded as staging_match.
            local status = fp_state.parse_value(ngx.shared.tls_fp_blocklist:get(key))
            verdict = (status == "active") and "block" or "allow"
            cache:set(key, verdict, 60)
        end

        ngx.ctx.bac_cache_hit = cache_hit

        if verdict == "block" then
            bac_log.set_verdict("tls_fp", "block", "tls_fp_blocklist")
            -- Stamp before enforce: in shadow this returns and still proxies,
            -- so cascade_ms must not swallow the upstream time. The return
            -- keeps a later stage from overwriting the block.
            bac_log.mark_cascade_end()
            policy.enforce(403)
            return
        end

        tls_fp.run(fp)
    end
end

rate_limit.run(fp)

-- L5: the only place a challenge is decided, and the only physical issue point.
if config.stage_enabled(config.defaults, "verification") then
    verification.run()

    local ctx = ngx.ctx.bac
    if ctx and ctx.verdict == "challenge" then
        local branch = verification.classify_branch({
            user_agent = ngx.var.http_user_agent,
            method     = ngx.var.request_method,
            accept     = ngx.var.http_accept,
            upgrade    = ngx.var.http_upgrade,
        })
        if branch == "B" then
            bac_log.set_verdict("verification", "block", "non_browser_blocked")
            ngx.shared.metrics:incr("challenge_branch_b_total", 1, 0)
            bac_log.mark_cascade_end()
            policy.enforce(403)
            return
        elseif branch == "C" then
            bac_log.set_verdict("verification", "block", "unchallengeable_request")
            ngx.shared.metrics:incr("challenge_branch_c_total", 1, 0)
            bac_log.mark_cascade_end()
            policy.enforce(403)
            return
        else
            -- Active mode only; in shadow the response is untouched. ngx.exec
            -- keeps the client's URL, so the reload lands back on it.
            local p = policy.get(ngx.var.host or "")
            if p and p.mode == "active" then
                return ngx.exec("@challenge_page")
            end
        end
    end
end

bac_log.mark_cascade_end()
