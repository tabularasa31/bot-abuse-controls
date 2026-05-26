-- L1 hygiene stage (rules-reference L1, phase1-spec "hygiene"; RFC §A2).
--
-- Runs first in the cascade (cheapest checks). Records the would-be verdict
-- (and the informational tag) through bac_log.
--
-- Mode-gated enforcement: when a blocking hygiene rule (method_not_allowed
-- or ua_blacklist) matches, the would-be verdict is recorded via bac_log
-- and then policy.enforce(403) decides whether to physically 403. For a
-- host with policy.mode=active the request gets 403 right here (cascade
-- dies, later stages do not run). For mode=shadow (pool default) enforce
-- is a no-op: the cascade continues to tls_fp/rate_limit so their would-be
-- verdicts and tags still accumulate in the log, with last-writer-wins on
-- the verdict ("финальное сработавшее правило"). The per-rule choice
-- mirrors phase1-spec §36 "blocking rules return 403 in боевой режим" and
-- rules-reference L1: both method_not_allowed and ua_blacklist are
-- declared blocking.
--
-- Why hygiene does not short-circuit the cascade in shadow: the design
-- accepts losing the hygiene-rule label in the log to a later, more
-- specific match (tls_fp_blocklist). A bot that trips method_not_allowed
-- AND has a blocklisted fp is more usefully recorded as a tls_fp hit; in
-- active mode hygiene's ngx.exit wins because it fires first, which is
-- the same trade-off the tls_fp_blocklist branch in verdict.lua makes
-- (see its header comment).
--
-- Informational tag (NOT a rule — emits no verdict, never stops the cascade):
--   * hygiene:header_anomaly — header combination a real browser does not
--     send but lazy automation does (base case: HTTP/2 with no Accept). Header
--     heuristics false-positive easily on unusual-but-legitimate clients, so
--     this only accumulates in `tags` and is weighed at L5 alongside other
--     signals (vision.md / rules-reference.md T0 / phase1-spec.md). Always
--     evaluated, even when a blocking rule also fires — tags accumulate
--     independently of the verdict.
--
-- Blocking checks, in order (first hygiene match wins; this only decides which
-- hygiene rule is recorded — it does not stop the wider cascade):
--   1.  method_not_allowed     — method outside the configured whitelist
--   2.  ua_blacklist           — UA matches the combined regex of ACTIVE
--                                system patterns. Staged patterns are dropped
--                                (build_combined skips status=staging) and not
--                                yet recorded into staging_match: A11 implemented
--                                staging_match for the three tls_fp catalogs
--                                (tls_fp.lua); extending it to ua_blacklist /
--                                ip_blocklist is the "и далее" follow-up.
--   2b. policy.ua_blacklist    — UA matches the per-host pattern list pulled
--                                from policy[host].ua_blacklist (86exr05xt).
--                                Compiled once per (host, gen) in
--                                policy_matchers; empty list = no-op.
--
-- resource_id is intentionally NOT derived here: the edge works from Host
-- only and the backend enriches resource_id on log ingest (ADR-005,
-- config-distribution.md). bac_log already records host and emits
-- resource_id as null.
--
-- Config model. Unlike the production edge (RFC §A2/§В1: a backend-built
-- combined regex pushed via Channel C with a generation counter and a
-- per-worker shared-dict cache), the demo stand loads ua_blacklist.conf from
-- disk once in init_by_lua (config.lua). build() runs there — in the master
-- before workers fork — so the method set and combined regex are inherited by
-- every worker for free; no shared dict, no generation handshake (hot-reload
-- is out of scope).

local policy          = require "policy"
local policy_matchers = require "policy_matchers"

local _M = {
    enabled    = true,
    method_set = {},
    active_re  = nil,
}

-- pure: combined regex of ACTIVE ua_blacklist patterns, or nil when none.
-- ua_list is config.ua_blacklist: array of { value = <pattern>, attrs = {} }.
function _M.build_combined(ua_list)
    local active = {}
    for _, e in ipairs(ua_list or {}) do
        local pat = e.value
        local status = e.attrs and e.attrs.status
        if pat and pat ~= "" and status ~= "staging" then
            active[#active + 1] = pat
        end
    end
    if #active == 0 then return nil end
    return "(" .. table.concat(active, ")|(") .. ")"
end

-- pure: header anomaly heuristic. Base case (RFC §A2 / vision.md T0): an
-- HTTP/2 request with no Accept header — real browsers always send Accept on
-- HTTP/2. Returns true when the request looks anomalous.
function _M.header_anomaly(server_protocol, accept)
    return server_protocol == "HTTP/2.0" and not accept
end

-- pure: lookup set from a method whitelist (array or single string).
function _M.method_lookup(whitelist)
    local set = {}
    if type(whitelist) == "table" then
        for _, m in ipairs(whitelist) do set[m] = true end
    elseif type(whitelist) == "string" then
        set[whitelist] = true
    end
    return set
end

-- Called once in init_by_lua, after config.load(). Compiles the on-disk
-- config into the per-process state the request path reads.
function _M.build(config)
    local defaults = config.defaults or {}
    local hygiene_cfg = defaults.hygiene or {}

    _M.method_set = _M.method_lookup(hygiene_cfg.method_whitelist)

    -- ua_blacklist rule can be disabled via defaults.conf.
    local ua_rule = (defaults.blocking or {}).ua_blacklist or {}
    if ua_rule.enabled == false then
        _M.active_re = nil
    else
        _M.active_re = _M.build_combined(config.ua_blacklist)
    end

    -- Stage off via the shared kill-switch helper (config-templates.md kill_switch).
    _M.enabled = require("config").stage_enabled(defaults, "hygiene")

    return _M
end

-- Called per request from verdict.lua, after bac_log.init(). Records the
-- header_anomaly tag and the would-be verdict via bac_log. For a host with
-- policy.mode=active a matched blocking rule physically 403s the request
-- via policy.enforce (cascade stops inside hygiene.run). For mode=shadow
-- the function returns normally; verdict.lua continues the cascade. The
-- boolean return (true when a hygiene blocking rule matched) is
-- informational only — verdict.lua does not branch on it (per-stage
-- last-writer-wins on the verdict is intentional).
function _M.run()
    if not _M.enabled then return false end

    local bac_log = require "bac_log"

    -- Informational tag — evaluated first and unconditionally so it is
    -- recorded even when a blocking rule fires below (tags accumulate
    -- independently of the verdict).
    if _M.header_anomaly(ngx.var.server_protocol, ngx.var.http_accept) then
        bac_log.add_tag("hygiene:header_anomaly")
    end

    -- 1. method whitelist (only when one is configured).
    if next(_M.method_set) and not _M.method_set[ngx.var.request_method] then
        bac_log.set_verdict("hygiene", "block", "method_not_allowed")
        -- mode-gate: active → ngx.exit(403); shadow → no-op, cascade
        -- continues so later stages still tag/verdict (see header comment).
        policy.enforce(403)
        return true
    end

    -- 2. ua_blacklist (active patterns). System list first, then the
    --    per-host list from policy[host].ua_blacklist. Both are
    --    namespaced in the log via the rule name (`ua_blacklist` vs
    --    `policy.ua_blacklist`) so analytics can attribute hits.
    local ua = ngx.var.http_user_agent or ""
    if _M.active_re then
        -- "jo": JIT + per-worker compile cache keyed by the regex string.
        -- ngx.re.find returns (nil, nil, err) on a bad pattern rather than
        -- throwing — treat that as fail-open and never flag on our own error.
        local from, _, err = ngx.re.find(ua, _M.active_re, "jo")
        if err then
            ngx.log(ngx.ERR, "ua_blacklist regex error, fail-open: ", err)
        elseif from then
            bac_log.set_verdict("hygiene", "block", "ua_blacklist")
            policy.enforce(403)
            return true
        end
    end

    -- 2b. per-host ua_blacklist (policy[host].ua_blacklist). Compiled
    -- once per (host, gen) in policy_matchers via the same combined-
    -- alternation shape build_combined produces. nil when the host has
    -- no custom patterns (pool default) — pre-PR behaviour preserved.
    local pm = policy_matchers.get(ngx.var.host)
    if pm.ua_blacklist_re then
        local from, _, err = ngx.re.find(ua, pm.ua_blacklist_re, "jo")
        if err then
            ngx.log(ngx.ERR, "policy.ua_blacklist regex error, fail-open: ", err)
        elseif from then
            bac_log.set_verdict("hygiene", "block", "policy.ua_blacklist")
            policy.enforce(403)
            return true
        end
    end

    return false
end

return _M
