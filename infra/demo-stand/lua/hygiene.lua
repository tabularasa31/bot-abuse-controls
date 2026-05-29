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
--                                system patterns. Staged patterns (status=
--                                staging) are kept out of active_re and matched
--                                separately via staging_re (step 3): they record
--                                staging_match: ["ua_blacklist:<pattern>"] and
--                                never block (A11 staged rollout, 86exrtjpc).
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
-- Config model. The method whitelist + the kill-switch flags are compiled once
-- in init_by_lua (build(), master pre-fork) from defaults.conf. The ua_blacklist
-- patterns follow the production RFC §A2/§В1 model (A11, 86exrtjpc): a
-- backend-built combined regex (+ a staging pattern list) pushed via Channel C
-- with a generation counter and a per-worker cache. build() seeds the
-- cold-start matchers from the local ua_blacklist.conf and init.lua seeds gen 0
-- into the antibot_ua_blacklist shared_dict; refresh() (per request, gen-cached)
-- then swaps to the Channel C snapshot (gen 1+, sourced from catalogs/
-- ua_blacklist.yaml). The per-host policy.ua_blacklist (step 2b) is a separate
-- catalog applied via policy_matchers and is unaffected.

local policy          = require "policy"
local policy_matchers = require "policy_matchers"
local staging_metrics = require "staging_metrics"

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

-- pure: STAGING ua_blacklist branch (A11, 86exrtjpc). Returns (combined_re,
-- patterns): a combined regex over status=staging patterns (cheap "any match"
-- gate) plus the flat pattern list (for per-pattern attribution into
-- staging_match — a combined match alone can't say which alternative fired).
-- (nil, {}) when there are no staged patterns. Staged patterns NEVER block:
-- run() records staging_match: ["ua_blacklist:<pattern>"] and falls through.
function _M.build_staging(ua_list)
    local staging = {}
    for _, e in ipairs(ua_list or {}) do
        local pat = e.value
        local status = e.attrs and e.attrs.status
        if pat and pat ~= "" and status == "staging" then
            staging[#staging + 1] = pat
        end
    end
    if #staging == 0 then return nil, {} end
    return "(" .. table.concat(staging, ")|(") .. ")", staging
end

-- pure: wrap a plain array of patterns into a combined alternation, or nil for
-- an empty list. Used by refresh() to build staging_re from the Channel C
-- pattern list (build_staging does the same for the parse_list shape).
function _M.combine_patterns(patterns)
    if not patterns or #patterns == 0 then return nil end
    return "(" .. table.concat(patterns, ")|(") .. ")"
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

    -- ua_blacklist rule can be disabled via defaults.conf. The toggle
    -- is stored separately from active_re because the per-host check
    -- (policy[host].ua_blacklist via policy_matchers) must also honour
    -- the kill-switch: an operator disabling the rule for incident
    -- rollback expects no UA-based blocking ANYWHERE, system or
    -- per-host (codex P1 on PR #71). active_re=nil collapses the
    -- "no system patterns" and "rule disabled" cases — we can't
    -- distinguish them from run() without the explicit flag.
    local ua_rule = (defaults.blocking or {}).ua_blacklist or {}
    _M.ua_blacklist_enabled = ua_rule.enabled ~= false
    if not _M.ua_blacklist_enabled then
        _M.active_re = nil
        -- Staging observation honours the same kill-switch: an operator
        -- disabling ua_blacklist for incident rollback expects no UA matching
        -- anywhere, including observe-only staging.
        _M.staging_re = nil
        _M.staging_patterns = {}
    else
        _M.active_re = _M.build_combined(config.ua_blacklist)
        _M.staging_re, _M.staging_patterns = _M.build_staging(config.ua_blacklist)
    end

    -- Stage off via the shared kill-switch helper (config-templates.md kill_switch).
    _M.enabled = require("config").stage_enabled(defaults, "hygiene")

    -- Per-worker gen cache for the Channel C ua_blacklist refresh (A11,
    -- 86exrtjpc). nil = "first refresh rebuilds from current gen". The matchers
    -- set above from the local conf are the cold-start state; refresh() takes
    -- over once init.lua seeds gen 0 (conf) and Channel C lands gen 1+ (yaml).
    _M._cached_gen_ua = nil

    return _M
end

-- refresh — gen-cached rebuild of active_re / staging from the Channel C
-- ua_blacklist snapshot (A11, 86exrtjpc). The catalog arrives as two keys per
-- generation in antibot_ua_blacklist: `active:<gen>` (combined regex string)
-- and `staging:<gen>` (cjson array of staged patterns). Cheap in steady state
-- (one meta:get + int compare); rebuilds only on a gen flip. Honours the
-- ua_blacklist kill-switch (active/staging stay nil when disabled). When the
-- gen key is absent (catalog never seeded/pulled) it keeps the build()-time
-- conf state — safe fallback identical to pre-Channel-C behaviour.
function _M.refresh()
    if not ngx or not ngx.shared then return end
    local meta = ngx.shared.meta
    if not meta then return end
    local gen = meta:get("ua_blacklist_gen")
    if gen == nil or gen == _M._cached_gen_ua then return end
    local dict = ngx.shared.antibot_ua_blacklist
    if not dict then return end

    if not _M.ua_blacklist_enabled then
        local prev = _M.staging_patterns
        _M.active_re        = nil
        _M.staging_re       = nil
        _M.staging_patterns = {}
        _M._cached_gen_ua   = gen
        staging_metrics.reconcile("ua_blacklist", prev, {})
        return
    end

    local active = dict:get("active:" .. gen)
    _M.active_re = (type(active) == "string" and active ~= "") and active or nil

    local cjson = package.loaded["cjson.safe"] or require "cjson.safe"
    local raw = dict:get("staging:" .. gen)
    local pats = {}
    if type(raw) == "string" and raw ~= "" then
        local decoded = cjson.decode(raw)
        if type(decoded) == "table" then
            for _, p in ipairs(decoded) do
                if type(p) == "string" and p ~= "" then pats[#pats + 1] = p end
            end
        end
    end
    local prev = _M.staging_patterns
    _M.staging_patterns = pats
    _M.staging_re       = _M.combine_patterns(pats)
    _M._cached_gen_ua   = gen
    staging_metrics.reconcile("ua_blacklist", prev, pats)
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

    -- Pull the latest Channel C ua_blacklist snapshot (A11). Cheap in steady
    -- state (gen compare); rebuilds active_re / staging only on a gen flip.
    _M.refresh()

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
    -- Gated on the same _M.ua_blacklist_enabled flag as the system
    -- list: an operator disabling the ua_blacklist rule expects no UA
    -- blocking, including per-host.
    if _M.ua_blacklist_enabled then
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
    end

    -- 3. Staged ua_blacklist patterns (A11, 86exrtjpc). Observe-only: matched
    -- with the same predicate as the active list but writes only staging_match
    -- (["ua_blacklist:<pattern>"]) — never a verdict, never a 403, never a
    -- short-circuit. Reached only when no active rule matched above (those
    -- return), so this records what WOULD fire after promotion to active.
    -- Gated on the same ua_blacklist_enabled kill-switch (staging_re is nil
    -- when disabled). The combined regex is the cheap gate; on a hit we loop
    -- the small staged list to attribute the specific pattern(s).
    if _M.staging_re then
        local from, _, err = ngx.re.find(ua, _M.staging_re, "jo")
        if err then
            ngx.log(ngx.ERR, "ua_blacklist staging regex error, fail-open: ", err)
        elseif from then
            for _, pat in ipairs(_M.staging_patterns) do
                if ngx.re.find(ua, pat, "jo") then
                    bac_log.add_staging_match("ua_blacklist:" .. pat)
                end
            end
        end
    end

    return false
end

return _M
