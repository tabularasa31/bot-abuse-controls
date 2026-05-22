-- L1 hygiene stage (rules-reference L1, phase1-spec "hygiene"; RFC §A2).
--
-- Runs first in the cascade (cheapest checks). Records the would-be verdict
-- (and the informational tag) through bac_log.
--
-- Phase 1 is OBSERVE-ONLY: nothing is physically blocked (no ngx.exit) — the
-- request always reaches origin and the structured log records what WOULD
-- have happened (phase1-spec: "каскад в MVP только наблюдает, ничего не
-- блокирует"). Flipping a rule to enforce is the future per-rule-enforce
-- task, not Phase 1.
--
-- run() does NOT short-circuit the cascade: the caller (verdict.lua) keeps
-- going to the tls_fp stage, which is the only stage that actually enforces
-- (ngx.exit on a blocklisted fp). Stopping here would let a request bypass an
-- active tls_fp block by also tripping an observe-only hygiene rule. The
-- bac_log verdict is last-writer-wins, so a later tls_fp block overwrites the
-- hygiene verdict; otherwise the hygiene verdict stands ("финальное
-- сработавшее правило").
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
--   1. method_not_allowed — method outside the configured whitelist
--   2. ua_blacklist       — UA matches the combined regex of ACTIVE patterns
--                           (staged patterns are not applied — staging is its
--                           own task, A11; bac_log.add_staging_match is a
--                           no-op in Phase 1)
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
-- header_anomaly tag and the would-be verdict via bac_log. Never blocks the
-- request and never stops the cascade (observe-only); the boolean return
-- (true when a hygiene blocking rule matched) is informational only.
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
        return true
    end

    -- 2. ua_blacklist (active patterns).
    if _M.active_re then
        local ua = ngx.var.http_user_agent or ""
        -- "jo": JIT + per-worker compile cache keyed by the regex string.
        -- ngx.re.find returns (nil, nil, err) on a bad pattern rather than
        -- throwing — treat that as fail-open and never flag on our own error.
        local from, _, err = ngx.re.find(ua, _M.active_re, "jo")
        if err then
            ngx.log(ngx.ERR, "ua_blacklist regex error, fail-open: ", err)
        elseif from then
            bac_log.set_verdict("hygiene", "block", "ua_blacklist")
            return true
        end
    end

    return false
end

return _M
