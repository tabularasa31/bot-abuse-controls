-- L1 hygiene: the cheapest checks, run first.
--
-- Blocking rules are the method whitelist and the UA blacklist (system list
-- first, then the per-host one). Both record the verdict and then go through
-- policy.enforce, so shadow mode keeps accumulating verdicts and tags from the
-- later stages instead of stopping here. That deliberately lets a more specific
-- later match, such as a blocklisted fingerprint, take the label in the log.
--
-- hygiene:header_anomaly is a tag, not a rule: header heuristics false-positive
-- on unusual but legitimate clients, so it is weighed at L5 and never blocks.
--
-- Staged UA patterns are matched separately and only record staging_match.
--
-- resource_id is not derived here: the edge works from the Host, and the
-- backend enriches it on ingest.
local policy          = require "policy"
local policy_matchers = require "policy_matchers"
local staging_metrics = require "staging_metrics"

local _M = {
    enabled    = true,
    method_set = {},
    active_re  = nil,
}

-- Combined regex over the active patterns, or nil when there are none.
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

-- Returns (combined_re, patterns). The regex is the cheap gate; the list is
-- needed because a combined match cannot say which alternative fired.
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

-- Wraps a plain pattern array into an alternation, or nil when empty.
function _M.combine_patterns(patterns)
    if not patterns or #patterns == 0 then return nil end
    return "(" .. table.concat(patterns, ")|(") .. ")"
end

-- A real browser always sends Accept on HTTP/2.
function _M.header_anomaly(server_protocol, accept)
    return server_protocol == "HTTP/2.0" and not accept
end

-- Lookup set from a method whitelist (array or single string).
function _M.method_lookup(whitelist)
    local set = {}
    if type(whitelist) == "table" then
        for _, m in ipairs(whitelist) do set[m] = true end
    elseif type(whitelist) == "string" then
        set[whitelist] = true
    end
    return set
end

-- Compiles the on-disk config into the state the request path reads.
function _M.build(config)
    local defaults = config.defaults or {}
    local hygiene_cfg = defaults.hygiene or {}

    _M.method_set = _M.method_lookup(hygiene_cfg.method_whitelist)

    -- Kept separate from active_re, which cannot distinguish "no patterns"
    -- from "rule disabled". The per-host list has to honour the same switch:
    -- disabling the rule during an incident must stop all UA blocking.
    local ua_rule = (defaults.blocking or {}).ua_blacklist or {}
    _M.ua_blacklist_enabled = ua_rule.enabled ~= false
    if not _M.ua_blacklist_enabled then
        _M.active_re = nil
        -- Staging observation honours the same switch.
        _M.staging_re = nil
        _M.staging_patterns = {}
    else
        _M.active_re = _M.build_combined(config.ua_blacklist)
        _M.staging_re, _M.staging_patterns = _M.build_staging(config.ua_blacklist)
    end

    _M.enabled = require("config").stage_enabled(defaults, "hygiene")

    -- nil means the first refresh rebuilds. The matchers above are the
    -- cold-start state until the catalog lands.
    _M._cached_gen_ua = nil

    return _M
end

-- Rebuilds the matchers on a generation flip; in steady state this is one dict
-- read and an integer compare. A missing generation keeps the cold-start state.
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

-- The boolean return is informational; the caller does not branch on it.
function _M.run()
    if not _M.enabled then return false end

    _M.refresh()

    local bac_log = require "bac_log"

    -- Unconditional, so the tag is recorded even when a rule blocks below.
    if _M.header_anomaly(ngx.var.server_protocol, ngx.var.http_accept) then
        bac_log.add_tag("hygiene:header_anomaly")
    end

    if next(_M.method_set) and not _M.method_set[ngx.var.request_method] then
        bac_log.set_verdict("hygiene", "block", "method_not_allowed")
        policy.enforce(403)
        return true
    end

    -- System list first, then the per-host one. The rule names differ so hits
    -- stay attributable.
    local ua = ngx.var.http_user_agent or ""
    if _M.active_re then
        -- "jo" caches the compiled regex per worker. A bad pattern returns an
        -- error rather than throwing; fail open, never flag on our own fault.
        local from, _, err = ngx.re.find(ua, _M.active_re, "jo")
        if err then
            ngx.log(ngx.ERR, "ua_blacklist regex error, fail-open: ", err)
        elseif from then
            bac_log.set_verdict("hygiene", "block", "ua_blacklist")
            policy.enforce(403)
            return true
        end
    end

    -- Compiled once per (host, gen); nil when the host has no custom patterns.
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

    -- Observe-only, and only reached when nothing active matched — so it
    -- records what promotion to active would have done.
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
