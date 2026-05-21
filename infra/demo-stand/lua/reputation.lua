-- L2 reputation stage — system IP lists (rules-reference L2, vision §2.3–2.4).
--
-- Two source-IP checks via lua-resty-ipmatcher (CIDR-aware, IPv4 + IPv6):
--   1. ip_whitelist (category allow)    — our monitoring / check services.
--   2. ip_blocklist (category blocking) — known-bad IPs/CIDRs.
-- Whitelist is checked FIRST (vision §2.3 before §2.4): a whitelisted IP wins
-- and the blocklist is not consulted.
--
-- Runs AFTER hygiene, BEFORE tls_fp (cascade order hygiene → reputation →
-- tls_fp → rate_limits → verification).
--
-- Phase 1 is OBSERVE-ONLY, exactly like hygiene.lua: run() records the
-- would-be verdict via bac_log but NEVER ngx.exit and NEVER short-circuits the
-- cascade. In particular an ip_whitelist match does NOT fastpass here. In
-- production an allow short-circuits L3–L5 and a block returns 403; on the
-- stand it must not, because skipping the later stages would let a whitelisted
-- IP bypass an active tls_fp block (the same trap hygiene.lua documents). The
-- bac_log verdict is last-writer-wins, so a later tls_fp block overwrites the
-- reputation verdict; otherwise the reputation verdict stands ("финальное
-- сработавшее правило"). Production fastpass/403 enforcement is a future
-- per-rule-enforce task, not Phase 1.
--
-- Data. Phase 1: static whitelist_ip.conf / blocklist_ip.conf, parsed once in
-- init_by_lua (config.lua) and compiled into ipmatcher objects by build()
-- below — done in the master before workers fork, so every worker inherits the
-- matchers for free (no shared dict; hot-reload is out of scope). Phase 3: the
-- same data arrives as the ip_whitelist / ip_blocklist catalogs over Channel C
-- into shared dicts antibot_ip_whitelist / antibot_ip_blocklist
-- (config-distribution.md); the rule names, stage, category and log contract
-- are unchanged across the phase boundary — only the data source changes.
--
-- Staging: blocklist entries with status=staging are excluded from the active
-- matcher (mirrors hygiene's ua_blacklist and init.lua's fp seeding). Recording
-- staged matches for promotion analytics lands with its own task (A11).
--
-- ASN/geo (asn_block / geo_whitelist) and per-resource policy ip_whitelist are
-- separate tasks (A6 / B8) and are intentionally not handled here.

local _M = {
    enabled   = true,
    whitelist = nil,  -- ipmatcher or nil when no active entries
    blocklist = nil,  -- ipmatcher or nil when no active entries
}

-- pure: array of `value` strings from a parsed list (config_loader.parse_list
-- output: { { value = "<ip-or-cidr>", attrs = { status = ... } }, ... }),
-- excluding status=staging entries. Returns {} when the list is nil/empty/
-- all-staging. No ngx / ipmatcher dependency so it is unit-testable under bare
-- luajit (tests/reputation_test.lua).
function _M.active_values(list)
    local out = {}
    for _, e in ipairs(list or {}) do
        local v = e.value
        local status = e.attrs and e.attrs.status
        if v and v ~= "" and status ~= "staging" then
            out[#out + 1] = v
        end
    end
    return out
end

-- Called once in init_by_lua, after config.load(). Compiles the on-disk IP
-- lists into the per-process ipmatcher objects the request path reads. An
-- empty active list yields a nil matcher (run() skips it) — an empty blocklist
-- is the Phase 1 default and must not error.
function _M.build(config)
    local ipmatcher = require "resty.ipmatcher"

    local function matcher(list)
        local values = _M.active_values(list)
        if #values == 0 then return nil, 0 end
        local m, err = ipmatcher.new(values)
        if not m then
            ngx.log(ngx.ERR, "reputation: ipmatcher.new failed: ", tostring(err))
            return nil, 0
        end
        return m, #values
    end

    local wl_n, bl_n
    _M.whitelist, wl_n = matcher(config.whitelist_ip)
    _M.blocklist, bl_n = matcher(config.blocklist_ip)

    -- Stage off when the global kill-switch or the per-stage reputation switch
    -- is set (config-templates.md kill_switch; defaults.conf [kill_switch.*]).
    local ks = (config.defaults or {}).kill_switch or {}
    _M.enabled = not ((ks.global or {}).enabled == true
                      or (ks.per_stage or {}).reputation == true)

    return _M, wl_n, bl_n
end

-- Called per request from verdict.lua, after bac_log.init(). Records the
-- would-be verdict via bac_log. Never blocks and never stops the cascade
-- (observe-only); the boolean return (true when a rule matched) is
-- informational only.
function _M.run()
    if not _M.enabled then return false end

    local ip = ngx.var.remote_addr
    if not ip then return false end

    local bac_log = require "bac_log"

    -- whitelist first (vision §2.3): a match wins, blocklist not consulted.
    if _M.whitelist and _M.whitelist:match(ip) then
        bac_log.set_verdict("reputation", "allow", "ip_whitelist")
        return true
    end

    -- blocklist (vision §2.4).
    if _M.blocklist and _M.blocklist:match(ip) then
        bac_log.set_verdict("reputation", "block", "ip_blocklist")
        return true
    end

    return false
end

return _M
