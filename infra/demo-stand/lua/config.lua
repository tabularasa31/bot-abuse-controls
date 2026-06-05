-- Cascade configuration, loaded once in init_by_lua and held read-only.
--
-- load() reads on-disk cascade configs (Phase 1: defaults, whitelist_ip,
-- blocklist_ip, ua_blacklist, asn_datacenters; Phase 2: tls_fp_blocklist)
-- and stashes the parsed result on this module's table. Because init_by_lua
-- runs in the master before workers fork, every worker inherits these
-- fields for free — no shared dict needed for config that only changes on
-- restart (hot-reload is a separate task per the A3 ticket's out-of-scope
-- list).
--
-- PR2 (ADR-006): tls_fp_catalog и tls_fp_browser_profiles больше не
-- читаются с диска — они приезжают через Channel C из git-репо catalogs/
-- (см. catalog_pull.lua descriptors). На эдже tls_fp.lua сам собирает
-- lookup-таблицы из shared_dict через refresh() при гене-флипе.
--
-- A missing or unreadable file is fatal: the acceptance criterion is that
-- the stand loads ALL configs at start, so we fail loudly rather than run
-- a half-configured cascade.

local loader = require "config_loader"

local _M = {
    dir = os.getenv("BAC_CONFIG_DIR") or "/etc/nginx/config",
}

local function path(name)
    return _M.dir .. "/" .. name
end

local function load_or_die(parse, name)
    local result, err = parse(path(name))
    if not result then
        error("config: cannot load " .. name .. ": " .. tostring(err))
    end
    return result
end

-- Operator override file for the kill-switch toggles (A12). On the stand
-- Channel A = file/mount (no Puppet), so an operator flips the global /
-- per-stage switches by dropping this gitignored file in the config dir and
-- running `nginx -s reload` — without editing the git-tracked defaults.conf
-- and without recreating the container. Absent/unreadable => the defaults.conf
-- [kill_switch.*] baseline stands (this file is optional, unlike the eight
-- required configs). Only the [kill_switch.*] subtree is read; the file shares
-- defaults.conf's INI syntax so the same true/false coercion applies.
local KILL_SWITCH_LOCAL = "kill_switch.local.conf"

-- Take an override value only when it coerced to a boolean. A typo
-- (`tls_fp = on`) leaves the parser with a non-boolean, and the kill checks
-- below test `== true`, so it would silently fail to kill — dangerous on an
-- emergency lever edited under incident pressure. We keep the baseline and log
-- loudly instead of swallowing the typo.
local function apply_toggle(dst, key, v, where)
    if type(v) == "boolean" then
        dst[key] = v
    else
        ngx.log(ngx.ERR, "config: ignoring non-boolean ", where,
            " in ", KILL_SWITCH_LOCAL, " (got ", type(v), "); baseline kept")
    end
end

-- Forward declarations so overlay_local can reference these as upvalues; the
-- `function name()` definitions below bind to these locals (not globals).
local overlay_kill_switch, overlay_edge_protection

-- Apply the operator override file (KILL_SWITCH_LOCAL) onto the git-tracked
-- defaults. Parsed ONCE here and fed to both the kill-switch overlay and the
-- edge-protection overlay — the file is the single operator lever surface on
-- the stand (Channel A = file/mount), so a new operational toggle rides the
-- same parse + same `nginx -s reload` lifecycle as the kill-switch.
local function overlay_local(defaults)
    local parsed = loader.parse_ini(path(KILL_SWITCH_LOCAL))
    if not parsed then return end
    overlay_kill_switch(defaults, parsed)
    overlay_edge_protection(defaults, parsed)
end

function overlay_kill_switch(defaults, parsed)
    local ks = parsed.kill_switch
    if type(ks) ~= "table" then return end

    defaults.kill_switch = defaults.kill_switch or {}
    local dst = defaults.kill_switch

    if type(ks.global) == "table" and ks.global.enabled ~= nil then
        dst.global = dst.global or {}
        apply_toggle(dst.global, "enabled", ks.global.enabled, "global.enabled")
    end
    if type(ks.per_stage) == "table" then
        dst.per_stage = dst.per_stage or {}
        for stage, v in pairs(ks.per_stage) do
            apply_toggle(dst.per_stage, stage, v, "per_stage." .. stage)
        end
    end
end

-- Edge self-protection overlay (defaults.conf [edge_protection]). Same
-- operator-lever semantics as the kill-switch: deny_nontenant flips the
-- $edge_action path in nginx.demo.conf's `location /` from "render landing"
-- to "return 444" for any non-tenant Host (Host: <edge-IP>, garbage, HTTP/1.0
-- without Host), so a flood aimed at the edge's own IP is dropped before the
-- cascade instead of being served a landing page on every request. Tenant
-- traffic ($origin != "") is untouched. Reload-applied, no container recreate.
function overlay_edge_protection(defaults, parsed)
    local ep = parsed.edge_protection
    if type(ep) ~= "table" or ep.deny_nontenant == nil then return end
    defaults.edge_protection = defaults.edge_protection or {}
    apply_toggle(defaults.edge_protection, "deny_nontenant",
        ep.deny_nontenant, "edge_protection.deny_nontenant")
end

function _M.load()
    _M.defaults                = load_or_die(loader.parse_ini,  "defaults.conf")
    overlay_local(_M.defaults)
    _M.whitelist_ip            = load_or_die(loader.parse_list, "whitelist_ip.conf")
    _M.blocklist_ip            = load_or_die(loader.parse_list, "blocklist_ip.conf")
    _M.ua_blacklist            = load_or_die(loader.parse_list, "ua_blacklist.conf")
    _M.asn_datacenters         = load_or_die(loader.parse_list, "asn_datacenters.conf")
    _M.tls_fp_blocklist        = load_or_die(loader.parse_list, "tls_fp_blocklist.conf")
    -- tls_fp_catalog / tls_fp_browser_profiles переехали в catalogs/ (PR2,
    -- ADR-006). На эдже их собирает tls_fp.refresh() из shared_dict.
    return _M
end

-- Shared kill-switch predicate for a cascade stage's build(). True unless the
-- global kill-switch or this stage's per-stage switch is set (config-templates.md
-- kill_switch; defaults.conf [kill_switch.*]). Centralised so every stage
-- (hygiene/reputation/rate_limits/…) computes the toggle identically.
function _M.stage_enabled(defaults, stage)
    local ks = (defaults or {}).kill_switch or {}
    return not ((ks.global or {}).enabled == true
                or (ks.per_stage or {})[stage] == true)
end

-- True when the global kill-switch is set. verdict.lua checks this before the
-- cascade (and before bac_log.init) so the whole cascade goes no-op: traffic
-- passes straight to the origin and NO BAC_LOG record is written (vision.md
-- §"Аварийные рычаги": "Lua-модуль делает no-op ... логов антибота нет").
-- Distinct from stage_enabled, which folds the global switch into a per-stage
-- skip — that path still emits a (cascade-bypassing) log; the global gate must
-- suppress the log entirely.
function _M.global_kill(defaults)
    local ks = (defaults or {}).kill_switch or {}
    return (ks.global or {}).enabled == true
end

-- Edge self-protection predicate (defaults.conf [edge_protection], overridable
-- via kill_switch.local.conf). True → nginx.demo.conf's `location /` drops
-- non-tenant Host traffic with `return 444` before the cascade, instead of
-- rendering the bundled landing. Read per-request from a set_by_lua_block; the
-- value only changes on reload (init_by_lua re-runs config.load), so this is a
-- plain table read, no shared_dict needed. Defaults to false (landing) so the
-- stand still works out-of-box.
function _M.edge_deny_nontenant(defaults)
    local ep = (defaults or {}).edge_protection or {}
    return ep.deny_nontenant == true
end

return _M
