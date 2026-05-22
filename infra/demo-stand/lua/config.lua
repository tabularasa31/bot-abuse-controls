-- Cascade configuration, loaded once in init_by_lua and held read-only.
--
-- load() reads all eight config files (Phase 1: defaults, whitelist_ip,
-- blocklist_ip, ua_blacklist, asn_datacenters; Phase 2: tls_fp_blocklist,
-- tls_fp_catalog, tls_fp_browser_profiles) and stashes the parsed result
-- on this module's table. Because init_by_lua runs in the master before
-- workers fork, every worker inherits these fields for free — no shared
-- dict needed for config that only changes on restart (hot-reload is a
-- separate task per the A3 ticket's out-of-scope list).
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

local function overlay_kill_switch(defaults)
    local parsed = loader.parse_ini(path(KILL_SWITCH_LOCAL))
    if not parsed then return end
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

function _M.load()
    _M.defaults                = load_or_die(loader.parse_ini,  "defaults.conf")
    overlay_kill_switch(_M.defaults)
    _M.whitelist_ip            = load_or_die(loader.parse_list, "whitelist_ip.conf")
    _M.blocklist_ip            = load_or_die(loader.parse_list, "blocklist_ip.conf")
    _M.ua_blacklist            = load_or_die(loader.parse_list, "ua_blacklist.conf")
    _M.asn_datacenters         = load_or_die(loader.parse_list, "asn_datacenters.conf")
    _M.tls_fp_blocklist        = load_or_die(loader.parse_list, "tls_fp_blocklist.conf")
    _M.tls_fp_catalog          = load_or_die(loader.parse_ini,  "tls_fp_catalog.conf")
    _M.tls_fp_browser_profiles = load_or_die(loader.parse_ini,  "tls_fp_browser_profiles.conf")
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

return _M
