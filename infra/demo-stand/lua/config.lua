-- Cascade configuration, loaded once in init_by_lua and held read-only.
--
-- init_by_lua runs in the master before workers fork, so every worker inherits
-- these fields and no shared dict is needed for config that only changes on a
-- restart. A missing or unreadable required file is fatal: better to fail
-- loudly than to serve a half-configured cascade.
--
-- The tls_fp catalogs are not read from disk — they arrive over Channel C and
-- tls_fp.lua builds its tables from the shared_dict.
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

-- The operator's lever surface: a gitignored override file applied on reload,
-- so the switches can be flipped without editing the tracked defaults or
-- recreating the container. Optional, unlike the required configs.
local KILL_SWITCH_LOCAL = "kill_switch.local.conf"

-- Only a real boolean is taken. A typo such as `tls_fp = on` would otherwise
-- silently fail to kill anything — on a lever edited under incident pressure.
local function apply_toggle(dst, key, v, where)
    if type(v) == "boolean" then
        dst[key] = v
    else
        ngx.log(ngx.ERR, "config: ignoring non-boolean ", where,
            " in ", KILL_SWITCH_LOCAL, " (got ", type(v), "); baseline kept")
    end
end

-- Forward declarations, so the definitions below bind to these locals.
local overlay_kill_switch, overlay_edge_protection

-- Parsed once and fed to both overlays, so a new operational toggle rides the
-- same file and the same reload.
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

-- deny_nontenant rejects a non-tenant TLS handshake, dropping a flood aimed at
-- the edge's own IP before the cascade and before the handshake crypto. The
-- HTTP layer already drops non-tenant traffic with 444 regardless.
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
    return _M
end

-- Centralised so every stage computes the toggle identically.
function _M.stage_enabled(defaults, stage)
    local ks = (defaults or {}).kill_switch or {}
    return not ((ks.global or {}).enabled == true
                or (ks.per_stage or {})[stage] == true)
end

-- Distinct from stage_enabled: a disabled stage still emits a log record, while
-- the global kill must suppress the record entirely.
function _M.global_kill(defaults)
    local ks = (defaults or {}).kill_switch or {}
    return (ks.global or {}).enabled == true
end

-- Read once per handshake. The value only changes on reload, so a plain table
-- read is enough and no shared_dict is involved.
function _M.edge_deny_nontenant(defaults)
    local ep = (defaults or {}).edge_protection or {}
    return ep.deny_nontenant == true
end

return _M
