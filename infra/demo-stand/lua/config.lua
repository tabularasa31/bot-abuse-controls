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

function _M.load()
    _M.defaults                = load_or_die(loader.parse_ini,  "defaults.conf")
    _M.whitelist_ip            = load_or_die(loader.parse_list, "whitelist_ip.conf")
    _M.blocklist_ip            = load_or_die(loader.parse_list, "blocklist_ip.conf")
    _M.ua_blacklist            = load_or_die(loader.parse_list, "ua_blacklist.conf")
    _M.asn_datacenters         = load_or_die(loader.parse_list, "asn_datacenters.conf")
    _M.tls_fp_blocklist        = load_or_die(loader.parse_list, "tls_fp_blocklist.conf")
    _M.tls_fp_catalog          = load_or_die(loader.parse_ini,  "tls_fp_catalog.conf")
    _M.tls_fp_browser_profiles = load_or_die(loader.parse_ini,  "tls_fp_browser_profiles.conf")
    return _M
end

return _M
