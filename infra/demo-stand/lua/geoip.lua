-- GeoLite2 lookup for the L2 reputation stage (A6).
--
-- Wraps the vendored resty.maxminddb (FFI over libmaxminddb) with two
-- profiles: `country` (GeoLite2-Country.mmdb → ISO country code) and `asn`
-- (GeoLite2-ASN.mmdb → autonomous system number). reputation.lua calls
-- lookup() per request to fill the geo_country / asn log fields and to drive
-- the reputation:asn_dc tag.
--
-- Why the stand does the lookup itself: the prod edge does not (yet) expose
-- $geoip_* and providing a MaxMind base is out of our hands. Per CLAUDE.md the
-- stand reproduces edge behaviour in its own Lua, so it carries its own
-- GeoLite2 database and resolves locally.
--
-- FAIL-OPEN by design. The GeoLite2 .mmdb files are license-gated (MaxMind)
-- and NOT committed (see infra/demo-stand/scripts/fetch-geoip.sh). A checkout
-- without them — or a host without libmaxminddb — must still start the stand:
-- init() logs and disables geo, and lookup() returns nil,nil (geo simply
-- undetermined, the geo_country/asn log fields stay null, the asn_dc tag never
-- fires). Geo is observe-only signal, never a hard dependency of the cascade.

local _M = { ready = false }

-- Database location. The fetch script drops the two .mmdb files here and
-- docker-compose mounts the dir read-only into the container.
local DB_DIR     = os.getenv("BAC_GEOIP_DIR") or "/etc/nginx/geoip"
local COUNTRY_DB = DB_DIR .. "/GeoLite2-Country.mmdb"
local ASN_DB     = DB_DIR .. "/GeoLite2-ASN.mmdb"

-- Leaf paths into each database (libmaxminddb aget_value-style path arrays).
local COUNTRY_PATH = { "country", "iso_code" }              -- → "CN"
local ASN_PATH     = { "autonomous_system_number" }         -- → 24940

local mmdb  -- the resty.maxminddb module, set on successful init

-- Called once from init_by_lua (master, before workers fork) so every worker
-- inherits the opened mmdb handles. Returns true when geo is live, false (and
-- stays disabled) on any problem — never raises.
function _M.init()
    local ok, lib = pcall(require, "resty.maxminddb")
    if not ok then
        ngx.log(ngx.WARN, "[demo] geoip: resty.maxminddb unavailable, geo disabled: ", tostring(lib))
        return false
    end

    -- ffi.load('libmaxminddb') + MMDB_open happen inside init(); a missing
    -- shared lib raises, a missing/corrupt .mmdb returns nil,err — guard both.
    local ok2, res, err = pcall(lib.init, { country = COUNTRY_DB, asn = ASN_DB })
    if not ok2 then
        ngx.log(ngx.WARN, "[demo] geoip: init crashed, geo disabled: ", tostring(res))
        return false
    end
    if not res then
        ngx.log(ngx.WARN, "[demo] geoip: GeoLite2 not loaded (", tostring(err),
            "), geo disabled — place GeoLite2-Country.mmdb / GeoLite2-ASN.mmdb in ",
            DB_DIR, " (scripts/fetch-geoip.sh)")
        return false
    end

    mmdb = lib
    _M.ready = true
    ngx.log(ngx.NOTICE, "[demo] geoip: GeoLite2 loaded (country+asn) from ", DB_DIR)
    return true
end

-- lookup(ip) -> cc, asn. Either may be nil (db disabled, ip not found, or a
-- malformed address). Country code is upper-cased; ASN is returned as a string
-- so it matches asn_datacenters.conf entries (also strings). Never raises.
function _M.lookup(ip)
    if not _M.ready or not ip then return nil, nil end

    local cc, asn

    -- maxminddb.lookup returns the leaf scalar on a path hit, or nil+err on a
    -- miss / not-found; pcall guards against an unexpected FFI error.
    local ok, val = pcall(mmdb.lookup, ip, COUNTRY_PATH, "country")
    if ok and type(val) == "string" and val ~= "" then
        cc = val:upper()
    end

    local ok2, val2 = pcall(mmdb.lookup, ip, ASN_PATH, "asn")
    if ok2 and type(val2) == "number" then
        asn = tostring(val2)
    end

    return cc, asn
end

return _M
