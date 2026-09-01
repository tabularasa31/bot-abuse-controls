-- GeoLite2 country and ASN lookup for the L2 reputation stage.
--
-- Fail-open by design: the .mmdb files are licence-gated and not committed, so
-- a checkout without them, or a host without libmaxminddb, must still start.
-- Geo then stays undetermined and the asn_dc tag never fires. It is an
-- observe-only signal, never a hard dependency of the cascade.

local _M = { ready = false }

-- Where fetch-geoip.sh drops the databases; mounted read-only.
local DB_DIR     = os.getenv("BAC_GEOIP_DIR") or "/etc/nginx/geoip"
local COUNTRY_DB = DB_DIR .. "/GeoLite2-Country.mmdb"
local ASN_DB     = DB_DIR .. "/GeoLite2-ASN.mmdb"

-- Leaf paths into each database (libmaxminddb aget_value-style path arrays).
local COUNTRY_PATH = { "country", "iso_code" }              -- → "CN"
local ASN_PATH     = { "autonomous_system_number" }         -- → 24940

local mmdb  -- the resty.maxminddb module, set on successful init

-- Called from init_by_lua before workers fork, so each inherits the open
-- handles. Never raises; false means geo stays disabled.
function _M.init()
    local ok, lib = pcall(require, "resty.maxminddb")
    if not ok then
        ngx.log(ngx.WARN, "[demo] geoip: resty.maxminddb unavailable, geo disabled: ", tostring(lib))
        return false
    end

    -- A missing shared library raises; a missing or corrupt database returns
    -- nil,err. Guard both.
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

-- Returns (country, asn), either possibly nil. The ASN is a string so it
-- compares directly against the catalog entries. Never raises.
function _M.lookup(ip)
    if not _M.ready or not ip then return nil, nil end

    local cc, asn

    -- pcall guards against an unexpected FFI error.
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
