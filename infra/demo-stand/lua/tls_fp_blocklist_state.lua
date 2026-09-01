-- Key format for the tls_fp blocklist shared_dict: `fp .. ":" .. gen`.
--
-- Keying by generation lets a catalog swap (§C1) write the new generation,
-- flip meta:tls_fp_blocklist_gen, then drop the old one — readers move to the new
-- set atomically without a per-key race. This module is the single owner of
-- that format so the §A1 read (verdict.lua), the static seed (init.lua) and
-- the /__admin view never drift.

local _M = {}

-- meta shared_dict keys for the catalog. Exported here so init.lua and
-- catalog_pull.lua do not duplicate the literals and do not drift on a future rename
-- (from audit: a hard-coded "tls_fp_blocklist_etag" in init.lua's
-- divergence recovery was a sync trap).
_M.META_GEN_KEY  = "tls_fp_blocklist_gen"
_M.META_ETAG_KEY = "tls_fp_blocklist_etag"

function _M.key(fp, gen)
    return fp .. ":" .. gen
end

-- parse_value: parses the value of a tls_fp_blocklist record (the value in the
-- shared_dict, NOT the key) into (status, verdict). The A11 wire format (Channel C,
-- store.buildTLSFPBlocklist) is "<status>:<verdict>", e.g. "active:block" /
-- "staging:block". The status separates blocking (active → verdict=block) from
-- observation (staging → staging_match, with no block).
--
-- A legacy bare "block" (an old init seed or a pre-A11 backend payload) is treated
-- as active — backward compatibility, so that changing the wire format does not require an
-- X-Catalog-Version major bump (catalog_pull accepts major=1). nil or a
-- non-string → nil (the reader treats it as "no record" = allow).
function _M.parse_value(v)
    if type(v) ~= "string" then return nil end
    local status, verdict = v:match("^([^:]+):(.+)$")
    if status then return status, verdict end
    return "active", v
end

-- Inverse of key(): if `key` belongs to generation `gen` return the bare fp,
-- else nil. Used by the /__admin view and the §C1 pull's old-generation sweep.
function _M.match(key, gen)
    local suffix = ":" .. gen
    if key:sub(-#suffix) == suffix then
        return key:sub(1, -#suffix - 1)
    end
    return nil
end

return _M
