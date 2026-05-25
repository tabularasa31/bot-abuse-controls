-- Key format for the tls_fp blocklist shared_dict: `fp .. ":" .. gen`.
--
-- Keying by generation lets a catalog swap (§В1) write the new generation,
-- flip meta:tls_fp_blocklist_gen, then drop the old one — readers move to the new
-- set atomically without a per-key race. This module is the single owner of
-- that format so the §A1 read (verdict.lua), the static seed (init.lua) and
-- the /__admin view never drift.

local _M = {}

-- meta shared_dict keys for the catalog. Exported here so init.lua and
-- catalog_pull.lua не дублируют литералы и не drift'ят при будущем rename
-- (PR-62 round-8 audit: hard-coded "tls_fp_blocklist_etag" в init.lua
-- divergence-recovery был sync-trap).
_M.META_GEN_KEY  = "tls_fp_blocklist_gen"
_M.META_ETAG_KEY = "tls_fp_blocklist_etag"

function _M.key(fp, gen)
    return fp .. ":" .. gen
end

-- Inverse of key(): if `key` belongs to generation `gen` return the bare fp,
-- else nil. Used by the /__admin view and the §В1 pull's old-generation sweep.
function _M.match(key, gen)
    local suffix = ":" .. gen
    if key:sub(-#suffix) == suffix then
        return key:sub(1, -#suffix - 1)
    end
    return nil
end

return _M
