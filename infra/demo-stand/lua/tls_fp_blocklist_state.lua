-- Key format for the tls_fp blocklist shared_dict: `fp .. ":" .. gen`.
--
-- Keying by generation lets a catalog swap (§C1) write the new generation,
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

-- parse_value: разбирает значение записи tls_fp_blocklist (значение в
-- shared_dict, НЕ ключ) в (status, verdict). Wire-формат A11 (Channel C,
-- store.buildTLSFPBlocklist): "<status>:<verdict>", напр. "active:block" /
-- "staging:block". status разводит блокировку (active → verdict=block) от
-- наблюдения (staging → staging_match, без блокировки).
--
-- Legacy bare "block" (старый init-seed / pre-A11 backend payload) трактуем
-- как active — backward-compat, чтобы смена wire-формата не требовала
-- X-Catalog-Version major bump (catalog_pull принимает major=1). nil /
-- не-строка → nil (читатель трактует как «нет записи» = allow).
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
