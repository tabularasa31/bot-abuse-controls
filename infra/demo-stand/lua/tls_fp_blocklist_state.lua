-- Key format for the tls_fp blocklist shared_dict: `fp:gen`.
--
-- Keying by generation makes a catalog swap atomic: the pull writes the new
-- generation, flips the gen marker, then drops the old one, so readers move
-- across without a per-key race. Single owner of the format, so readers and
-- seeders cannot drift.

local _M = {}

-- Exported so init.lua and catalog_pull.lua share the literals.
_M.META_GEN_KEY  = "tls_fp_blocklist_gen"
_M.META_ETAG_KEY = "tls_fp_blocklist_etag"

function _M.key(fp, gen)
    return fp .. ":" .. gen
end

-- Splits a record value "<status>:<verdict>" into (status, verdict). A bare
-- "block" from a pre-status payload counts as active, so the format change
-- needed no catalog major bump.
function _M.parse_value(v)
    if type(v) ~= "string" then return nil end
    local status, verdict = v:match("^([^:]+):(.+)$")
    if status then return status, verdict end
    return "active", v
end

-- Inverse of key(): the bare fp when `key` belongs to `gen`, else nil.
function _M.match(key, gen)
    local suffix = ":" .. gen
    if key:sub(-#suffix) == suffix then
        return key:sub(1, -#suffix - 1)
    end
    return nil
end

return _M
