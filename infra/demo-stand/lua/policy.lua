-- Per-host policy reader and the mode gate for the cascade.
--
-- get(host) always returns a table: an unknown host or a decode failure falls
-- back to POOL_DEFAULT, which must stay in step with the backend's.
--
-- enforce(status) is the single point where a verdict becomes a response, or
-- shadow-mode customers would start receiving 4xx from new enforcement points.
local _M = {}

local cjson      = require "cjson.safe"
local cjson_base = require "cjson"   -- empty_array_mt sentinel

-- A `{}` that cjson encodes as `[]`, since the list fields are arrays.
local function empty_array()
    return setmetatable({}, cjson_base.empty_array_mt)
end

-- Built per call, so a caller cannot mutate a shared instance.
local function new_pool_default()
    return {
        mode          = "shadow",
        strictness    = "standard",
        ua_blacklist  = empty_array(),
        ip_whitelist  = empty_array(),
        ip_blocklist  = empty_array(),
        asn_block     = empty_array(),
        geo_whitelist = empty_array(),
        rate_rules    = empty_array(),
        attack_mode   = false,
    }
end

-- Host names are case-insensitive, and the header is client-controlled, so the
-- key is also capped to fit the dict's limit.
local function canonical_host(host)
    if not host or host == "" then return nil end
    host = string.lower(host)
    if #host > 64 then
        host = ngx.md5(host)
    end
    return host
end

-- Mirror the backend validators, so an unknown value fails loudly.
local VALID_MODES         = { shadow = true, active = true }
local VALID_STRICTNESSES  = { standard = true, permissive = true }

-- A missing or unknown mode would silently demote an active customer to shadow.
-- origin_ip survives the fallback: routing must not depend on enum validity, or
-- a schema change would drop a tenant's traffic entirely.
local function decode_entry(raw, host)
    local p, err = cjson.decode(raw)
    if not p or type(p) ~= "table" then
        ngx.log(ngx.ERR, "policy: decode failed for ", host, ": ", tostring(err))
        return new_pool_default()
    end
    local function fallback()
        local d = new_pool_default()
        if type(p.origin_ip) == "string" and p.origin_ip ~= "" then
            d.origin_ip = p.origin_ip
        end
        return d
    end
    if type(p.mode) ~= "string" or not VALID_MODES[p.mode] then
        ngx.log(ngx.ERR, "policy: invalid mode for ", host, ": ",
            tostring(p.mode), " — falling back to pool default")
        return fallback()
    end
    if type(p.strictness) ~= "string" or not VALID_STRICTNESSES[p.strictness] then
        ngx.log(ngx.ERR, "policy: invalid strictness for ", host, ": ",
            tostring(p.strictness), " — falling back to pool default")
        return fallback()
    end
    return p
end

-- A customer onboards a domain, so one row covers its subdomains; an explicit
-- subdomain row still wins.
local function lookup(host)
    if not host or host == "" then return new_pool_default() end
    local dict = ngx.shared.antibot_policy
    local meta = ngx.shared.meta
    if not dict or not meta then return new_pool_default() end
    local gen = meta:get("antibot_policy_gen")
    if not gen then return new_pool_default() end

    local candidate = string.lower(host)
    while candidate and candidate ~= "" do
        local key = canonical_host(candidate)
        local raw = key and dict:get(key .. ":" .. gen)
        if raw then
            return decode_entry(raw, candidate)
        end
        local dot = candidate:find(".", 1, true)
        if not dot then break end
        local parent = candidate:sub(dot + 1)
        -- Never inherit from a bare TLD: such a row can only exist through
        -- manual SQL, and it would hand its policy to every domain under it.
        if not parent:find(".", 1, true) then break end
        candidate = parent
    end
    return new_pool_default()
end

-- Memoized per request: the cascade and the logger read the same host, and each
-- miss costs a dict read and a decode. A flip mid-request is deliberately
-- invisible.
--
-- The returned table is read-only — every caller gets the same instance.
function _M.get(host)
    local ctx = ngx.ctx
    if not ctx then return lookup(host) end
    local key = canonical_host(host) or ""
    local cache = ctx.policy_cache
    if not cache then
        cache = {}
        ctx.policy_cache = cache
    end
    local hit = cache[key]
    if hit ~= nil then return hit end
    local p = lookup(host)
    cache[key] = p
    return p
end

-- Exposed so the pull writes keys with the same normalisation this reads.
_M.canonical_host = canonical_host

-- ctx-free, for the ssl phase where ngx.ctx is not reliably per-request.
function _M.origin_ip(host)
    return lookup(host).origin_ip
end

-- Exits only under mode=active; under shadow it returns and the caller carries
-- on. Record the verdict before calling. Headers are skipped in shadow: that
-- response belongs to the origin.
function _M.enforce(status, headers)
    if _M.get(ngx.var.host).mode == "active" then
        if headers then
            for k, v in pairs(headers) do
                ngx.header[k] = v
            end
        end
        return ngx.exit(status)
    end
end

return _M
