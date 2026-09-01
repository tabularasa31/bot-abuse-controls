-- Per-host policy reader and the mode gate for the whole cascade.
--
-- Policy arrives over Channel C into a shared_dict keyed `<host>:<gen>`, with
-- the generation flipped atomically by the pull. get(host) always returns a
-- table: an unknown host, a missing dict or a decode failure all fall back to
-- POOL_DEFAULT, which must stay in step with the backend's PoolDefault().
--
-- enforce(status) is the single point where a verdict becomes a response. Any
-- stage that wants to affect the response goes through it, or shadow-mode
-- customers would start receiving 4xx from new enforcement points. The verdict
-- is recorded before the call, so it lands in the log in either mode.
local _M = {}

local cjson      = require "cjson.safe"
local cjson_base = require "cjson"   -- empty_array_mt sentinel

-- A `{}` that cjson encodes as `[]`. The list fields are arrays on the wire, so
-- the defaults have to encode as arrays too.
local function empty_array()
    return setmetatable({}, cjson_base.empty_array_mt)
end

-- Must match catalog.PoolDefault() in the backend. Built per call, so a caller
-- cannot mutate a shared instance and leak it into the next request.
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

-- Host names are case-insensitive, so a mixed-case policy row still has to
-- resolve. Length is capped as well: shared_dict keys stop at 255 bytes and the
-- Host header is client-controlled.
local function canonical_host(host)
    if not host or host == "" then return nil end
    host = string.lower(host)
    if #host > 64 then
        host = ngx.md5(host)
    end
    return host
end

-- Mirror the backend validators. If the backend gains a value the edge does not
-- know, the edge fails stale and says so, rather than silently demoting.
local VALID_MODES         = { shadow = true, active = true }
local VALID_STRICTNESSES  = { standard = true, permissive = true }

-- A policy with a missing or unknown `mode` would silently demote an active
-- customer to shadow, so it falls back loudly instead. origin_ip survives the
-- fallback: routing must not depend on enum validity, or a schema change would
-- drop a tenant's traffic entirely rather than just failing enforcement stale.
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

-- Uncached read with a parent-domain walk: a customer onboards a domain, so one
-- row has to cover its subdomains, while an explicit subdomain row still wins.
-- Most specific match first.
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
        -- Never walk up to a bare TLD. The backend rejects public-suffix rows on
        -- write, so one can only exist through manual SQL, and inheriting it
        -- would hand its policy to every domain under it. An exact single-label
        -- lookup still matches on the first iteration.
        if not parent:find(".", 1, true) then break end
        candidate = parent
    end
    return new_pool_default()
end

-- Memoized per request: the cascade and the logger both read the same host, and
-- each miss costs a dict read plus a full decode. A generation flip mid-request
-- is deliberately invisible — consistency within one request matters more than
-- shaving the staleness window.
--
-- The returned table is read-only. Every caller in the request gets the same
-- instance, so mutating it corrupts the view for the rest of them; per-request
-- state belongs on ngx.ctx.
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

-- ctx-free, for the ssl_certificate_by_lua phase where ngx.ctx is not reliably
-- per-request and the memoized get() would leak across handshakes.
function _M.origin_ip(host)
    return lookup(host).origin_ip
end

-- Exits with `status` only under mode=active; under shadow it returns and the
-- caller carries on to the origin. Record the verdict before calling.
--
-- `headers` is skipped in shadow mode: that response belongs to the origin and
-- must not carry our headers.
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
