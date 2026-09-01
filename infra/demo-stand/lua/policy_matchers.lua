-- Compiles a host's policy lists into matchers, cached by (host, generation):
-- the generation flips on every pull, which invalidates the old entry for free.
-- A TTL on top means a worker that stops receiving pulls still recovers.
--
-- Request-time only: the lookups touch ngx.ctx and the shared dicts.

local lrucache  = require "resty.lrucache"
local ipmatcher = require "resty.ipmatcher"
local policy    = require "policy"

local _M = {}

-- One live entry per host: the previous generation's age out.
local CACHE_SIZE = 256
-- Longer than the pull interval, so the entry survives normal misses; finite,
-- so a stuck generation eventually re-decodes.
local CACHE_TTL  = 300

local cache_inst, cache_err = lrucache.new(CACHE_SIZE)
if not cache_inst then
    -- Unreachable in practice; a dummy keeps correctness and loses only speed.
    ngx.log(ngx.ERR, "policy_matchers: lrucache.new failed: ", cache_err,
        " — running without matcher cache")
    cache_inst = nil
end

-- Returned for hosts with no list fields at all. Cached too, so it costs one
-- allocation per host rather than per request.
local EMPTY = {
    whitelist         = nil,
    blocklist         = nil,
    asn_block         = nil,  -- nil set ≡ "no entries"; reputation guards with `next(...)`
    geo_whitelist     = nil,
    ua_blacklist_re   = nil,
}

-- nil for an empty result, so callers can test the value directly. The type
-- filter matters: cjson decodes JSON null as userdata.
local function to_set(arr)
    if not arr or #arr == 0 then return nil end
    local set = {}
    for _, v in ipairs(arr) do
        local t = type(v)
        if (t == "string" or t == "number") and v ~= "" then
            set[tostring(v)] = true
        end
    end
    return next(set) and set or nil
end

-- Fail-stale: a malformed CIDR yields nil, so the rule does not fire.
local function compile_ip(cidrs, host, label)
    if not cidrs or #cidrs == 0 then return nil end
    local clean = {}
    for _, c in ipairs(cidrs) do
        if type(c) == "string" and c ~= "" then
            clean[#clean + 1] = c
        end
    end
    if #clean == 0 then return nil end
    local m, err = ipmatcher.new(clean)
    if not m then
        ngx.log(ngx.ERR, "policy_matchers: ipmatcher.new failed for ",
            label, " of host=", host, ": ", tostring(err))
        return nil
    end
    return m
end

-- No status filtering: a per-host list comes from the dashboard, so every entry
-- is active — staging is a catalog property, not a policy one.
local function compile_ua(patterns)
    if not patterns or #patterns == 0 then return nil end
    local nonempty = {}
    for _, p in ipairs(patterns) do
        if type(p) == "string" and p ~= "" then
            nonempty[#nonempty + 1] = p
        end
    end
    if #nonempty == 0 then return nil end
    return "(" .. table.concat(nonempty, ")|(") .. ")"
end

-- Returns EMPTY when every list is empty.
local function build(host, p)
    local wl  = compile_ip(p.ip_whitelist, host, "policy.ip_whitelist")
    local bl  = compile_ip(p.ip_blocklist, host, "policy.ip_blocklist")
    local asn = to_set(p.asn_block)
    local geo = to_set(p.geo_whitelist)
    local ua  = compile_ua(p.ua_blacklist)
    if not (wl or bl or asn or geo or ua) then return EMPTY end
    return {
        whitelist         = wl,
        blocklist         = bl,
        asn_block         = asn,
        geo_whitelist     = geo,
        ua_blacklist_re   = ua,
    }
end

-- Always returns a bundle, so callers need no nil guards. Cached twice: per
-- request, because two stages ask for the same host, and per worker by
-- generation.
function _M.get(host)
    if not host or host == "" then return EMPTY end
    local ctx = ngx.ctx
    local req_cache
    if ctx then
        req_cache = ctx.policy_matchers_cache
        if req_cache then
            local hit = req_cache[host]
            if hit then return hit end
        end
    end
    local meta = ngx.shared.meta
    if not meta then return EMPTY end
    local gen = meta:get("antibot_policy_gen")
    if not gen then return EMPTY end
    local canonical = policy.canonical_host(host)
    if not canonical then return EMPTY end
    local key = canonical .. ":" .. gen
    local m
    if cache_inst then
        m = cache_inst:get(key)
    end
    if not m then
        local p = policy.get(host)
        m = build(canonical, p)
        if cache_inst then
            cache_inst:set(key, m, CACHE_TTL)
        end
    end
    if ctx then
        if not req_cache then
            req_cache = {}
            ctx.policy_matchers_cache = req_cache
        end
        req_cache[host] = m
    end
    return m
end

-- Exposed so callers can detect "no per-host lists" by identity. Read-only.
_M.EMPTY = EMPTY

_M._to_set     = to_set
_M._compile_ua = compile_ua

return _M
