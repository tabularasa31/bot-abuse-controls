-- Compiles a host's policy lists into runtime matchers.
--
-- Reputation and hygiene need the raw policy lists as ipmatcher objects, lookup
-- sets and a combined UA regex. Building those per request is too expensive, so
-- they are cached by (host, generation): the generation flips atomically on
-- every catalog pull, which invalidates the old entry for free. Entries also
-- carry a TTL, so a worker that somehow stops receiving pulls still recovers.
--
-- Request-time only: the lookups touch ngx.ctx and the shared dicts.

local lrucache  = require "resty.lrucache"
local ipmatcher = require "resty.ipmatcher"
local policy    = require "policy"

local _M = {}

-- One live entry per host, since the previous generation's entries become
-- unreachable on a flip and age out.
local CACHE_SIZE = 256
-- 5 minutes: longer than the catalog pull interval (30s) so the cached
-- entry survives a few requests' worth of misses; shorter than infinity
-- so a gen that gets stuck (worker isolated from backend) eventually
-- gives up on the stale matchers and re-decodes from shared_dict.
local CACHE_TTL  = 300

local cache_inst, cache_err = lrucache.new(CACHE_SIZE)
if not cache_inst then
    -- Should be unreachable — resty.lrucache.new only errors on bad size.
    -- Log and use a dummy that always misses; correctness preserved
    -- (every call hits the compile path), only perf suffers.
    ngx.log(ngx.ERR, "policy_matchers: lrucache.new failed: ", cache_err,
        " — running without matcher cache")
    cache_inst = nil
end

-- A sentinel returned for hosts whose policy carries no list fields at
-- all. reputation/hygiene check the constituent fields for nil before
-- doing any matching, so an EMPTY object is a valid no-op shape. We
-- still cache it (one allocation per host instead of per request).
local EMPTY = {
    whitelist         = nil,
    blocklist         = nil,
    asn_block         = nil,  -- nil set ≡ "no entries"; reputation guards with `next(...)`
    geo_whitelist     = nil,
    ua_blacklist_re   = nil,
}

-- Returns nil for an empty result, so callers can test the value directly. The
-- type filter matters: cjson decodes JSON null as userdata, whose tostring
-- would shadow a real key.
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

-- Fail-stale: a malformed CIDR logs and yields nil, so the rule does not fire
-- for that host rather than erroring.
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
-- is active by definition — staging is a catalog property, not a policy one.
-- Type-filtered so a malformed payload cannot turn into a 500.
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

-- build — compile one Policy into its matcher bundle. Pure-ish:
-- depends on ipmatcher (which itself only reads its input) and the
-- helpers above. Returns EMPTY when every list is empty.
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

-- Always returns a bundle: an unregistered host gets the shared empty sentinel,
-- so callers can test a field without nil guards.
--
-- Cached twice: per request, because hygiene and reputation both ask for the
-- same host, and per worker keyed by generation, which survives across
-- requests and is invalidated by the next pull.
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

-- EMPTY exposed for callers that want to detect "no per-host lists" by
-- identity (`m == policy_matchers.EMPTY`) — cheaper than walking fields.
-- Treat as read-only (same contract as policy.get's returned Policy).
_M.EMPTY = EMPTY

-- Pure helpers exposed for unit-testing without ngx / openresty deps.
_M._to_set     = to_set
_M._compile_ua = compile_ua

return _M
