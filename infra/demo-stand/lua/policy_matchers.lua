-- policy_matchers.lua — per-host policy lists compiled into runtime matchers
-- (86exr05xt).
--
-- policy.get(host) returns the raw Policy table (mode, strictness, plus list
-- fields ua_blacklist / ip_whitelist / ip_blocklist / asn_block /
-- geo_whitelist). Reputation and hygiene need the lists as ipmatcher
-- objects / lookup sets / a combined UA regex — compiling them per request
-- is too expensive (lua-resty-ipmatcher walks all CIDRs to build a
-- patricia trie; the regex compile is JIT'd by `jo` flag but the
-- combine-into-alternation step is still O(N)). Cache by (host, gen):
-- the gen flips atomically on every Channel C pull (catalog_pull.lua), so
-- a fresh policy invalidates the old key automatically and the old key
-- ages out via LRU. TTL on cache entries is a defence-in-depth so a
-- worker that never receives another pull (B7 broken? gen stuck) still
-- eventually re-runs the lookup.
--
-- The module is request-time only: lookups call ngx.shared.meta and may
-- call policy.get which expects ngx.ctx. Do not call from init phase.

local lrucache  = require "resty.lrucache"
local ipmatcher = require "resty.ipmatcher"
local policy    = require "policy"

local _M = {}

-- Sized for the demo (≤O(10) clients) plus headroom for future fanout.
-- One entry per (host, gen) — gen flips on every catalog pull, so the
-- effective working set is N_hosts × 1 (the previous gen's entries
-- become unreachable on flip and age out). 256 covers ~250 hosts before
-- LRU eviction kicks in; bump if the dashboard ever onboards more.
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

-- to_set — array of strings/numbers → { [v] = true }. nil/empty array
-- returns nil so callers can do `if set then` cheaply.
local function to_set(arr)
    if not arr or #arr == 0 then return nil end
    local set = {}
    for _, v in ipairs(arr) do
        if v ~= nil and v ~= "" then
            set[tostring(v)] = true
        end
    end
    return next(set) and set or nil
end

-- compile_ip — wraps ipmatcher.new with fail-stale: a malformed CIDR
-- (shouldn't happen after backend ValidateCIDR, but defence in depth)
-- logs ERR and yields nil so the rule simply doesn't fire — pre-PR
-- behaviour preserved for that one host.
local function compile_ip(cidrs, host, label)
    if not cidrs or #cidrs == 0 then return nil end
    local m, err = ipmatcher.new(cidrs)
    if not m then
        ngx.log(ngx.ERR, "policy_matchers: ipmatcher.new failed for ",
            label, " of host=", host, ": ", tostring(err))
        return nil
    end
    return m
end

-- compile_ua — combine an array of UA regex strings into a single
-- alternation, same shape hygiene's build_combined produces from the
-- attrs-list form. Returns nil if the array is empty so the caller can
-- skip the ngx.re.find entirely. No status filtering: per-host lists
-- come from the dashboard, every entry is "active" by definition (the
-- staging/active toggle is a catalog property, not a policy one).
local function compile_ua(patterns)
    if not patterns or #patterns == 0 then return nil end
    local nonempty = {}
    for _, p in ipairs(patterns) do
        if p and p ~= "" then nonempty[#nonempty + 1] = p end
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

-- get(host) → matcher bundle. Always non-nil; an unregistered host or
-- a host with all-empty lists returns the shared EMPTY sentinel so
-- callers can field-test (`if m.blocklist then ...`) without nil guards.
function _M.get(host)
    if not host or host == "" then return EMPTY end
    local meta = ngx.shared.meta
    if not meta then return EMPTY end
    local gen = meta:get("antibot_policy_gen")
    if not gen then return EMPTY end
    local canonical = policy.canonical_host(host)
    if not canonical then return EMPTY end
    local key = canonical .. ":" .. gen
    if cache_inst then
        local hit = cache_inst:get(key)
        if hit then return hit end
    end
    local p = policy.get(host)
    local m = build(canonical, p)
    if cache_inst then
        cache_inst:set(key, m, CACHE_TTL)
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
