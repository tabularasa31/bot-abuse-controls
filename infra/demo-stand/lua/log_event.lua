-- log_by_lua handler: emits the structured record and increments the counters
-- edge_stats reports.
--
-- Requests that never entered the cascade (/__health and friends) have no ctx
-- and are skipped, so both the log stream and the counters cover only traffic
-- that was actually judged.

local bac_log = require "bac_log"
local recent  = require "recent"

local ctx = ngx.ctx.bac
if not ctx then return end

local m = ngx.shared.metrics
m:incr("requests_total", 1, 0)
m:incr("verdict_" .. ctx.verdict .. "_total", 1, 0)
-- Tri-state: nil means the cache was never consulted (the clearance fastpath
-- skips it). Counting that as a miss would skew the hit ratio with traffic
-- that never touched the cache.
if ngx.ctx.bac_cache_hit == true then
    m:incr("cache_hit_total", 1, 0)
elseif ngx.ctx.bac_cache_hit == false then
    m:incr("cache_miss_total", 1, 0)
end

-- Key shape "rule:<stage>:<rule>"; neither code contains ":", so the split
-- back out is unambiguous.
if ctx.rule then
    m:incr("rule:" .. ctx.stage .. ":" .. ctx.rule, 1, 0)
end

-- Flags and tags need their own counters because neither survives as the
-- terminal `rule`, and both would otherwise be invisible.
for _, flag in ipairs(ctx.flags) do
    m:incr("flag:" .. flag, 1, 0)
end
for _, tag in ipairs(ctx.tags) do
    m:incr("tag:" .. tag, 1, 0)
end

-- Staging matches feed the promotion decision rather than the verdict, so they
-- are counted separately.
for _, entry in ipairs(ctx.staging_match) do
    m:incr("staging:" .. entry, 1, 0)
end

-- dict:add succeeds only on first sight, which is exactly the unique-fp gauge.
local fp = ctx.tls_fp
local seen = ngx.shared.fp_seen
if fp and seen then
    if seen:add(fp, 1) then
        m:incr("fp_unique", 1, 0)
    else
        seen:incr(fp, 1, 0)
    end
end

-- host and flags are carried so a reader can tell which policy a block belongs
-- to and why it fired.
recent.record({
    t       = ngx.time(),
    fp      = fp,
    ip      = ngx.var.remote_addr,
    ua      = ngx.var.http_user_agent,
    host    = ngx.var.host,
    status  = tonumber(ngx.var.status),
    stage   = ctx.stage,
    verdict = ctx.verdict,
    rule    = ctx.rule,
    flags   = ctx.flags,
})

bac_log.emit()
