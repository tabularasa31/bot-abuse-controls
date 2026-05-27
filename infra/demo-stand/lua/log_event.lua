-- log_by_lua handler. Two jobs:
--   1. Emit the single Phase 1 structured JSON record (via bac_log).
--   2. Increment the metrics shared_dict counters that /metrics serves.
--
-- Runs AFTER access_by_lua, so ngx.ctx.bac is populated. Requests that
-- bypass verdict.lua (e.g. /__health, /metrics) never called init, have
-- no ctx, and are skipped — counters and the log stream reflect only
-- requests that actually went through the pipeline.

local bac_log = require "bac_log"
local recent  = require "recent"

local ctx = ngx.ctx.bac
if not ctx then return end

local m = ngx.shared.metrics
m:incr("requests_total", 1, 0)
m:incr("verdict_" .. ctx.verdict .. "_total", 1, 0)
-- Tri-state: bac_cache_hit is explicitly set to true/false in verdict.lua
-- only when the verdict_cache was actually consulted (L3 tls_fp path). It
-- stays `nil` when the cache lookup was skipped — currently that's the C3
-- clearance fastpath (`ngx.ctx.clearance_valid` → tls_fp blocklist/cache
-- block bypassed; fp itself is still computed for L4 rate_tls_fp). Counting
-- nil as a miss would pollute antibot_cache_hit_ratio with cookie-fastpath
-- traffic that never touched the cache.
if ngx.ctx.bac_cache_hit == true then
    m:incr("cache_hit_total", 1, 0)
elseif ngx.ctx.bac_cache_hit == false then
    m:incr("cache_miss_total", 1, 0)
end

-- Per-rule counter (which rule fired, on which stage). Key shape
-- "rule:<stage>:<rule>" — metrics.lua parses it back out. Rule codes and
-- stage codes contain no ":", so the split is unambiguous.
if ctx.rule then
    m:incr("rule:" .. ctx.stage .. ":" .. ctx.rule, 1, 0)
end

-- Soft-flag and tag counters (A9). Flags are soft challenge signals
-- (tls_fp_impersonator / tls_fp_suspicious_ciphers) that may be overwritten as
-- the terminal `rule`, so they need their own counter to stay observable;
-- tags (tls_fp:*, reputation:*, hygiene:*) likewise never become `rule`. Key
-- shapes "flag:<flag>" / "tag:<tag>" — metrics.lua parses them back out. Both
-- code-spaces are tiny, so iterating the (usually empty) arrays is cheap.
for _, flag in ipairs(ctx.flags) do
    m:incr("flag:" .. flag, 1, 0)
end
for _, tag in ipairs(ctx.tags) do
    m:incr("tag:" .. tag, 1, 0)
end

-- Staged-pattern match counter (A11). Each entry is already "<catalog>:
-- <pattern_id>"; key shape "staging:<catalog>:<pattern_id>" (metrics.lua parses
-- it back out). Staging matches feed the promotion workflow, not the verdict,
-- so they get their own counter like flags/tags. Usually empty → cheap.
for _, entry in ipairs(ctx.staging_match) do
    m:incr("staging:" .. entry, 1, 0)
end

-- fp cardinality: dict:add succeeds only the first time we see an fp, so it
-- doubles as a first-seen signal for the unique-fp gauge.
local fp = ctx.tls_fp
local seen = ngx.shared.fp_seen
if fp and seen then
    if seen:add(fp, 1) then
        m:incr("fp_unique", 1, 0)
    else
        seen:incr(fp, 1, 0)
    end
end

-- Live ring buffer for /__admin.
recent.record({
    t       = ngx.time(),
    fp      = fp,
    ip      = ngx.var.remote_addr,
    ua      = ngx.var.http_user_agent,
    status  = tonumber(ngx.var.status),
    stage   = ctx.stage,
    verdict = ctx.verdict,
    rule    = ctx.rule,
})

bac_log.emit()
