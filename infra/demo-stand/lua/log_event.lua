-- log_by_lua handler. Two jobs:
--   1. Emit the single Phase 1 structured JSON record (via bac_log).
--   2. Increment the metrics shared_dict counters that /metrics serves.
--
-- Runs AFTER access_by_lua, so ngx.ctx.bac is populated. Requests that
-- bypass verdict.lua (e.g. /__health, /metrics) never called init, have
-- no ctx, and are skipped — counters and the log stream reflect only
-- requests that actually went through the pipeline.

local bac_log = require "bac_log"

local ctx = ngx.ctx.bac
if not ctx then return end

local m = ngx.shared.metrics
m:incr("requests_total", 1, 0)
m:incr("verdict_" .. ctx.verdict .. "_total", 1, 0)
if ngx.ctx.bac_cache_hit then
    m:incr("cache_hit_total", 1, 0)
else
    m:incr("cache_miss_total", 1, 0)
end

bac_log.emit()
