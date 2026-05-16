-- log_by_lua_block handler. Two jobs:
--   1. Increment the metrics shared_dict counters that /metrics serves.
--   2. Emit a one-line structured log per request for retrospection.
--
-- Runs AFTER access_by_lua, so ngx.ctx.antibot_* are populated. For
-- requests that bypass verdict.lua (e.g. /__health, /metrics), the
-- ctx keys are nil and we skip the increment so the counters reflect
-- only requests that actually went through the pipeline.

local fp      = ngx.ctx.antibot_fp
local verdict = ngx.ctx.antibot_verdict
if not fp then return end

local m = ngx.shared.metrics
m:incr("requests_total", 1, 0)
m:incr("verdict_" .. verdict .. "_total", 1, 0)
if ngx.ctx.antibot_cache_hit then
    m:incr("cache_hit_total", 1, 0)
else
    m:incr("cache_miss_total", 1, 0)
end

-- Per-request structured line. Truncate UA so a rogue 4 KB UA can't
-- bloat the log. fp itself is short; full cipher list is in the fp
-- prefix counts so we don't repeat it here.
local ua = ngx.var.http_user_agent or ""
if #ua > 200 then ua = ua:sub(1, 197) .. "..." end

ngx.log(ngx.NOTICE, string.format(
    "ANTIBOT verdict=%s fp=%s status=%s uri=%s remote=%s ua=%q rt=%s",
    verdict,
    fp,
    ngx.var.status,
    ngx.var.uri,
    ngx.var.remote_addr,
    ua,
    ngx.var.request_time))
