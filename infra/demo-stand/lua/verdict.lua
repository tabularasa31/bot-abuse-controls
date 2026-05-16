-- Demo-stand verdict.lua. Same compute_fp + cache + blocklist pipeline
-- as production (infra/nginx-lua-poc/lua/verdict.lua), with one
-- addition: stash fp/verdict into ngx.ctx so log_event.lua can pick
-- them up for metrics increment and structured logging. The block
-- behaviour (ngx.exit(403) on block verdict) is identical to prod —
-- this stand is showing real enforcement, not shadow mode.

local ja4 = require "ja4_compute"

local fp, parts = ja4.compute()

local cache = ngx.shared.verdict_cache
local cached = cache:get(fp)

local verdict
local cache_hit = (cached ~= nil)
if cached == "block" or cached == "allow" then
    verdict = cached
else
    verdict = ngx.shared.fp_blocklist:get(fp) or "allow"
    cache:set(fp, verdict, 60)
end

ngx.ctx.antibot_fp        = fp
ngx.ctx.antibot_fp_parts  = parts
ngx.ctx.antibot_verdict   = verdict
ngx.ctx.antibot_cache_hit = cache_hit

if verdict == "block" then
    return ngx.exit(403)
end
-- allow: fall through to the location's content handler
