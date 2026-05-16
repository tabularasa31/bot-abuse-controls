-- Shadow-mode verdict. Computes fp, looks up blocklist, stashes the
-- "would-have-done" verdict in ngx.ctx for log_event.lua to emit — but
-- NEVER actually blocks the request. Always falls through to the proxy.
--
-- Why a separate file from infra/nginx-lua-poc/lua/verdict.lua?
-- ------------------------------------------------------------
-- The PoC verdict.lua is the merge-and-ship target; we keep it minimal
-- and call ngx.exit(403). Shadow mode is observation-only: we want to
-- run the full verdict pipeline (compute_fp, cache, blocklist lookup) so
-- the timings and cache behaviour match production, but skip the exit so
-- no real traffic gets dropped. Flipping shadow→active later is a config
-- change (swap which verdict.lua the nginx conf points at), not code.

local ja4 = require "ja4_compute"

local fp, parts = ja4.compute()

local cache = ngx.shared.verdict_cache
local cached = cache:get(fp)

local verdict
if cached == "block" or cached == "allow" then
    verdict = cached
else
    verdict = ngx.shared.fp_blocklist:get(fp) or "allow"
    cache:set(fp, verdict, 60)
end

-- Stash for log_event.lua. Use ngx.ctx because log_by_lua runs in the
-- same request context.
ngx.ctx.antibot_fp = fp
ngx.ctx.antibot_fp_parts = parts
ngx.ctx.antibot_verdict = verdict
ngx.ctx.antibot_cache_hit = (cached ~= nil)

-- SHADOW MODE: do NOT exit. Even if verdict == "block", fall through to
-- proxy. The log line in log_event.lua records the would-be-block.
