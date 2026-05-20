-- Demo-stand access_by_lua handler.
--
-- Two responsibilities:
--   1. Initialise the per-request BAC log context (request_id, start
--      time, resource_id) so latency_ms covers the whole cascade and
--      log_event.lua can emit the final structured record.
--   2. Run the existing TLS-fingerprint block decision (compute_fp +
--      cache + blocklist), identical to production.
--
-- The fp-based block is the Phase 2 `tls_fp` stage; it is recorded
-- through the same bac_log contract the Phase 1 cascade stages
-- (hygiene / reputation / rate_limits — separate tasks) will use. The
-- stand runs shadow: blocklist.lua ships empty, so verdict is always
-- "allow" and nothing is blocked. The ngx.exit(403) path stays wired so
-- adding fps to the blocklist flips it to active without code changes.

local ja4     = require "ja4_compute"
local bac_log = require "bac_log"

bac_log.init()

local fp = ja4.compute()
bac_log.set_tls_fp(fp)

local cache  = ngx.shared.verdict_cache
local cached = cache:get(fp)
local cache_hit = (cached ~= nil)

local verdict
if cached == "block" or cached == "allow" then
    verdict = cached
else
    verdict = ngx.shared.fp_blocklist:get(fp) or "allow"
    cache:set(fp, verdict, 60)
end

-- Cache outcome is metrics-only; stash it for log_event.lua's counters.
ngx.ctx.bac_cache_hit = cache_hit

if verdict == "block" then
    bac_log.set_verdict("tls_fp", "block", "tls_fp_blocklist")
    return ngx.exit(403)
end
-- allow: fall through. Context keeps its defaults (stage=egress,
-- verdict=pass) — no Phase 1 rule fired on this stand yet.
