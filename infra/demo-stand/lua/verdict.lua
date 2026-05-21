-- Demo-stand access_by_lua handler.
--
-- Responsibilities:
--   1. Initialise the per-request BAC log context (request_id, start
--      time, resource_id) so latency_ms covers the whole cascade and
--      log_event.lua can emit the final structured record.
--   2. Run the L1 `hygiene` stage (hygiene.lua: method_not_allowed /
--      ua_blacklist + the hygiene:header_anomaly tag) — observe-only.
--   3. Run the existing TLS-fingerprint block decision (compute_fp +
--      cache + blocklist), identical to production.
--
-- The fp-based block is the Phase 2 `tls_fp` stage; it is recorded
-- through the same bac_log contract as hygiene. The remaining Phase 1
-- stages (reputation / rate_limits) are separate tasks. The
-- stand runs shadow: tls_fp_blocklist.conf ships empty (init.lua seeds the
-- fp_blocklist dict from it), so verdict is always "allow" and nothing is
-- blocked. The ngx.exit(403) path stays wired so adding an fp to that
-- config and restarting flips it to active without code changes.

local ja4     = require "ja4_compute"
local bac_log = require "bac_log"
local hygiene = require "hygiene"

bac_log.init()

-- L1 hygiene (method_not_allowed / ua_blacklist). Phase 1 is
-- observe-only: hygiene.run() records the would-be verdict via bac_log and
-- returns true when a rule fired. We then stop the cascade (the would-be
-- final rule is this one) and fall through to origin WITHOUT blocking — no
-- ngx.exit. See hygiene.lua for why this differs from the tls_fp stage below.
if hygiene.run() then
    return
end

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
