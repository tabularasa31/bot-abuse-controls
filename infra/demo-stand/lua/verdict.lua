-- Demo-stand access_by_lua handler.
--
-- Responsibilities:
--   1. Initialise the per-request BAC log context (request_id, start
--      time, resource_id) so latency_ms covers the whole cascade and
--      log_event.lua can emit the final structured record.
--   2. Run the L1 `hygiene` stage (hygiene.lua: method_not_allowed /
--      ua_blacklist + the hygiene:header_anomaly tag) — observe-only.
--   3. Run the L2 `reputation` stage (reputation.lua: ip_whitelist /
--      ip_blocklist via lua-resty-ipmatcher) — observe-only.
--   4. Run the existing TLS-fingerprint block decision (compute_fp +
--      cache + blocklist), identical to production.
--
-- The fp-based block is the Phase 2 `tls_fp` stage; it is recorded
-- through the same bac_log contract as hygiene/reputation. The remaining
-- Phase 1 stages (rate_limits) are separate tasks. The
-- stand runs shadow: tls_fp_blocklist.conf ships empty (init.lua seeds the
-- fp_blocklist dict from it), so verdict is always "allow" and nothing is
-- blocked. The ngx.exit(403) path stays wired so adding an fp to that
-- config and restarting flips it to active without code changes.

local ja4        = require "ja4_compute"
local bac_log    = require "bac_log"
local hygiene    = require "hygiene"
local reputation = require "reputation"
local rate_limit = require "rate_limit"
local fp_state   = require "fp_blocklist_state"

bac_log.init()

-- L1 hygiene (method_not_allowed / ua_blacklist + hygiene:header_anomaly tag).
-- Observe-only: records the would-be verdict and tag via bac_log but never
-- blocks. We deliberately do NOT short-circuit the cascade here — the tls_fp
-- stage below is the only stage that actually enforces (ngx.exit on a
-- blocklisted fp), so every request must still reach it. Returning early
-- would let a request bypass an active tls_fp block simply by also tripping
-- an (observe-only) hygiene rule. Last-writer-wins on the verdict matches the
-- phase1-spec "финальное сработавшее правило" logging contract: if tls_fp
-- later blocks it overwrites the hygiene verdict; otherwise the hygiene
-- verdict stands.
hygiene.run()

-- L2 reputation (ip_whitelist / ip_blocklist). Observe-only and, like
-- hygiene, deliberately does NOT short-circuit the cascade — not even on an
-- ip_whitelist allow. A fastpass here would let a whitelisted IP skip the
-- tls_fp block below; on the stand every request must still reach tls_fp.
-- Last-writer-wins: a later tls_fp block overwrites the reputation verdict.
reputation.run()

local fp = ja4.compute()
bac_log.set_tls_fp(fp)

local cache  = ngx.shared.verdict_cache
local cached = cache:get(fp)
local cache_hit = (cached ~= nil)

local verdict
if cached == "block" or cached == "allow" then
    verdict = cached
else
    -- §A1 read: the blocklist is keyed `fp .. ":" .. gen`, where `gen` is the
    -- generation the catalog pull (§В1) last published in ngx.shared.meta. On
    -- the stand there is no pull yet, so init.lua seeds generation 0 and gen
    -- stays 0; reading through the generation key keeps this forward-compatible
    -- with the pull bumping it (task 86exmk08u) without touching this path.
    local gen = fp_state.sync(ngx.shared.meta:get("fp_blocklist_gen") or 0)
    verdict = ngx.shared.fp_blocklist:get(fp_state.key(fp, gen)) or "allow"
    cache:set(fp, verdict, 60)
end

-- Cache outcome is metrics-only; stash it for log_event.lua's counters.
ngx.ctx.bac_cache_hit = cache_hit

if verdict == "block" then
    bac_log.set_verdict("tls_fp", "block", "tls_fp_blocklist")
    return ngx.exit(403)
end

-- L4 rate_limits (rate_ip / rate_ip_ua / rate_api / rate_scan_urls). Runs last
-- in the cascade. Observe-only like hygiene/reputation: records the would-be
-- verdict via bac_log but never returns 429 / delays / short-circuits.
-- last-writer-wins means a rate block overwrites the egress default here.
rate_limit.run()

-- Fall through. If no rate profile fired the context keeps its defaults
-- (stage=egress, verdict=pass).
