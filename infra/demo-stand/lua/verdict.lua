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
--   5. Run the tls_fp soft rules + tls_fp:* tags (tls_fp.lua: A9) — the
--      observe-only, non-blocking half of the tls_fp stage.
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
local tls_fp     = require "tls_fp"
local rate_limit = require "rate_limit"
local fp_state   = require "fp_blocklist_state"
local config     = require "config"

-- Global kill-switch (A12). When set, the whole cascade is a no-op: we return
-- before bac_log.init so the request proxies straight to the origin and emits
-- NO BAC_LOG record (log_event.lua skips when ngx.ctx.bac is unset). This is
-- the catastrophe lever from vision.md §"Аварийные рычаги" — protection must
-- never take the site down. Toggled via the gitignored kill_switch.local.conf
-- (config.lua), applied on `nginx -s reload`, no container recreate.
if config.global_kill(config.defaults) then
    return
end

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

-- Per-stage kill-switch for tls_fp (A12). This gate covers the fp compute +
-- blocklist block-path that live inline here (not in tls_fp.lua, which gates
-- its own soft rules via _M.enabled). When killed, fp stays nil — which is the
-- same "fp not computed" signal rate_limit.run treats as a graceful skip of the
-- rate_tls_fp profile (A10), so the per-IP profiles keep working.
local fp
if config.stage_enabled(config.defaults, "tls_fp") then
    fp = ja4.compute()
    bac_log.set_tls_fp(fp)

    -- §A1 read: pin the generation the catalog pull (§В1) last published and
    -- key BOTH the verdict cache and the blocklist by `fp:gen`. Sharing the
    -- generation key makes a catalog swap atomic for the cache too: when gen
    -- bumps, old-gen cache entries become unreachable and age out on their TTL,
    -- so the flip takes effect immediately instead of being masked by a stale
    -- bare-fp entry for up to 60s. No pull on the stand yet, so gen stays at
    -- the 0 init.lua seeds.
    local gen = ngx.shared.meta:get(fp_state.META_GEN_KEY) or 0
    local key = fp_state.key(fp, gen)

    local cache  = ngx.shared.verdict_cache
    local cached = cache:get(key)
    local cache_hit = (cached ~= nil)

    local verdict
    if cached == "block" or cached == "allow" then
        verdict = cached
    else
        verdict = ngx.shared.fp_blocklist:get(key) or "allow"
        cache:set(key, verdict, 60)
    end

    -- Cache outcome is metrics-only; stash it for log_event.lua's counters.
    ngx.ctx.bac_cache_hit = cache_hit

    if verdict == "block" then
        bac_log.set_verdict("tls_fp", "block", "tls_fp_blocklist")
        return ngx.exit(403)
    end

    -- tls_fp soft rules + tls_fp:* tags (A9). Observe-only: records the would-be
    -- challenge verdict and the soft flags / informational tags via bac_log but
    -- never blocks or short-circuits. Runs after the blocklist check (a
    -- blocklisted fp has already exited above) and after reputation, so the
    -- cross-layer tls_fp:dc_browser tag can see reputation:asn_dc.
    tls_fp.run(fp)
end

-- L4 rate_limits (rate_ip / rate_ip_ua / rate_api / rate_tls_fp /
-- rate_scan_urls). Runs last in the cascade. Observe-only like hygiene/
-- reputation: records the would-be verdict via bac_log but never returns 429 /
-- delays / short-circuits. last-writer-wins means a rate block overwrites the
-- egress default here. `fp` is passed so rate_tls_fp can key on it (and skip
-- gracefully when the fp was not computed for this request).
rate_limit.run(fp)

-- Fall through. If no rate profile fired the context keeps its defaults
-- (stage=egress, verdict=pass).
