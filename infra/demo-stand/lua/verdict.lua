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
-- Phase 1 stages (rate_limits) are separate tasks.
--
-- Mode-gated enforcement (B11): the only physical exit in the cascade —
-- tls_fp_blocklist hit below — goes through policy.enforce(403). For
-- clients with policy[host].mode=shadow (pool default), the would-be
-- verdict is still recorded via bac_log.set_verdict and the request
-- passes through to origin. For clients with mode=active, ngx.exit(403)
-- fires. Future enforcement points (rate_limit 429, per-host
-- ip_blocklist, challenge) MUST go through the same helper — see
-- policy.lua header for the convention.

local ja4        = require "ja4_compute"
local bac_log    = require "bac_log"
local hygiene    = require "hygiene"
local reputation = require "reputation"
local tls_fp     = require "tls_fp"
local rate_limit = require "rate_limit"
local fp_state   = require "tls_fp_blocklist_state"
local config     = require "config"
local policy     = require "policy"
local clearance  = require "clearance"
local verification = require "verification"

-- Global kill-switch (A12). When set, the whole cascade is a no-op: we return
-- before bac_log.init so the request proxies straight to the origin and emits
-- NO BAC_LOG record (log_event.lua skips when ngx.ctx.bac is unset). This is
-- the catastrophe lever from vision.md §"Emergency levers" — protection must
-- never take the site down. Toggled via the gitignored kill_switch.local.conf
-- (config.lua), applied on `nginx -s reload`, no container recreate.
if config.global_kill(config.defaults) then
    return
end

bac_log.init()

-- L1 hygiene (method_not_allowed / ua_blacklist + hygiene:header_anomaly tag).
-- Mode-gated: hygiene.run records the would-be verdict and informational
-- tag via bac_log; on a blocking rule it then calls policy.enforce(403) so
-- a mode=active host gets 403 right inside run (ngx.exit, cascade dies).
-- For mode=shadow (pool default) enforce is a no-op and run returns
-- normally, so the cascade continues to tls_fp / rate_limit and their
-- would-be verdicts/tags still accumulate — last-writer-wins matches
-- phase1-spec's "the final rule that fired" (e.g., a later tls_fp
-- block overwrites the hygiene verdict in the log).
hygiene.run()

-- L2 reputation (ip_whitelist / ip_blocklist / dormant geo_blocklist).
-- Mode-gated like hygiene: ip_blocklist / geo_blocklist call
-- policy.enforce(403) so mode=active hosts get 403 right inside run; for
-- mode=shadow the would-be verdict is logged and the cascade continues.
-- The allow-side (ip_whitelist, verified_bots) still does NOT short-
-- circuit the cascade — a whitelisted IP that is also tls_fp_blocklisted
-- must still hit tls_fp downstream, regardless of mode. Real allow-side
-- fastpass is paired with per-host policy.ip_whitelist application
-- (86exr05xt), not this stage.
reputation.run()

-- L2.1 clearance cookie verify (C3). vision §2.1 / rules-reference rule
-- `cookie_valid`. HMAC-stateless: the secret is loaded through C1, with no
-- network calls. A valid cookie → verdict=allow,rule=cookie_valid plus the
-- skip flag `ngx.ctx.clearance_valid`, which L3 (tls_fp below) and L5
-- (challenge, C5+ not implemented yet) honour by skipping themselves; L4
-- (rate_limit) applies to the cookie holder as usual (vision §2.1,
-- "it skips L3 and L5, but NOT L4").
--
-- Ordering relative to hygiene/reputation. clearance.run comes AFTER them,
-- so last-writer-wins works in our favour: an L1 hygiene block
-- (method/ua_blacklist) sets verdict=block BEFORE us — we do not write over
-- it (see the `ctx.verdict ~= "block"` guard below), and the block correctly
-- survives to log_event. Same for reputation ip_blocklist: written before
-- clearance, and we do not clobber it. If nothing blocking fired,
-- clearance sets verdict=allow, which may later be overwritten by
-- L4 rate_limit (also by design — vision §2.1, "if a rate limit fired,
-- the L4 rule wins").
--
-- Every outcome (valid/invalid/expired/missing/wrong_site/malformed/no_secret)
-- feeds the `antibot_clearance_verify_total{result=...}` metric (metrics.lua).
-- The counter is incremented here rather than in clearance.verify() so that
-- verify stays a pure function for unit tests (the same convention as policy
-- and rate_limit: the module decides "what", the caller decides what to do with it).
--
-- ASYMMETRY WARN — the metric reflects only requests that reached this
-- point in access_by_lua. In mode=active a hygiene/reputation block through
-- `policy.enforce(403)` calls `ngx.exit(403)` ABOVE us, so clearance.run
-- never runs for them. So the sum of the six clearance_verify_* counters
-- does NOT equal requests_total for active-mode hosts; it equals
-- (requests_total - active_mode_early_blocks). Dashboards computing
-- "cookie funnel coverage" must normalise against the post-L1/L2.2-block
-- baseline rather than raw requests_total (from review).
--
-- The per-stage kill switch (A12). clearance is its own per-stage off
-- switch, so that on a regression in clearance.verify / lua-resty-openssl
-- the operator can disable L2.1 alone without zeroing the whole cascade
-- through the global A12. The gate is checked through config.stage_enabled —
-- the same protocol as hygiene/reputation/tls_fp/rate_limits/verification.
if config.stage_enabled(config.defaults, "clearance") then
    local host = ngx.var.host or ""
    -- The attack_mode pre-attack gate (C7). Under attack_mode=on for the host
    -- we pass the under-attack TTL threshold into verify: a cookie with a long
    -- (normal) TTL was issued BEFORE the attack started → verify returns
    -- RESULT_STALE_PRE_ATTACK and we do NOT fastpath it (we set no
    -- clearance_valid and leave the verdict alone) — the request walks the
    -- cascade to L5 for a challenge. A during-attack cookie (a short TTL)
    -- fastpaths as usual. Telling them apart by TTL type is vision §5.3, see
    -- the clearance.lua header. The ip_whitelist/verified_bot fastpath under
    -- attack is untouched — it lives at L2 (reputation above), not here.
    -- policy.get is contractually non-nil (the POOL_DEFAULT fallback), but we
    -- guard with `p and` for consistency with challenge_verify.lua /
    -- verification.lua — one pattern for reading policy on the edge (from review).
    local opts
    local p = policy.get(host)
    if p and p.attack_mode then
        local max_ttl
        local allow = config.defaults and config.defaults.allow
        if type(allow) == "table" and type(allow.cookie_valid) == "table" then
            max_ttl = tonumber(allow.cookie_valid.ttl_seconds_under_attack)
        end
        opts = { attack_mode = true, max_under_attack_ttl = max_ttl }
    end
    local result = clearance.verify(host, opts)
    ngx.shared.metrics:incr("clearance_verify_" .. result .. "_total", 1, 0)
    if result == clearance.RESULT_VALID then
        local ctx = ngx.ctx.bac
        -- Do not clobber a block that already fired (hygiene/reputation above).
        -- Per rules-reference: cookie_valid skips L3 and L5, but L1 and
        -- L2.2/2.3 (including ip_blocklist) still apply — their block
        -- outranks our allow. When a block is already set:
        --   * we do NOT overwrite the verdict in the log;
        --   * we do NOT set clearance_valid — the L3 soft rules (tls_fp:* tags
        --     plus the impersonator/suspicious_ciphers flags) must still run,
        --     so that the shadow-mode log keeps the full "would-be" picture
        --     for a blocked-but-cookie-holding request (from review).
        --     Without this guard, L3 observability is silently lost for
        --     exactly the profile the soft rules were designed against —
        --     a stolen cookie plus a bad fingerprint.
        if ctx and ctx.verdict ~= "block" then
            ngx.ctx.clearance_valid = true
            bac_log.set_verdict("reputation", "allow", "cookie_valid")
        end
    end
end

-- Per-stage kill-switch for tls_fp (A12). This gate covers the fp compute +
-- blocklist block-path that live inline here (not in tls_fp.lua, which gates
-- its own soft rules via _M.enabled). When killed, fp stays nil — which is the
-- same "fp not computed" signal rate_limit.run treats as a graceful skip of the
-- rate_tls_fp profile (A10), so the per-IP profiles keep working.
--
-- [C3] Clearance fastpath skips ONLY the L3 decision (blocklist hit + soft
-- rules + tls_fp:* tags), NOT the fp compute. rate_tls_fp is part of L4
-- (rate_limits), and per vision §2.1 / rules-reference rule 3 cookie_valid
-- "it skips L3 and L5, but NOT L4" — including rate_tls_fp. If the fingerprint
-- stayed nil under a cookie, rate_limit.run would skip rate_tls_fp_profile
-- (the `fp_ok` guard in rate_limit.lua) and a cookie holder would get a free
-- bypass of the per-fingerprint limit for the cookie's 24-hour TTL (from review).
-- So we still compute the fingerprint and put it into bac_log, while
-- `if not clearance_valid` wraps only the cache/blocklist check and `tls_fp.run(fp)`.
local fp
if config.stage_enabled(config.defaults, "tls_fp") then
    fp = ja4.compute()
    bac_log.set_tls_fp(fp)

    if not ngx.ctx.clearance_valid then
        -- §A1 read: pin the generation the catalog pull (§C1) last published and
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
            -- §A1 + A11: the Channel C value carries status ("<status>:block").
            -- Only an ACTIVE entry blocks here; a staged fp resolves to "allow"
            -- so the request falls through to tls_fp.run(), which records
            -- staging_match from tls_fp.blocklist_staging (built from the same
            -- snapshot in refresh()). parse_value tolerates the legacy bare
            -- "block" seed (treated as active).
            local status = fp_state.parse_value(ngx.shared.tls_fp_blocklist:get(key))
            verdict = (status == "active") and "block" or "allow"
            cache:set(key, verdict, 60)
        end

        -- Cache outcome is metrics-only; stash it for log_event.lua's counters.
        ngx.ctx.bac_cache_hit = cache_hit

        if verdict == "block" then
            bac_log.set_verdict("tls_fp", "block", "tls_fp_blocklist")
            -- B11: active → ngx.exit(403) below; shadow → enforce is a no-op,
            -- we then `return` from access_by_lua to short-circuit the rest of
            -- the cascade so a later stage (tls_fp soft / rate_limit) can't
            -- overwrite the "block" verdict via last-writer-wins. The log
            -- reflects the same final state the active path would have
            -- emitted (verdict=block, rule=tls_fp_blocklist), the only
            -- difference being that the request still proxies to origin.
            -- Stamp cascade end BEFORE enforce: in shadow this returns and the
            -- request still proxies to origin, so cascade_ms must capture only
            -- the cascade, not the upstream/client tail (gemini review #97).
            bac_log.mark_cascade_end()
            policy.enforce(403)
            return
        end

        -- tls_fp soft rules + tls_fp:* tags (A9). Observe-only: records the would-be
        -- challenge verdict and the soft flags / informational tags via bac_log but
        -- never blocks or short-circuits. Runs after the blocklist check (a
        -- blocklisted fp has already exited above) and after reputation, so the
        -- cross-layer tls_fp:dc_browser tag can see reputation:asn_dc.
        tls_fp.run(fp)
    end
end

-- L4 rate_limits (rate_ip / rate_ip_ua / rate_api / rate_tls_fp /
-- rate_scan_urls). Runs last in the cascade. Mode-gated: a fired
-- profile calls policy.enforce(429, {Retry-After=...}) — mode=active
-- hosts get a real 429 with the Retry-After header (window size as
-- upper bound); mode=shadow records the would-be verdict and lets the
-- request reach origin. last-writer-wins on the verdict, so a rate
-- block overwrites the egress default. `fp` is passed so rate_tls_fp
-- can key on it (and skip gracefully when the fp was not computed
-- for this request).
rate_limit.run(fp)

-- L5 verification — should_challenge() (C4). The challenge decision happens
-- exactly here. Before C4 the tls_fp soft block set verdict=challenge itself,
-- which broke rules-reference ("L3/L4 flags only mark, the decision happens at L5")
-- and ignored the per-resource Strictness. Now tls_fp only accumulates flags,
-- and verification.decide() reads (flags, policy.strictness, policy.attack_mode)
-- and writes verdict=challenge / verdict=permissive / nothing. Observe-only:
-- physical challenge issuance (Branch A — JS challenge, Branch B/C — block)
-- is a separate ticket, C5; for now the verdict only goes into bac_log.
--
-- It is gated by the `verification` per-stage kill switch (defaults.conf
-- [kill_switch.per_stage]). When disabled, the system soft flags stay in
-- `flags` (for analytics) but turn into neither a challenge nor a
-- permissive — the verdict stays as L4 left it (pass /
-- block / allow).
if config.stage_enabled(config.defaults, "verification") then
    verification.run()

    -- L5.2 — the physical dispatch (C5). verification.run() set
    -- verdict=challenge in bac_log; the physical branch routing happens
    -- here, so that policy.enforce stays the single point of mode gating (the
    -- same convention as tls_fp_blocklist above plus rate_limit). decide()
    -- chooses the verdict; classify_branch() chooses branch A/B/C; this block
    -- is the only point of physical issue/block at L5.
    --
    -- Mode-gating:
    --   * Branch A in mode=active → render the challenge page, ngx.exit(200).
    --     In shadow we do NOT serve the page: the would-be verdict is already
    --     in the log (`verdict=challenge`) and the request goes to the origin
    --     as usual. That preserves shadow mode's observe-only contract: the
    --     edge does not change the response until the customer switches to active.
    --   * Branch B/C — we write the block into the log (regardless of mode) and
    --     call policy.enforce(403): active → 403, shadow → a no-op, and the
    --     request continues to the origin. The same scheme as
    --     tls_fp_blocklist.
    local ctx = ngx.ctx.bac
    if ctx and ctx.verdict == "challenge" then
        local branch = verification.classify_branch({
            user_agent = ngx.var.http_user_agent,
            method     = ngx.var.request_method,
            accept     = ngx.var.http_accept,
            upgrade    = ngx.var.http_upgrade,
        })
        if branch == "B" then
            bac_log.set_verdict("verification", "block", "non_browser_blocked")
            ngx.shared.metrics:incr("challenge_branch_b_total", 1, 0)
            bac_log.mark_cascade_end()   -- shadow proxies on; stamp before enforce (review #97)
            policy.enforce(403)
            return
        elseif branch == "C" then
            bac_log.set_verdict("verification", "block", "unchallengeable_request")
            ngx.shared.metrics:incr("challenge_branch_c_total", 1, 0)
            bac_log.mark_cascade_end()   -- shadow proxies on; stamp before enforce (review #97)
            policy.enforce(403)
            return
        else
            -- Branch A — the JS challenge. Only in active mode, otherwise
            -- shadow would break "the edge does not change the response". In
            -- shadow the challenge verdict stays in the log and the request goes to the origin.
            --
            -- ngx.exec into the internal `@challenge_page` (rather than ngx.print
            -- here) is the standard §A8 pattern from edge-lua-vs-sidecar:
            -- access_by_lua switches the request to a content_by_lua
            -- handler, which writes the body. The client's URL is preserved
            -- (important: after window.location.reload() the browser goes to
            -- the original URL with the new cookie, not to "/_challenge").
            -- policy.get guarantees a non-nil POOL_DEFAULT fallback, but
            -- keeping it in a local removes the repeated
            -- shared_dict lookup (policy.get caches in ngx.ctx, but reading
            -- `.mode` twice through two nested index operations reads worse)
            -- and guards against a theoretical break of the
            -- policy.get contract (from review).
            local p = policy.get(ngx.var.host or "")
            if p and p.mode == "active" then
                return ngx.exec("@challenge_page")
            end
        end
    end
end

-- End of the access-phase cascade for the PASS path: stamp it so bac_log can
-- split cascade_ms (our intake + check overhead) from the upstream/origin time
-- and the client-delivery tail. block/challenge paths exit earlier via
-- ngx.exit/ngx.exec and never reach here — fine, they have no upstream.
bac_log.mark_cascade_end()

-- Fall through. If no rate profile fired and L5 issued no challenge/permissive,
-- the context keeps its defaults (stage=egress, verdict=pass).
