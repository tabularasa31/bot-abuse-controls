-- access_by_lua entry. Computes a real handshake-derived fingerprint
-- (see ja4_compute.lua) and runs the verdict pipeline.
--
-- Verdict pipeline:
--   1. Compute fp from $ssl_ciphers + $ssl_curves + $ssl_protocol
--      + $ssl_alpn_protocol + $ssl_server_name.
--   2. verdict_cache:get(fp)            -- hot path, no shared_dict scan
--   3. fp_blocklist:get(fp)             -- cold path on cache miss
--   4. cache the result for 60s
--   5. block path: ngx.exit(403)
--   6. allow path: return (nginx serves location /)
--
-- Fail-open guarantee. The pipeline is *additive* on top of nginx; if our
-- code crashes the request must still be served. compute() is wrapped in
-- pcall because it does the most parsing work and is the only place a
-- malformed nginx env (truncated $ssl_*, missing var, etc.) could throw.
-- shared_dict :get/:set don't throw, so they don't need a wrapper.
-- See docs/security-review.md §"Fail-open philosophy".

-- Deployment feature flag. The CDN operator puppet template always renders
-- `set $abuse_controls_enabled "true"` or `"false"` from hiera (default
-- "false" in common.yaml; per-host override flips to "true" during the
-- canary rollout — see docs/CDN operator-rollout/canary-plan.md). When the
-- var is explicitly "false", skip the pipeline.
--
-- When the var is UNSET (demo stand, shadow stand, any deployment that
-- doesn't bother with the flag) we fall through to running normally —
-- so demo and shadow don't need to know about this flag at all.
if ngx.var.abuse_controls_enabled == "false" then return end

local ja4 = require "ja4_compute"

local ok, fp_or_err = pcall(ja4.compute)
if not ok then
    -- Lua error inside compute. Log for postmortem and fall through to
    -- allow — DO NOT propagate the error (would 500 the request, which
    -- breaks the contract that the antibot never causes a 5xx itself).
    ngx.log(ngx.ERR, "compute_fp errored, fail-open: ", fp_or_err)
    return
end
local fp = fp_or_err

local cache = ngx.shared.verdict_cache
local cached = cache:get(fp)
if cached == "block" then
    return ngx.exit(403)
elseif cached == "allow" then
    return
end

local list = ngx.shared.fp_blocklist
local verdict = list:get(fp) or "allow"

cache:set(fp, verdict, 60)
-- NOTICE level so the line survives a production `error_log ... notice;`
-- setting — the monitoring doc parses these lines for verdict counts and
-- needs them at the same level the rest of production runs at. INFO would
-- get filtered out in steady-state.
ngx.log(ngx.NOTICE, "verdict=", verdict, " (cold) fp=", fp,
                    " ua=", ngx.var.http_user_agent or "-")

if verdict == "block" then
    return ngx.exit(403)
end
-- allow: fall through to content handler
