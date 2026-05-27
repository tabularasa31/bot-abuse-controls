-- proxy_target — decides where `location /` sends a request based on the
-- incoming Host header.
--
-- Two destinations exist on the demo stand:
--   1. ORIGIN_URL — the protected-client upstream (today: dashboard.example.com
--      → DASHBOARD_BACKEND_IP via origin_resolve). Reached when Host matches a
--      registered proxied client.
--   2. BAC's own surface — the bundled landing page, plus /__admin, /__health,
--      /metrics. Reached when Host is anything else (including bac.example.com
--      and unknown / IP-literal / random Hosts that drive-by scanners send).
--
-- Why a catch-all to BAC instead of proxying everything to ORIGIN_URL or
-- returning 421:
--   * Before this change, an unknown Host (Host: example.com, Host: <edge-IP>,
--     empty HTTP/1.0 Host) got proxied to ORIGIN_URL with `proxy_set_header Host
--     $origin_host` rewriting Host to the dashboard hostname. The dashboard
--     backend then received scanner traffic with a legitimate-looking Host
--     header — wasted CPU on the backend, and polluted its per-vhost metrics.
--   * Returning 421/444 (PR #89 first draft) over-blocked: README quickstart
--     uses `curl -k https://localhost/`, which would never match a registered
--     client, and custom-domain operator deploys would also be 421'd. Codex
--     flagged this on PR #89 and the 421 was removed before merge.
--   * Catch-all-to-BAC has neither problem: unknown-Host traffic never reaches
--     the dashboard backend, AND it gets a friendly landing response (cascade
--     still runs first, so bad UA / tls-fp / etc. still get 403). Scanners see
--     a normal-looking page, no signal we're filtering them.
--
-- The proxied-client list lives in env vars for now (DASHBOARD_PUBLIC_HOST +
-- ORIGIN_URL). Multi-tenant follow-up (ClickUp 86exrefdz) moves this into
-- policy alongside per-host mode/strictness/origin_ip, so adding a new client
-- doesn't need a nginx.demo.conf change.
local _M = {}

-- Module-level config cache. Populated lazily on the first origin() call
-- and reused for every subsequent request — env vars don't change in a
-- worker's lifetime (nginx -s reload re-runs init_by_lua* and re-requires
-- modules, so a deploy that changes the env produces a fresh cache).
--
-- Calling os.getenv() per-request was the alternative and Gemini flagged
-- it on PR #90: each set_by_lua_block fires once per request, getenv is
-- a syscall-flavoured C lookup, doing it on the hot path is wasteful for
-- a value that never changes. The cache also gives a single place to
-- enforce the lowercase normalisation needed for case-insensitive Host
-- matching (ngx.var.host is already lowercased by nginx, but the operator-
-- supplied env var may not be — the comparison only works if both sides
-- live in the same case domain).
local cached_cfg

local function load_cfg_from_env()
    return {
        proxied_host = string.lower(os.getenv("DASHBOARD_PUBLIC_HOST") or "dashboard.example.com"),
        origin_url   = os.getenv("ORIGIN_URL") or "",
    }
end

-- _reset_cache — test-only hook. Clears the module-level config cache so
-- a test can swap env between cases. Production callers should never use
-- this; the per-worker cache is the whole point of the optimisation.
function _M._reset_cache()
    cached_cfg = nil
end

-- origin(host, cfg_override) — return the upstream URL to proxy to, or
-- "" for BAC's own surface.
--
-- host          — ngx.var.host (already lowercased by nginx, no port).
--                 May be nil or "".
-- cfg_override  — TEST-ONLY second argument. Production callers in
--                 nginx.demo.conf pass nil; the module then reads
--                 DASHBOARD_PUBLIC_HOST / ORIGIN_URL from env once and
--                 caches them. Tests pass an explicit table
--                 {proxied_host=..., origin_url=...} to vary config
--                 across cases without touching the real environment.
--                 The override path applies the same lowercase
--                 normalisation as the env-load path, so tests cover
--                 the case-insensitive comparison too.
--
-- Returns the configured origin_url iff host matches the configured
-- proxied_host AND both config fields are non-empty. Otherwise returns
-- "" (caller in nginx.demo.conf uses `$origin = ""` to short-circuit
-- to /__landing in `location /`, which then serves BAC's bundled
-- landing while still running the cascade via access_by_lua).
function _M.origin(host, cfg_override)
    if not host or host == "" then return "" end

    local cfg
    if cfg_override then
        cfg = {
            proxied_host = string.lower(cfg_override.proxied_host or ""),
            origin_url   = cfg_override.origin_url or "",
        }
    else
        cached_cfg = cached_cfg or load_cfg_from_env()
        cfg = cached_cfg
    end

    if cfg.proxied_host == "" or cfg.origin_url == "" then return "" end
    if host == cfg.proxied_host then return cfg.origin_url end
    return ""
end

return _M
