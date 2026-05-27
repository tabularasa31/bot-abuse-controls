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
-- ORIGIN_URL). Multi-tenant follow-up (sister ClickUp ticket 86exrefdz) moves
-- this into policy alongside per-host mode/strictness/origin_ip, so adding a
-- new client doesn't need a nginx.demo.conf change.
local _M = {}

-- origin(host, env) — return the upstream URL to proxy to, or "" for BAC.
--
-- host  — ngx.var.host (lowercased, no port). May be nil or "".
-- env   — table with two fields:
--           proxied_host = DASHBOARD_PUBLIC_HOST (single proxied client today)
--           origin_url   = ORIGIN_URL (upstream for that client)
--         Both treated as "" when nil. Either being empty means "no proxied
--         client configured" — everything routes to BAC.
--
-- Returns env.origin_url iff host == env.proxied_host AND both env fields are
-- non-empty. Otherwise returns "" (caller in nginx.demo.conf uses `$origin = ""`
-- to short-circuit to /__landing in `location /`, which then serves BAC's
-- bundled landing while still running the cascade via access_by_lua).
function _M.origin(host, env)
    if not host or host == "" then return "" end
    local proxied  = (env and env.proxied_host) or ""
    local upstream = (env and env.origin_url)   or ""
    if proxied == "" or upstream == "" then return "" end
    if host == proxied then return upstream end
    return ""
end

return _M
