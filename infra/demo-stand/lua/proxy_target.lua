-- proxy_target — decides where `location /` sends a request, based on the
-- incoming Host header and per-host Policy (Channel C).
--
-- Two destinations exist on the demo stand:
--   1. A tenant's origin — a protected client backend. Reached when the
--      incoming Host is a registered tenant: a host whose Policy carries a
--      non-empty `origin_ip`. The upstream is `https://<host>`, with the
--      hostname rewritten to `origin_ip` by origin_resolve (bypassing DNS,
--      loop-safe). Host header / SNI sent upstream stay `<host>`.
--   2. BAC's own surface — the bundled landing page, plus /__admin,
--      /__health, /metrics. Reached for ANY other Host (bac.example.com,
--      unknown / IP-literal / random Hosts that drive-by scanners send, and
--      hosts that have a Policy row but no `origin_ip`).
--
-- Why a catch-all to BAC instead of proxying everything or returning 421:
--   * Unknown-Host traffic never reaches a tenant backend — no wasted CPU,
--     no polluted per-vhost metrics on someone else's origin.
--   * 421/444 over-blocks (README probes, health checks). The cascade still
--     runs first for the BAC path (access_by_lua), so bad UA / tls-fp / etc.
--     still get 403; scanners just see a normal-looking landing.
--
-- The tenant set is SOLELY Policy (ClickUp 86exrefdz). There is no env-based
-- single-tenant fallback: `DASHBOARD_PUBLIC_HOST` / `DASHBOARD_BACKEND_IP` /
-- `ORIGIN_URL` no longer route anything. Adding a tenant is one
-- `PATCH /antibot/v1/policy/<host> {"origin_ip": ...}` — no nginx/compose
-- change. This stand is a multi-tenant SaaS edge, not a single-origin proxy.
local _M = {}

-- origin_ip_for(host, policy_override) — the tenant's backend IP, or nil/""
-- if `host` is not a registered tenant.
--
-- policy_override — TEST-ONLY second argument. Production callers pass nil
-- and the lookup goes through policy.get(host) (ngx.ctx-memoized, so calling
-- it from both origin() and backend() in the same request is cheap). Tests
-- pass a table {host = origin_ip, ...} (or a function host -> origin_ip) to
-- vary the tenant set without an ngx/shared-dict harness.
local function origin_ip_for(host, policy_override)
    if policy_override ~= nil then
        if type(policy_override) == "function" then
            return policy_override(host)
        end
        return policy_override[host]
    end
    return require("policy").get(host).origin_ip
end

-- origin(host, policy_override) — the upstream URL to proxy to, or "" for
-- BAC's own surface.
--
-- host — ngx.var.host (already lowercased by nginx, no port). May be nil/"".
--
-- Returns `https://<host>` iff `host` is a registered tenant (Policy has a
-- non-empty origin_ip). The network-layer rewrite to origin_ip happens in
-- $origin_resolve via origin_resolve.resolve(); Host/SNI sent upstream stay
-- `<host>` (derived from this $origin). Otherwise returns "" — the caller in
-- nginx.demo.conf uses `$origin = ""` to short-circuit to /__landing while
-- still running the cascade via access_by_lua.
function _M.origin(host, policy_override)
    if not host or host == "" then return "" end
    host = string.lower(host)
    local ip = origin_ip_for(host, policy_override)
    if type(ip) == "string" and ip ~= "" then
        return "https://" .. host
    end
    return ""
end

-- backend(host, policy_override) — (origin_ip, loop_host) for
-- origin_resolve.resolve(): the IP to rewrite the upstream hostname to, and
-- the hostname inside $origin that the rewrite targets.
--
-- For a tenant → (origin_ip, host): resolve() rewrites `https://<host>`'s
-- hostname to origin_ip (IPv6-bracketed as needed). For a non-tenant →
-- ("", ""): resolve() returns its input unchanged, but $origin is "" for
-- non-tenants anyway, so this branch never reaches proxy_pass.
function _M.backend(host, policy_override)
    if not host or host == "" then return "", "" end
    host = string.lower(host)
    local ip = origin_ip_for(host, policy_override)
    if type(ip) == "string" and ip ~= "" then
        return ip, host
    end
    return "", ""
end

return _M
