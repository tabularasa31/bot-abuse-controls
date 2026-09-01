-- Decides where `location /` sends a request, from the Host header and
-- per-host policy.
--
-- The edge is tenant-only. A host whose policy carries a non-empty origin_ip
-- is proxied to `https://<host>`; everything else returns "" and the caller
-- drops it with 444. Unknown-Host traffic is never a real visit, so there is
-- nothing to serve it. Adding a tenant is a single policy PATCH, with no
-- nginx or compose change.
local _M = {}

-- `policy_override` is test-only: a table {host = origin_ip} or a function
-- host -> origin_ip, so tests can vary the tenant set without a shared-dict
-- harness. Production callers pass nil and go through policy.get, which
-- memoizes on ngx.ctx.
local function origin_ip_for(host, policy_override)
    if policy_override ~= nil then
        if type(policy_override) == "function" then
            return policy_override(host)
        end
        return policy_override[host]
    end
    return require("policy").get(host).origin_ip
end

function _M.origin(host, policy_override)
    if not host or host == "" then return "" end
    host = string.lower(host)
    local ip = origin_ip_for(host, policy_override)
    if type(ip) == "string" and ip ~= "" then
        return "https://" .. host
    end
    return ""
end

-- Returns (origin_ip, loop_host) for origin_resolve.resolve: the IP to rewrite
-- to, and the hostname inside $origin that the rewrite targets.
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
