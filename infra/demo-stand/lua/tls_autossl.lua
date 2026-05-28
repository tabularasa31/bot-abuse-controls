-- tls_autossl — on-demand TLS for tenant custom domains via lua-resty-auto-ssl
-- (Let's Encrypt http-01). Keeps the OpenResty edge as the TLS terminator —
-- required, because the cascade fingerprints the CLIENT's TLS handshake
-- ($ssl_* / JA4 in tls_fp.lua); a TLS-terminating proxy in front (Caddy etc.)
-- would hide the client handshake and break bot detection. So the cert must be
-- chosen here, per-SNI, at handshake time.
--
-- Design (fallback-safe):
--   * The static ssl_certificate in nginx.demo.conf stays the FALLBACK. Every
--     name it already covers (the stand's own base domain — bac/dashboard
--     under *.example.com, the edge IP) keeps working with zero ACME.
--   * auto-ssl issues a Let's Encrypt cert ONLY for a custom tenant domain:
--     a host that (a) is a registered tenant in policy (non-empty origin_ip)
--     and (b) is NOT under the stand base domain (those use the static cert).
--   * allow_domain gating is the anti-abuse / anti-rate-limit guard: without
--     it, anyone pointing DNS at the edge could trigger issuance and burn the
--     Let's Encrypt rate limit. Tying it to policy means only hosts the
--     operator deliberately onboarded (via PATCH origin_ip) get a cert.
--
-- If anything here fails (module missing, init error), ssl_certificate() is a
-- no-op and nginx serves the static fallback cert — i.e. current behaviour.
-- That is the whole point of the pcall in setup(): a broken auto-ssl must
-- never take HTTPS down for existing tenants.
--
-- Env:
--   AUTO_SSL_DIR        storage dir (default /etc/resty-auto-ssl), writable by
--                       the worker user; mount a volume so certs survive
--                       restarts (and to avoid re-issuing / rate limits).
--   AUTO_SSL_STAGING    "true" → Let's Encrypt staging CA (untrusted certs,
--                       high rate limits) for bring-up; unset/"false" → prod.
--   STAND_BASE_DOMAIN   the stand's own apex (default example.com); hosts
--                       at/under it are served by the static fallback cert,
--                       never ACME.
local _M = {}

local LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

-- allow_domain(host, opts) — decide whether to obtain/serve an on-demand cert.
-- opts (test-only): { base_domain = "...", origin_ip = function(host)->ip }.
-- In production opts is nil: base_domain from STAND_BASE_DOMAIN, origin_ip from
-- policy.origin_ip. Pure-ish (deps injectable) so it's unit-testable.
function _M.allow_domain(host, opts)
    if not host or host == "" then return false end
    host = string.lower(host)

    local base = opts and opts.base_domain
    if base == nil then base = string.lower(os.getenv("STAND_BASE_DOMAIN") or "example.com") end
    -- Hosts at/under the stand base domain are covered by the static
    -- (wildcard/SAN) fallback cert — never ACME them.
    if base ~= "" then
        if host == base or host:sub(-(#base + 1)) == ("." .. base) then
            return false
        end
    end

    -- Otherwise: only a registered tenant (policy has a non-empty origin_ip)
    -- gets a cert. Everyone else (random Host, scanner SNI) is refused, so
    -- they can't trigger issuance.
    local lookup = opts and opts.origin_ip
    local ip
    if lookup then
        ip = lookup(host)
    else
        ip = require("policy").origin_ip(host)
    end
    return type(ip) == "string" and ip ~= ""
end

-- setup() — build + init the auto-ssl instance (call from init_by_lua, master).
-- Wrapped by the caller in pcall; on any failure auto_ssl stays nil and
-- ssl_certificate() no-ops → static fallback cert.
function _M.setup()
    local auto_ssl = (require "resty.auto-ssl").new()
    auto_ssl:set("dir", os.getenv("AUTO_SSL_DIR") or "/etc/resty-auto-ssl")
    auto_ssl:set("allow_domain", function(domain) return _M.allow_domain(domain) end)
    if (os.getenv("AUTO_SSL_STAGING") or "") == "true" then
        auto_ssl:set("ca", LE_STAGING)
    end
    auto_ssl:init()
    _M._auto_ssl = auto_ssl
    return auto_ssl
end

function _M.init_worker()
    if _M._auto_ssl then _M._auto_ssl:init_worker() end
end

-- ssl_certificate() — per-handshake cert selection. No-op when auto-ssl isn't
-- active → nginx serves the static fallback cert (current behaviour).
function _M.ssl_certificate()
    if _M._auto_ssl then _M._auto_ssl:ssl_certificate() end
end

function _M.hook_server()
    if _M._auto_ssl then _M._auto_ssl:hook_server() end
end

function _M.challenge_server()
    if _M._auto_ssl then _M._auto_ssl:challenge_server() end
end

return _M
