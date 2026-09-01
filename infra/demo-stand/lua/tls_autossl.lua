-- On-demand Let's Encrypt certificates for tenant custom domains, over
-- lua-resty-acme (http-01).
--
-- The edge has to stay the TLS terminator: the cascade fingerprints the
-- client's handshake, and a terminating proxy in front would hide it and break
-- detection. So the certificate is chosen here, per SNI, at handshake time.
--
-- The static certificate stays the fallback and every name it already covers
-- keeps working without ACME. Issuance is gated on the host being a registered
-- tenant and not under the stand's own base domain — without that gate anyone
-- pointing DNS at the edge could trigger issuance and burn the Let's Encrypt
-- rate limit.
--
-- Every entry point is pcall-wrapped and fails open to the static certificate:
-- a broken auto-ssl must never take HTTPS down for existing tenants.
--
-- Env: AUTO_SSL_DIR (storage; mount a volume so certs and the account key
-- survive restarts), AUTO_SSL_STAGING, ACME_ACCOUNT_EMAIL, STAND_BASE_DOMAIN.
local _M = {}

-- Cached at module load: os.getenv cannot be JIT-compiled, and this runs in the
-- handshake path for a value that never changes in a worker's life. A reload
-- re-requires the module. _reset_cache is a test hook.
local DEFAULT_BASE_DOMAIN
function _M._reset_cache()
    DEFAULT_BASE_DOMAIN = string.lower(os.getenv("STAND_BASE_DOMAIN") or "example.com")
end
_M._reset_cache()

-- Whether to obtain an on-demand certificate for this host. `opts` injects the
-- dependencies for tests; production passes nil.
function _M.allow_domain(host, opts)
    if not host or host == "" then return false end
    host = string.lower(host)

    local base = opts and opts.base_domain
    if base == nil then base = DEFAULT_BASE_DOMAIN end
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

-- Whether the edge serves this SNI at all — true for the base domain and for
-- registered tenants. The counterpart to allow_domain, which asks whether to
-- issue a certificate: the base domain answers no there and yes here.
function _M.sni_known(host, opts)
    if not host or host == "" then return false end
    host = string.lower(host)

    local base = opts and opts.base_domain
    if base == nil then base = DEFAULT_BASE_DOMAIN end
    if base ~= "" and (host == base or host:sub(-(#base + 1)) == ("." .. base)) then
        return true
    end

    -- if/else rather than `or`: for a real non-tenant the injected lookup
    -- returns nil, and `or` would fall through to the real policy module.
    --
    -- The require is deliberately not pcall-wrapped. The caller already wraps
    -- the decision in a pcall that fails open; catching here would instead fail
    -- closed and could drop a real tenant's handshake on a transient error.
    local lookup = opts and opts.origin_ip
    local ip
    if lookup then
        ip = lookup(host)
    else
        ip = require("policy").origin_ip(host)
    end
    return type(ip) == "string" and ip ~= ""
end

-- Aborts the handshake for a present SNI that is neither a tenant nor a
-- base-domain name — the cheapest disposal available for a flood announcing a
-- bogus SNI, since nothing HTTP has been read yet.
--
-- A handshake with no SNI is not rejected here: there is no name to judge, so
-- the static certificate is served and the HTTP layer drops it by its empty
-- origin. The two layers are complementary.
--
-- Nothing is logged per handshake — under a flood the logging would become the
-- bottleneck, so the counter is the signal.
--
-- The decision is wrapped in a pcall that fails open, because a throw here
-- happens before the caller's own pcall and would abort the handshake. The exit
-- stays outside it: pcall would swallow the control-flow exception and turn a
-- reject into a silent pass.
function _M.reject_unknown_sni()
    local ok, reject = pcall(function()
        local config = require "config"
        if not config.edge_deny_nontenant(config.defaults) then return false end
        local ssl  = require "ngx.ssl"
        local host = ssl.server_name()   -- nil when the client sent no SNI
        return host and host ~= "" and not _M.sni_known(host)
    end)
    if not ok or not reject then return end

    local metrics = ngx.shared.metrics
    if metrics then metrics:incr("edge_sni_rejected_total", 1, 0) end
    return ngx.exit(ngx.ERROR)
end

-- setup() — configure lua-resty-acme autossl (call from init_by_lua, master).
-- Wrapped by the caller in pcall; on any failure _M._ready stays false and
-- ssl_certificate() no-ops → static fallback cert. require is done HERE (not at
-- module load) so unit tests can require this module without resty.acme.
function _M.setup()
    local autossl = require "resty.acme.autossl"
    autossl.init({
        tos_accepted              = true,
        staging                   = (os.getenv("AUTO_SSL_STAGING") or "") == "true",
        account_email             = os.getenv("ACME_ACCOUNT_EMAIL"),
        domain_whitelist_callback = function(domain) return _M.allow_domain(domain) end,
        storage_adapter           = "file",
        storage_config            = { dir = os.getenv("AUTO_SSL_DIR") or "/etc/resty-auto-ssl" },
    })
    _M._ready = true
end

-- init_worker() — pcall-wrapped: a throw here (e.g. renewal-timer registration
-- failure) must NOT abort the init_worker_by_lua block, otherwise the steps
-- after it (catalog_pull.start) would never run and the worker would silently
-- stop pulling Channel C. Same fallback-safety contract as ssl_certificate().
function _M.init_worker()
    if not _M._ready then return end
    local ok, err = pcall(function() require("resty.acme.autossl").init_worker() end)
    if not ok then
        ngx.log(ngx.ERR, "[demo] on-demand TLS: init_worker() failed, ",
            "renewal disabled (issuance/serving unaffected): ", tostring(err))
    end
end

-- Per-handshake certificate selection. If lua-resty-acme throws, log and fall
-- through: with no certificate set by Lua, OpenResty serves the static
-- fallback and HTTPS stays up.
function _M.ssl_certificate()
    -- Edge self-protection (step 2) runs FIRST, independent of _ready: an
    -- unknown SNI is dropped at the handshake even when on-demand TLS is
    -- inactive (static-cert-only stand). If it doesn't reject, fall through to
    -- per-SNI cert selection. ngx.exit inside reject_unknown_sni ends the phase.
    _M.reject_unknown_sni()

    if not _M._ready then return end
    local ok, err = pcall(function() require("resty.acme.autossl").ssl_certificate() end)
    if not ok then
        ngx.log(ngx.ERR, "[demo] on-demand TLS: ssl_certificate() failed, ",
            "falling back to static cert: ", tostring(err))
    end
end

-- serve_http_challenge() — answers /.well-known/acme-challenge/* during issuance.
-- pcall-wrapped so a challenge-handler error returns cleanly instead of 500.
function _M.serve_http_challenge()
    if not _M._ready then return end
    local ok, err = pcall(function() require("resty.acme.autossl").serve_http_challenge() end)
    if not ok then
        ngx.log(ngx.ERR, "[demo] on-demand TLS: serve_http_challenge() failed: ", tostring(err))
    end
end

return _M
