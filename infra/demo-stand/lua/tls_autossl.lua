-- tls_autossl — on-demand TLS for tenant custom domains via lua-resty-acme
-- (pure-Lua Let's Encrypt, http-01). Keeps the OpenResty edge as the TLS
-- terminator — required, because the cascade fingerprints the CLIENT's TLS
-- handshake ($ssl_* / JA4 in tls_fp.lua); a TLS-terminating proxy in front
-- (Caddy etc.) would hide the client handshake and break bot detection. So the
-- cert must be chosen here, per-SNI, at handshake time.
--
-- (lua-resty-acme, not lua-resty-auto-ssl: the latter bundles a C helper that
-- fails to build on modern toolchains and is unmaintained. lua-resty-acme is
-- pure Lua and reuses resty.openssl + resty.http already in the image.)
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
--   AUTO_SSL_DIR        file-storage dir (default /etc/resty-auto-ssl),
--                       writable by the worker user; mount a volume so certs +
--                       the ACME account key survive restarts (avoid re-issuing
--                       / LE rate limits).
--   AUTO_SSL_STAGING    "true" → Let's Encrypt staging CA (untrusted certs,
--                       high rate limits) for bring-up; unset/"false" → prod.
--   ACME_ACCOUNT_EMAIL  email for the Let's Encrypt account (recommended).
--   STAND_BASE_DOMAIN   the stand's own apex (default example.com); hosts
--                       at/under it are served by the static fallback cert,
--                       never ACME.
local _M = {}

-- STAND_BASE_DOMAIN cached at module load (init_by_lua master): allow_domain
-- runs in the ssl handshake path, and os.getenv is a syscall-flavoured C call
-- that LuaJIT can't compile — don't pay it per handshake for a value that
-- never changes in a worker's lifetime (gemini review on PR #95). A reload
-- re-requires the module → fresh value. _reset_cache is the test hook to swap
-- env between cases.
local DEFAULT_BASE_DOMAIN
function _M._reset_cache()
    DEFAULT_BASE_DOMAIN = string.lower(os.getenv("STAND_BASE_DOMAIN") or "example.com")
end
_M._reset_cache()

-- allow_domain(host, opts) — decide whether to obtain/serve an on-demand cert.
-- opts (test-only): { base_domain = "...", origin_ip = function(host)->ip }.
-- In production opts is nil: base_domain from the cached STAND_BASE_DOMAIN,
-- origin_ip from policy.origin_ip. Pure-ish (deps injectable) so it's
-- unit-testable.
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

-- sni_known(host, opts) — is this SNI a name the edge legitimately serves?
-- True for (a) the stand base domain and its subdomains (bac/dashboard, served
-- by the static fallback cert) and (b) a registered tenant (policy origin_ip).
-- False for everything else (random / scanner SNI, IP-literal SNI). This is the
-- edge-self-protection counterpart to allow_domain: allow_domain answers "ACME
-- this?" (base domain → NO, it uses the static cert), whereas sni_known answers
-- "serve this at all?" (base domain → YES). Same dot-boundary base match and
-- the same injectable deps (opts.base_domain / opts.origin_ip) for unit tests.
function _M.sni_known(host, opts)
    if not host or host == "" then return false end
    host = string.lower(host)

    local base = opts and opts.base_domain
    if base == nil then base = DEFAULT_BASE_DOMAIN end
    if base ~= "" and (host == base or host:sub(-(#base + 1)) == ("." .. base)) then
        return true
    end

    -- if/else (not `lookup and lookup(host) or require(...)`): a real non-tenant
    -- makes the injected lookup return nil, and the `or` would then fall through
    -- to require("policy") — defeating the test injection. Mirror allow_domain.
    local lookup = opts and opts.origin_ip
    local ip
    if lookup then
        ip = lookup(host)
    else
        ip = require("policy").origin_ip(host)
    end
    return type(ip) == "string" and ip ~= ""
end

-- reject_unknown_sni() — TLS-layer edge self-protection (step 2). When
-- edge_protection.deny_nontenant is on, abort the handshake for a PRESENT SNI
-- that is neither a tenant nor a base-domain name, BEFORE any HTTP is read —
-- the cheapest disposal the edge can do for an L7 flood that announces a
-- bogus/foreign SNI. ngx.exit(ngx.ERROR) sends a TLS alert and closes.
--
-- No-SNI handshakes (host nil — the common case for a flood hitting the raw
-- edge IP) are NOT rejected here: there is no name to judge, so we serve the
-- static fallback cert and let the HTTP-layer `return 444` (step 1) dispose of
-- the request by its empty $origin. The two layers are complementary — TLS
-- reject catches wrong-SNI, HTTP 444 catches no-SNI / IP-literal Host.
--
-- No per-handshake ngx.log: under a flood this fires on every connection, and a
-- log line per drop would itself become the bottleneck. The
-- edge_sni_rejected_total counter is the visible signal instead.
function _M.reject_unknown_sni()
    local config = require "config"
    if not config.edge_deny_nontenant(config.defaults) then return end

    local ok, ssl = pcall(require, "ngx.ssl")
    if not ok then return end   -- no ngx.ssl (e.g. unit test) → never reject
    local host = ssl.server_name()   -- nil when the client sent no SNI
    if host and host ~= "" and not _M.sni_known(host) then
        ngx.shared.metrics:incr("edge_sni_rejected_total", 1, 0)
        return ngx.exit(ngx.ERROR)
    end
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

-- ssl_certificate() — per-handshake cert selection. pcall-wrapped: if
-- lua-resty-acme throws (storage error, lock failure, internal bug), DON'T
-- abort the handshake — log and fall through. With no cert set by Lua,
-- OpenResty serves the static fallback cert (fullchain.pem) → no HTTPS outage
-- (gemini high review on PR #95). No-op when auto-ssl isn't active.
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
