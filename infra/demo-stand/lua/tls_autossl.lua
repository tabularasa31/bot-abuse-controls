-- On-demand Let's Encrypt certificates for tenant custom domains.
--
-- The edge stays the TLS terminator, because the cascade fingerprints the
-- client handshake, so the certificate is chosen here per SNI. Issuance is
-- gated on the host being a registered tenant: without that gate anyone
-- pointing DNS at the edge could burn the rate limit.
--
-- Every entry point fails open to the static certificate — a broken auto-ssl
-- must never take HTTPS down.
local _M = {}

-- Cached: os.getenv cannot be JIT-compiled and this runs per handshake.
local DEFAULT_BASE_DOMAIN
function _M._reset_cache()
    DEFAULT_BASE_DOMAIN = string.lower(os.getenv("STAND_BASE_DOMAIN") or "example.com")
end
_M._reset_cache()

-- `opts` injects the dependencies for tests; production passes nil.
function _M.allow_domain(host, opts)
    if not host or host == "" then return false end
    host = string.lower(host)

    local base = opts and opts.base_domain
    if base == nil then base = DEFAULT_BASE_DOMAIN end
    -- The base domain is covered by the static certificate.
    if base ~= "" then
        if host == base or host:sub(-(#base + 1)) == ("." .. base) then
            return false
        end
    end

    -- Only a registered tenant, so nobody else can trigger issuance.
    local lookup = opts and opts.origin_ip
    local ip
    if lookup then
        ip = lookup(host)
    else
        ip = require("policy").origin_ip(host)
    end
    return type(ip) == "string" and ip ~= ""
end

-- Whether the edge serves this SNI at all. The counterpart to allow_domain:
-- the base domain answers no there and yes here.
function _M.sni_known(host, opts)
    if not host or host == "" then return false end
    host = string.lower(host)

    local base = opts and opts.base_domain
    if base == nil then base = DEFAULT_BASE_DOMAIN end
    if base ~= "" and (host == base or host:sub(-(#base + 1)) == ("." .. base)) then
        return true
    end

    -- The require is deliberately not pcall-wrapped: the caller already fails
    -- open, and catching here would fail closed and drop a tenant's handshake.
    local lookup = opts and opts.origin_ip
    local ip
    if lookup then
        ip = lookup(host)
    else
        ip = require("policy").origin_ip(host)
    end
    return type(ip) == "string" and ip ~= ""
end

-- Aborts the handshake for an SNI that is neither a tenant nor the base domain,
-- before any HTTP is read. A handshake with no SNI carries no name to judge and
-- is left to the HTTP layer.
--
-- Nothing is logged per handshake: under a flood that would be the bottleneck.
--
-- The decision fails open, but the exit stays outside the pcall — it would
-- swallow the control flow and turn a reject into a silent pass.
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

-- The require is here rather than at module load so tests need no resty.acme.
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

-- A throw here would abort init_worker and silently stop the catalog pull.
function _M.init_worker()
    if not _M._ready then return end
    local ok, err = pcall(function() require("resty.acme.autossl").init_worker() end)
    if not ok then
        ngx.log(ngx.ERR, "[demo] on-demand TLS: init_worker() failed, ",
            "renewal disabled (issuance/serving unaffected): ", tostring(err))
    end
end

-- Falls through on error: with no certificate set, the static one is served.
function _M.ssl_certificate()
    -- Runs first and independent of _ready, so an unknown SNI is dropped even
    -- when on-demand TLS is inactive.
    _M.reject_unknown_sni()

    if not _M._ready then return end
    local ok, err = pcall(function() require("resty.acme.autossl").ssl_certificate() end)
    if not ok then
        ngx.log(ngx.ERR, "[demo] on-demand TLS: ssl_certificate() failed, ",
            "falling back to static cert: ", tostring(err))
    end
end

-- Answers the ACME challenge during issuance.
function _M.serve_http_challenge()
    if not _M._ready then return end
    local ok, err = pcall(function() require("resty.acme.autossl").serve_http_challenge() end)
    if not ok then
        ngx.log(ngx.ERR, "[demo] on-demand TLS: serve_http_challenge() failed: ", tostring(err))
    end
end

return _M
