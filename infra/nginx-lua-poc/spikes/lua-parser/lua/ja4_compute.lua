-- JA4-style fingerprint computed in access_by_lua from nginx-exposed
-- TLS handshake variables. No custom OpenResty build, no FFI.
--
-- WHY THIS IS NOT STRICT FOXIO JA4
-- --------------------------------
-- FoxIO JA4 requires the full ClientHello extension list +
-- signature_algorithms, which OpenSSL only exposes during the
-- SSL_CLIENT_HELLO_CB. lua-resty-core's ngx.ssl.clienthello.* API
-- exposes specific extension bodies in the ssl_client_hello_by_lua
-- phase, but does not expose the full extension-presence list nor the
-- offered cipher list. Bridging that data to access_by_lua requires
-- OpenSSL ex_data via FFI or a worker-shared map keyed by SSL session
-- — both add ~150-200 lines of FFI/glue with session-reuse and SSL
-- pointer-reuse edge cases.
--
-- This module instead uses nginx's standard $ssl_* vars (available
-- since nginx 1.11.7), which give us most of the JA4 components except
-- extensions:
--   $ssl_protocol         -> TLS version
--   $ssl_ciphers          -> client-offered cipher list (strongest signal)
--   $ssl_curves           -> client-offered EC curves
--   $ssl_alpn_protocol    -> negotiated ALPN
--   $ssl_server_name      -> SNI
--
-- Result fp:
--   * Real (built from TLS handshake invariants, not synthetic md5)
--   * Spoof-resistant (cipher list fixed by client TLS library;
--     UA swap doesn't change it)
--   * Browser-vs-automation distinguishing (Chrome cipher list != curl)
--   * Stable per (client TLS stack) — same client = same fp
--
-- NOT byte-identical to FoxIO JA4 — cannot cross-validate exact hash
-- against the FoxIO Python `ja4` library. See docs/phase2-fp-catalog.md.
--
-- Format: "L<ver><sni><cipher_cnt><alpn>_<sha256(sorted_ciphers):12>_<sha256(curves|alpn|ver):12>"
--   prefix "L" = "lua-lite", versions/sni/count layout mirrors JA4_a
--   so the value is grep-friendly alongside real JA4 if we ever ship
--   both side by side.

local resty_sha256 = require "resty.sha256"
local str_to_hex   = require("resty.string").to_hex
local helpers      = require "ja4_helpers"

local _M = {}

local function sha256_12(s)
    local h = resty_sha256:new()
    h:update(s)
    return str_to_hex(h:final()):sub(1, 12)
end

function _M.compute()
    local ciphers = ngx.var.ssl_ciphers or ""
    local curves  = ngx.var.ssl_curves  or ""
    local alpn    = ngx.var.ssl_alpn_protocol or ""
    local tls_ver = ngx.var.ssl_protocol or ""
    local sni     = ngx.var.ssl_server_name or ""

    local ver  = helpers.tls_ver_code(tls_ver)
    local snic = helpers.sni_char(sni)

    -- Cipher list: split + strip GREASE, then sort+hash. Counts come
    -- from the post-strip list so they match the JA4 spec (GREASE not
    -- counted).
    local list = helpers.split_strip_grease(ciphers)
    local cipher_count = #list
    if cipher_count > 99 then cipher_count = 99 end

    local ja_b = "000000000000"
    if cipher_count > 0 then
        table.sort(list)
        ja_b = sha256_12(table.concat(list, ","))
    end

    local curves_canonical = table.concat(helpers.split_strip_grease(curves), ":")

    local alpn_two = helpers.alpn_two(alpn)
    local prefix = string.format("L%s%s%02d%s", ver, snic, cipher_count, alpn_two)

    -- Curves + alpn hash (substitute for the missing extension hash).
    -- Uses GREASE-stripped curves + normalised 2-digit ver (not raw
    -- tls_ver) so the hash is stable across both reload AND nginx-build
    -- variations. See infra/nginx-lua-poc/lua/ja4_compute.lua for the
    -- full rationale comment.
    local ja_c = sha256_12(curves_canonical .. "|" .. alpn .. "|" .. ver)

    return prefix .. "_" .. ja_b .. "_" .. ja_c,
           { ciphers = ciphers, curves = curves, alpn = alpn,
             tls_ver = tls_ver, sni = sni }
end

return _M
