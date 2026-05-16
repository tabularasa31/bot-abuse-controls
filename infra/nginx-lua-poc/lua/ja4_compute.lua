-- JA4-style fingerprint computed in access_by_lua from nginx-exposed
-- TLS handshake variables. No custom OpenResty build, no FFI.
--
-- WHY THIS IS NOT STRICT FOXIO JA4
-- --------------------------------
-- FoxIO JA4 requires the full ClientHello extension list + signature_algorithms,
-- which OpenSSL only exposes during the SSL_CLIENT_HELLO_CB. lua-resty-core's
-- `ngx.ssl.clienthello.get_client_hello_ext(type)` exposes specific extension
-- *bodies* in the `ssl_client_hello_by_lua` phase, but does not expose the
-- full extension-presence list nor the offered cipher list. Bridging that data
-- to `access_by_lua` requires either OpenSSL ex_data via FFI or a worker-shared
-- map keyed by SSL session — both add ~150-200 lines of FFI/glue with edge
-- cases on session reuse and SSL pointer reuse.
--
-- This module instead uses nginx's standard `$ssl_*` vars (available since
-- nginx 1.11.7) which give us most of the JA4 components except extensions:
--   $ssl_protocol         -> TLS version
--   $ssl_ciphers          -> client-offered cipher list (the strongest signal)
--   $ssl_curves           -> client-offered EC curves
--   $ssl_alpn_protocol    -> negotiated ALPN
--   $ssl_server_name      -> SNI
--
-- The resulting hash is:
--   * Real (built from TLS handshake invariants, not synthetic md5)
--   * Spoof-resistant (cipher list is fixed by the client's TLS library; UA
--     swap doesn't change it)
--   * Browser-vs-automation distinguishing (Chrome cipher list != curl)
--   * Stable per (client TLS stack) - same client = same fp
--
-- It is NOT byte-identical to FoxIO JA4 → cannot cross-validate against the
-- FoxIO Python `ja4` library for exact-match. Spike RESULTS.md captures this.
--
-- Format: "L13d27_<sha256(sorted_ciphers):12>_<sha256(curves|alpn):12>"
--   prefix "L" = "lua-lite", versions/sni/count layout mirror JA4_a so the
--   value is grep-friendly alongside real JA4 if we ever ship both.

local resty_sha256 = require "resty.sha256"
local str_to_hex   = require("resty.string").to_hex

local _M = {}

local TLS_VER_CODE = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"]   = "10",
}

local function sha256_12(s)
    local h = resty_sha256:new()
    h:update(s)
    return str_to_hex(h:final()):sub(1, 12)
end

-- RFC 8701 GREASE: nginx renders unknown cipher / curve values as
-- "0x<4 hex>". GREASE values are 0x?A?A where both bytes are equal AND the
-- low nibble is 0xA — i.e. 0x0A0A, 0x1A1A, ..., 0xFAFA (16 values per slot).
-- Chrome and Safari rotate GREASE per TLS connection; if we keep them in the
-- hash input, the same browser produces a different fp on every reload.
-- Strip before sort+hash so the fp is stable per (client TLS library), which
-- is the property that makes the signal useful.
local function is_grease(token)
    -- Fast path: named ciphers ("TLS_AES_...", "ECDHE-...") never match —
    -- skip the regex entirely. Only "0x<hex>" tokens can be GREASE.
    if token:byte(1) ~= 48 or token:byte(2) ~= 120 then  -- '0', 'x'
        return false
    end
    return token:match("^0x([0-9a-f])a%1a$") ~= nil
end

-- Split colon-separated token list, stripping GREASE.
local function split_strip_grease(s)
    local out = {}
    if #s > 0 then
        for tok in s:gmatch("[^:]+") do
            if not is_grease(tok) then
                out[#out + 1] = tok
            end
        end
    end
    return out
end

function _M.compute()
    local ciphers = ngx.var.ssl_ciphers or ""
    local curves  = ngx.var.ssl_curves  or ""
    local alpn    = ngx.var.ssl_alpn_protocol or ""
    local tls_ver = ngx.var.ssl_protocol or ""
    local sni     = ngx.var.ssl_server_name or ""

    local ver  = TLS_VER_CODE[tls_ver] or "00"
    local snic = (#sni > 0) and "d" or "i"

    -- Single pass over $ssl_ciphers: split + strip GREASE, then sort+hash.
    -- cipher_count derived from #list (post-strip), matches the JA4 spec
    -- which excludes GREASE from the count too.
    local list = split_strip_grease(ciphers)
    local cipher_count = #list
    if cipher_count > 99 then cipher_count = 99 end

    local ja_b = "000000000000"
    if cipher_count > 0 then
        table.sort(list)
        ja_b = sha256_12(table.concat(list, ","))
    end

    -- Curves: strip GREASE too. Order is preserved (the spec does NOT sort
    -- curves), but GREASE removal is required for stable hash across reloads.
    local curve_list = split_strip_grease(curves)
    local curves_canonical = table.concat(curve_list, ":")

    -- ALPN first-and-last char, lowercased. "h2" -> "h2", "http/1.1" -> "h1".
    local alpn_two = "00"
    if #alpn >= 2 then
        alpn_two = (alpn:sub(1, 1) .. alpn:sub(-1)):lower()
    end

    local prefix = string.format("L%s%s%02d%s", ver, snic, cipher_count, alpn_two)

    -- Curves + alpn hash (substitute for the missing extension hash). Uses
    -- the GREASE-stripped curves so the hash is stable across browser reloads.
    local ja_c = sha256_12(curves_canonical .. "|" .. alpn .. "|" .. tls_ver)

    return prefix .. "_" .. ja_b .. "_" .. ja_c,
           { ciphers = ciphers, curves = curves, alpn = alpn,
             tls_ver = tls_ver, sni = sni }
end

return _M
