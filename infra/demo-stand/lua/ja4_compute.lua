-- JA4-style fingerprint built in access_by_lua from nginx's $ssl_* variables.
--
-- This is deliberately not byte-identical to FoxIO JA4 and cannot be
-- cross-validated against it. Strict JA4 needs the full ClientHello
-- extension list, which OpenSSL only exposes in the client-hello callback;
-- bridging that into access_by_lua costs a few hundred lines of FFI with
-- session-reuse edge cases. The $ssl_* variables carry every other component,
-- including the client-offered cipher list — the strongest signal, fixed by
-- the client's TLS library and unchanged by swapping the User-Agent.
--
-- Format: L<ver><sni><cipher_cnt><alpn>_<sha256(sorted_ciphers):12>_<sha256(curves|alpn|ver):12>
-- The "L" prefix marks the variant; the rest mirrors the JA4_a layout so both
-- can be grepped side by side.

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

    -- Count after stripping GREASE, as the JA4 spec requires.
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

    -- Stands in for the extension hash we cannot reach. Uses the normalised
    -- `ver` rather than raw $ssl_protocol so the value survives nginx builds
    -- that render the protocol string differently.
    local ja_c = sha256_12(curves_canonical .. "|" .. alpn .. "|" .. ver)

    return prefix .. "_" .. ja_b .. "_" .. ja_c,
           { ciphers = ciphers, curves = curves, alpn = alpn,
             tls_ver = tls_ver, sni = sni }
end

return _M
