-- Demo-stand ja4_compute. Byte-identical to infra/nginx-lua-poc/lua/ja4_compute.lua.
-- Kept as a sibling file (rather than symlink-mounted) so the demo
-- stand is self-contained and can be inspected by a reviewer without
-- chasing mount points.
--
-- IMPORTANT: keep this in sync with the production copy. Both files
-- are unit-tested by tests/ja4_helpers_test.lua via the shared helpers
-- module after PR #6 lands.

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

-- RFC 8701 GREASE. See infra/nginx-lua-poc/lua/ja4_compute.lua for
-- the full rationale comment; this is the same code.
local function is_grease(token)
    if token:byte(1) ~= 48 then return false end
    local b2 = token:byte(2)
    if b2 ~= 120 and b2 ~= 88 then return false end
    return token:match("^0[xX]([0-9a-fA-F])[aA]%1[aA]$") ~= nil
end

local function split_strip_grease(s)
    local out = {}
    if s and #s > 0 then
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

    local list = split_strip_grease(ciphers)
    local cipher_count = #list
    if cipher_count > 99 then cipher_count = 99 end

    local ja_b = "000000000000"
    if cipher_count > 0 then
        table.sort(list)
        ja_b = sha256_12(table.concat(list, ","))
    end

    local curves_canonical = table.concat(split_strip_grease(curves), ":")

    local alpn_two = "00"
    if #alpn >= 2 then
        alpn_two = (alpn:sub(1, 1) .. alpn:sub(-1)):lower()
    end

    local prefix = string.format("L%s%s%02d%s", ver, snic, cipher_count, alpn_two)
    local ja_c = sha256_12(curves_canonical .. "|" .. alpn .. "|" .. tls_ver)

    return prefix .. "_" .. ja_b .. "_" .. ja_c,
           { ciphers = ciphers, curves = curves, alpn = alpn,
             tls_ver = tls_ver, sni = sni }
end

return _M
