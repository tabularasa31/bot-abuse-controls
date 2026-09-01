-- Pure-Lua helpers used by ja4_compute. Split out so they can be
-- unit-tested without an OpenResty runtime: no ngx.*, no resty.* deps.

local _M = {}

_M.TLS_VER_CODE = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"]   = "10",
}

-- RFC 8701 GREASE: nginx renders unknown values as "0x<4 hex>", and GREASE is
-- the subset where both bytes match and the low nibble is 0xA. Case varies
-- between nginx and OpenSSL builds, so both are accepted.
function _M.is_grease(token)
    -- Named ciphers never start with "0x", so skip the pattern for the vast
    -- majority of tokens.
    if token:byte(1) ~= 48 then return false end   -- '0' = 0x30 = 48
    local b2 = token:byte(2)
    if b2 ~= 120 and b2 ~= 88 then return false end -- 'x'=120, 'X'=88
    -- %1 is byte-exact, so the repeated digit must match including case; the
    -- surrounding classes accept either.
    return token:match("^0[xX]([0-9a-fA-F])[aA]%1[aA]$") ~= nil
end

-- Splits a colon-separated list, dropping GREASE entries.
function _M.split_strip_grease(s)
    local out = {}
    if s and #s > 0 then
        for tok in s:gmatch("[^:]+") do
            if not _M.is_grease(tok) then
                out[#out + 1] = tok
            end
        end
    end
    return out
end

-- First and last character of the first ALPN protocol: "http/1.1" -> "h1",
-- empty -> "00".
function _M.alpn_two(alpn)
    if not alpn or #alpn < 2 then return "00" end
    return (alpn:sub(1, 1) .. alpn:sub(-1)):lower()
end

-- SNI indicator: "d" (present) / "i" (absent).
function _M.sni_char(sni)
    return (sni and #sni > 0) and "d" or "i"
end

-- TLS version → JA4 2-digit code, or "00" if unrecognised.
function _M.tls_ver_code(ver)
    return _M.TLS_VER_CODE[ver or ""] or "00"
end

return _M
