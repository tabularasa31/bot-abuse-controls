-- Pure-Lua helpers used by ja4_compute. Split out so they can be
-- unit-tested without an OpenResty runtime: no ngx.*, no resty.* deps.

local _M = {}

_M.TLS_VER_CODE = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"]   = "10",
}

-- RFC 8701 GREASE detection. Stock nginx renders unknown cipher /
-- curve values as "0x<4 hex>"; GREASE is the subset where both bytes
-- are equal AND the low nibble is 0xA (0x0A0A, 0x1A1A, ..., 0xFAFA).
-- Accepts both lowercase ("0x6a6a") and uppercase ("0X1A1A") since
-- different nginx builds / OpenSSL versions vary on the case.
function _M.is_grease(token)
    -- Named ciphers ("TLS_AES_...", "ECDHE-...") never start with "0x"
    -- — fast-skip via raw byte check so we don't run the pattern on
    -- the >99% of tokens that can't be GREASE.
    if token:byte(1) ~= 48 then return false end   -- '0' = 0x30 = 48
    local b2 = token:byte(2)
    if b2 ~= 120 and b2 ~= 88 then return false end -- 'x'=120, 'X'=88
    -- Backreference %1 stays byte-exact (so first and third hex digits
    -- must literally match, including case), but [aA] / [0-9a-fA-F]
    -- around it accept either case for the structural chars.
    return token:match("^0[xX]([0-9a-fA-F])[aA]%1[aA]$") ~= nil
end

-- Split a colon-separated token list, dropping GREASE entries. Returns
-- a Lua array. Used for both $ssl_ciphers and $ssl_curves.
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

-- ALPN encoding for JA4-style prefix: first char + last char of the
-- first ALPN protocol, lowercased. "h2" -> "h2", "http/1.1" -> "h1",
-- empty/missing -> "00".
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
