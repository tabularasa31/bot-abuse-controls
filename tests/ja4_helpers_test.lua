-- Unit tests for infra/nginx-lua-poc/lua/ja4_helpers.lua. Pure Lua;
-- runs under any luajit or lua 5.1+ with no openresty / resty deps.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine, same runtime as prod)
--
-- Each test calls one helper with a documented input and asserts the
-- output. Failures print expected vs actual and bump a counter; the
-- process exits non-zero if any failed.

package.path = "infra/nginx-lua-poc/lua/?.lua;./infra/nginx-lua-poc/lua/?.lua;" .. package.path
local helpers = require "ja4_helpers"

local failed, passed = 0, 0

local function check(actual, expected, label)
    if actual == expected then
        passed = passed + 1
    else
        failed = failed + 1
        io.stderr:write(string.format(
            "FAIL  %s\n      expected: %s\n      actual:   %s\n",
            label, tostring(expected), tostring(actual)))
    end
end

local function check_list(actual, expected, label)
    -- Array equality by length + per-index comparison.
    if type(actual) ~= "table" then
        failed = failed + 1
        io.stderr:write(string.format("FAIL  %s: actual is not a table (%s)\n",
            label, type(actual)))
        return
    end
    if #actual ~= #expected then
        failed = failed + 1
        io.stderr:write(string.format("FAIL  %s: length mismatch (expected %d, got %d)\n      expected: {%s}\n      actual:   {%s}\n",
            label, #expected, #actual,
            table.concat(expected, ","), table.concat(actual, ",")))
        return
    end
    for i = 1, #expected do
        if actual[i] ~= expected[i] then
            failed = failed + 1
            io.stderr:write(string.format("FAIL  %s [%d]: expected %s, got %s\n",
                label, i, tostring(expected[i]), tostring(actual[i])))
            return
        end
    end
    passed = passed + 1
end

-- ===========================================================================
-- is_grease()
-- ===========================================================================
-- All 16 GREASE values per RFC 8701.

local lowercase_grease = {
    "0x0a0a", "0x1a1a", "0x2a2a", "0x3a3a", "0x4a4a", "0x5a5a", "0x6a6a",
    "0x7a7a", "0x8a8a", "0x9a9a", "0xaaaa", "0xbaba", "0xcaca", "0xdada",
    "0xeaea", "0xfafa",
}
for _, g in ipairs(lowercase_grease) do
    check(helpers.is_grease(g), true, "is_grease lowercase " .. g)
end

local uppercase_grease = {
    "0X0A0A", "0X1A1A", "0X2A2A", "0X6A6A", "0XCACA", "0XFAFA",
}
for _, g in ipairs(uppercase_grease) do
    check(helpers.is_grease(g), true, "is_grease uppercase " .. g)
end

-- Mixed case — backreference is byte-exact, so first and third hex
-- characters must be the same case AND value. "0x1A1a" matches (first
-- nibble "1", third nibble "1" — same byte). "0xAaAa" matches (first
-- "A", third "A").
check(helpers.is_grease("0x1A1a"), true,  "is_grease mixed 0x1A1a")
check(helpers.is_grease("0XaAaA"), true,  "is_grease mixed 0XaAaA")

-- Non-GREASE values
local not_grease = {
    "TLS_AES_128_GCM_SHA256",   -- named cipher
    "ECDHE-RSA-AES128-SHA",     -- named cipher
    "DES-CBC3-SHA",             -- legacy named
    "0x00ff",                   -- TLS_EMPTY_RENEGOTIATION_INFO_SCSV — known cipher, not GREASE
    "0xc02f",                   -- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    "0x1a1b",                   -- close to 0x1a1a but second byte differs
    "0x1b1b",                   -- both bytes equal but low nibble is 0xb, not 0xa
    "0xcacb",                   -- close to 0xcaca but second byte differs
    "0x00aa",                   -- low nibble 0xa but high byte differs from low byte
    "",                         -- empty string
    "x",                        -- doesn't start with "0"
    "0",                        -- single-char
}
for _, n in ipairs(not_grease) do
    check(helpers.is_grease(n), false, "is_grease NOT " .. (n == "" and "(empty)" or n))
end

-- ===========================================================================
-- split_strip_grease()
-- ===========================================================================

check_list(
    helpers.split_strip_grease(""),
    {},
    "split_strip_grease empty")

check_list(
    helpers.split_strip_grease(nil),
    {},
    "split_strip_grease nil")

check_list(
    helpers.split_strip_grease("AES128-SHA"),
    {"AES128-SHA"},
    "split_strip_grease single named")

check_list(
    helpers.split_strip_grease("AES128-SHA:AES256-SHA"),
    {"AES128-SHA", "AES256-SHA"},
    "split_strip_grease two named")

check_list(
    helpers.split_strip_grease("0x6a6a:AES128-SHA:AES256-SHA"),
    {"AES128-SHA", "AES256-SHA"},
    "split_strip_grease GREASE first (Chrome pattern)")

check_list(
    helpers.split_strip_grease("AES128-SHA:0x1a1a:AES256-SHA"),
    {"AES128-SHA", "AES256-SHA"},
    "split_strip_grease GREASE middle")

check_list(
    helpers.split_strip_grease("0x6a6a:0xcaca:AES128-SHA"),
    {"AES128-SHA"},
    "split_strip_grease two GREASE prefix")

check_list(
    helpers.split_strip_grease("0x00ff:AES128-SHA"),
    {"0x00ff", "AES128-SHA"},
    "split_strip_grease non-GREASE hex preserved")

-- ===========================================================================
-- alpn_two() / sni_char() / tls_ver_code()
-- ===========================================================================

check(helpers.alpn_two("h2"),        "h2", "alpn_two h2")
check(helpers.alpn_two("http/1.1"),  "h1", "alpn_two http/1.1")
check(helpers.alpn_two("h3"),        "h3", "alpn_two h3")
check(helpers.alpn_two("HTTP/2.0"),  "h0", "alpn_two HTTP/2.0 lowercased")
check(helpers.alpn_two(""),          "00", "alpn_two empty")
check(helpers.alpn_two(nil),         "00", "alpn_two nil")
check(helpers.alpn_two("x"),         "00", "alpn_two single char")

check(helpers.sni_char("antibot.local"), "d", "sni_char present")
check(helpers.sni_char(""),              "i", "sni_char empty")
check(helpers.sni_char(nil),             "i", "sni_char nil")

check(helpers.tls_ver_code("TLSv1.3"), "13", "tls_ver_code 1.3")
check(helpers.tls_ver_code("TLSv1.2"), "12", "tls_ver_code 1.2")
check(helpers.tls_ver_code("TLSv1.1"), "11", "tls_ver_code 1.1")
check(helpers.tls_ver_code("TLSv1"),   "10", "tls_ver_code 1.0")
check(helpers.tls_ver_code("SSLv3"),   "00", "tls_ver_code unknown")
check(helpers.tls_ver_code(""),        "00", "tls_ver_code empty")
check(helpers.tls_ver_code(nil),       "00", "tls_ver_code nil")

-- ===========================================================================
-- Reporting
-- ===========================================================================

io.stdout:write(string.format("\n%d passed, %d failed (%d total)\n",
    passed, failed, passed + failed))
os.exit(failed == 0 and 0 or 1)
