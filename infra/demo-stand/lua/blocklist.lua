-- Demo-stand seed blocklist. Pre-populated with the 3 automation fps
-- from docs/phase2-fp-catalog.md so the "curl gets 403, browser gets
-- 200" demo works out of the box.
--
-- A reviewer can confirm the entries by hitting /__fp from each
-- client and matching the response against this table.

local _M = {}

_M.entries = {
    -- curl 8.7.1 (macOS LibreSSL), 49 ciphers, h2 ALPN
    ["L13d49h2_de2bb2c70653_d07b7f455339"] = "block",
    -- Go-http-client/1.1 (alpine), 13 ciphers, no ALPN
    ["L13d1300_69e852b66fc7_747a969b1fb5"] = "block",
    -- python-requests 2.32.5 (Python 3.9 alpine), 30 ciphers, http/1.1
    ["L13i30h1_bcf826a2cd28_8c35449021c4"] = "block",
}

return _M
