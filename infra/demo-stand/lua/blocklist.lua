-- Demo-stand seed blocklist. Pre-populated with the 3 automation fps
-- from docs/phase2-fp-catalog.md so the "curl gets 403, browser gets
-- 200" demo works out of the box.
--
-- A reviewer can confirm the entries by hitting /__fp from each
-- client and matching the response against this table.

local _M = {}

-- Post-ver-fix hashes (PR #6: ja_c hashes the normalised 2-digit ver
-- code, not the raw $ssl_protocol string). Captured 2026-05-16 on
-- macOS arm64 against the production ja4_compute.
--
-- Note on SNI variants: clients usually send SNI when the URL host is
-- a domain ("d" prefix), and skip it for IP literals ("i" prefix).
-- Reviewers hitting the demo on a public domain produce the "d"
-- variant; local 127.0.0.1 testing produces "i". Seed BOTH so the
-- visible-blocking demo works either way. ja_b and ja_c are identical
-- across variants (same client, same cipher list, same curves/alpn);
-- only the prefix's SNI char flips.
_M.entries = {
    -- curl 8.7.1 (macOS LibreSSL), 49 ciphers, h2 ALPN
    ["L13d49h2_de2bb2c70653_2d5fbeed7632"] = "block",  -- SNI
    ["L13i49h2_de2bb2c70653_2d5fbeed7632"] = "block",  -- no SNI (IP literal)
    -- Go-http-client/1.1 (alpine), 13 ciphers, no ALPN
    ["L13d1300_69e852b66fc7_1bb3b57910c1"] = "block",  -- SNI
    ["L13i1300_69e852b66fc7_1bb3b57910c1"] = "block",  -- no SNI
    -- python-requests 2.32.5 (Python 3.9 alpine), 30 ciphers, http/1.1
    ["L13d30h1_bcf826a2cd28_60bdc24aefcc"] = "block",  -- SNI (real-host case)
    ["L13i30h1_bcf826a2cd28_60bdc24aefcc"] = "block",  -- no SNI (IP literal)
}

return _M
