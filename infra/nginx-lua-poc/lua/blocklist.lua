-- Hardcoded blocklist of real handshake-derived fingerprints.
--
-- Fingerprint formula (see ja4_compute.lua):
--   L<ver><sni><cipher_cnt><alpn>_<sha256(sorted_ciphers):12>_<sha256(curves|alpn|ver):12>
--
-- The leading "L" prefix distinguishes this from strict FoxIO JA4 ("t"
-- prefix). The "L" stands for "Lua-lite" — we hash the cipher list +
-- handshake metadata exposed by stock nginx ($ssl_ciphers, $ssl_curves,
-- $ssl_protocol, $ssl_alpn_protocol, $ssl_server_name) but DO NOT include
-- the full ClientHello extension list. See docs/phase2-fp-catalog.md for
-- the trade-off rationale and Phase 2 spike comparison.
--
-- After bring-up, run scripts/lua-poc-probe.sh to capture fp values for
-- curl / python-requests / Go-http-client (plus manual browser probes for
-- Chrome / Firefox / Safari), then paste below.

local _M = {}

-- Populate from probe output. Each entry: [fingerprint] = "block"|"allow"
-- Allow is the default (see verdict.lua); listing "allow" here is purely
-- to document a known browser fingerprint and pin a fast-path cache entry.
--
-- IMPORTANT: real handshake fps are STILL host-specific — the client's TLS
-- library version, OpenSSL build flags, and OS curl flavour all affect the
-- cipher list. macOS LibreSSL curl emits a different fp than Linux OpenSSL
-- curl. Re-capture on your host:
--   1. docker compose -f docker-compose.lua-poc.yml --profile lua-only up -d --build
--   2. ./scripts/lua-poc-probe.sh
--   3. paste fp values into _M.entries below
--   4. docker compose ... restart

_M.entries = {
    -- (empty by default — see comment above)
}

-- Reference: captured 2026-05-16 on macOS arm64 (LibreSSL curl, OpenResty
-- alpine native arm64). Uncomment to reproduce the Phase 2 bench numbers
-- in docs/lua-poc-results.md exactly.
--
-- _M.entries = {
--     ["L13d49h2_de2bb2c70653_2d5fbeed7632"] = "block",  -- curl/8.7.1
--     ["L13d1300_69e852b66fc7_1bb3b57910c1"] = "block",  -- Go-http-client/1.1
--     ["L13i30h1_bcf826a2cd28_60bdc24aefcc"] = "block",  -- python-requests/2.32.5
-- }

return _M
