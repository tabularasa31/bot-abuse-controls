-- Hardcoded blocklist of synthetic fingerprints.
--
-- WHY synthetic, not real JA3?
-- ----------------------------
-- This PoC measures the Lua verdict-path architecture cost
-- (shared_dict lookup + cache + ngx.exit). It does NOT prove
-- that JA3/JA4 can be computed in pure Lua — that question is
-- Phase 2 (either custom OpenResty build with JA3 patched into
-- OpenSSL, e.g. vela-security/openresty-ssl-ja3, or FoxIO C
-- module rebuilt with --with-http_lua_module). Phase 1 already
-- proved JA4 via FoxIO works; the architectural decision being
-- tested here is whether the verdict pipeline running in Lua
-- can keep up with edge nginx, independent of fingerprint source.
--
-- Synthetic fingerprint formula (see verdict.lua):
--   fp = md5(ssl_cipher .. ":" .. ssl_protocol .. ":" .. substr(ua, 0, 32))
--
-- After first bring-up, run scripts/lua-poc-probe.sh against the
-- live stand and copy the synthetic fingerprints curl/python/go
-- produce into the "block" table below; then docker compose restart.

local _M = {}

-- Populate from probe output. Each entry: [fingerprint] = "block"|"allow"
-- Allow is the default (see verdict.lua); listing "allow" here is purely
-- to document a known browser fingerprint and pin a fast-path cache entry.
-- IMPORTANT: synthetic fps are host-specific — they depend on which
-- TLS stack the *client* uses (LibreSSL on macOS picks different ciphers
-- than OpenSSL on Linux), so the hashes captured below WILL NOT match
-- on your machine. Re-capture on your host:
--   1. docker compose -f docker-compose.lua-poc.yml --profile lua-only up -d --build
--   2. ./scripts/lua-poc-probe.sh                       # gets fp= lines
--   3. paste them into _M.entries below
--   4. docker compose ... restart
--
-- The entries below are kept as REFERENCE only (the exact set used to
-- produce the numbers in docs/lua-poc-results.md, on macOS arm64
-- with LibreSSL). They are commented out by default so a fresh clone
-- starts with an empty blocklist — every request reaches the allow
-- path. After you re-capture, either replace this block or add your
-- own entries alongside.

_M.entries = {
    -- (empty by default — see comment above)
}

-- Reference: captured 2026-05-16 on macOS arm64 (LibreSSL curl, OpenSSL
-- wrk, alpine docker for go/python). Uncomment to reproduce the bench
-- numbers in docs/lua-poc-results.md exactly.
--
-- _M.entries = {
--     ["4634153596f003da988bb6b065cfa947"] = "block",  -- curl/8.7.1 (LibreSSL macOS)
--     ["a389dcca20a077ee1b1bb6246f013cda"] = "block",  -- Go-http-client/1.1 (alpine)
--     ["73801183cd1eb532c6b8b2b81a3bcd90"] = "block",  -- python-requests/2.34.0
--     ["c6214dd22b76c2a7a27165fdfdee9236"] = "block",  -- wrk -H "UA: curl/8.7.1" (OpenSSL)
-- }

return _M
