-- Shadow-mode reference blocklist. Pre-populated with the 3 automation
-- fps from docs/phase2-fp-catalog.md so that "would_verdict=block" log
-- lines start appearing on day 1 — gives you ground-truth counts of how
-- many requests are obvious automation, without any risk of blocking
-- legitimate traffic (shadow mode never enforces).
--
-- IMPORTANT host-specificity caveat (same as in PoC #2 blocklist.lua):
-- these fps were captured on macOS arm64 with LibreSSL curl + alpine
-- Go/Python in containers. Real production traffic will have a wider
-- distribution. Use these as starter entries; the catalog will grow from
-- shadow-log analysis (see scripts/analyze-shadow-log.sh).
--
-- DO NOT add browser fps here in shadow mode — even though they were
-- captured for the catalog, marking them "block" would inflate the
-- "would_block" count and obscure the automation-vs-browser signal in
-- the shadow logs. If you want to count browsers separately, add a
-- different verdict tag and extend log_event.lua to record it.

local _M = {}

_M.entries = {
    -- Automation clients — captured 2026-05-16 on macOS arm64.
    -- Same hashes as the reference set in
    -- infra/nginx-lua-poc/lua/blocklist.lua (commented-out section).
    ["L13d49h2_de2bb2c70653_d07b7f455339"] = "block",  -- curl/8.7.1 (LibreSSL)
    ["L13d1300_69e852b66fc7_747a969b1fb5"] = "block",  -- Go-http-client/1.1
    ["L13i30h1_bcf826a2cd28_8c35449021c4"] = "block",  -- python-requests/2.32.5
}

return _M
