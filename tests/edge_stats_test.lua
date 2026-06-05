-- Unit tests for infra/demo-stand/lua/edge_stats.lua — the EDGE_STATS stdout
-- dump that replaces the removed /metrics endpoint. Pure parts only (snapshot +
-- iso8601); the timer/emit path touches ngx + stdout and is exercised on the
-- live stand. Loads under bare luajit (the module body has no ngx deps).
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

local edge_stats = require "edge_stats"

local passed, failed = 0, 0
local function eq(actual, want, name)
    if actual == want then
        passed = passed + 1
    else
        failed = failed + 1
        io.write(string.format("FAIL %s: got %s, want %s\n",
            name, tostring(actual), tostring(want)))
    end
end

-- iso8601 -----------------------------------------------------------------
-- epoch 0 = 1970-01-01T00:00:00Z; 1700000000 = 2023-11-14T22:13:20Z (UTC).
eq(edge_stats.iso8601(0), "1970-01-01T00:00:00Z", "iso8601 epoch 0")
eq(edge_stats.iso8601(1700000000), "2023-11-14T22:13:20Z", "iso8601 known epoch")
eq(edge_stats.iso8601(1700000000.9), "2023-11-14T22:13:20Z", "iso8601 floors fractional")
eq(edge_stats.iso8601(nil), "1970-01-01T00:00:00Z", "iso8601 nil → epoch 0")

-- snapshot ----------------------------------------------------------------
-- A getter backed by a fixed table; absent keys return nil (→ 0 in snapshot).
local data = {
    edge_nontenant_dropped_total = 1200,
    edge_sni_rejected_total      = 34,
    requests_total               = 5000,
    verdict_block_total          = 42,
    cache_hit_total              = 90,
    cache_miss_total             = 10,
    fp_unique                    = 7,
    blocklist_entries            = 3,
}
local function get(k) return data[k] end

local s = edge_stats.snapshot(get, 1700001000, 1700000000, "edge-7")
eq(s.type, "edge_stats", "snapshot: type stamped")
eq(s.edge_id, "edge-7", "snapshot: edge_id stamped")
eq(s.edge_nontenant_dropped_total, 1200, "snapshot: drop counter passed through")
eq(s.edge_sni_rejected_total, 34, "snapshot: sni reject passed through")
eq(s.requests_total, 5000, "snapshot: requests passed through")
eq(s.verdict_pass_total, 0, "snapshot: absent key → 0")
eq(s.cache_hit_ratio, 0.9, "snapshot: cache ratio = hit/(hit+miss)")
eq(s.uptime_seconds, 1000, "snapshot: uptime = now - start_time")
eq(s.timestamp, "2023-11-14T22:30:00Z", "snapshot: timestamp = iso8601(now=1700001000)")

-- Empty / nil getter → all zeros, ratio 0 (no div-by-zero), no crash.
local z = edge_stats.snapshot(function() return nil end, 100, 100, nil)
eq(z.edge_id, "", "snapshot: nil edge_id → empty string")
eq(z.edge_nontenant_dropped_total, 0, "snapshot: nil getter → 0")
eq(z.cache_hit_ratio, 0, "snapshot: 0 hits+misses → ratio 0 (no div-by-zero)")
eq(z.uptime_seconds, 0, "snapshot: now==start_time → 0 uptime")

-- Missing now/start_time → uptime 0 (defensive).
local d = edge_stats.snapshot(get, nil, nil, "e")
eq(d.uptime_seconds, 0, "snapshot: nil now/start → 0 uptime")

io.write(string.format("\nedge_stats_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
