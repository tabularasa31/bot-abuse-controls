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
-- snapshot() now ENUMERATES a flat {key=value} map of the whole metrics dict
-- (collect() fills it via m:get_keys/m:get). Plain scalars go top-level; the
-- dynamic prefixed families are grouped; start_time / catalog_last_pull_ts:* are
-- internal and excluded.
local data = {
    edge_nontenant_dropped_total = 1200,
    edge_sni_rejected_total      = 34,
    requests_total               = 5000,
    verdict_block_total          = 42,
    cache_hit_total              = 90,
    cache_miss_total             = 10,
    fp_unique                    = 7,
    blocklist_entries            = 3,
    -- counter families a curated allowlist previously dropped (the fix — these
    -- must now appear in the snapshot):
    clearance_verify_wrong_site_total = 5,
    challenge_invalid_replay_total    = 9,
    ["edge_sidecar_version_mismatch_total:policy"] = 1,
    -- dynamic prefixed families → grouped into nested objects:
    ["rule:hygiene:ua_blacklist"]      = 11,
    ["flag:tls_fp_impersonator"]       = 2,
    ["tag:reputation:asn_dc"]          = 4,
    ["staging:ua_blacklist:badbot"]    = 6,
    -- internal → must NOT be dumped raw:
    start_time                         = 1700000000,
    ["catalog_last_pull_ts:policy"]    = 1700000900,
}

local s = edge_stats.snapshot(data, 1700001000, 1700000000, "edge-7")
eq(s.type, "edge_stats", "snapshot: type stamped")
eq(s.edge_id, "edge-7", "snapshot: edge_id stamped")
eq(s.edge_nontenant_dropped_total, 1200, "snapshot: drop counter passed through")
eq(s.edge_sni_rejected_total, 34, "snapshot: sni reject passed through")
eq(s.requests_total, 5000, "snapshot: requests passed through")
eq(s.verdict_pass_total, nil, "snapshot: absent scalar → absent (not forced to 0)")
-- the regression fix: enumerated families that the old KEYS allowlist dropped
eq(s.clearance_verify_wrong_site_total, 5, "snapshot: clearance counter now exported")
eq(s.challenge_invalid_replay_total, 9, "snapshot: challenge counter now exported")
eq(s.version_mismatch.policy, 1, "snapshot: version_mismatch grouped by catalog")
-- dynamic prefixed families grouped, label = remainder after the prefix
eq(s.rules["hygiene:ua_blacklist"], 11, "snapshot: rule:* grouped into rules{}")
eq(s.flags["tls_fp_impersonator"], 2, "snapshot: flag:* grouped into flags{}")
eq(s.tags["reputation:asn_dc"], 4, "snapshot: tag:* grouped into tags{}")
eq(s.staging["ua_blacklist:badbot"], 6, "snapshot: staging:* grouped into staging{}")
-- internal keys excluded
eq(s.start_time, nil, "snapshot: start_time not dumped raw")
eq(s["catalog_last_pull_ts:policy"], nil, "snapshot: catalog_last_pull_ts:* not dumped raw")
-- derived
eq(s.cache_hit_ratio, 0.9, "snapshot: cache ratio = hit/(hit+miss)")
eq(s.uptime_seconds, 1000, "snapshot: uptime = now - start_time")
eq(s.timestamp, "2023-11-14T22:30:00Z", "snapshot: timestamp = iso8601(now=1700001000)")

-- Empty / nil map → empty buckets, ratio 0 (no div-by-zero), no crash.
local z = edge_stats.snapshot(nil, 100, 100, nil)
eq(z.edge_id, "", "snapshot: nil edge_id → empty string")
eq(type(z.rules), "table", "snapshot: rules bucket present even when empty")
eq(next(z.rules), nil, "snapshot: rules bucket empty for empty map")
eq(z.cache_hit_ratio, 0, "snapshot: 0 hits+misses → ratio 0 (no div-by-zero)")
eq(z.uptime_seconds, 0, "snapshot: now==start_time → 0 uptime")

-- Missing now/start_time → uptime 0 (defensive).
local d = edge_stats.snapshot(data, nil, nil, "e")
eq(d.uptime_seconds, 0, "snapshot: nil now/start → 0 uptime")

io.write(string.format("\nedge_stats_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
