-- edge_stats — periodic aggregate stats dump to stdout (push, not expose).
--
-- Replaces the deleted /metrics pull endpoint (Phase 1 edge mgmt-plane cleanup).
-- The counters that have NO other window once /metrics is gone are the ones that
-- bypass the per-request BAC_LOG stream:
--   * edge_nontenant_dropped_total — the HTTP 444 fires before access_by_lua, so
--     no BAC_LOG record is written for the dropped request.
--   * edge_sni_rejected_total — the TLS reject happens in the handshake, before
--     there is any HTTP request to log.
--   * cache hit/miss ratio, fp_unique, blocklist_entries — gauges that only ever
--     lived in the `metrics` shared dict, never in BAC_LOG.
-- A worker-0 timer reads them every `interval` seconds and writes ONE
--   EDGE_STATS {json}
-- line to stdout. promtail (which already tails the container stdout and ships
-- `BAC_LOG` lines to Loki) is extended to also capture the `EDGE_STATS` prefix
-- under a `kind="edge_stats"` label. This is AGGREGATE (one line per interval,
-- not per request), so it adds no per-request log I/O and is safe under a flood.
--
-- NOT dumped here: the per-rule / per-flag / per-tag / staging shared-dict
-- counters (`rule:*`, `flag:*`, `tag:*`, `staging:*`). Those are per-request and
-- fully reconstructable from BAC_LOG in Loki (log_event.lua emits stage/verdict/
-- rule on every record), so they need no separate exporter.

local _M = { interval = 30 }

-- Curated scalar snapshot keys (see module header for why exactly these).
local KEYS = {
    "edge_nontenant_dropped_total",
    "edge_sni_rejected_total",
    "requests_total",
    "verdict_pass_total",
    "verdict_block_total",
    "verdict_challenge_total",
    "verdict_allow_total",
    "cache_hit_total",
    "cache_miss_total",
    "fp_unique",
    "blocklist_entries",
    -- BAC_LOG shipper health (was /metrics antibot_bac_log_*). shipper_loaded==0
    -- is the silent-shipper-down alert; ship_failed/dropped show backpressure.
    "bac_log_enqueued_total",
    "bac_log_shipped_total",
    "bac_log_ship_failed_total",
    "bac_log_dropped_overflow_total",
    "bac_log_dropped_disabled_total",
    "bac_log_shipper_loaded",
}

-- pure: RFC3339 UTC second-precision timestamp for `epoch` seconds. promtail's
-- timestamp stage parses this with RFC3339Nano (variable fractional digits, so a
-- second-precision value is accepted). No ngx dep → unit-testable.
function _M.iso8601(epoch)
    return os.date("!%Y-%m-%dT%H:%M:%S", math.floor(epoch or 0)) .. "Z"
end

-- pure: build the snapshot table. `get(key)` returns the counter value or nil.
-- `now`/`start_time` are epoch seconds (uptime gauge). `edge_id` stamps the
-- record so Loki can split per-edge. Dependencies injected for unit tests.
function _M.snapshot(get, now, start_time, edge_id)
    local s = { type = "edge_stats", edge_id = edge_id or "" }
    for _, k in ipairs(KEYS) do
        s[k] = get(k) or 0
    end
    local total = s.cache_hit_total + s.cache_miss_total
    s.cache_hit_ratio = total > 0 and (s.cache_hit_total / total) or 0
    s.uptime_seconds = (now and start_time) and (now - start_time) or 0
    s.timestamp = _M.iso8601(now)
    return s
end

-- emit one EDGE_STATS line to stdout. Reads ngx.shared.metrics; pcall-guarded by
-- the timer wrapper in start(). Mirrors bac_log.lua's stdout contract: write the
-- prefix + JSON + newline straight to stdout (not via ngx.log, which would wrap
-- the line in nginx's error-log formatting and break the promtail regex).
-- read the deployed git sha: prefer the live .revision file (scripts/update.sh
-- writes it after a hot reload, so it survives reloads that froze REVISION at
-- container start), fall back to the REVISION env, then "unknown". Mirrors what
-- the removed /__version handler did.
local function revision()
    local f = io.open("/etc/nginx/lua/.revision", "r")
    if f then
        local rev = f:read("*l")
        f:close()
        if rev and rev ~= "" then return rev end
    end
    return os.getenv("REVISION") or "unknown"
end

-- collect() — assemble the full stats table (counters + deploy metadata +
-- Channel C staleness). The single source of truth used by BOTH emit() (push to
-- stdout → Loki) and the private /__stats handler (pull, for the B13 integration
-- tests + operator debugging on the :9090 mgmt plane). Reads ngx.shared.metrics;
-- returns nil if that dict is unavailable.
function _M.collect()
    local m = ngx.shared.metrics
    if not m then return nil end
    local snap = _M.snapshot(
        function(k) return m:get(k) end,
        ngx.now(),
        m:get("start_time"),
        os.getenv("EDGE_ID") or "stand-bac")

    -- Deploy metadata that used to live behind /__version (removed Phase 1):
    -- folded in so operators verify "what's deployed / did the secret rotation
    -- take / cascade version" from Loki (or /__stats) instead of an HTTP
    -- endpoint. pcall-guarded — a load hiccup must not stop the dump.
    snap.commit = revision()
    local ok_cv, cv = pcall(function() return require("challenge").template_version() end)
    snap.cascade_version = ok_cv and cv or nil
    local ok_fp, fp = pcall(function() return require("challenge_secret").fingerprint() end)
    snap.challenge_secret_fp = ok_fp and fp or nil

    -- Channel C liveness (was /metrics antibot_edge_catalog_staleness_seconds):
    -- seconds since the last successful backend contact per catalog, -1 if never.
    -- The alert signal for a dead pull channel; promtail drops nginx error.log
    -- lines (only BAC_LOG/EDGE_STATS prefixes survive), so without this the
    -- staleness WARNs would never reach Loki. pcall-guarded.
    local ok_st, stale = pcall(function()
        local cp = require "catalog_pull"
        local now = ngx.time()
        local out = {}
        for name in pairs(cp.catalogs or {}) do
            -- catalog_pull stamps `catalog_last_pull_ts:<name>` (ngx.time epoch
            -- seconds) into the metrics dict on every successful 200/304.
            local ts = m:get("catalog_last_pull_ts:" .. name)
            out[name] = ts and (now - ts) or -1
        end
        return out
    end)
    snap.catalog_staleness_seconds = ok_st and stale or nil

    return snap
end

function _M.emit()
    local snap = _M.collect()
    if not snap then return end
    local line = require("cjson.safe").encode(snap)
    if not line then return end
    io.stdout:write("EDGE_STATS ", line, "\n")
    io.stdout:flush()
end

-- start(opts) — register the worker-0 emit timer. opts.interval overrides the
-- 30s default. Guarded to worker 0 so an N-worker pool emits a single line per
-- interval (the metrics dict is shared, so any worker sees the global totals).
-- Call from init_worker_by_lua_block.
function _M.start(opts)
    opts = opts or {}
    local interval = tonumber(opts.interval) or _M.interval
    if ngx.worker.id() ~= 0 then return end
    local ok, err = ngx.timer.every(interval, function()
        local pok, perr = pcall(_M.emit)
        if not pok then
            ngx.log(ngx.ERR, "edge_stats: emit failed: ", tostring(perr))
        end
    end)
    if not ok then
        ngx.log(ngx.ERR, "edge_stats: timer.every failed: ", tostring(err))
    end
end

return _M
