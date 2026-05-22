-- /metrics handler. Emits Prometheus text-format counters drawn from
-- the metrics shared_dict (incremented by log_event.lua). Output is
-- scrape-friendly; a real Prometheus can poll this endpoint directly.
--
-- For a production deployment we'd replace this with lua-resty-prometheus
-- (cascade task В3) which has proper histograms etc. This implementation
-- is intentionally simple — a few counters plus a derived gauge — so a
-- reviewer can read it and understand what's being measured.

local m = ngx.shared.metrics

local function get(key) return m:get(key) or 0 end

local now = ngx.time()
local uptime = now - (m:get("start_time") or now)
local requests = get("requests_total")
local hits     = get("cache_hit_total")
local misses   = get("cache_miss_total")
local cache_hit_ratio = (hits + misses) > 0 and (hits / (hits + misses)) or 0

ngx.header.content_type = "text/plain; version=0.0.4; charset=utf-8"
ngx.say(string.format([[
# HELP antibot_requests_total Requests that went through the verdict pipeline.
# TYPE antibot_requests_total counter
antibot_requests_total %d

# HELP antibot_verdict_total Requests by verdict, since worker start.
# TYPE antibot_verdict_total counter
antibot_verdict_total{verdict="pass"} %d
antibot_verdict_total{verdict="block"} %d
antibot_verdict_total{verdict="challenge"} %d
antibot_verdict_total{verdict="allow"} %d

# HELP antibot_cache_total Cache hits vs misses on the per-fp verdict cache.
# TYPE antibot_cache_total counter
antibot_cache_total{outcome="hit"} %d
antibot_cache_total{outcome="miss"} %d

# HELP antibot_cache_hit_ratio Derived ratio = hits / (hits + misses).
# TYPE antibot_cache_hit_ratio gauge
antibot_cache_hit_ratio %.4f

# HELP antibot_blocklist_entries Number of fps currently in the blocklist shared_dict.
# TYPE antibot_blocklist_entries gauge
antibot_blocklist_entries %d

# HELP antibot_fp_blocklist_gen Current tls_fp blocklist catalog generation (0 = static seed; bumped by the §В1 catalog pull).
# TYPE antibot_fp_blocklist_gen gauge
antibot_fp_blocklist_gen %d

# HELP antibot_uptime_seconds Seconds since this worker started.
# TYPE antibot_uptime_seconds gauge
antibot_uptime_seconds %d

# HELP antibot_fp_unique Distinct TLS fingerprints seen since worker start.
# TYPE antibot_fp_unique gauge
antibot_fp_unique %d
]],
    requests,
    get("verdict_pass_total"),
    get("verdict_block_total"),
    get("verdict_challenge_total"),
    get("verdict_allow_total"),
    hits,
    misses,
    cache_hit_ratio,
    get("blocklist_entries"),
    ngx.shared.meta:get("fp_blocklist_gen") or 0,
    uptime,
    get("fp_unique")))

-- Per-rule counters live in the metrics dict under "rule:<stage>:<rule>"
-- keys (written by log_event.lua). Emit them as a labelled counter. Cheap
-- here because the rule code-space is tiny.
local lines = { "# HELP antibot_rule_total Times each rule fired, by stage.",
                "# TYPE antibot_rule_total counter" }
for _, key in ipairs(m:get_keys(0)) do
    local stage, rule = key:match("^rule:([^:]+):(.+)$")
    if stage then
        lines[#lines + 1] = string.format(
            'antibot_rule_total{stage="%s",rule="%s"} %d', stage, rule, get(key))
    end
end
ngx.say(table.concat(lines, "\n"))
