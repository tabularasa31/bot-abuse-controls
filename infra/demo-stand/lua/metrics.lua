-- /metrics handler. Emits Prometheus text-format counters drawn from
-- the metrics shared_dict (incremented by log_event.lua). Output is
-- scrape-friendly; a real Prometheus can poll this endpoint directly.
--
-- For a production deployment we'd replace this with lua-resty-prometheus
-- (cascade task В3) which has proper histograms etc. This implementation
-- is intentionally simple — a few counters plus a derived gauge — so a
-- reviewer can read it and understand what's being measured.

local fp_state    = require "tls_fp_blocklist_state"
local catalog_pull = require "catalog_pull"

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

# HELP antibot_tls_fp_blocklist_gen Current tls_fp blocklist catalog generation (0 = static seed; bumped by the §В1 catalog pull).
# TYPE antibot_tls_fp_blocklist_gen gauge
antibot_tls_fp_blocklist_gen %d

# HELP antibot_tls_fp_catalog_gen Current tls_fp_catalog generation (0 = init seed; bumped on each successful Channel C pull). PR-62.
# TYPE antibot_tls_fp_catalog_gen gauge
antibot_tls_fp_catalog_gen %d

# HELP antibot_tls_fp_browser_profiles_gen Current tls_fp_browser_profiles generation (0 = init seed; bumped on each successful Channel C pull). PR-62.
# TYPE antibot_tls_fp_browser_profiles_gen gauge
antibot_tls_fp_browser_profiles_gen %d

# HELP antibot_uptime_seconds Seconds since this worker started.
# TYPE antibot_uptime_seconds gauge
antibot_uptime_seconds %d

# HELP antibot_fp_unique Distinct TLS fingerprints seen since worker start.
# TYPE antibot_fp_unique gauge
antibot_fp_unique %d

# HELP antibot_clearance_verify_total L2.1 clearance cookie verify outcomes (C3). valid = HMAC ok + matching site + not expired (fastpath fired, L3/L5 skipped). invalid = HMAC mismatch or compute failure. expired = HMAC ok but exp <= now (checked before wrong_site so apex-Domain scoped cookies don't false-alarm as cross-tenant). missing = no cookie header. malformed = cookie structure unparseable. wrong_site = HMAC ok + not expired but cookie's bound site != request host (cross-tenant leak attempt). no_secret = operational — challenge_secret not loaded (C1 file missing/truncated after reload); kept distinct from invalid so a secret-outage spike is not masked by an attack-shaped invalid spike. NB the six (or seven, with no_secret) counters do NOT sum to requests_total under mode=active: hygiene/reputation policy.enforce(403) early-exits some requests BEFORE clearance.verify runs.
# TYPE antibot_clearance_verify_total counter
antibot_clearance_verify_total{result="valid"} %d
antibot_clearance_verify_total{result="invalid"} %d
antibot_clearance_verify_total{result="expired"} %d
antibot_clearance_verify_total{result="missing"} %d
antibot_clearance_verify_total{result="malformed"} %d
antibot_clearance_verify_total{result="wrong_site"} %d
antibot_clearance_verify_total{result="no_secret"} %d
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
    ngx.shared.meta:get(fp_state.META_GEN_KEY) or 0,
    ngx.shared.meta:get("tls_fp_catalog_gen") or 0,
    ngx.shared.meta:get("tls_fp_browser_profiles_gen") or 0,
    uptime,
    get("fp_unique"),
    get("clearance_verify_valid_total"),
    get("clearance_verify_invalid_total"),
    get("clearance_verify_expired_total"),
    get("clearance_verify_missing_total"),
    get("clearance_verify_malformed_total"),
    get("clearance_verify_wrong_site_total"),
    get("clearance_verify_no_secret_total")))

-- Per-rule / per-flag / per-tag counters live in the metrics dict under
-- "rule:<stage>:<rule>", "flag:<flag>" and "tag:<tag>" keys (written by
-- log_event.lua). Emit them as labelled counters. Cheap here because the
-- rule/flag/tag code-spaces are tiny. One get_keys pass classifies all
-- prefixes (rule/flag/tag/staging/catalog_last_pull_ts/
-- edge_sidecar_version_mismatch_total) so we hit the dict lock once.
local rule_lines = { "# HELP antibot_rule_total Times each rule fired, by stage.",
                     "# TYPE antibot_rule_total counter" }
local flag_lines = { "# HELP antibot_flag_total Times each soft challenge flag accumulated.",
                     "# TYPE antibot_flag_total counter" }
local tag_lines  = { "# HELP antibot_tag_total Times each informational tag was attached.",
                     "# TYPE antibot_tag_total counter" }
local stg_lines  = { "# HELP antibot_staging_match_total Times each staged pattern matched (observe-only, feeds the staging→active promotion workflow).",
                     "# TYPE antibot_staging_match_total counter" }
local pulled_ts  = {}   -- catalog → last pull ts (or nil if never)
local vmis       = {}   -- catalog → version-mismatch count
for _, key in ipairs(m:get_keys(0)) do
    local stage, rule = key:match("^rule:([^:]+):(.+)$")
    if stage then
        rule_lines[#rule_lines + 1] = string.format(
            'antibot_rule_total{stage="%s",rule="%s"} %d', stage, rule, get(key))
    end
    local flag = key:match("^flag:(.+)$")
    if flag then
        flag_lines[#flag_lines + 1] = string.format(
            'antibot_flag_total{flag="%s"} %d', flag, get(key))
    end
    local tag = key:match("^tag:(.+)$")
    if tag then
        tag_lines[#tag_lines + 1] = string.format(
            'antibot_tag_total{tag="%s"} %d', tag, get(key))
    end
    -- "staging:<catalog>:<pattern_id>" — the pattern label keeps both halves.
    -- Unlike rule/flag/tag codes (internal constants), a pattern_id can be a
    -- free-form config token (a tls_fp_blocklist fp), so escape per the
    -- Prometheus text format — an unescaped " / \ / newline would make the
    -- whole /metrics output unparseable and break scraping for the target.
    local pattern = key:match("^staging:(.+)$")
    if pattern then
        local label = pattern:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n")
        stg_lines[#stg_lines + 1] = string.format(
            'antibot_staging_match_total{pattern="%s"} %d', label, get(key))
    end
    local pulled = key:match("^catalog_last_pull_ts:(.+)$")
    if pulled then pulled_ts[pulled] = m:get(key) end
    local vcat = key:match("^edge_sidecar_version_mismatch_total:(.+)$")
    if vcat then vmis[vcat] = get(key) end
end
ngx.say(table.concat(rule_lines, "\n"))
ngx.say(table.concat(flag_lines, "\n"))
ngx.say(table.concat(tag_lines, "\n"))
ngx.say(table.concat(stg_lines, "\n"))

-- Channel C catalog staleness (B5, RFC §В1 "edge_catalog_staleness_seconds").
-- catalog_pull.handle_response stamps `catalog_last_pull_ts:<name>` on every
-- successful contact with antibot-backend — both 200 (new data) and 304
-- (ETag matches, no new data, channel still healthy). This gauge is
-- now - that timestamp. We iterate over the KNOWN catalog list
-- (catalog_pull.catalogs) rather than over keys that exist in the dict, so a
-- catalog that has never been pulled still gets a -1 series — dashboards
-- distinguish "never pulled" from "metric missing" (codex review).
--
-- Semantics: this is a LIVENESS gauge ("seconds since last contact with
-- backend"), not a freshness gauge ("seconds since data last changed").
-- The alert condition from config-distribution §Channel C and B6 ("≤30s
-- fast / ≤15m PR catalogs") fires only when backend stops answering — not
-- when the catalog payload has been the same for a week (the steady state
-- for PR-merged lists). If we ever need "data age" separately, that's a
-- different metric (e.g. age of the ETag), not this one.
local stale_lines = { "# HELP antibot_edge_catalog_staleness_seconds Seconds since the last successful contact with antibot-backend (200 or 304); grows only when ticks fail (transport / non-200/304 / decode). -1 if no contact has succeeded since worker start.",
                      "# TYPE antibot_edge_catalog_staleness_seconds gauge" }
local vmis_lines  = { "# HELP antibot_edge_sidecar_version_mismatch_total Times a catalog response was rejected because X-Catalog-Version major disagreed with the edge's supported major.",
                      "# TYPE antibot_edge_sidecar_version_mismatch_total counter" }
for name in pairs(catalog_pull.catalogs) do
    local ts = pulled_ts[name]
    local age = ts and (now - ts) or -1
    stale_lines[#stale_lines + 1] = string.format(
        'antibot_edge_catalog_staleness_seconds{catalog="%s"} %d', name, age)
    vmis_lines[#vmis_lines + 1] = string.format(
        'antibot_edge_sidecar_version_mismatch_total{catalog="%s"} %d',
        name, vmis[name] or 0)
end
ngx.say(table.concat(stale_lines, "\n"))
ngx.say(table.concat(vmis_lines, "\n"))

-- BAC_LOG shipper (B6 edge-side, log_shipper.lua). Per-worker очередь
-- наполняется bac_log.emit'ом, фоновый таймер дренирует батчами на
-- antibot-backend /v1/logs. Дашборды смотрят на:
--   enqueued        — общий поток (≈ requests-через-каскад минус bypass);
--   dropped{reason="overflow"} — очередь полная, бэкенд не успевает
--                                (реальная нагрузка);
--   dropped{reason="disabled"} — shipper выключен (ANTIBOT_BACKEND_URL
--                                пустой) — config-issue, не нагрузка;
--   shipped         — успешно доставленные строки на backend;
--   ship_failed     — провальные POST'ы (батч теряется, потери ≈
--                     shipped - enqueued + sum(dropped) только при != 0);
--   batches_ok      — счётчик удачных батчей, для оценки пропускной
--                     способности (shipped / batches_ok ≈ avg батч);
--   shipper_loaded  — gauge 0/1: 0 если модуль не загрузился вовсе
--                     (syntax-bug / missing dep) — алерт на shipper_loaded==0
--                     ловит silent-failure, когда все остальные метрики
--                     на нуле и непонятно «нет трафика» это или «модуль
--                     никогда не стартовал».
ngx.say(string.format([[
# HELP antibot_bac_log_enqueued_total BAC_LOG lines added to the per-worker shipper queue.
# TYPE antibot_bac_log_enqueued_total counter
antibot_bac_log_enqueued_total %d

# HELP antibot_bac_log_dropped_total BAC_LOG lines dropped, by reason. overflow = queue full (backend can't keep up); disabled = ANTIBOT_BACKEND_URL unset (config issue, edge sees traffic but cannot ship).
# TYPE antibot_bac_log_dropped_total counter
antibot_bac_log_dropped_total{reason="overflow"} %d
antibot_bac_log_dropped_total{reason="disabled"} %d

# HELP antibot_bac_log_shipped_total BAC_LOG lines successfully POSTed to antibot-backend /v1/logs (202).
# TYPE antibot_bac_log_shipped_total counter
antibot_bac_log_shipped_total %d

# HELP antibot_bac_log_ship_failed_total Batches that failed to POST (transport error or non-202 response). Whole batch is lost (no retry; B9 disk-queue closes this gap).
# TYPE antibot_bac_log_ship_failed_total counter
antibot_bac_log_ship_failed_total %d

# HELP antibot_bac_log_batches_ok_total Successful batch POSTs. shipped/batches_ok ≈ average batch size.
# TYPE antibot_bac_log_batches_ok_total counter
antibot_bac_log_batches_ok_total %d

# HELP antibot_bac_log_shipper_loaded 1 if log_shipper.start() finished setup successfully (timer + http module + mTLS snapshot ready) OR was intentionally disabled by empty ANTIBOT_BACKEND_URL. 0 if start() bailed on an error path (resty.http missing, ngx.timer.every failed, or module never required at all). Alert on == 0 — это silent shipper-down, не intentional disabled.
# TYPE antibot_bac_log_shipper_loaded gauge
antibot_bac_log_shipper_loaded %d
]],
    get("bac_log_enqueued_total"),
    get("bac_log_dropped_overflow_total"),
    get("bac_log_dropped_disabled_total"),
    get("bac_log_shipped_total"),
    get("bac_log_ship_failed_total"),
    get("bac_log_batches_ok_total"),
    get("bac_log_shipper_loaded")))
