-- Demo-stand init (init_by_lua). Loads the cascade config files, seeds the
-- fp_blocklist shared_dict from tls_fp_blocklist.conf, primes the metrics
-- shared_dict with zero-valued counter keys (so /metrics shows them from the
-- very first scrape), and records the start time for /__version uptime.
--
-- The fp_blocklist dict is the one config the request path consumes today
-- (verdict.lua). The other catalogs (ip/ua/asn lists, tls_fp catalog/
-- profiles, defaults) are parsed and held on the `config` module for the
-- cascade-rule tasks that will read them — they are not wired into a
-- verdict here (rules are out of scope for the A3 config-files task).

local config = require "config"
config.load()

-- Compile the L1 hygiene stage (method whitelist + ua_blacklist combined
-- regex) from the loaded config. Done here in the master so every worker
-- inherits the compiled state on fork — see hygiene.lua.
require("hygiene").build(config)

-- Compile the L2 reputation stage (ip_whitelist / ip_blocklist CIDR matchers)
-- from the loaded config — also in the master so workers inherit the matchers
-- on fork (see reputation.lua). Returns the active entry counts for the
-- startup log below.
local reputation, rep_wl, rep_bl = require("reputation").build(config)

-- Compile the L4 rate_limits stage (GCRA profiles from defaults.conf
-- [blocking.rate_*] thresholds) — also in the master so workers inherit the
-- profile list on fork (see rate_limit.lua; the shared dict holds only per-key
-- TAT state). Returns the active profile count for the startup log.
local _, rate_n = require("rate_limit").build(config)

-- Open the GeoLite2 databases (country + asn) once in the master so workers
-- inherit the handles on fork. Fail-open: if the license-gated .mmdb files (or
-- libmaxminddb) are absent the stand still starts and geo is simply
-- undetermined — geoip.init() logs the reason. Feeds the reputation:asn_dc tag
-- and the geo_country/asn log fields (A6).
require("geoip").init()

-- Seed the fp_blocklist shared_dict from tls_fp_blocklist.conf. Entries are
-- active unless explicitly status=staging (staging matches-but-doesn't-block;
-- the staging path lands with its own task). An empty file => SHADOW mode.
local fp_dict = ngx.shared.fp_blocklist
local n = 0
for _, entry in ipairs(config.tls_fp_blocklist) do
    if entry.attrs.status ~= "staging" then
        local ok, err = fp_dict:set(entry.value, "block")
        if ok then
            n = n + 1
        else
            ngx.log(ngx.ERR, "fp_blocklist:set failed: ", err)
        end
    end
end

-- One line per catalog so a reviewer can confirm at start that every config
-- loaded (acceptance: "Lua успешно подгружает все конфиги").
ngx.log(ngx.NOTICE, "[demo] configs loaded from ", config.dir, ": ",
    "tls_fp_blocklist=", #config.tls_fp_blocklist,
    " ip_blocklist=", #config.blocklist_ip,
    " ip_whitelist=", #config.whitelist_ip,
    " ua_blacklist=", #config.ua_blacklist,
    " asn_datacenters=", #config.asn_datacenters)
-- Marker text is a contract: scripts/analyze.py INIT_RE parses the
-- blocklist size out of "[demo] fp_blocklist loaded: N". Do not reword
-- without updating that regex, or daily reports mislabel the stand SHADOW.
ngx.log(ngx.NOTICE, "[demo] fp_blocklist loaded: ", n, " active entries")
-- Reputation matchers: active (non-staging) entry counts compiled into the
-- ipmatcher objects. Empty whitelist/blocklist => that check is a no-op.
local asn_dc_n = 0
for _ in pairs(reputation.asn_dc_set) do asn_dc_n = asn_dc_n + 1 end
ngx.log(ngx.NOTICE, "[demo] reputation matchers: ip_whitelist=", rep_wl,
    " active, ip_blocklist=", rep_bl, " active, asn_dc=", asn_dc_n,
    " (geo_blocklist dormant — per-resource policy source is Phase 3)")
ngx.log(ngx.NOTICE, "[demo] rate_limits profiles: ", rate_n,
    " active (observe-only — verdict logged, no 429/delay in Phase 1)")

-- Prime metrics counters so they're visible at zero rather than absent.
local metrics = ngx.shared.metrics
for _, key in ipairs({
    "requests_total",
    "verdict_pass_total",
    "verdict_block_total",
    "verdict_challenge_total",
    "verdict_allow_total",
    "cache_hit_total",
    "cache_miss_total",
    "fp_unique",
}) do
    metrics:safe_add(key, 0)
end
metrics:set("start_time", ngx.time())
metrics:set("blocklist_entries", n)

if n == 0 then
    ngx.log(ngx.NOTICE, "[demo] mode: SHADOW (empty fp blocklist — nothing blocked)")
else
    ngx.log(ngx.NOTICE, "[demo] mode: ACTIVE blocking on ", n, " fp(s) (ngx.exit(403) on block)")
end
