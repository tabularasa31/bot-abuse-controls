-- Demo-stand init. Loads blocklist, primes the metrics shared_dict
-- with the counter keys (so /metrics shows zero-valued counters from
-- the very first scrape rather than missing keys), records the start
-- time for /__version uptime calculation.

local blocklist = require "blocklist"

local fp_dict = ngx.shared.fp_blocklist
local n = 0
for fp, verdict in pairs(blocklist.entries) do
    local ok, err = fp_dict:set(fp, verdict)
    if ok then
        n = n + 1
    else
        ngx.log(ngx.ERR, "fp_blocklist:set failed: ", err)
    end
end
ngx.log(ngx.NOTICE, "[demo] fp_blocklist loaded: ", n, " entries")

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
}) do
    metrics:safe_add(key, 0)
end
metrics:set("start_time", ngx.time())
metrics:set("blocklist_entries", n)

if n == 0 then
    ngx.log(ngx.NOTICE, "[demo] mode: SHADOW (empty blocklist — nothing blocked)")
else
    ngx.log(ngx.NOTICE, "[demo] mode: ACTIVE blocking on ", n, " fp(s) (ngx.exit(403) on block)")
end
