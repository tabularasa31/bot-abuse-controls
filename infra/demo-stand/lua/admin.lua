-- /__admin status page. Read-only HTML view of what the stand is doing
-- right now: counters, the rules that have fired, a live ring buffer of
-- recent requests, and the blocklist contents. No mutation surface. Lets a
-- reviewer eyeball the pipeline without learning Prometheus query syntax.

local recent   = require "recent"
local fp_state = require "fp_blocklist_state"
local m        = ngx.shared.metrics
local fp_dict  = ngx.shared.fp_blocklist

local function get(key) return m:get(key) or 0 end

local requests   = get("requests_total")
local passes     = get("verdict_pass_total")
local blocks     = get("verdict_block_total")
local challenges = get("verdict_challenge_total")
local allows     = get("verdict_allow_total")
local hits       = get("cache_hit_total")
local misses     = get("cache_miss_total")
local fp_unique  = get("fp_unique")

local hit_ratio = (hits + misses) > 0
    and string.format("%.1f%%", 100 * hits / (hits + misses)) or "n/a"
local block_pct = requests > 0
    and string.format("%.2f%%", 100 * blocks / requests) or "0%"

-- Blocklist keys are `fp .. ":" .. gen`; keep only the current generation and
-- show bare fingerprints (fp_state.match strips the suffix).
local cur_gen = ngx.shared.meta:get(fp_state.META_GEN_KEY) or 0
local blocklist_keys = {}
for _, key in ipairs(fp_dict:get_keys(50)) do
    local fp = fp_state.match(key, cur_gen)
    if fp then
        blocklist_keys[#blocklist_keys + 1] = fp
    end
end
local blocklist_n    = #blocklist_keys
local mode    = blocklist_n > 0 and "ACTIVE" or "SHADOW"
local edge_id = os.getenv("EDGE_ID") or "stand-bac"

local now = ngx.time()
local uptime_s = now - (m:get("start_time") or now)
local uptime_h = string.format("%dh %dm %ds",
    math.floor(uptime_s / 3600), math.floor(uptime_s / 60) % 60, uptime_s % 60)

local HTML_ESCAPE = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
                      ['"'] = "&quot;", ["'"] = "&#39;" }
local function esc(s)
    if s == nil then return "" end
    return (tostring(s):gsub("[&<>\"']", HTML_ESCAPE))
end

-- Rules fired (parsed from "rule:<stage>:<rule>" keys in the metrics dict).
local rules = {}
for _, key in ipairs(m:get_keys(0)) do
    local stage, rule = key:match("^rule:([^:]+):(.+)$")
    if stage then rules[#rules + 1] = { stage = stage, rule = rule, n = get(key) } end
end
table.sort(rules, function(a, b) return a.n > b.n end)

local buf = {}
local function add(s) buf[#buf + 1] = s end

add([[<!doctype html>
<html><head><meta charset="utf-8"><title>abuse-controls demo admin</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif; max-width: 960px;
       margin: 2em auto; padding: 0 1em; color: #222; line-height: 1.5; }
h1, h2 { margin-top: 1.5em; }
table { border-collapse: collapse; width: 100%; margin: 0.5em 0; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid #eee;
         font-size: 13px; vertical-align: top; }
code { background: #f4f4f4; padding: 1px 4px; border-radius: 2px; font-size: 12px; }
.metric { display: inline-block; margin-right: 2em; }
.metric strong { font-size: 1.4em; }
.shadow { color: #2e7d32; font-weight: 700; }
.active { color: #c62828; font-weight: 700; }
.v-block { color: #c62828; } .v-pass { color: #2e7d32; }
.v-challenge { color: #e65100; } .v-allow { color: #1565c0; }
.note { color: #666; font-size: 13px; }
.empty { color: #888; font-style: italic; }
hr { border: 0; border-top: 1px solid #eee; margin: 2em 0; }
</style></head><body>

<h1>abuse-controls demo stand</h1>
<p class="note">Mode: <span class="]] .. (mode == "ACTIVE" and "active" or "shadow") .. [[">]] .. mode .. [[</span>
&middot; edge_id <code>]] .. esc(edge_id) .. [[</code>.
]] .. (mode == "SHADOW"
    and "The verdict pipeline runs on every request and logs a verdict, but the blocklist is empty so nothing is blocked (200 for everyone)."
    or  ("Blocking is active on " .. blocklist_n .. " fingerprint(s) — matching clients get 403.")) .. [[
Same pipeline as production. <a href="https://github.com/tabularasa31/abuse-controls">repo</a>.</p>

<h2>Counters</h2>
]])
add('<div class="metric"><strong>' .. requests .. '</strong><br>requests</div>')
add('<div class="metric"><strong>' .. passes .. '</strong><br>pass</div>')
add('<div class="metric"><strong>' .. blocks .. '</strong><br>block (' .. block_pct .. ')</div>')
add('<div class="metric"><strong>' .. challenges .. '</strong><br>challenge</div>')
add('<div class="metric"><strong>' .. allows .. '</strong><br>allow</div>')
add('<div class="metric"><strong>' .. fp_unique .. '</strong><br>unique fp</div>')
add('<div class="metric"><strong>' .. hit_ratio .. '</strong><br>cache hit ratio</div>')
add('<div class="metric"><strong>' .. esc(uptime_h) .. '</strong><br>uptime</div>')

-- Rules fired
add("<h2>Rules fired</h2>")
if #rules == 0 then
    add('<p class="empty">No rule has fired yet.</p>')
else
    add("<table><tr><th>stage</th><th>rule</th><th>count</th></tr>")
    for _, r in ipairs(rules) do
        add("<tr><td>" .. esc(r.stage) .. "</td><td><code>" .. esc(r.rule)
            .. "</code></td><td>" .. r.n .. "</td></tr>")
    end
    add("</table>")
end

-- Recent requests (live ring buffer)
local recs = recent.snapshot(20)
add("<h2>Recent requests (last " .. #recs .. ")</h2>")
if #recs == 0 then
    add('<p class="empty">No requests through the pipeline yet.</p>')
else
    add("<table><tr><th>time</th><th>verdict</th><th>rule</th><th>fp</th>"
        .. "<th>ip</th><th>status</th><th>ua</th></tr>")
    for _, e in ipairs(recs) do
        local t = e.t and os.date("!%H:%M:%S", e.t) or "?"
        local ua = e.ua or ""
        if #ua > 48 then ua = ua:sub(1, 48) .. "…" end
        add("<tr><td>" .. esc(t) .. "</td>"
            .. '<td class="v-' .. esc(e.verdict) .. '">' .. esc(e.verdict) .. "</td>"
            .. "<td><code>" .. esc(e.rule or "") .. "</code></td>"
            .. "<td><code>" .. esc(e.fp or "") .. "</code></td>"
            .. "<td>" .. esc(e.ip) .. "</td>"
            .. "<td>" .. esc(e.status) .. "</td>"
            .. "<td>" .. esc(ua) .. "</td></tr>")
    end
    add("</table>")
    add('<p class="note">In-memory ring buffer, newest first; survives no restart. Bypass endpoints (/__fp, /__health, …) are not recorded.</p>')
end

-- Blocklist
local extra = blocklist_n >= 50 and " (showing first 50)" or ""
add("<h2>Blocklist (" .. blocklist_n .. " entries" .. extra .. ")</h2>")
if blocklist_n == 0 then
    add('<p class="empty">Empty — shadow mode. Seed fps to enable blocking.</p>')
else
    add("<table><tr><th>fingerprint</th><th>verdict</th></tr>")
    for _, key in ipairs(blocklist_keys) do
        add("<tr><td><code>" .. esc(key) .. "</code></td><td>"
            .. esc(fp_dict:get(key) or "?") .. "</td></tr>")
    end
    add("</table>")
end

-- What to try
add("<h2>What to try</h2><ul>")
add('<li>Open <a href="/">/</a> in a browser — 200 (browser fp is not blocked).</li>')
if mode == "SHADOW" then
    add('<li><code>curl -k https://&lt;this-host&gt;/</code> — 200 too (shadow: nothing is blocked); the fp is computed and logged. To enable blocking, seed fps into <code>lua/blocklist.lua</code>.</li>')
else
    add('<li><code>curl -k https://&lt;this-host&gt;/</code> — 403 if its fp is in the blocklist above.</li>')
end
add('<li>Hit <a href="/__fp">/__fp</a> from any client to see its fp.</li>')
add('<li>Hit <a href="/metrics">/metrics</a> for Prometheus-scrape format.</li>')
add('<li>Compare <code>wrk</code> against <a href="/">/</a> vs <a href="/baseline/">/baseline/</a> to measure pipeline overhead.</li>')
add("</ul></body></html>")

ngx.header.content_type = "text/html; charset=utf-8"
ngx.say(table.concat(buf))
