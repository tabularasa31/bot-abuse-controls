-- /__admin status page. Renders a small HTML view of the same data
-- /metrics exposes, plus the actual blocklist contents. Read-only —
-- no mutation surface. Designed for a reviewer to eyeball "what is
-- this stand doing right now" without learning Prometheus query syntax.

local m = ngx.shared.metrics
local fp_dict = ngx.shared.fp_blocklist

local function get(key) return m:get(key) or 0 end

local requests = get("requests_total")
local passes   = get("verdict_pass_total")
local blocks   = get("verdict_block_total")
local hits     = get("cache_hit_total")
local misses   = get("cache_miss_total")
local hit_ratio = (hits + misses) > 0
    and string.format("%.1f%%", 100 * hits / (hits + misses))
    or "n/a"
local block_pct = requests > 0
    and string.format("%.2f%%", 100 * blocks / requests)
    or "0%"

local now = ngx.time()
local uptime_s = now - (m:get("start_time") or now)
local uptime_h = string.format("%dh %dm %ds",
    math.floor(uptime_s / 3600),
    math.floor(uptime_s / 60) % 60,
    uptime_s % 60)

-- HTML-escape values before injecting into the rendered page. Blocklist
-- entries today come from a static Lua table (trusted source), but the
-- catalog hot-reload (RFC §В1) will pull entries from the sidecar at
-- runtime — at that point an attacker-controlled fp string would be
-- rendered into HTML. Escape now so the demo doesn't become a footgun
-- the moment that pipeline lands.
local HTML_ESCAPE = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
                      ['"'] = "&quot;", ["'"] = "&#39;" }
local function html_escape(s)
    if not s then return "" end
    return (tostring(s):gsub("[&<>\"']", HTML_ESCAPE))
end

-- List blocklist entries (max 50 shown — anything more is unreadable
-- in HTML and the operator should query the shared_dict directly).
local keys = fp_dict:get_keys(50)
local rows = {}
for _, key in ipairs(keys) do
    rows[#rows + 1] = string.format(
        "<tr><td><code>%s</code></td><td>%s</td></tr>",
        html_escape(key), html_escape(fp_dict:get(key) or "?"))
end
local extra = #keys >= 50 and " (showing first 50)" or ""

ngx.header.content_type = "text/html; charset=utf-8"
ngx.say(string.format([[<!doctype html>
<html><head><meta charset="utf-8"><title>abuse-controls demo admin</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif; max-width: 800px;
       margin: 2em auto; padding: 0 1em; color: #222; line-height: 1.5; }
h1, h2 { margin-top: 1.5em; }
table { border-collapse: collapse; width: 100%%; margin: 0.5em 0; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid #eee;
         font-size: 14px; }
code { background: #f4f4f4; padding: 1px 4px; border-radius: 2px; font-size: 13px; }
.metric { display: inline-block; margin-right: 2em; }
.metric strong { font-size: 1.4em; }
hr { border: 0; border-top: 1px solid #eee; margin: 2em 0; }
.note { color: #666; font-size: 13px; }
</style></head><body>

<h1>abuse-controls demo stand</h1>
<p class="note">Active blocking; the verdict pipeline runs on every request.
Same code as production. See
<a href="https://github.com/tabularasa31/abuse-controls">repo</a> for sources
and decision records.</p>

<h2>Counters</h2>
<div class="metric"><strong>%d</strong><br>requests</div>
<div class="metric"><strong>%d</strong><br>passes</div>
<div class="metric"><strong>%d</strong><br>blocks (%s)</div>
<div class="metric"><strong>%s</strong><br>cache hit ratio</div>
<div class="metric"><strong>%s</strong><br>uptime</div>

<h2>Blocklist (%d entries%s)</h2>
<table><tr><th>fingerprint</th><th>verdict</th></tr>
%s
</table>

<h2>What to try</h2>
<ul>
  <li>Open <a href="/">/</a> in this browser — should be 200 (browser fp is not in the blocklist)</li>
  <li><code>curl -k https://&lt;this-host&gt;/</code> — should be 403 (curl fp is seeded)</li>
  <li>Hit <a href="/__fp">/__fp</a> from any client to see its fp</li>
  <li>Hit <a href="/metrics">/metrics</a> for Prometheus-scrape format</li>
  <li>Compare <code>wrk</code> against <a href="/">/</a> vs <a href="/baseline/">/baseline/</a>
      to measure the verdict pipeline overhead</li>
</ul>

</body></html>
]],
    requests, passes, blocks, block_pct, hit_ratio, uptime_h,
    #keys, extra, table.concat(rows, "\n")))
