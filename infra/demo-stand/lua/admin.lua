-- /__admin status page. HTML view of what the stand is doing right now:
-- counters, the rules that have fired, a live ring buffer of recent
-- requests, and the blocklist contents. Lets a reviewer eyeball the
-- pipeline without learning Prometheus query syntax.
--
-- Mutation: ONE button per blocked-request row — «add IP to per-resource
-- ip_whitelist» (C6, false-positive recovery loop, vision §5.2). On the
-- real product the same operation is done from the client's dashboard;
-- /__admin stands in as that dashboard for the demo. The button POSTs to
-- /__admin/recover_ip (recovery.lua), which proxies into backend Policy
-- API (B10). Nothing else here mutates.

local recent   = require "recent"
local fp_state = require "tls_fp_blocklist_state"
local m        = ngx.shared.metrics
local fp_dict  = ngx.shared.tls_fp_blocklist

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

-- Blocklist keys are `fp .. ":" .. gen`; keep only the current generation,
-- holding the bare fp for display and its verdict (looked up by the full key,
-- not the stripped one). get_keys(0) returns every key — fine for the stand's
-- small blocklist — so a generation swap in flight can't truncate the current
-- set to an arbitrary 50.
local cur_gen = ngx.shared.meta:get(fp_state.META_GEN_KEY) or 0
local blocklist = {}
for _, key in ipairs(fp_dict:get_keys(0)) do
    local fp = fp_state.match(key, cur_gen)
    if fp then
        blocklist[#blocklist + 1] = { fp = fp, verdict = fp_dict:get(key) or "?" }
    end
end
local blocklist_n    = #blocklist
local mode    = blocklist_n > 0 and "ACTIVE" or "SHADOW"
local edge_id = os.getenv("EDGE_ID") or "stand-bac"

-- [C1] Phase 4 HMAC secret fingerprint (challenge_secret.lua). Surfaced
-- read-only so a reviewer can confirm a rotation reload landed; the secret
-- itself never leaves init_by_lua memory.
local challenge_secret_fp = require("challenge_secret").fingerprint()

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
Same pipeline as production. <a href="https://github.com/tabularasa31/abuse-controls">repo</a>.<br>
Challenge HMAC secret: ]] .. (challenge_secret_fp
    and ('<code>loaded</code> (fp=<code>' .. esc(challenge_secret_fp) .. '</code>)')
    or '<code>not configured</code> <span class="note">(Phase 4 file mount; see README)</span>') .. [[</p>

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

-- Blocked requests — C6 recovery widget. Filters the same recent-ring as
-- the live view below, but only verdict=block and only rules where a
-- per-resource IP whitelist actually fixes the FP (L5 Branch B/C, plus
-- L2/L3 IP/fp blocks where whitelisting the source is the right escape).
-- Rules like rate_* or ua_blacklist hit on UA — whitelisting the IP also
-- unsticks them at L2.3 (per-resource ip_whitelist fastpasses before
-- rate_limit/tls_fp run), so we show those too. The button is the only
-- mutation surface on /__admin; everything else is read-only.
local all_recs = recent.snapshot(50)
local blocked_recs = {}
for _, e in ipairs(all_recs) do
    if e.verdict == "block" then blocked_recs[#blocked_recs + 1] = e end
end
add('<h2>Blocked requests — recovery (last ' .. #blocked_recs .. ')</h2>')
add('<p class="note">Demo: this widget stands in for the client dashboard. ' ..
    '«Whitelist IP» adds the client IP to the per-resource <code>ip_whitelist</code> ' ..
    'via the same backend Policy API the real dashboard calls (B10). ' ..
    'Propagation SLA ≤ 30s (vision §5.2): backend reloader ≤ 5s + edge ' ..
    '<code>catalog_pull</code> ≤ 30s; next request from that IP fastpasses on ' ..
    'L2.3 (<code>rule=ip_whitelist</code>) and never reaches L5.</p>')
if #blocked_recs == 0 then
    add('<p class="empty">No blocked requests in the buffer.</p>')
else
    add('<table id="recovery-table"><tr><th>time</th><th>host</th><th>rule</th>' ..
        '<th>ip</th><th>ua</th><th>flags</th><th>action</th></tr>')
    for i, e in ipairs(blocked_recs) do
        local t = e.t and os.date("!%H:%M:%S", e.t) or "?"
        local ua = e.ua or ""
        if #ua > 40 then ua = ua:sub(1, 40) .. "…" end
        local flags = ""
        if type(e.flags) == "table" then
            flags = table.concat(e.flags, ",")
            if #flags > 64 then flags = flags:sub(1, 64) .. "…" end
        end
        local host = e.host or ""
        local ip = e.ip or ""
        local row_id = "rec-" .. tostring(i)
        add('<tr id="' .. row_id .. '">' ..
            '<td>' .. esc(t) .. '</td>' ..
            '<td>' .. esc(host) .. '</td>' ..
            '<td><code>' .. esc(e.rule or "") .. '</code></td>' ..
            '<td><code>' .. esc(ip) .. '</code></td>' ..
            '<td>' .. esc(ua) .. '</td>' ..
            '<td><code>' .. esc(flags) .. '</code></td>' ..
            '<td>')
        if host ~= "" and ip ~= "" then
            add('<button type="button" class="rcv-btn" ' ..
                'data-host="' .. esc(host) .. '" ' ..
                'data-ip="' .. esc(ip) .. '" ' ..
                'data-row="' .. row_id .. '">Whitelist IP</button>')
        else
            add('<span class="empty">missing host/ip</span>')
        end
        add('</td></tr>')
    end
    add('</table>')
    -- Inline JS: tiny fetch + status pill, no external deps. The endpoint
    -- echoes {ok,host,cidr,changed,propagation_seconds}; we display it via
    -- textContent / createElement (not innerHTML) so a malicious backend
    -- payload can't inject HTML into /__admin — review on PR #88.
    add([[
<script>
document.querySelectorAll('.rcv-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var host = btn.dataset.host, ip = btn.dataset.ip, rowId = btn.dataset.row;
    var row  = document.getElementById(rowId);
    btn.disabled = true; btn.textContent = '...';
    function setCell(color, parts) {
      var cell = row.querySelector('td:last-child');
      while (cell.firstChild) cell.removeChild(cell.firstChild);
      var span = document.createElement('span');
      span.style.color = color;
      parts.forEach(function(p) {
        if (p.tag) {
          var el = document.createElement(p.tag);
          el.textContent = p.text;
          span.appendChild(el);
        } else {
          span.appendChild(document.createTextNode(p.text));
        }
      });
      cell.appendChild(span);
    }
    fetch('/__admin/recover_ip', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({host: host, ip: ip})
    }).then(function(r) { return r.json().then(function(j){ return {s:r.status, j:j}; }); })
      .then(function(res) {
        if (res.s === 200 && res.j.ok) {
          var verb = res.j.changed ? 'whitelisted' : 'already whitelisted';
          setCell('#2e7d32', [
            {text: '✓ ' + verb + ' ('},
            {tag: 'code', text: String(res.j.cidr || '')},
            {text: '); ≤ ' + Number(res.j.propagation_seconds || 30) +
                   's to fastpass'},
          ]);
        } else {
          var msg = res.j.error || ('HTTP ' + res.s);
          setCell('#c62828', [{text: '✗ ' + String(msg)}]);
        }
      }).catch(function(e) {
        btn.disabled = false; btn.textContent = 'Whitelist IP';
        setCell('#c62828', [{text: '✗ ' + String(e)}]);
      });
  });
});
</script>
]])
end

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
    for i = 1, math.min(blocklist_n, 50) do
        local e = blocklist[i]
        add("<tr><td><code>" .. esc(e.fp) .. "</code></td><td>"
            .. esc(e.verdict) .. "</td></tr>")
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
