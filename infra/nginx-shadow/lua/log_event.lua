-- log_by_lua_block handler. Emits one JSON line per request to nginx
-- error log at NOTICE level. The shadow-mode verdict.lua stashes fp /
-- verdict / parts into ngx.ctx; we pull them out, combine with request
-- metadata, and serialise.
--
-- Why error log and not access log: error log already streams to
-- stdout via the Dockerfile's symlink, which the docker logging driver
-- ships wherever you point it (json-file by default; can route to
-- syslog / fluentd / loki / etc. via docker compose config).
--
-- Format choice: JSON because jq is the lingua franca of log analysis.
-- One line per request keeps each event grep-able and self-contained.
-- Field naming follows OpenTelemetry-ish conventions where reasonable
-- (http.method, http.status_code, etc.) so future shipping to a real
-- observability stack is a renaming exercise, not a re-design.

local cjson = require "cjson.safe"

local fp      = ngx.ctx.antibot_fp
local verdict = ngx.ctx.antibot_verdict

-- If verdict.lua didn't run (e.g. /__health bypass), skip — nothing
-- meaningful to log.
if not fp then return end

local parts = ngx.ctx.antibot_fp_parts or {}

-- Truncate UA so a 4 KB rogue UA doesn't bloat the log line.
local ua = ngx.var.http_user_agent or ""
if #ua > 200 then ua = ua:sub(1, 197) .. "..." end

-- Truncate cipher list — full list can be 600+ bytes, blows up log size.
-- Cipher count is in fp prefix already; we keep the list only when it
-- would help debugging an outlier fp. Cap at 256 bytes.
local ciphers = parts.ciphers or ""
if #ciphers > 256 then ciphers = ciphers:sub(1, 253) .. "..." end

-- ngx.var.{request,upstream_response}_time can be:
--   * a normal number string ("0.012")
--   * "-" (nginx writes this when the upstream couldn't be reached)
--   * a comma-separated list ("0.001, 0.002") if proxy_next_upstream retried
-- Bare tonumber returns nil on the latter two, and `nil * 1000` crashes
-- the request. ms() handles all three by taking the LAST numeric piece
-- (most-recent attempt for the retry case) and returning 0 if nothing
-- parses — same shape as a missing-but-present field.
local function ms(raw)
    if not raw or raw == "" or raw == "-" then return 0 end
    -- Split on comma — for retries we want the latest attempt's time.
    local last
    for piece in raw:gmatch("[^,%s]+") do last = piece end
    return (tonumber(last) or 0) * 1000
end

local event = {
    ts                  = ngx.now(),
    -- request
    method              = ngx.var.request_method,
    host                = ngx.var.host,
    uri                 = ngx.var.uri,
    status              = ngx.var.status,           -- upstream response code
    request_time_ms     = ms(ngx.var.request_time),
    upstream_time_ms    = ms(ngx.var.upstream_response_time),
    bytes_sent          = tonumber(ngx.var.bytes_sent) or 0,
    -- client
    remote_addr         = ngx.var.remote_addr,
    ua                  = ua,
    referer             = ngx.var.http_referer,
    -- fingerprint
    fp                  = fp,
    fp_cipher_list      = ciphers,
    fp_curves           = parts.curves,
    fp_alpn             = parts.alpn,
    fp_tls_ver          = parts.tls_ver,
    fp_sni              = parts.sni,
    -- verdict
    would_verdict       = verdict,                  -- "allow" | "block" (never enforced in shadow)
    cache_hit           = ngx.ctx.antibot_cache_hit,
    mode                = "shadow",
}

local line = cjson.encode(event)
if line then
    ngx.log(ngx.NOTICE, "ANTIBOT_EVENT ", line)
end
