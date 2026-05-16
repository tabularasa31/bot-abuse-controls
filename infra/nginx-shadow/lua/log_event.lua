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

local event = {
    ts                  = ngx.now(),
    -- request
    method              = ngx.var.request_method,
    host                = ngx.var.host,
    uri                 = ngx.var.uri,
    status              = ngx.var.status,           -- upstream response code
    request_time_ms     = tonumber(ngx.var.request_time) * 1000,
    upstream_time_ms    = tonumber(ngx.var.upstream_response_time or 0) * 1000,
    bytes_sent          = tonumber(ngx.var.bytes_sent),
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
