-- Spike 3 verdict.lua. FoxIO module exposes $http_ssl_ja4 (per its
-- HTTP-context naming) as the canonical JA4 hash.
local fp = ngx.var.http_ssl_ja4 or ngx.var.ssl_ja4 or "missing"

local cache = ngx.shared.verdict_cache
local cached = cache:get(fp)
if cached == "block" then return ngx.exit(403)
elseif cached == "allow" then return end

local verdict = ngx.shared.fp_blocklist:get(fp) or "allow"
cache:set(fp, verdict, 60)
ngx.log(ngx.INFO, "verdict=", verdict, " (cold) fp=", fp)
if verdict == "block" then return ngx.exit(403) end
