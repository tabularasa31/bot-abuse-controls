-- Spike 1 verdict.lua. compute_fp reads real JA3 MD5 from resty.ssl provided
-- by the vela-security patched OpenResty build.

local ssl = require "resty.ssl"

local info = ssl.ja3()
local fp = info.hash    -- MD5 of the canonical ja3 string

local cache = ngx.shared.verdict_cache
local cached = cache:get(fp)
if cached == "block" then return ngx.exit(403)
elseif cached == "allow" then return end

local verdict = ngx.shared.fp_blocklist:get(fp) or "allow"
cache:set(fp, verdict, 60)
ngx.log(ngx.INFO, "verdict=", verdict, " (cold) fp=", fp)
if verdict == "block" then return ngx.exit(403) end
