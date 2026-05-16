-- Spike 2 verdict.lua. Same pipeline as the PoC #2 verdict.lua, only
-- `compute_fp()` is replaced with a real (handshake-derived) fingerprint
-- from ja4_compute.

local ja4 = require "ja4_compute"

local fp, _ = ja4.compute()

local cache = ngx.shared.verdict_cache
local cached = cache:get(fp)
if cached == "block" then
    return ngx.exit(403)
elseif cached == "allow" then
    return
end

local list = ngx.shared.fp_blocklist
local verdict = list:get(fp) or "allow"

cache:set(fp, verdict, 60)
ngx.log(ngx.INFO, "verdict=", verdict, " (cold) fp=", fp)

if verdict == "block" then
    return ngx.exit(403)
end
-- allow: fall through to content handler
