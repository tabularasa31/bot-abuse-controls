-- access_by_lua entry. Computes a real handshake-derived fingerprint
-- (see ja4_compute.lua) and runs the verdict pipeline.
--
-- Verdict pipeline (unchanged from PoC #2):
--   1. Compute fp from $ssl_ciphers + $ssl_curves + $ssl_protocol
--      + $ssl_alpn_protocol + $ssl_server_name.
--   2. verdict_cache:get(fp)            -- hot path, no shared_dict scan
--   3. fp_blocklist:get(fp)             -- cold path on cache miss
--   4. cache the result for 60s
--   5. block path: ngx.exit(403)
--   6. allow path: return (nginx serves location /)

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
