-- access_by_lua entry. Computes a synthetic per-client fingerprint
-- (see blocklist.lua for the "why synthetic" justification) and
-- runs the verdict path that the production system will run on the
-- real JA3/JA4 once we wire it in (Phase 2).
--
-- Verdict pipeline:
--   1. Compute synthetic fp from cipher + protocol + UA prefix.
--   2. verdict_cache:get(fp)            -- hot path, no shared_dict scan
--   3. fp_blocklist:get(fp)             -- cold path on cache miss
--   4. cache the result for 60s
--   5. block path: ngx.exit(403)
--   6. allow path: return (nginx serves location /)

local md5 = ngx.md5

local cipher   = ngx.var.ssl_cipher   or "-"
local protocol = ngx.var.ssl_protocol or "-"
local ua       = ngx.var.http_user_agent or "-"
if #ua > 32 then ua = ua:sub(1, 32) end

local fp = md5(cipher .. ":" .. protocol .. ":" .. ua)

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
ngx.log(ngx.INFO, "verdict=", verdict, " (cold) fp=", fp, " ua=", ua)

if verdict == "block" then
    return ngx.exit(403)
end
-- allow: fall through to content handler
