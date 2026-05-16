-- Debug endpoint handler. Dumps the per-request fingerprint so the
-- probe script can capture it and we can populate blocklist.lua.

local md5 = ngx.md5

local cipher   = ngx.var.ssl_cipher   or "-"
local protocol = ngx.var.ssl_protocol or "-"
local ua_full  = ngx.var.http_user_agent or "-"
local ua       = ua_full
if #ua > 32 then ua = ua:sub(1, 32) end

local fp = md5(cipher .. ":" .. protocol .. ":" .. ua)

ngx.header.content_type = "text/plain"
ngx.say("fp=", fp)
ngx.say("cipher=", cipher)
ngx.say("protocol=", protocol)
ngx.say("ua=", ua_full)
