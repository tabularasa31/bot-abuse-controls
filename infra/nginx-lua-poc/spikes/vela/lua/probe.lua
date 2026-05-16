-- Spike 1 /__fp endpoint. Dumps the full ja3() struct so we can inspect
-- ciphers / extensions / curves the patched OpenSSL captured.
local ssl   = require "resty.ssl"
local cjson = require "cjson"

local info = ssl.ja3()
info.ua = ngx.var.http_user_agent or "-"
ngx.header.content_type = "application/json"
ngx.say(cjson.encode(info))
