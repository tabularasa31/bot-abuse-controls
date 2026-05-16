-- /__fp educational endpoint. Returns the same fp + raw components
-- that the production probe.lua does. Bypasses the verdict pipeline
-- so it works even if your client's fp is in the blocklist — useful
-- to show a sceptical reviewer "your fp is this, and here's the raw
-- input that produced it".

local ja4 = require "ja4_compute"
local fp, parts = ja4.compute()

ngx.header.content_type = "text/plain"
ngx.say("fp=",      fp)
ngx.say("tls_ver=", parts.tls_ver)
ngx.say("sni=",     parts.sni)
ngx.say("alpn=",    parts.alpn)
ngx.say("ciphers=", parts.ciphers)
ngx.say("curves=",  parts.curves)
ngx.say("ua=",      ngx.var.http_user_agent or "-")
ngx.say("")
ngx.say("# This is the fp the verdict pipeline computed for THIS request.")
ngx.say("# It bypasses the blocklist lookup intentionally — /__fp always")
ngx.say("# returns 200 so you can inspect your own fingerprint even when")
ngx.say("# your client would otherwise be blocked at /.")
