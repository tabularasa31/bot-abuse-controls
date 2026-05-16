-- Debug endpoint for the Spike 2 stand. Dumps the real handshake-derived
-- fingerprint plus the raw nginx-exposed components that fed into it.

local ja4 = require "ja4_compute"

local fp, parts = ja4.compute()

ngx.header.content_type = "text/plain"
ngx.say("fp=",           fp)
ngx.say("tls_ver=",      parts.tls_ver)
ngx.say("sni=",          parts.sni)
ngx.say("alpn=",         parts.alpn)
ngx.say("ciphers=",      parts.ciphers)
ngx.say("curves=",       parts.curves)
ngx.say("ua=",           ngx.var.http_user_agent or "-")
