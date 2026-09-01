-- Returns the caller's own fingerprint and the raw handshake components it was
-- built from. Bypasses the cascade, so it still answers a client whose
-- fingerprint is blocklisted.

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

-- X-Demo-IP allows probing an arbitrary address; "-" means GeoLite2 is not
-- loaded or has no entry.
local geoip = require "geoip"
local probe_ip = ngx.var.http_x_demo_ip
if not probe_ip or probe_ip == "" then probe_ip = ngx.var.remote_addr end
local cc, asn = geoip.lookup(probe_ip)
ngx.say("ip=",        probe_ip or "-")
ngx.say("geoip_cc=",  cc or "-")
ngx.say("geoip_asn=", asn or "-")

ngx.say("")
ngx.say("# This is the fp the verdict pipeline computed for THIS request.")
ngx.say("# It bypasses the blocklist lookup intentionally — /__fp always")
ngx.say("# returns 200 so you can inspect your own fingerprint even when")
ngx.say("# your client would otherwise be blocked at /.")
