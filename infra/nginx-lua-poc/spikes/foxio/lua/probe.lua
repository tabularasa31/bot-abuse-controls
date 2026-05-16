ngx.header.content_type = "text/plain"
ngx.say("fp=",          ngx.var.http_ssl_ja4 or ngx.var.ssl_ja4 or "missing")
ngx.say("ja4_string=",  ngx.var.http_ssl_ja4_string or ngx.var.ssl_ja4_string or "-")
ngx.say("ja4s=",        ngx.var.http_ssl_ja4s or ngx.var.ssl_ja4s or "-")
ngx.say("ja4h=",        ngx.var.http_ssl_ja4h or ngx.var.ssl_ja4h or "-")
ngx.say("ua=",          ngx.var.http_user_agent or "-")
