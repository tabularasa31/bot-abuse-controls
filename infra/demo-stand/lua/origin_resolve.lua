-- origin_resolve — substitute the hostname inside ORIGIN_URL with the
-- operator-configured origin IP, bypassing the http-level resolver.
--
-- Why this exists. The stand's public hostname (e.g. dashboard.example.com)
-- points at THIS edge. If `proxy_pass $origin` runs with a variable and the
-- ORIGIN_URL still contains that hostname, nginx hands it to the resolver
-- (resolver.conf — 1.1.1.1 / 8.8.8.8), which dutifully returns the edge's
-- own public IP — and the cascade proxies into itself. Each loop iteration
-- doubles the headers (X-Forwarded-For grows), and the connection eventually
-- dies with 400 "Request Header Or Cookie Too Large". The intermediate
-- iterations show up in BAC_LOG with `ip = <edge public IP>`, which looks
-- like the edge is blocking itself — see the investigation around the
-- $origin_resolve commit history.
--
-- docker-compose's `extra_hosts:` writes to /etc/hosts inside the container,
-- but nginx's variable-driven `resolver` path BYPASSES /etc/hosts. The fix
-- is to short-circuit the lookup: substitute the public hostname in
-- ORIGIN_URL with the operator-configured IP directly. Upstream Host header
-- and SNI are set separately (proxy_set_header Host $origin_host;
-- proxy_ssl_name $origin_sni) so the backend's vhost selection and TLS
-- cert serving still see the public hostname — only the network-layer
-- destination is rewritten.
--
-- This module is the pure-Lua part of $origin_resolve in nginx.demo.conf;
-- factoring it out lets us unit-test the substitution (tests/origin_resolve_test.lua)
-- and keeps the nginx config small.
--
-- Multi-tenant note. Today the stand fronts exactly one client
-- (dashboard.example.com) via a single ORIGIN_URL / DASHBOARD_BACKEND_IP
-- pair. When the stand grows to multiple clients (clientX.com, clientY.io, …),
-- the {public_host → origin_ip} pairing belongs in policy (B11) — see the
-- follow-up TODO in policy.lua. resolve() then takes a per-host origin_ip
-- instead of the single env var; the substitution logic itself does not
-- change.
local _M = {}

-- resolve(origin, origin_ip)
--
-- origin     — ORIGIN_URL as nginx sees it (e.g. "https://dashboard.example.com"
--              or "http://dashboard.example.com:8443/path"). May be nil or "".
-- origin_ip  — operator-configured backend IP (DASHBOARD_BACKEND_IP for the
--              single-tenant case). May be nil or "".
--
-- Returns the origin URL with its hostname portion replaced by origin_ip,
-- preserving scheme, port (if any) and path. If either input is empty, the
-- original origin is returned unchanged — that is the "don't try to be
-- clever" case for $origin = "" (bac.example.com landing path,
-- handled separately upstream).
--
-- The substitution is UNCONDITIONAL with respect to the incoming Host
-- header. Previously this lived inline in $origin_resolve gated on
-- `Host == "dashboard.example.com"`; that gating let any other Host
-- (IP-scanners sending Host: <edge-IP>, scanners with empty/random Host,
-- HTTP/1.0 clients) fall through to the unmodified URL and loop. The
-- substitution applies to whatever hostname ORIGIN_URL contains, so the
-- network destination is always the operator-configured IP regardless of
-- what the client put in its Host header. The Host/SNI sent UPSTREAM are
-- still ORIGIN_URL-driven (see nginx.demo.conf $origin_host/$origin_sni),
-- so the backend continues to see the registered public hostname for
-- vhost selection.
function _M.resolve(origin, origin_ip)
    if not origin or origin == "" then return origin end
    if not origin_ip or origin_ip == "" then return origin end

    -- If origin_ip is IPv6 (contains a colon and isn't already bracketed),
    -- wrap it in brackets so the resulting URL is RFC 3986-shaped
    -- (`scheme://[v6]:port/path`). IPv4 and already-bracketed values pass
    -- through unchanged. The substitution itself is the same for both
    -- families — only the way the literal sits inside the URL differs.
    local formatted_ip = origin_ip
    if origin_ip:find(":", 1, true) and not origin_ip:find("^%[") then
        formatted_ip = "[" .. origin_ip .. "]"
    end

    -- Match `scheme://host` and replace `host` with formatted_ip.
    -- Try the bracketed IPv6 form first (`[…]`), then fall back to the
    -- IPv4/hostname form (`[^:/]+`). The IPv4 pattern would stop at the
    -- first `:` inside `[2001:db8::1]` and corrupt the URL, hence the
    -- two-step match. Both patterns preserve trailing `:port` and `/path`.
    -- gsub returns (new_string, count); we use count to detect "no match"
    -- so a bare hostname (no scheme) is returned as-is rather than
    -- silently mangled.
    local rewritten, n = origin:gsub("^(https?://)%[[^%]]+%]", "%1" .. formatted_ip)
    if n == 0 then
        rewritten, n = origin:gsub("^(https?://)[^:/]+", "%1" .. formatted_ip)
    end
    if n == 0 then
        return origin
    end
    return rewritten
end

return _M
