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

-- resolve(origin, origin_ip, loop_host)
--
-- origin     — ORIGIN_URL as nginx sees it (e.g. "https://dashboard.example.com"
--              or "http://dashboard.example.com:8443/path"). May be nil or "".
-- origin_ip  — operator-configured backend IP that loop_host should be
--              rewritten to. DASHBOARD_BACKEND_IP for the single-tenant
--              case. May be nil or "".
-- loop_host  — the public hostname that the rewrite is targeting (i.e.
--              the hostname that resolves back to THIS edge and would
--              otherwise loop). DASHBOARD_PUBLIC_HOST for the single-
--              tenant case. May be nil or "".
--
-- Returns the origin URL with its hostname portion replaced by origin_ip,
-- preserving scheme, port (if any) and path — but ONLY when origin's
-- hostname matches loop_host. Any other ORIGIN_URL (a custom origin per
-- the README quickstart, an operator's own `ORIGIN_URL=https://your-
-- origin.example`) is returned unchanged so the rewrite cannot
-- accidentally point custom-origin traffic at the dashboard backend.
-- This is the bug Codex flagged on PR #89: an unconditional rewrite
-- regressed every non-dashboard deployment.
--
-- If any of the three inputs is empty, the original origin is returned
-- unchanged — that covers $origin = "" (bac.example.com landing
-- path, handled separately upstream), unset DASHBOARD_BACKEND_IP, and
-- unset DASHBOARD_PUBLIC_HOST. The substitution is gated on the
-- HOSTNAME INSIDE ORIGIN_URL, not on the incoming Host header — that
-- distinction is the actual fix for the loop. Earlier versions gated
-- on `ngx.var.host == "dashboard.example.com"`, which let
-- IP-scanners (Host: <edge-IP>) fall through to the unmodified URL
-- and into the loop. Origin-side gating is loop-safe regardless of
-- what the client puts in its Host header, and preserves custom-
-- origin operators.
--
-- The Host/SNI sent UPSTREAM are still ORIGIN_URL-driven (see
-- nginx.demo.conf $origin_host / $origin_sni), so the backend
-- continues to see the registered public hostname for vhost
-- selection.
function _M.resolve(origin, origin_ip, loop_host)
    if not origin    or origin    == "" then return origin end
    if not origin_ip or origin_ip == "" then return origin end
    if not loop_host or loop_host == "" then return origin end

    -- Extract origin's hostname (bracketed IPv6 first, then v4/hostname).
    -- If it doesn't match loop_host, bail out unchanged — that's the
    -- custom-origin path (operator points ORIGIN_URL at their own
    -- backend; nothing to rewrite, nothing to loop).
    local origin_host = origin:match("^https?://%[([^%]]+)%]")
                     or origin:match("^https?://([^:/]+)")
    if origin_host ~= loop_host then return origin end

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
