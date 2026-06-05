-- origin_resolve — substitute the hostname inside the chosen upstream URL
-- ($origin = `https://<tenant>`) with the tenant's origin IP, bypassing the
-- http-level resolver.
--
-- Why this exists. A tenant's public hostname (e.g. clientx.com) points at
-- THIS edge. If `proxy_pass $origin` runs with a variable and $origin still
-- contains that hostname, nginx hands it to the resolver (resolver.conf —
-- 1.1.1.1 / 8.8.8.8), which dutifully returns the edge's own public IP — and
-- the cascade proxies into itself. Each loop iteration doubles the headers
-- (X-Forwarded-For grows), and the connection eventually dies with 400
-- "Request Header Or Cookie Too Large". The intermediate iterations show up
-- in BAC_LOG with `ip = <edge public IP>`, which looks like the edge is
-- blocking itself — see the investigation around the $origin_resolve commit
-- history (PR #89).
--
-- docker-compose's `extra_hosts:` writes to /etc/hosts inside the container,
-- but nginx's variable-driven `resolver` path BYPASSES /etc/hosts. The fix
-- is to short-circuit the lookup: substitute the tenant hostname in $origin
-- with its origin_ip directly. Upstream Host header and SNI are set
-- separately (proxy_set_header Host $origin_host; proxy_ssl_name
-- $origin_sni) so the backend's vhost selection and TLS cert serving still
-- see the public hostname — only the network-layer destination is rewritten.
--
-- This module is the pure-Lua part of $origin_resolve in nginx.demo.conf;
-- factoring it out lets us unit-test the substitution (tests/origin_resolve_test.lua)
-- and keeps the nginx config small.
--
-- Multi-tenant note (ClickUp 86exrefdz, done). The {public_host → origin_ip}
-- pairing lives in Policy: $origin is `https://<tenant>` and (origin_ip,
-- loop_host) come from proxy_target.backend(ngx.var.host), which reads
-- policy.get(host).origin_ip. resolve() is per-host and env-free; the
-- substitution logic itself is unchanged from the single-tenant version.
local _M = {}

-- resolve(origin, origin_ip, loop_host)
--
-- origin     — the chosen upstream URL as nginx sees it (e.g.
--              "https://clientx.com" or "https://dashboard.example.com").
--              `https://<tenant>` from proxy_target.origin(). May be nil/"".
-- origin_ip  — the tenant's backend IP (Policy origin_ip) that loop_host
--              should be rewritten to. May be nil or "".
-- loop_host  — the public hostname that the rewrite is targeting (i.e.
--              the hostname that resolves back to THIS edge and would
--              otherwise loop) — the tenant host. May be nil or "".
--
-- Returns the origin URL with its hostname portion replaced by origin_ip,
-- preserving scheme, port (if any) and path — but ONLY when origin's
-- hostname matches loop_host. If it doesn't match, the URL is returned
-- unchanged (defensive: the caller always passes the same host in $origin
-- and loop_host for a tenant, so a mismatch only happens on misuse).
--
-- If any of the three inputs is empty, the original origin is returned
-- unchanged — that covers $origin = "" (non-tenant path — dropped with 444
-- upstream) and the non-tenant ("", "") backend() result. The
-- substitution is gated on the HOSTNAME INSIDE $origin, not on the incoming
-- Host header — that distinction is the loop fix from PR #89. Earlier
-- versions gated on `ngx.var.host == "dashboard.example.com"`, which let
-- IP-scanners (Host: <edge-IP>) fall through to the unmodified URL and into
-- the loop. Origin-side gating is loop-safe regardless of the Host header.
--
-- The Host/SNI sent UPSTREAM are $origin-driven (nginx.demo.conf
-- $origin_host / $origin_sni), so the backend sees the tenant's public
-- hostname for vhost selection and TLS cert serving.
function _M.resolve(origin, origin_ip, loop_host)
    if not origin    or origin    == "" then return origin end
    if not origin_ip or origin_ip == "" then return origin end
    if not loop_host or loop_host == "" then return origin end

    -- Extract origin's hostname (bracketed IPv6 first, then v4/hostname).
    -- If it doesn't match loop_host, bail out unchanged.
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

    -- Escape `%` for use as a gsub REPLACEMENT string: in the replacement,
    -- `%` introduces a capture reference (%0-%9) or `%%`. The backend
    -- validator rejects zone-scoped IPv6 (`fe80::1%eth0`), but a value
    -- written straight to the DB (legacy / manual SQL) could still carry a
    -- `%`; without this escape gsub would error or corrupt the URL at
    -- request time. Defense-in-depth alongside ValidateOriginIP (codex P2).
    local repl = formatted_ip:gsub("%%", "%%%%")

    -- Match `scheme://host` and replace `host` with formatted_ip.
    -- Try the bracketed IPv6 form first (`[…]`), then fall back to the
    -- IPv4/hostname form (`[^:/]+`). The IPv4 pattern would stop at the
    -- first `:` inside `[2001:db8::1]` and corrupt the URL, hence the
    -- two-step match. Both patterns preserve trailing `:port` and `/path`.
    -- gsub returns (new_string, count); we use count to detect "no match"
    -- so a bare hostname (no scheme) is returned as-is rather than
    -- silently mangled.
    local rewritten, n = origin:gsub("^(https?://)%[[^%]]+%]", "%1" .. repl)
    if n == 0 then
        rewritten, n = origin:gsub("^(https?://)[^:/]+", "%1" .. repl)
    end
    if n == 0 then
        return origin
    end
    return rewritten
end

return _M
