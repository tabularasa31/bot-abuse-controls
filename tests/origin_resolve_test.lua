-- Unit tests for infra/demo-stand/lua/origin_resolve.lua.
-- Pure function — no ngx, no shared_dict, no I/O.

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

local origin_resolve = require "origin_resolve"

local passed, failed = 0, 0
local function eq(actual, want, name)
    if actual == want then
        passed = passed + 1
    else
        failed = failed + 1
        io.write(string.format("FAIL %s: got %q, want %q\n",
            name, tostring(actual), tostring(want)))
    end
end

-- DASHBOARD_PUBLIC_HOST / DASHBOARD_BACKEND_IP defaults used by the stand.
-- Tests pass them explicitly; `D` and `IP` keep call sites short.
local D, IP = "dashboard.example.com", "<TENANT_ORIGIN_IP>"

-- ====================================================================
-- Happy path: origin's hostname matches loop_host → substitution applies,
-- preserving scheme/port/path.
-- ====================================================================
eq(origin_resolve.resolve("https://" .. D, IP, D),
   "https://" .. IP,
   "https hostname only → ip")

eq(origin_resolve.resolve("http://" .. D, IP, D),
   "http://" .. IP,
   "http scheme preserved")

eq(origin_resolve.resolve("https://" .. D .. "/path/to/thing", IP, D),
   "https://" .. IP .. "/path/to/thing",
   "path preserved after substitution")

eq(origin_resolve.resolve("https://" .. D .. ":8443", IP, D),
   "https://" .. IP .. ":8443",
   "port preserved after substitution")

eq(origin_resolve.resolve("https://" .. D .. ":8443/api", IP, D),
   "https://" .. IP .. ":8443/api",
   "port + path preserved")

-- ====================================================================
-- Custom-origin operators: ORIGIN_URL points at someone OTHER than the
-- loop_host → returned unchanged. This is the Codex P2 regression that
-- the loop_host gate fixes — operators following the README quickstart
-- (`ORIGIN_URL=https://your-origin.example`) must NOT have their
-- traffic silently redirected to DASHBOARD_BACKEND_IP.
-- ====================================================================
eq(origin_resolve.resolve("https://your-origin.example", IP, D),
   "https://your-origin.example",
   "custom origin (host != loop_host) → unchanged")

eq(origin_resolve.resolve("https://your-origin.example:8443/api", IP, D),
   "https://your-origin.example:8443/api",
   "custom origin with port/path → unchanged")

eq(origin_resolve.resolve("https://192.0.2.10", IP, D),
   "https://192.0.2.10",
   "operator pointed origin at an IP directly → unchanged")

-- ====================================================================
-- Pass-throughs when there's nothing to substitute.
-- ====================================================================
eq(origin_resolve.resolve("", IP, D),
   "",
   "empty origin → empty (non-tenant path → 444)")

eq(origin_resolve.resolve(nil, IP, D),
   nil,
   "nil origin → nil")

eq(origin_resolve.resolve("https://" .. D, "", D),
   "https://" .. D,
   "empty origin_ip → original origin (no DASHBOARD_BACKEND_IP)")

eq(origin_resolve.resolve("https://" .. D, nil, D),
   "https://" .. D,
   "nil origin_ip → original origin")

eq(origin_resolve.resolve("https://" .. D, IP, ""),
   "https://" .. D,
   "empty loop_host → original origin (no DASHBOARD_PUBLIC_HOST)")

eq(origin_resolve.resolve("https://" .. D, IP, nil),
   "https://" .. D,
   "nil loop_host → original origin")

-- ====================================================================
-- Origin URLs that don't fit `scheme://host` are returned as-is, not mangled.
-- ====================================================================
eq(origin_resolve.resolve(D, IP, D),
   D,
   "bare hostname (no scheme) → unchanged")

eq(origin_resolve.resolve("ftp://example.com", IP, D),
   "ftp://example.com",
   "non-http(s) scheme → unchanged")

-- ====================================================================
-- IPv6 — neither the resolver path nor the operator config currently use
-- it (resolver.conf has `ipv6=off`, DASHBOARD_BACKEND_IP is IPv4), but
-- the substitution shouldn't corrupt v6-shaped URLs if someone does
-- point ORIGIN_URL or DASHBOARD_BACKEND_IP at an IPv6 literal. Three
-- properties matter: (1) `[v6]` in the origin URL must be matched as a
-- single host token (not split on the inner `:`s); (2) loop_host
-- comparison must work with the unbracketed v6 literal; (3) an IPv6
-- origin_ip must be bracketed in the output so the URL stays
-- RFC 3986-shaped.
-- ====================================================================
eq(origin_resolve.resolve("https://[2001:db8::1]:8443/x", IP, "2001:db8::1"),
   "https://" .. IP .. ":8443/x",
   "IPv6 in origin (matches loop_host) → replaced by IPv4 (brackets dropped)")

eq(origin_resolve.resolve("https://[2001:db8::1]", IP, "2001:db8::1"),
   "https://" .. IP,
   "IPv6-only origin (no port, no path) → IPv4")

eq(origin_resolve.resolve("https://" .. D .. ":8443/x", "2001:db8::2", D),
   "https://[2001:db8::2]:8443/x",
   "IPv6 origin_ip → wrapped in brackets")

eq(origin_resolve.resolve("https://[2001:db8::1]:8443/x", "2001:db8::2", "2001:db8::1"),
   "https://[2001:db8::2]:8443/x",
   "IPv6 origin replaced by IPv6 origin_ip (both bracketed)")

eq(origin_resolve.resolve("https://" .. D, "[2001:db8::2]", D),
   "https://[2001:db8::2]",
   "already-bracketed origin_ip not double-wrapped")

eq(origin_resolve.resolve("https://[2001:db8::3]:8443/x", IP, "2001:db8::1"),
   "https://[2001:db8::3]:8443/x",
   "IPv6 origin but different from loop_host → unchanged")

-- ====================================================================
-- Defense-in-depth: an origin_ip containing `%` (e.g. a zone-scoped IPv6
-- literal `fe80::1%eth0` that slipped past the backend validator via manual
-- SQL) must NOT be interpreted as a gsub replacement escape. The `%` is
-- escaped to `%%` before substitution, so it lands literally in the URL
-- instead of erroring or corrupting it (codex P2 on PR #94). The value is
-- nonsensical as a destination, but resolve() must fail safe (literal),
-- not throw, and the validator is the real gate.
eq(origin_resolve.resolve("https://" .. D, "fe80::1%eth0", D),
   "https://[fe80::1%eth0]",
   "origin_ip with `%` (zone) → `%` survives literally, no gsub corruption")

-- ====================================================================
-- Summary
-- ====================================================================
io.write(string.format("origin_resolve_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
