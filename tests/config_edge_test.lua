-- Unit tests for the edge self-protection toggle (feature/edge-deny-nontenant).
-- Covers the two pure pieces that gate the `return 444` path in
-- nginx.demo.conf's `location /`:
--   1. config.edge_deny_nontenant(defaults) — the per-request predicate read
--      from a set_by_lua_block. No ngx deps (config.lua's module body only
--      requires config_loader and defines functions), so it loads under bare
--      luajit like the other host tests.
--   2. config_loader.parse_ini coercion of "[edge_protection] deny_nontenant"
--      — the parse step that feeds the operator-override overlay. "true"/"false"
--      MUST become booleans, else the `== true` check in the predicate / the
--      apply_toggle guard silently keeps the baseline.
-- The overlay itself (overlay_local) is file-IO + ngx.log bound and is
-- exercised on the live stand via `nginx -s reload`, not here.
--
-- Run with:
--   make test            (host luajit, fastest)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

local config = require "config"
local loader = require "config_loader"

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

-- 1. predicate ------------------------------------------------------------
eq(config.edge_deny_nontenant({ edge_protection = { deny_nontenant = true } }),
   true, "deny_nontenant=true → true")
eq(config.edge_deny_nontenant({ edge_protection = { deny_nontenant = false } }),
   false, "deny_nontenant=false → false")
-- Missing section / key → default off (out-of-box landing behaviour).
eq(config.edge_deny_nontenant({ edge_protection = {} }),
   false, "empty section → false")
eq(config.edge_deny_nontenant({}), false, "no section → false")
eq(config.edge_deny_nontenant(nil), false, "nil defaults → false")
-- Defensive: a non-boolean (parser typo that slipped past coercion) must NOT
-- read as enabled — the predicate tests `== true`, so only a real boolean true
-- arms the drop. Mirrors apply_toggle's fail-safe.
eq(config.edge_deny_nontenant({ edge_protection = { deny_nontenant = "true" } }),
   false, "string 'true' → false (not boolean)")

-- 2. parser coercion ------------------------------------------------------
-- Write a tiny INI to a temp file and confirm the section nests + the value
-- coerces to a boolean (not the truthy string "false").
local tmp = os.tmpname()
do
    local f = assert(io.open(tmp, "w"))
    f:write("[edge_protection]\n")
    f:write("deny_nontenant = true\n")
    f:close()
end
local parsed, perr = loader.parse_ini(tmp)
os.remove(tmp)   -- remove BEFORE asserting so a parse failure doesn't leak the temp file
assert(parsed, perr)
eq(type(parsed.edge_protection), "table", "parse: section nests to a table")
eq(parsed.edge_protection.deny_nontenant, true, "parse: value coerces to boolean true")

local tmp2 = os.tmpname()
do
    local f = assert(io.open(tmp2, "w"))
    f:write("[edge_protection]\n")
    f:write("deny_nontenant = false\n")
    f:close()
end
local parsed2, perr2 = loader.parse_ini(tmp2)
os.remove(tmp2)   -- remove BEFORE asserting (test hygiene)
assert(parsed2, perr2)
eq(parsed2.edge_protection.deny_nontenant, false, "parse: 'false' coerces to boolean false")

-- summary -----------------------------------------------------------------
io.write(string.format("\nconfig_edge_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
