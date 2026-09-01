-- Unit tests for infra/demo-stand/lua/policy.lua get()/lookup().
-- Focus: origin_ip routing must survive the mode/strictness enum-guard
-- fallback (/ PR #94 review #1) — a malformed mode must not deroute
-- a registered tenant to the non-tenant 444 drop.
--
-- Runs under bare luajit: stub cjson(.safe) + ngx (shared dicts, ctx, log)
-- before requiring policy, same pattern as catalog_pull_test.lua.

-- decode stub: dict raw value is used as a key into this table.
local decode_table = {}
package.loaded["cjson.safe"] = {
    decode = function(s)
        local v = decode_table[s]
        if v == nil then return nil, "no decode stub for " .. tostring(s) end
        return v
    end,
    encode = function(_) return "encoded" end,
}
-- policy.lua requires real cjson only for empty_array_mt sentinel.
package.loaded["cjson"] = { empty_array_mt = {} }

local function new_dict()
    local d = { _store = {} }
    function d:get(k) return self._store[k] end
    function d:set(k, v) self._store[k] = v; return true end
    return d
end

_G.ngx = _G.ngx or {}
ngx.ERR = "ERR"
ngx.log = function() end
ngx.md5 = function(s) return "md5(" .. s .. ")" end
ngx.shared = { antibot_policy = new_dict(), meta = new_dict() }
ngx.ctx = {}   -- fresh per "request"; tests reset between cases

package.path = "infra/demo-stand/lua/?.lua;" .. package.path
local policy = require "policy"

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

-- Seed one generation. raw value == dict key so decode_table[raw] resolves.
ngx.shared.meta:set("antibot_policy_gen", 0)
local function seed(host, tbl)
    local key = host .. ":0"
    ngx.shared.antibot_policy:set(key, key)
    decode_table[key] = tbl
end
local function fresh_request() ngx.ctx = {} end

seed("good.example", { mode = "active", strictness = "standard", origin_ip = "203.0.113.9" })
seed("badmode.example", { mode = "bogus", strictness = "standard", origin_ip = "203.0.113.10" })
seed("badstrict.example", { mode = "active", strictness = "loose", origin_ip = "203.0.113.11" })
seed("badmode_noip.example", { mode = "bogus", strictness = "standard" })

-- Valid policy: returned verbatim.
fresh_request()
eq(policy.get("good.example").mode, "active", "valid policy: mode preserved")
eq(policy.get("good.example").origin_ip, "203.0.113.9", "valid policy: origin_ip preserved")

-- Invalid mode: enforcement falls back to shadow, but origin_ip (routing)
-- MUST survive — otherwise the tenant silently derouts to the non-tenant 444 drop.
fresh_request()
eq(policy.get("badmode.example").mode, "shadow", "invalid mode → shadow fallback")
eq(policy.get("badmode.example").origin_ip, "203.0.113.10",
   "invalid mode → origin_ip still preserved (routing survives)")

-- Invalid strictness: same — origin_ip survives.
fresh_request()
eq(policy.get("badstrict.example").strictness, "standard", "invalid strictness → standard fallback")
eq(policy.get("badstrict.example").origin_ip, "203.0.113.11",
   "invalid strictness → origin_ip still preserved")

-- Invalid mode AND no origin_ip: plain pool default, origin_ip absent (nil).
fresh_request()
eq(policy.get("badmode_noip.example").origin_ip, nil,
   "invalid mode, no origin_ip → nil (not a tenant)")

-- Unregistered host: pool default, no origin_ip → not a tenant.
fresh_request()
eq(policy.get("unknown.example").mode, "shadow", "unregistered → pool default shadow")
eq(policy.get("unknown.example").origin_ip, nil, "unregistered → no origin_ip")

-- Parent-domain fallback (walk-up): registering the apex covers subdomains.
seed("svinnar.example", { mode = "active", strictness = "permissive", origin_ip = "198.51.100.7" })
seed("api.svinnar.example", { mode = "shadow", strictness = "standard", origin_ip = "198.51.100.8" })

-- www.<apex> has no own row → inherits the apex policy (mode + origin_ip).
fresh_request()
eq(policy.get("www.svinnar.example").mode, "active", "www → inherits apex mode")
eq(policy.get("www.svinnar.example").origin_ip, "198.51.100.7", "www → inherits apex origin_ip")
eq(policy.get("www.svinnar.example").strictness, "permissive", "www → inherits apex strictness")

-- Deep subdomain also walks up to the apex.
fresh_request()
eq(policy.get("a.b.svinnar.example").origin_ip, "198.51.100.7", "deep subdomain → inherits apex")

-- The apex itself still resolves to its own row.
fresh_request()
eq(policy.get("svinnar.example").origin_ip, "198.51.100.7", "apex → own row")

-- An explicit subdomain row OVERRIDES the apex (most specific wins).
fresh_request()
eq(policy.get("api.svinnar.example").origin_ip, "198.51.100.8", "explicit subdomain row overrides apex")
-- ...and a subdomain UNDER that explicit row still walks up to the nearest one.
fresh_request()
eq(policy.get("v2.api.svinnar.example").origin_ip, "198.51.100.8", "sub-subdomain → nearest (api) row")

-- Unrelated domain doesn't match — and the walk never climbs into a public
-- suffix (no row for it → pool default), so no cross-domain leakage.
fresh_request()
eq(policy.get("evil.example.org").origin_ip, nil, "unrelated domain → pool default (no walk-up match)")
fresh_request()
eq(policy.get("www.example").origin_ip, nil, "single-label parent not a registered row → pool default")

io.write(string.format("policy_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
