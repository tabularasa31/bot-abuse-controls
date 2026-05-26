-- policy.lua — per-host Policy reader + mode-gated enforcement helper (B11).
--
-- Sources:
--   * antibot_policy shared_dict, populated by catalog_pull.lua's `policy`
--     descriptor (full map(host → Policy) pulled from Channel C
--     /catalog/policy). Keys are `<host>:<gen>`; values are cjson-encoded
--     Policy tables.
--   * meta:antibot_policy_gen, flipped atomically by catalog_pull on each
--     successful pull (§В1 atomic-swap).
--
-- get(host) returns a non-nil Policy table. Missing host / missing
-- shared_dict / missing gen / decode failure all fall back to POOL_DEFAULT
-- below, which mirrors backend's catalog.PoolDefault() (antibot-backend/
-- internal/catalog/data.go:170). Drift between the two would surface as
-- /__policy showing one mode for an unregistered host and BAC_LOG
-- showing another — keep them in sync.
--
-- enforce(status) is the single mode-gate for the cascade. Stages that
-- want to physically affect the response (status, body) MUST go through
-- it instead of calling ngx.exit() directly — otherwise `mode=shadow`
-- clients would silently start receiving 4xx from new enforcement points,
-- breaking the observe-only contract. bac_log.set_verdict is called BEFORE
-- enforce, so the would-be verdict is recorded in either mode; only the
-- physical exit is gated.
--
-- Today the only caller is verdict.lua's tls_fp_blocklist branch. Future
-- enforcement points (rate_limit 429, hygiene/reputation per-host block,
-- challenge) hook into the same helper — see PROGRESS.md follow-up tickets.

local _M = {}

local cjson      = require "cjson.safe"
local cjson_base = require "cjson"   -- empty_array_mt sentinel

-- empty_array — short-hand for a `{}` that cjson.encode emits as JSON `[]`
-- rather than `{}`. Used for POOL_DEFAULT list fields below: dashboard and
-- other Channel C clients expect array-shape for ua_blacklist / ip_*
-- / asn_block / geo_whitelist / rate_rules (see Data.Policy json tags in
-- backend data.go), so the default returned to /__policy must match.
local function empty_array()
    return setmetatable({}, cjson_base.empty_array_mt)
end

-- POOL_DEFAULT: must match catalog.PoolDefault() in the backend
-- (antibot-backend/internal/catalog/data.go:170). Built per-call via
-- new_pool_default() so callers can't accidentally mutate a shared
-- instance and leak state across requests.
local function new_pool_default()
    return {
        mode          = "shadow",
        strictness    = "standard",
        ua_blacklist  = empty_array(),
        ip_whitelist  = empty_array(),
        ip_blocklist  = empty_array(),
        asn_block     = empty_array(),
        geo_whitelist = empty_array(),
        rate_rules    = empty_array(),
        attack_mode   = false,
    }
end

-- canonical_host — match the dashboard write path. Backend's antibotapi
-- stores policy rows under the {site} path param as received, but DNS host
-- names are case-insensitive (RFC 4343). nginx already lowercases
-- $host, so for a request-side caller this is a no-op; for callers that
-- pass an arbitrary string (/__policy?host=Foo.Example) we normalise here
-- so a mixed-case PATCH still resolves. Also caps length: shared_dict
-- keys are limited to 255 bytes; a malicious client-controlled Host could
-- otherwise crash the lookup. RFC 1035 says ≤253 chars total, but defence
-- in depth — hash anything past 64 to keep the dict key short.
local function canonical_host(host)
    if not host or host == "" then return nil end
    host = string.lower(host)
    if #host > 64 then
        host = ngx.md5(host)
    end
    return host
end

-- VALID_MODES / VALID_STRICTNESSES — mirror antibot-backend's
-- ValidateMode / ValidateStrictness (validate.go:46-48). Drift here would
-- mean the edge silently demotes a valid policy (e.g., backend adds a
-- third mode the edge doesn't know about) instead of failing loud —
-- intentional fail-stale, but the operator should see it in error.log.
local VALID_MODES         = { shadow = true, active = true }
local VALID_STRICTNESSES  = { standard = true, permissive = true }

-- get(host) → Policy table. Always non-nil. Falls back to POOL_DEFAULT on
-- any miss/error so callers can read `.mode` / `.strictness` directly
-- without nil-guards. The fallback also covers schema drift (missing /
-- invalid mode|strictness): pool default treats the host as shadow rather
-- than guessing, and the ERR-log surfaces the bad payload to the operator.
function _M.get(host)
    local key_host = canonical_host(host)
    if not key_host then return new_pool_default() end
    local dict = ngx.shared.antibot_policy
    local meta = ngx.shared.meta
    if not dict or not meta then return new_pool_default() end
    local gen = meta:get("antibot_policy_gen")
    if not gen then return new_pool_default() end
    local raw = dict:get(key_host .. ":" .. gen)
    if not raw then return new_pool_default() end
    local p, err = cjson.decode(raw)
    if not p or type(p) ~= "table" then
        ngx.log(ngx.ERR, "policy: decode failed for ", host, ": ", tostring(err))
        return new_pool_default()
    end
    -- Enum guards: a malformed Policy that's missing `mode` or carries a
    -- value outside the known set would otherwise silently degrade an
    -- active client to shadow (`nil == "active"` is false). Fail to pool
    -- default + ERR so the misconfiguration is visible.
    if type(p.mode) ~= "string" or not VALID_MODES[p.mode] then
        ngx.log(ngx.ERR, "policy: invalid mode for ", host, ": ",
            tostring(p.mode), " — falling back to pool default")
        return new_pool_default()
    end
    if type(p.strictness) ~= "string" or not VALID_STRICTNESSES[p.strictness] then
        ngx.log(ngx.ERR, "policy: invalid strictness for ", host, ": ",
            tostring(p.strictness), " — falling back to pool default")
        return new_pool_default()
    end
    return p
end

-- canonical_host is exposed so catalog_pull's `policy` apply() writes
-- shared_dict keys with the same normalisation get() reads. Drift between
-- the two would resurface the case-sensitivity bug this guards against.
_M.canonical_host = canonical_host

-- enforce(status) — physically exit with `status` iff the current Host's
-- policy is mode=active. mode=shadow returns nil so the caller falls
-- through to its next instruction (typically continuing the cascade and
-- proxying to origin). The would-be verdict must already be recorded via
-- bac_log.set_verdict before this call so analytics see the block intent
-- in either mode.
function _M.enforce(status)
    if _M.get(ngx.var.host).mode == "active" then
        return ngx.exit(status)
    end
end

return _M
