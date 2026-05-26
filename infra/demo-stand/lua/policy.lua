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
-- Today the only caller is verdict.lua:101 (tls_fp_blocklist). Future
-- enforcement points (rate_limit 429, hygiene/reputation per-host block,
-- challenge) hook into the same helper — see PROGRESS.md follow-up tickets.

local _M = {}

local cjson = require "cjson.safe"

-- POOL_DEFAULT: must match catalog.PoolDefault() in the backend
-- (antibot-backend/internal/catalog/data.go:170). Empty tables use `{}`
-- which Lua treats as an array-shaped value — fine for our readers
-- (bac_log emits mode/strictness only; /__policy serialises whole struct
-- and cjson.encode renders `{}` as a JSON array, but consumers
-- (dashboard / Channel C clients) already expect array-shape for these
-- list fields, see Data.Policy field tags).
local POOL_DEFAULT = {
    mode         = "shadow",
    strictness   = "standard",
    ua_blacklist = {},
    ip_whitelist = {},
    ip_blocklist = {},
    asn_block    = {},
    geo_whitelist = {},
    rate_rules   = {},
    attack_mode  = false,
}

-- get(host) → Policy table. Always non-nil. Falls back to POOL_DEFAULT on
-- any miss/error so callers can read `.mode` / `.strictness` directly
-- without nil-guards.
function _M.get(host)
    if not host or host == "" then return POOL_DEFAULT end
    local dict = ngx.shared.antibot_policy
    local meta = ngx.shared.meta
    if not dict or not meta then return POOL_DEFAULT end
    local gen = meta:get("antibot_policy_gen")
    if not gen then return POOL_DEFAULT end
    local raw = dict:get(host .. ":" .. gen)
    if not raw then return POOL_DEFAULT end
    local p, err = cjson.decode(raw)
    if not p or type(p) ~= "table" then
        ngx.log(ngx.ERR, "policy: decode failed for ", host, ": ", tostring(err))
        return POOL_DEFAULT
    end
    return p
end

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
