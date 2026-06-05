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
-- Policy fields are passed through verbatim from the Channel C payload, so
-- get(host).origin_ip (multi-tenant routing, 86exrefdz) is available without
-- a dedicated reader: proxy_target.lua treats a non-empty origin_ip as the
-- marker of a proxied tenant. POOL_DEFAULT deliberately omits origin_ip
-- (nil → unregistered host is not a tenant → dropped with 444).
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

-- decode_entry(raw, host) — decode one shared_dict raw Policy value + enum-guard
-- it. Shared by the walk-up in lookup(). Always returns a non-nil Policy table.
--
-- Enum guards: a malformed Policy missing `mode` / carrying an unknown value
-- would otherwise silently degrade an active client to shadow
-- (`nil == "active"` is false). Fail to pool default + ERR so the
-- misconfiguration is visible. origin_ip is PRESERVED through this fallback:
-- routing (proxy_target, 86exrefdz) must not depend on mode/strictness
-- validity, otherwise a forward-compat schema change would silently deroute
-- a tenant to the non-tenant 444 drop instead of just failing enforcement stale.
local function decode_entry(raw, host)
    local p, err = cjson.decode(raw)
    if not p or type(p) ~= "table" then
        ngx.log(ngx.ERR, "policy: decode failed for ", host, ": ", tostring(err))
        return new_pool_default()
    end
    local function fallback()
        local d = new_pool_default()
        if type(p.origin_ip) == "string" and p.origin_ip ~= "" then
            d.origin_ip = p.origin_ip
        end
        return d
    end
    if type(p.mode) ~= "string" or not VALID_MODES[p.mode] then
        ngx.log(ngx.ERR, "policy: invalid mode for ", host, ": ",
            tostring(p.mode), " — falling back to pool default")
        return fallback()
    end
    if type(p.strictness) ~= "string" or not VALID_STRICTNESSES[p.strictness] then
        ngx.log(ngx.ERR, "policy: invalid strictness for ", host, ": ",
            tostring(p.strictness), " — falling back to pool default")
        return fallback()
    end
    return p
end

-- lookup(host) — uncached read path with PARENT-DOMAIN fallback (86exrefdz).
-- A client onboards a whole DOMAIN, so policy must cover its subdomains too
-- (otherwise `www.<domain>` and friends fall to pool-default shadow / non-
-- tenant). We try the exact host, then strip the leftmost label and retry up
-- the domain, returning the FIRST existing entry (most specific wins): a single
-- `пример.рф` row covers `www.пример.рф`, `app.пример.рф`, … with the same
-- mode/strictness/origin_ip, while an explicit `api.пример.рф` row still
-- overrides for that subdomain. Public-suffix-safe: the walk only matches rows
-- that actually exist, and nobody registers a policy for `рф` / `co.uk`.
-- Always returns a non-nil Policy table so callers can read fields directly.
local function lookup(host)
    if not host or host == "" then return new_pool_default() end
    local dict = ngx.shared.antibot_policy
    local meta = ngx.shared.meta
    if not dict or not meta then return new_pool_default() end
    local gen = meta:get("antibot_policy_gen")
    if not gen then return new_pool_default() end

    local candidate = string.lower(host)
    while candidate and candidate ~= "" do
        local key = canonical_host(candidate)
        local raw = key and dict:get(key .. ":" .. gen)
        if raw then
            return decode_entry(raw, candidate)
        end
        -- Strip the leftmost label: www.x.com → x.com → com → stop.
        local dot = candidate:find(".", 1, true)
        if not dot then break end
        local parent = candidate:sub(dot + 1)
        -- Defense-in-depth: never walk up to a single-label candidate (a bare
        -- TLD like "com" / "рф"=xn--p1ai). The backend ValidateSite rejects
        -- public-suffix policy rows at write time (codex P1 on PR #100), so a
        -- public-suffix row can only exist via manual SQL — this stops the walk
        -- from inheriting it. (Single-label EXACT lookups still work — internal
        -- hosts like `staging` are matched on the first iteration above.)
        if not parent:find(".", 1, true) then break end
        candidate = parent
    end
    return new_pool_default()
end

-- get(host) → Policy table. Per-request memoization on ngx.ctx: the same
-- host is read multiple times per request (policy.enforce in the cascade,
-- bac_log.emit in log_by_lua), each call would otherwise repeat a
-- shared_dict lookup + cjson.decode of the full Policy JSON. Cache is
-- keyed by canonical host so /__policy?host=other still gets a fresh
-- lookup for a different name. Cache lives for one request only and dies
-- with ngx.ctx; gen-flips between two reads in the same request are
-- intentionally not visible (consistency within a single request > 30s
-- staleness window across requests).
--
-- READ-ONLY CONTRACT: callers MUST NOT mutate the returned table. The
-- same instance is handed back for every get() on the same host in the
-- same request — mutating it would smash the cached view for every
-- subsequent caller in this request (most often bac_log.emit reading
-- mode/strictness for the access record). If a future caller needs to
-- augment per-host state, attach it to ngx.ctx, not to the Policy table.
--
-- The `if not ctx` fallback is a belt-and-braces guard for callers in
-- phases where ngx.ctx isn't a table (e.g., balancer_by_lua* on some
-- builds). It will never fire from init_by_lua* — accessing ngx.ctx in
-- those phases raises before this check can run.
function _M.get(host)
    local ctx = ngx.ctx
    if not ctx then return lookup(host) end
    local key = canonical_host(host) or ""
    local cache = ctx.policy_cache
    if not cache then
        cache = {}
        ctx.policy_cache = cache
    end
    local hit = cache[key]
    if hit ~= nil then return hit end
    local p = lookup(host)
    cache[key] = p
    return p
end

-- canonical_host is exposed so catalog_pull's `policy` apply() writes
-- shared_dict keys with the same normalisation get() reads. Drift between
-- the two would resurface the case-sensitivity bug this guards against.
_M.canonical_host = canonical_host

-- origin_ip(host) — ctx-free read of a host's origin_ip (or nil). Used by
-- tls_autossl.allow_domain in the ssl_certificate_by_lua phase, where
-- ngx.ctx is not reliably a per-request table (it can leak across the
-- handshake), so the ctx-memoized get() is unsafe there. This calls lookup()
-- directly — one shared_dict read + decode per TLS handshake, which is fine
-- (handshakes are far rarer than requests, and on-demand issuance only
-- happens once per domain). Returns the string origin_ip or nil.
function _M.origin_ip(host)
    return lookup(host).origin_ip
end

-- enforce(status, headers) — physically exit with `status` iff the
-- current Host's policy is mode=active. mode=shadow returns nil so the
-- caller falls through to its next instruction (typically continuing
-- the cascade and proxying to origin). The would-be verdict must
-- already be recorded via bac_log.set_verdict before this call so
-- analytics see the block intent in either mode.
--
-- Optional `headers` table is applied via ngx.header[k]=v BEFORE the
-- exit — used for rate-limit's `Retry-After` (phase1-spec §"429 с
-- Retry-After") and future challenge response headers. Skipped in
-- shadow mode: the response is going to origin, our headers would
-- pollute the user's traffic.
function _M.enforce(status, headers)
    if _M.get(ngx.var.host).mode == "active" then
        if headers then
            for k, v in pairs(headers) do
                ngx.header[k] = v
            end
        end
        return ngx.exit(status)
    end
end

return _M
