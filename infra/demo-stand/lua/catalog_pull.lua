-- Channel C client on the edge (B5, RFC §В1).
--
-- Background ngx.timer.every per catalog: conditional GET against
-- antibot-backend, atomic generation swap into the catalog's
-- lua_shared_dict, explicit cleanup of the old generation. Fail-stale:
-- any transport / status / decode / version error is logged and skipped;
-- the previous generation stays in the dict, the timer keeps ticking.
--
-- Layout:
--   _M.catalogs     — per-catalog descriptors (endpoint, dict name, apply +
--                     sweep functions, meta-key names).
--   _M.handle_response(cat, dict, meta, res, err)
--                   — pure-ish response handler used both by fetch() and by
--                     tests. Returns "ok" / "not_modified" / "skip".
--   _M.fetch(name)  — one tick: build httpc, request, dispatch to
--                     handle_response.
--   _M.start(opts)  — wire ngx.timer.every per catalog in
--                     init_worker_by_lua_block. Guarded to worker 0 so a
--                     pool with N workers does N× fewer pulls, not N×.
--
-- Catalogs wired today (each has an edge consumer):
--   * tls_fp_blocklist        — verdict.lua (§A1 `fp:gen` lookup) + tls_fp
--                               staging (tls_fp.refresh, A11).
--   * verified_bot_ips        — verified_bots.lua (B8) bot_verified / pending.
--   * tls_fp_catalog          — tls_fp.lua tls_fp_impersonator (+ staging).
--   * tls_fp_browser_profiles — tls_fp.lua tls_fp_suspicious_ciphers (+ staging).
--   * ua_blacklist            — hygiene.lua (active + staging, A11 86exrtjpc).
--                               Object payload {active:<combined>, staging:[…]},
--                               stored as `active:<gen>` / `staging:<gen>`.
--   * ip_blocklist            — reputation.lua (active + staging, A11 86exrtjpc).
--                               Per-key `<cidr>:<gen>` → "<status>:block".
--   * policy                  — policy.lua / policy_matchers (B11).
-- ip_whitelist / asn_datacenters remain edge-local conf for now (their Channel C
-- migration is a follow-up — adding a descriptor without a consumer would write
-- to a dict nobody reads).

local cjson        = require "cjson.safe"
local fp_state     = require "tls_fp_blocklist_state"

local _M = {}

-- Major version of the X-Catalog-Version header we accept. Bump in lockstep
-- with backend B3 payload-shape changes; an incompatible major keeps the
-- previous generation and bumps edge_sidecar_version_mismatch_total.
_M.SUPPORTED_VERSION_MAJOR = "1"

-- Per-catalog payload writers / sweepers. `apply` writes the decoded body
-- into the dict under the NEW generation; `sweep` deletes the OLD gen's keys
-- after the gen flip (RFC §В1 explicit cleanup — per-entry TTL is wrong here
-- because the 304 short-circuit means entries never get re-written and would
-- silently age out, see §В1 "Why explicit cleanup instead of per-entry TTL").
-- Each descriptor carries `name` = the catalog-identifier (key in this
-- table) duplicated as a field, so handle_response can stamp metrics under
-- the CATALOG name rather than the dict name. metrics.lua iterates the
-- known catalogs by name and reads `catalog_last_pull_ts:<name>` /
-- `edge_sidecar_version_mismatch_total:<name>` — for tls_fp_blocklist the two
-- are the same string and the bug was invisible; verified_bot_ips
-- (dict_name=verified_bots) is the case that surfaced it (PR #55 review P1).
-- Keeping `name` and `dict_name` distinct also leaves room for two catalogs
-- to share a dict in the future (none today).
_M.catalogs = {
    tls_fp_blocklist = {
        name        = "tls_fp_blocklist",
        endpoint    = "/catalog/tls_fp_blocklist",
        dict_name   = "tls_fp_blocklist",
        gen_key     = fp_state.META_GEN_KEY,   -- "tls_fp_blocklist_gen"
        etag_key    = fp_state.META_ETAG_KEY,
        version_key = "tls_fp_blocklist_version",
        -- Возвращает (ok, count). `ok=false` если хоть один dict:set провалился
        -- (типично "no memory" при фрагментации shared_dict, либо ключ длиннее
        -- 255 байт). handle_response в этом случае откатится до flip'a и
        -- НЕ перейдёт на битое поколение — иначе sweep удалил бы старый gen,
        -- и в worst case эдж остался бы с частично записанным/пустым каталогом
        -- (gemini/codex review: violation of fail-stale).
        apply = function(dict, entries, new_gen)
            local n = 0
            for fp, verdict in pairs(entries) do
                local ok, err = dict:set(fp_state.key(fp, new_gen), verdict)
                if not ok then
                    ngx.log(ngx.ERR, "tls_fp_blocklist:set failed: ", err,
                        " (fp=", fp, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        -- get_keys(0) lock'ает весь shared_dict на время скана. Для текущего
        -- размера каталога (десятки–сотни fp) это микросекунды; gemini-review
        -- отметила, что на десятках тысяч ключей блокировка станет видна на
        -- p99 — тогда поедем на side-index "keys-of-gen-N" в отдельном ключе
        -- meta'и. Пока что 100% RFC §В1 алгоритм + комментарий.
        --
        -- Матчим через fp_state.match() (типизированный инверс key()) вместо
        -- сырого `:<gen>` суффикса: если в этот dict когда-нибудь начнёт
        -- писать что-то ещё (admin.lua, со-tenant каталог), сырой суффикс
        -- удалил бы их по совпадению хвоста (например, `manual_override:1`
        -- при sweep(1)). fp_state.match возвращает nil на любом ключе, чей
        -- хвост не соответствует ИМЕННО формату tls_fp_blocklist'a — sweep
        -- останется сфокусированным на своих записях.
        sweep = function(dict, old_gen)
            -- old_gen == 0 is the static seed from init.lua; sweeping it on
            -- the first pull is intentional — once the live catalog lands,
            -- the seed becomes redundant.
            if old_gen < 0 then return 0 end
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if fp_state.match(k, old_gen) then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },

    -- verified_bot_ips (B8) — map(ip → "<status>:<family>") with status
    -- in {verified, rejected} (config-distribution.md §catalogs). Stored
    -- key is `<ip>:<gen>`, mirroring tls_fp_blocklist's §В1 atomic-swap shape
    -- so two generations coexist during the write→flip→sweep window.
    -- Reader: verified_bots.classify(ip) composes the key from
    -- meta:get("verified_bots_gen"). Empty dict ⇒ all searchbot UAs land
    -- in provisional fastpath (bot_verified_pending), which is the
    -- SEO-safe default for a stand without backend (vision §Шаг 2.2).
    verified_bot_ips = {
        name        = "verified_bot_ips",
        endpoint    = "/catalog/verified_bot_ips",
        dict_name   = "verified_bots",
        gen_key     = "verified_bots_gen",
        etag_key    = "verified_bots_etag",
        version_key = "verified_bots_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for ip, val in pairs(entries) do
                local ok, err = dict:set(ip .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "verified_bots:set failed: ", err,
                        " (ip=", ip, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        -- Suffix-match `:<old_gen>` to find this generation's keys. The
        -- dict is written exclusively by this catalog (no admin.lua / no
        -- co-tenant), so the IP-shaped prefix has no collisions to worry
        -- about; if a future writer joins, switch to a typed match the
        -- way fp_state.match() guards tls_fp_blocklist (see tls_fp_blocklist's
        -- sweep comment for the worked example).
        --
        -- Перформанс — тот же trade-off, что в tls_fp_blocklist sweep'e:
        -- `dict:get_keys(0)` лочит весь shared_dict на время скана.
        -- nginx.demo.conf размечает verified_bots под "tens of thousands
        -- of IPs", где блокировка становится видна на p99 (gemini-review
        -- B5 и снова на этом PR). План тот же: side-index «keys-of-gen-N»
        -- в отдельном ключе `meta`, чтобы sweep шёл по узкому списку
        -- вместо полного скана. Пока что осознанно держим симметрию с
        -- tls_fp_blocklist'ом (RFC §В1 алгоритм) — мигрируем оба каталога
        -- одной задачей, когда реальный размер verified_bot_ips перейдёт
        -- этот порог (на стенде без backend dict пустой, фактического
        -- риска нет).
        sweep = function(dict, old_gen)
            -- The suffix-string match below is only safe for numeric, small,
            -- monotonically-growing generation IDs (no `:` inside, no
            -- string-typed gens). Lock that assumption load-bearing so a
            -- future change to non-numeric gens (e.g. a content hash to
            -- dedupe identical pulls) fails LOUD here instead of silently
            -- shadowing IP-shaped keys (review #5 on PR #55).
            assert(type(old_gen) == "number",
                "verified_bot_ips.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
            if old_gen < 0 then return 0 end
            local suffix = ":" .. old_gen
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if k:sub(-#suffix) == suffix then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },

    -- tls_fp_catalog (PR2, ADR-006) — каталог сигнатур автоматизации для
    -- tls_fp_impersonator (Phase 2+). Wire-payload: map(hash_b →
    -- "<status>:<family>"), симметрично verified_bot_ips. status ∈
    -- {active, staging}; staging читается, но эмитится только staging_match,
    -- не verdict (A11 staged rollout). Reader — tls_fp.read_entry().
    tls_fp_catalog = {
        name        = "tls_fp_catalog",
        endpoint    = "/catalog/tls_fp_catalog",
        dict_name   = "tls_fp_catalog",
        gen_key     = "tls_fp_catalog_gen",
        etag_key    = "tls_fp_catalog_etag",
        version_key = "tls_fp_catalog_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for hb, val in pairs(entries) do
                local ok, err = dict:set(hb .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "tls_fp_catalog:set failed: ", err,
                        " (hash_b=", hb, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        -- Тот же suffix-match подход, что и verified_bot_ips: gen — numeric,
        -- hash_b — hex без `:`. Контракт оставляем явным assert'ом на случай,
        -- если в будущем кто-то решит сделать gen строковым (content-hash).
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "tls_fp_catalog.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
            if old_gen < 0 then return 0 end
            local suffix = ":" .. old_gen
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if k:sub(-#suffix) == suffix then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },

    -- tls_fp_browser_profiles (PR2, ADR-006) — каталог ожидаемых cipher_cnt
    -- для семейств браузеров (tls_fp_suspicious_ciphers, Phase 2+).
    -- Wire-payload: map(family → "<status>:<expected_cipher_cnt>"). Малый
    -- размер (единицы записей), но единая модель atomic-swap для
    -- консистентности с остальными Channel C каталогами.
    tls_fp_browser_profiles = {
        name        = "tls_fp_browser_profiles",
        endpoint    = "/catalog/tls_fp_browser_profiles",
        dict_name   = "tls_fp_browser_profiles",
        gen_key     = "tls_fp_browser_profiles_gen",
        etag_key    = "tls_fp_browser_profiles_etag",
        version_key = "tls_fp_browser_profiles_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for family, val in pairs(entries) do
                local ok, err = dict:set(family .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "tls_fp_browser_profiles:set failed: ", err,
                        " (family=", family, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "tls_fp_browser_profiles.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
            if old_gen < 0 then return 0 end
            local suffix = ":" .. old_gen
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if k:sub(-#suffix) == suffix then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },

    -- ua_blacklist (A11, 86exrtjpc) — Channel C catalog of system UA patterns.
    -- Wire-payload is an OBJECT, not a per-key map: { "active": "<combined
    -- regex>", "staging": ["<pattern>", …] } (store.buildUABlacklist). We stash
    -- two keys per generation: `active:<gen>` (the combined string, used by
    -- hygiene with ngx.re "jo") and `staging:<gen>` (cjson array, matched
    -- per-pattern for staging_match attribution). hygiene.refresh() reads both
    -- on a gen flip. Reader builds nothing per-request beyond a gen compare.
    ua_blacklist = {
        name        = "ua_blacklist",
        endpoint    = "/catalog/ua_blacklist",
        dict_name   = "antibot_ua_blacklist",
        gen_key     = "ua_blacklist_gen",
        etag_key    = "ua_blacklist_etag",
        version_key = "ua_blacklist_version",
        apply = function(dict, entries, new_gen)
            -- entries = { active = "<combined>", staging = { ... } }. A missing
            -- field is tolerated (treated as empty) so a partial payload can't
            -- crash the pull — handle_response already type-checked `entries`
            -- is a table.
            local active = entries.active
            if type(active) ~= "string" then active = "" end
            local ok1, err1 = dict:set("active:" .. new_gen, active)
            if not ok1 then
                ngx.log(ngx.ERR, "ua_blacklist:set active failed: ", err1,
                    " (gen=", new_gen, ")")
                return false, 0
            end
            local staging = entries.staging
            if type(staging) ~= "table" then staging = {} end
            local encoded, eerr = cjson.encode(staging)
            if not encoded then
                ngx.log(ngx.ERR, "ua_blacklist:encode staging failed: ",
                    tostring(eerr), " (gen=", new_gen, ")")
                return false, 1
            end
            local ok2, err2 = dict:set("staging:" .. new_gen, encoded)
            if not ok2 then
                ngx.log(ngx.ERR, "ua_blacklist:set staging failed: ", err2,
                    " (gen=", new_gen, ")")
                return false, 1
            end
            return true, 2
        end,
        -- Fixed two-key layout per gen, so sweep just deletes the old gen's
        -- `active:` and `staging:` keys (no get_keys scan needed).
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "ua_blacklist.sweep: old_gen must be a number, got " ..
                type(old_gen))
            if old_gen < 0 then return 0 end
            local n = 0
            if dict:get("active:" .. old_gen) ~= nil then
                dict:delete("active:" .. old_gen); n = n + 1
            end
            if dict:get("staging:" .. old_gen) ~= nil then
                dict:delete("staging:" .. old_gen); n = n + 1
            end
            return n
        end,
    },

    -- ip_blocklist (A11, 86exrtjpc) — Channel C catalog of system IP/CIDR
    -- blocks. Wire-payload: map(cidr → "<status>:block") (store.buildIPBlocklist).
    -- Keys `<cidr>:<gen>` (suffix-match sweep, same shape as verified_bot_ips —
    -- CIDR may contain `:` for IPv6, but the gen is always the last `:`-segment).
    -- reputation.refresh() rebuilds the active matcher + staging matcher on a
    -- gen flip. The per-host policy ip_blocklist is a SEPARATE catalog (policy)
    -- applied via policy_matchers — not merged here.
    ip_blocklist = {
        name        = "ip_blocklist",
        endpoint    = "/catalog/ip_blocklist",
        dict_name   = "antibot_ip_blocklist",
        gen_key     = "ip_blocklist_gen",
        etag_key    = "ip_blocklist_etag",
        version_key = "ip_blocklist_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for cidr, val in pairs(entries) do
                local ok, err = dict:set(cidr .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "ip_blocklist:set failed: ", err,
                        " (cidr=", cidr, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "ip_blocklist.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
            if old_gen < 0 then return 0 end
            local suffix = ":" .. old_gen
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if k:sub(-#suffix) == suffix then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },

    -- policy (B11) — per-host Policy table delivered by Channel C as a
    -- single map(host → Policy). Wire-payload: JSON object where each
    -- value is the full Policy struct (mode/strictness/ua_blacklist/
    -- ip_blocklist/.../attack_mode). We re-encode each value as JSON
    -- before stashing under `<host>:<gen>` so the reader (policy.lua)
    -- does one cjson.decode per request — symmetric with verified_bots
    -- and tls_fp_catalog but at table granularity. Endpoint is called
    -- without `?site=` to pull the whole map at once; on the demo we
    -- have ≤O(10) clients, fits comfortably in 1m antibot_policy dict.
    --
    -- Host normalisation goes through policy.canonical_host so the
    -- write key matches what policy.get() looks up at request time
    -- (lowercased + length-capped). Backend may store a host with mixed
    -- case via PATCH; without the same normalisation here, the edge
    -- would silently miss and fall back to POOL_DEFAULT, masking active
    -- mode for the affected client.
    policy = {
        name        = "policy",
        endpoint    = "/catalog/policy",
        dict_name   = "antibot_policy",
        gen_key     = "antibot_policy_gen",
        etag_key    = "antibot_policy_etag",
        version_key = "antibot_policy_version",
        apply = function(dict, entries, new_gen)
            local canonical_host = require("policy").canonical_host
            -- Pre-flight: backend ValidateSite is case-preserving
            -- (validate.go:19-20), so two distinct policy rows whose
            -- hosts differ only by case (`Foo.example.com` and
            -- `foo.example.com`) collapse to the same shared_dict key
            -- after canonical_host. Lua's pairs() iteration order is
            -- unspecified, so picking "first-seen" would resolve which
            -- mode wins arbitrarily and inconsistently across pulls.
            -- Fail-stale instead: detect ALL collisions before any
            -- write, return false → handle_response keeps the previous
            -- gen, the operator sees an ERR for each duplicate and
            -- collapses the rows at the backend (or fixes case there).
            -- Skip empty keys (they were already silently ignored).
            local seen = {}
            local collided = false
            for host, _ in pairs(entries) do
                local key_host = canonical_host(host)
                if key_host then
                    if seen[key_host] then
                        ngx.log(ngx.ERR, "antibot_policy: host case collision: '",
                            host, "' and '", seen[key_host],
                            "' both canonicalize to '", key_host,
                            "' — failing the pull; collapse the duplicate at the backend")
                        collided = true
                    else
                        seen[key_host] = host
                    end
                end
            end
            if collided then
                return false, 0
            end
            local n = 0
            for host, p in pairs(entries) do
                local key_host = canonical_host(host)
                if not key_host then
                    ngx.log(ngx.WARN, "antibot_policy: skipping empty host key")
                else
                    local encoded, eerr = cjson.encode(p)
                    if not encoded then
                        ngx.log(ngx.ERR, "antibot_policy:encode failed: ",
                            tostring(eerr), " (host=", host, ", gen=", new_gen, ")")
                        return false, n
                    end
                    local ok, err = dict:set(key_host .. ":" .. new_gen, encoded)
                    if not ok then
                        ngx.log(ngx.ERR, "antibot_policy:set failed: ", err,
                            " (host=", host, ", gen=", new_gen, ")")
                        return false, n
                    end
                    n = n + 1
                end
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "policy.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
            if old_gen < 0 then return 0 end
            local suffix = ":" .. old_gen
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if k:sub(-#suffix) == suffix then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },
}

-- bump_metric — best-effort counter increment on the `metrics` shared_dict.
-- Same convention as log_event.lua; missing dict is silent so this module
-- still works in tests that don't wire a metrics dict.
local function bump_metric(key)
    local m = ngx.shared.metrics
    if m then m:incr(key, 1, 0) end
end

-- bump_last_pull_ts — stamp `catalog_last_pull_ts:<name>` with the current
-- time, where `name` is the catalog identifier (descriptor key) — NOT the
-- dict_name. metrics.lua iterates `catalog_pull.catalogs` by key and reads
-- this metric under the same key; using `dict_name` makes the staleness
-- gauge stuck at -1 for any catalog whose dict has a different name (this
-- was invisible for tls_fp_blocklist where name==dict_name; PR #55 review P1
-- surfaced it via verified_bot_ips → dict verified_bots). Called from both
-- the 200 and 304 paths in handle_response (both are "successful contact
-- with backend" — see the 304 branch comment for why this is a liveness
-- rather than freshness signal). Missing metrics dict is silent for the
-- same test-harness reason as bump_metric.
local function bump_last_pull_ts(cat)
    local m = ngx.shared.metrics
    if m then m:set("catalog_last_pull_ts:" .. cat.name, ngx.time()) end
end

-- version_compatible — single-major check. Accepts "1", "1.x", "1.x.y". An
-- empty / missing header is treated as compatible: older backend builds may
-- not set the header, and a missing header is an operator concern (visible
-- in logs), not a correctness one.
function _M.version_compatible(version)
    if not version or version == "" then return true end
    local major = version:match("^(%d+)")
    if not major then return false end
    return major == _M.SUPPORTED_VERSION_MAJOR
end

-- handle_response — process one HTTP result and apply it (or skip) under
-- the catalog descriptor. Returns one of:
--   "ok"           — 200 applied, gen flipped, old gen swept.
--   "not_modified" — 304, nothing touched (regression guard from round-3
--                    review: NEVER zero entries on 304).
--   "skip"         — anything else (transport error, non-200 status,
--                    decode failure, wrong decoded type, version
--                    mismatch). Previous generation stays in the dict.
function _M.handle_response(cat, dict, meta, res, err)
    -- Transport error: timeout, connection refused — lua-resty-http returns
    -- res=nil with err set.
    if res == nil then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, " fetch failed: ",
            tostring(err))
        return "skip"
    end

    if res.status == 304 then
        -- Round-3 regression: do NOT touch dict, do NOT bump gen. The 304
        -- short-circuit is the steady state — without this guard a catalog
        -- that hasn't changed for an hour would silently empty out.
        --
        -- BUT do bump catalog_last_pull_ts. 304 means backend answered and
        -- the ETag matched — Channel C is healthy, just no new data. The
        -- staleness gauge is meant to drive alerting on a dead channel
        -- (config-distribution §Channel C "edge_catalog_staleness_seconds
        -- ... drives alerting" with the ≤30s / ≤15m SLA from the B6 spec),
        -- not on stale-but-correct data. Skipping the bump here made the
        -- gauge grow linearly between catalog updates — for a `tls_fp_blocklist`
        -- that changes weekly via PR, the alert would fire 24/7 even with
        -- a perfectly healthy backend. Bump on 304 so the gauge means
        -- "seconds since the last successful contact" (the contract the
        -- alert is actually checking), not "seconds since the last data
        -- change" (a freshness signal that needs its own metric if we ever
        -- want it).
        bump_last_pull_ts(cat)
        return "not_modified"
    end

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, ": HTTP ", res.status)
        return "skip"
    end

    local version = res.headers and res.headers["X-Catalog-Version"]
    if not _M.version_compatible(version) then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, ": version mismatch ",
            tostring(version), " vs major=", _M.SUPPORTED_VERSION_MAJOR)
        -- Same naming contract as bump_last_pull_ts: keyed by the catalog
        -- NAME (descriptor key), which is what metrics.lua reads back.
        bump_metric("edge_sidecar_version_mismatch_total:" .. cat.name)
        return "skip"
    end

    -- cjson.safe returns nil + err on malformed JSON. The RFC §В1 pcall+
    -- type-check is collapsed into one decode (.safe never throws) plus
    -- one type check. The type check guards against decoded-but-not-a-table
    -- (a top-level JSON string/number is valid JSON but would crash pairs).
    local body = res.body or ""
    local entries, derr = cjson.decode(body)
    if entries == nil then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint,
            ": decode failed: ", tostring(derr))
        return "skip"
    end
    if type(entries) ~= "table" then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint,
            ": decoded value is ", type(entries), ", expected table")
        return "skip"
    end

    -- Order matters: write the new gen first, then flip the gen counter,
    -- then sweep the old gen. A reader that read meta:gen before the flip
    -- still resolves to old_gen and finds its entries; a reader that reads
    -- after the flip resolves to new_gen and finds those. See RFC §В1
    -- "Atomically flip readers" and verdict.lua's `fp:gen` lookup.
    local old_gen = meta:get(cat.gen_key) or 0
    local new_gen = old_gen + 1

    -- Apply: если хоть один dict:set провалился (no memory / key too long) —
    -- НЕ flip'аем gen и НЕ sweep'аем старый. Параллельно подчищаем уже
    -- записанные ключи нового gen, чтобы они не висели до следующего pull'a
    -- (occupying shared_dict впустую). Edge остаётся на прежнем gen,
    -- следующий тик попробует снова — fail-stale (gemini/codex review).
    local apply_ok, written = cat.apply(dict, entries, new_gen)
    if not apply_ok then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint,
            ": apply failed after ", written, " writes — keeping gen=", old_gen)
        cat.sweep(dict, new_gen)
        return "skip"
    end

    -- Сам flip. meta:set на 1m shared_dict с одним int практически не падает,
    -- но если упал — каталог нового gen уже в dict, а readers всё ещё резолвят
    -- старый. Сводим к тому же fail-stale: подчистим новый gen и держим старый.
    local ok_flip, flip_err = meta:set(cat.gen_key, new_gen)
    if not ok_flip then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, ": gen flip failed: ",
            tostring(flip_err), " — rolling back, keeping gen=", old_gen)
        cat.sweep(dict, new_gen)
        return "skip"
    end

    local etag = res.headers and res.headers["ETag"]
    if etag then meta:set(cat.etag_key, etag) end
    if version then meta:set(cat.version_key, version) end

    cat.sweep(dict, old_gen)

    -- Last-successful-contact timestamp drives edge_catalog_staleness_seconds
    -- in metrics.lua (gauge = now - last). Bumped on 200 (here) and on 304
    -- (above) — both mean "backend answered". A long run of skips (transport
    -- errors / non-200/304 statuses / decode failures) makes the gauge grow,
    -- which is the alert condition.
    bump_last_pull_ts(cat)

    return "ok"
end

-- Per-catalog in-flight guard. ngx.timer.every fires on its own schedule
-- regardless of whether the previous tick has finished; if a fetch takes
-- longer than the interval (slow backend, DNS retries, total per-step
-- timeout > interval), two ticks can run concurrently inside the worker
-- and interleave apply/flip/sweep on the same catalog. Worst observed
-- case: tick B's sweep(old_gen) deletes tick A's just-written entries
-- while requests already pinned to that gen are mid-lookup, briefly
-- falling through to "allow". Since OpenResty Lua is single-threaded
-- per worker (yields only on I/O), a plain table flag is enough — no
-- semaphore needed.
local in_flight = {}

-- fetch — one tick for one catalog. Resolves shared dicts, builds the
-- httpc, sends the conditional GET, hands the result to handle_response.
-- Any uncaught error inside is swallowed by the pcall in tick() so the
-- ngx.timer keeps running.
function _M.fetch(catalog_name)
    local cat = _M.catalogs[catalog_name]
    if not cat then
        ngx.log(ngx.ERR, "catalog_pull: unknown catalog ", tostring(catalog_name))
        return
    end

    -- In-flight guard: skip this tick if the previous one for the same
    -- catalog is still inside httpc:request_uri / handle_response. The
    -- skipped tick is just lost cadence — next ngx.timer.every firing
    -- will retry. No mutex contention because of single-threaded Lua.
    if in_flight[catalog_name] then
        ngx.log(ngx.NOTICE, "catalog_pull ", catalog_name,
            ": previous tick still in flight — skipping this one")
        return
    end
    in_flight[catalog_name] = true

    local dict = ngx.shared[cat.dict_name]
    local meta = ngx.shared.meta
    if not dict or not meta then
        ngx.log(ngx.ERR, "catalog_pull: missing shared_dict for ", catalog_name)
        in_flight[catalog_name] = nil
        return
    end

    local httpc_mod = _M.http_module
    if not httpc_mod then
        ngx.log(ngx.ERR, "catalog_pull: http module not configured")
        in_flight[catalog_name] = nil
        return
    end
    local httpc = httpc_mod.new()
    httpc:set_timeout(_M.timeout_ms)

    local etag = meta:get(cat.etag_key)
    local headers = { ["If-None-Match"] = etag or "" }
    if _M.backend_host_header then
        headers["Host"] = _M.backend_host_header
    end

    local req_opts = {
        method   = "GET",
        headers  = headers,
        ssl_verify = _M.ssl_verify,
    }
    -- [B6] mTLS — pass the pre-parsed client cert/key if start() managed to
    -- load them. Either both or neither (verified at load time); a partial
    -- parse leaves _M.parsed_cert == nil so we silently fall back to HTTPS
    -- without a client cert, which the backend will reject with a handshake
    -- error when AUTH_MODE=mtls — caught by the standard fail-stale path.
    if _M.parsed_cert and _M.parsed_key then
        req_opts.ssl_client_cert = _M.parsed_cert
        req_opts.ssl_client_priv_key = _M.parsed_key
    end
    local res, err = httpc:request_uri(_M.backend_url .. cat.endpoint, req_opts)

    -- pcall — handle_response может бросить из cat.apply/cat.sweep
    -- (например, через ngx.log при экзотическом аргументе). В этом случае
    -- in_flight остался бы взведённым навсегда и каталог тихо застрял.
    local ok, perr = pcall(_M.handle_response, cat, dict, meta, res, err)
    in_flight[catalog_name] = nil
    if not ok then
        ngx.log(ngx.ERR, "catalog_pull ", catalog_name,
            ": handle_response raised: ", perr)
    end
end

-- load_mtls_material — read PEM files and parse into the cdata form
-- lua-resty-http expects (ssl_client_cert / ssl_client_priv_key, returned by
-- ngx.ssl.parse_pem_cert / parse_pem_priv_key). Called once from start() in
-- init_worker_by_lua_block where ngx.ssl is available.
--
-- Failure mode: any error (file missing, parse failed, ngx.ssl absent) logs
-- and returns nil — _M.parsed_cert stays nil and fetch() proceeds without
-- mTLS. If the backend's AUTH_MODE=mtls that handshake fails and falls into
-- the normal fail-stale path (skip + previous gen preserved); operator sees
-- the error in error.log + a stuck staleness gauge in /metrics.
local function read_file(path)
    local f, ferr = io.open(path, "rb")
    if not f then return nil, ferr end
    local data, rerr = f:read("*a")
    f:close()
    if not data then return nil, rerr end
    return data
end

-- preload_mtls — call from init_by_lua (master, pre-privilege-drop). Reads
-- the PEM files as root, parses to cdata, and stashes on the module. Workers
-- forked from the master inherit `_M.parsed_cert` / `_M.parsed_key` (Lua
-- state + OpenSSL X509 cdata pointers are COW-shared on fork). Idempotent:
-- already-loaded material isn't re-read.
--
-- Why not just call from start() in init_worker: the worker phase runs after
-- nginx drops to the configured `user` (typically nobody), at which point
-- 0600 root-owned client keys are unreadable and mTLS silently disables.
function _M.preload_mtls(cert_path, key_path)
    if _M.parsed_cert and _M.parsed_key then return end
    _M.parsed_cert, _M.parsed_key = _M.load_mtls_material(cert_path, key_path)
end

function _M.load_mtls_material(cert_path, key_path)
    if not cert_path or cert_path == "" or not key_path or key_path == "" then
        return nil, nil
    end
    local ok_ssl, ssl = pcall(require, "ngx.ssl")
    if not ok_ssl then
        ngx.log(ngx.ERR, "catalog_pull: ngx.ssl not available — mTLS disabled")
        return nil, nil
    end

    local cert_pem, cerr = read_file(cert_path)
    if not cert_pem then
        ngx.log(ngx.ERR, "catalog_pull: read client cert ", cert_path, " failed: ", cerr)
        return nil, nil
    end
    local key_pem, kerr = read_file(key_path)
    if not key_pem then
        ngx.log(ngx.ERR, "catalog_pull: read client key ", key_path, " failed: ", kerr)
        return nil, nil
    end

    local parsed_cert, perr = ssl.parse_pem_cert(cert_pem)
    if not parsed_cert then
        ngx.log(ngx.ERR, "catalog_pull: parse_pem_cert failed: ", perr)
        return nil, nil
    end
    local parsed_key, kperr = ssl.parse_pem_priv_key(key_pem)
    if not parsed_key then
        ngx.log(ngx.ERR, "catalog_pull: parse_pem_priv_key failed: ", kperr)
        return nil, nil
    end
    return parsed_cert, parsed_key
end

-- start — call from init_worker_by_lua_block. Wires one ngx.timer.every per
-- requested catalog, guarded to worker 0 so an N-worker pool issues N×
-- fewer pulls (each catalog has one timer per machine, not per worker;
-- shared dicts are process-wide so a single writer suffices).
-- nonempty — treat empty strings the same as nil. Docker Compose's
-- `${VAR:-}` substitution produces empty strings when an env-var is unset
-- in .env, and an empty backend URL would otherwise be truthy in Lua and
-- send fetch() into the "bad uri" loop every 30s on every stand that
-- doesn't actually have a backend wired.
local function nonempty(s)
    if s == nil or s == "" then return nil end
    return s
end

-- truthy_env — coerce env strings to bool. Anything in (false|0|no|off) is
-- false; nil/empty/anything else is the default. Used for
-- ANTIBOT_BACKEND_SSL_VERIFY so the demo can opt into ssl_verify=false from
-- .env without on-host hacks in nginx.demo.conf (the previous approach made
-- update.sh's git merge --ff-only fragile).
local function truthy_env(s, default)
    s = nonempty(s)
    if s == nil then return default end
    s = s:lower()
    if s == "false" or s == "0" or s == "no" or s == "off" then return false end
    return true
end

function _M.start(opts)
    opts = opts or {}
    -- `nonempty()` is applied to opts as well as envs (gemini-review): a
    -- caller passing `start({ backend_url = "" })` — typically because they
    -- plumbed an env-var through code that didn't normalise it — should
    -- fall through to env / hard default rather than produce a "bad uri"
    -- loop. Same reasoning for the cert paths below.
    _M.backend_url         = nonempty(opts.backend_url)
                             or nonempty(os.getenv("ANTIBOT_BACKEND_URL"))
                             or "http://antibot-backend:8080"
    _M.backend_host_header = nonempty(opts.backend_host_header)
                             or nonempty(os.getenv("ANTIBOT_BACKEND_HOST"))
    _M.timeout_ms          = opts.timeout_ms or 5000
    if opts.ssl_verify ~= nil then
        _M.ssl_verify = opts.ssl_verify
    else
        _M.ssl_verify = truthy_env(os.getenv("ANTIBOT_BACKEND_SSL_VERIFY"), true)
    end
    _M.interval            = opts.interval or 30
    local catalogs         = opts.catalogs or { "tls_fp_blocklist" }

    -- [B6] mTLS material: preferred to be preloaded by init_by_lua (so 0600
    -- root-owned keys are readable before privilege drop). preload_mtls is
    -- idempotent; this call is a safety net for callers that wire start()
    -- without a preload step.
    local cert_path = nonempty(opts.client_cert_path)
                      or nonempty(os.getenv("ANTIBOT_BACKEND_CLIENT_CERT"))
    local key_path  = nonempty(opts.client_priv_key_path)
                      or nonempty(os.getenv("ANTIBOT_BACKEND_CLIENT_KEY"))
    _M.preload_mtls(cert_path, key_path)
    if _M.parsed_cert and _M.parsed_key then
        ngx.log(ngx.NOTICE, "catalog_pull: mTLS client cert active",
            cert_path and (" (cert=" .. cert_path .. ")") or "")
    end

    if not _M.http_module then
        local ok, mod = pcall(require, "resty.http")
        if not ok then
            ngx.log(ngx.ERR, "catalog_pull: lua-resty-http not available, ",
                "Channel C disabled — running on static seed only")
            return
        end
        _M.http_module = mod
    end

    if ngx.worker and ngx.worker.id() ~= 0 then
        -- Only worker 0 pulls; other workers read the shared_dict that
        -- worker 0 populates.
        return
    end

    for _, name in ipairs(catalogs) do
        local function tick(premature)
            if premature then return end
            local ok, e = pcall(_M.fetch, name)
            if not ok then
                ngx.log(ngx.ERR, "catalog_pull ", name, " tick failed: ", e)
            end
        end
        -- Cold-start: immediate first fetch (don't make the edge wait the
        -- full interval to leave the static seed), then steady cadence.
        local ok1, e1 = ngx.timer.at(0, tick)
        if not ok1 then
            ngx.log(ngx.ERR, "catalog_pull ", name,
                ": ngx.timer.at failed: ", e1)
        end
        local ok2, e2 = ngx.timer.every(_M.interval, tick)
        if not ok2 then
            ngx.log(ngx.ERR, "catalog_pull ", name,
                ": ngx.timer.every failed: ", e2)
        end
    end
end

return _M
