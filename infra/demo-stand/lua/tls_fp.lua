-- L3 tls_fp: the soft rules and the informational tags. The blocking half
-- stays in verdict.lua because it short-circuits the cascade; everything here
-- is observe-only.
--
-- Soft rules only accumulate a flag — L5 decides what to do with it:
-- tls_fp_impersonator fires when the UA claims a browser but the fingerprint
-- is a known automation signature, tls_fp_suspicious_ciphers when the cipher
-- count is not the one that family offers.
--
-- Staged catalog entries are kept out of the active tables and matched
-- separately, so the promotion decision has data before anything blocks.

local fp_state = require "tls_fp_blocklist_state"

local _M = {
    enabled  = true,
    catalog  = {},   -- { [hash_b] = automation_family } (active entries only)
    profiles = {},   -- { [browser_family] = expected_cipher_cnt } (active only)
    catalog_staging   = {},   -- { [hash_b] = automation_family }
    profiles_staging  = {},   -- { [browser_family] = expected_cipher_cnt }
    blocklist_staging = {},   -- { [fp] = true }
}

-- Anything else collapses to "other": no profile, never an impersonation.
local BROWSER_FAMILIES = {
    chrome = true, firefox = true, safari = true, edge = true,
}

-- Matched with a plain find against a lowercased UA, so this stays pure Lua.
local AUTOMATION_MARKERS = {
    "curl/", "python-requests", "python-urllib", "urllib", "go-http-client",
    "okhttp", "wget/", "libwww", "java/", "apache-httpclient", "node-fetch",
    "axios/", "scrapy", "aiohttp", "httpx", "guzzle", "postmanruntime",
}

-- Order matters: Edge carries both Chrome and Safari, and Chrome carries
-- Safari, so the most specific marker wins.
function _M.classify_ua(ua)
    if type(ua) ~= "string" or ua == "" then return "other" end
    local low = ua:lower()
    local function has(s) return low:find(s, 1, true) ~= nil end

    if has("edg/") or has("edga/") or has("edgios/") then return "edge" end
    if has("chrome/") or has("crios/") then return "chrome" end
    if has("firefox/") or has("fxios/") then return "firefox" end
    if has("safari/") and has("version/") then return "safari" end
    return "other"
end

function _M.is_automation_ua(ua)
    if type(ua) ~= "string" or ua == "" then return false end
    local low = ua:lower()
    for _, marker in ipairs(AUTOMATION_MARKERS) do
        if low:find(marker, 1, true) then return true end
    end
    return false
end

-- Anchored on the second segment, so it survives more segments being added.
function _M.hash_b(fp)
    if type(fp) ~= "string" then return nil end
    return fp:match("^[^_]+_([^_]+)_")
end

-- Matches only as far as the cipher-count digits, so the suffix can change.
function _M.cipher_count(fp)
    if type(fp) ~= "string" then return nil end
    local cc = fp:match("^L%d%d[di](%d%d)")
    return cc and tonumber(cc) or nil
end

-- Malformed entries are skipped: a partial payload must not break the request.
function _M.build_catalog(wire)
    local active, staging = {}, {}
    for hb, raw in pairs(wire or {}) do
        if type(raw) == "string" then
            local status, family = raw:match("^([^:]+):(.+)$")
            if family and family ~= "" then
                if status == "active" then
                    active[hb] = family
                elseif status == "staging" then
                    staging[hb] = family
                end
            end
        end
    end
    return active, staging
end

-- A non-numeric or non-positive count is skipped.
function _M.build_profiles(wire)
    local active, staging = {}, {}
    for family, raw in pairs(wire or {}) do
        if type(raw) == "string" then
            local status, cnt = raw:match("^([^:]+):(.+)$")
            local n = tonumber(cnt)
            if n and n > 0 then
                if status == "active" then
                    active[family] = n
                elseif status == "staging" then
                    staging[family] = n
                end
            end
        end
    end
    return active, staging
end

-- Only the staged fingerprints: the active ones are blocked in verdict.lua.
function _M.build_blocklist(wire)
    local staging = {}
    for fp, raw in pairs(wire or {}) do
        if type(raw) == "string" and fp_state.parse_value(raw) == "staging" then
            staging[fp] = true
        end
    end
    return staging
end

-- An automation UA matching its own automation fingerprint is honest, not an
-- impersonation, so a non-browser family never fires.
function _M.is_impersonator(ua_family, hb, catalog)
    if not BROWSER_FAMILIES[ua_family] then return false end
    if not hb then return false end
    return catalog[hb] ~= nil
end

-- Without a fallback the stage would be blind for the first 30 s after a
-- restart and through any backend outage. It applies only until the first pull:
-- afterwards an always-on fallback would mask a deliberate catalog change.
local COLD_START_PROFILES = {
    chrome  = 15,
    firefox = 16,
    safari  = 20,
    edge    = 15,
}

-- Afterwards the catalog is authoritative even when empty.
local function profiles_landed()
    local g = _M._cached_gen_profiles
    return type(g) == "number" and g > 0
end

-- Allowed only for the active call: on the staging one it would emit matches
-- for signatures that do not exist yet and poison the promotion metrics.
function _M.is_suspicious_ciphers(ua_family, cc, profiles, allow_fallback)
    local expected = profiles[ua_family]
    if not expected and allow_fallback and not profiles_landed() then
        expected = COLD_START_PROFILES[ua_family]
    end
    if not expected then return false end
    if not cc then return false end
    return cc ~= expected
end

-- Browser-shaped means the cipher count matches some profile — a property of
-- the TLS stack rather than of the spoofable UA.
function _M.fp_looks_like_browser(cc, profiles)
    if not cc then return false end
    for _, expected in pairs(profiles) do
        if cc == expected then return true end
    end
    -- Cold start only. After a pull an empty table means the backend profiles
    -- no browser at all, and nothing should match.
    if not profiles_landed() then
        for _, expected in pairs(COLD_START_PROFILES) do
            if cc == expected then return true end
        end
    end
    return false
end

function _M.has_tag(tags, want)
    for _, t in ipairs(tags or {}) do
        if t == want then return true end
    end
    return false
end

-- Only the cold start happens here: empty tables, filled by the first pull.
function _M.build(config)
    _M.catalog          = {}
    _M.profiles         = {}
    _M.catalog_staging  = {}
    _M.profiles_staging = {}
    _M.blocklist_staging = {}

    -- Gates only the soft rules and tags; the block path is governed separately.
    _M.enabled = require("config").stage_enabled(config.defaults or {}, "tls_fp")

    -- nil means the first refresh in this worker rebuilds from the current
    -- generation.
    _M._cached_gen_catalog   = nil
    _M._cached_gen_profiles  = nil
    _M._cached_gen_blocklist = nil

    -- The staged tables are empty until the first pull.
    return _M
end

-- Rebuilds the per-worker tables on a generation flip; in steady state one dict
-- read and a comparison. The rebuild scans under a lock, which is why it is per
-- generation and not per request — past ~10K entries it would need an index.
local function rebuild_from_dict(dict_name, cur_gen, builder)
    local dict = ngx.shared[dict_name]
    if not dict then return {}, {} end
    local suffix = ":" .. cur_gen
    local wire   = {}
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-#suffix) == suffix then
            local base = k:sub(1, -#suffix - 1)
            local val  = dict:get(k)
            if val then wire[base] = val end
        end
    end
    return builder(wire)
end

-- Keeps the staging counters honest across a flip: a new entry is primed at
-- zero, and one that left staging has its counter dropped.
local function reconcile_staging_metrics(catalog_name, prev_staging, new_staging)
    local m = ngx.shared.metrics
    if not m then return end
    local prefix = "staging:" .. catalog_name .. ":"

    -- The first few individually, so a non-memory error stays debuggable; the
    -- rest aggregated so shm pressure cannot flood the log.
    local VERBOSE_LIMIT = 3
    local fail_count, last_err = 0, nil
    for pattern_id in pairs(new_staging) do
        local ok, err = m:safe_add(prefix .. pattern_id, 0)
        if not ok and err ~= "exists" then
            fail_count = fail_count + 1
            last_err = err
            if fail_count <= VERBOSE_LIMIT then
                ngx.log(ngx.WARN, "tls_fp: ", catalog_name,
                    " staging-counter add failed (pattern=", pattern_id,
                    "): ", tostring(err))
            end
        end
    end
    if fail_count > VERBOSE_LIMIT then
        ngx.log(ngx.WARN, "tls_fp: ", catalog_name,
            " staging-counter priming: ", fail_count - VERBOSE_LIMIT,
            " additional failures elided (last err: ", tostring(last_err), ")")
    end

    -- Only when still zero: a non-zero counter is the match history the
    -- promotion decision was made from.
    if prev_staging then
        for pattern_id in pairs(prev_staging) do
            if not new_staging[pattern_id] then
                local key = prefix .. pattern_id
                if (m:get(key) or 0) == 0 then
                    m:delete(key)
                end
            end
        end
    end
end

function _M.refresh()
    if not ngx or not ngx.shared then return end
    local meta = ngx.shared.meta
    if not meta then return end

    local cat_gen = meta:get("tls_fp_catalog_gen") or 0
    if cat_gen ~= _M._cached_gen_catalog then
        local active, staging = rebuild_from_dict(
            "tls_fp_catalog", cat_gen, _M.build_catalog)
        -- Swap first, so a concurrent request cannot increment a counter that
        -- is about to be deleted.
        local prev_staging = _M.catalog_staging
        _M.catalog          = active
        _M.catalog_staging  = staging
        _M._cached_gen_catalog = cat_gen
        reconcile_staging_metrics("tls_fp_catalog", prev_staging, staging)
    end

    local prof_gen = meta:get("tls_fp_browser_profiles_gen") or 0
    if prof_gen ~= _M._cached_gen_profiles then
        local active, staging = rebuild_from_dict(
            "tls_fp_browser_profiles", prof_gen, _M.build_profiles)
        local prev_staging = _M.profiles_staging
        _M.profiles          = active
        _M.profiles_staging  = staging
        _M._cached_gen_profiles = prof_gen
        reconcile_staging_metrics("tls_fp_browser_profiles", prev_staging, staging)
    end

    -- Only the staging set; verdict.lua blocks the active entries directly.
    local bl_gen = meta:get(fp_state.META_GEN_KEY) or 0
    if bl_gen ~= _M._cached_gen_blocklist then
        local staging = rebuild_from_dict("tls_fp_blocklist", bl_gen, _M.build_blocklist)
        local prev_staging = _M.blocklist_staging
        _M.blocklist_staging     = staging
        _M._cached_gen_blocklist = bl_gen
        reconcile_staging_metrics("tls_fp_blocklist", prev_staging, staging)
    end
end

-- A soft signal never decides a challenge here; L5 does.
local function fire_soft(bac_log, rule)
    bac_log.add_flag(rule)
end

-- A blocklisted fingerprint has already exited, so only non-blocked ones reach
-- this. Observe-only.
function _M.run(fp)
    if not _M.enabled then return end

    -- Cheap in steady state: one dict read per catalog and an integer compare.
    _M.refresh()

    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local ctx = ngx.ctx.bac
    if not ctx then return end

    local ua        = ngx.var.http_user_agent or ""
    local ua_family = _M.classify_ua(ua)
    local cc        = ctx.tls_cipher_count or _M.cipher_count(fp)

    -- Tags first and unconditionally, so they are recorded whatever the rule.
    if _M.is_automation_ua(ua) then
        bac_log.add_tag("tls_fp:automation_ua")
    end
    -- Only a parsed false flags; a malformed fingerprint does not.
    if ctx.tls_sni_present == false then
        bac_log.add_tag("tls_fp:no_sni")
    end
    -- The cheap tag is checked first, so only the rare datacenter case pays for
    -- the profile scan.
    if _M.has_tag(ctx.tags, "reputation:asn_dc")
       and _M.fp_looks_like_browser(cc, _M.profiles) then
        bac_log.add_tag("tls_fp:dc_browser")
    end

    -- Both may fire; the later wins the terminal rule. hash_b is parsed only
    -- for a browser UA, since nothing else can match.
    local hb = BROWSER_FAMILIES[ua_family] and _M.hash_b(fp) or nil
    if _M.is_impersonator(ua_family, hb, _M.catalog) then
        fire_soft(bac_log, "tls_fp_impersonator")
    end
    if _M.is_suspicious_ciphers(ua_family, cc, _M.profiles, true) then
        fire_soft(bac_log, "tls_fp_suspicious_ciphers")
    end

    -- Same predicate as the active entries, but it only writes staging_match.
    if _M.is_impersonator(ua_family, hb, _M.catalog_staging) then
        bac_log.add_staging_match("tls_fp_catalog:" .. hb)
    end
    if _M.is_suspicious_ciphers(ua_family, cc, _M.profiles_staging, false) then
        bac_log.add_staging_match("tls_fp_browser_profiles:" .. ua_family)
    end
    if type(fp) == "string" and _M.blocklist_staging[fp] then
        bac_log.add_staging_match("tls_fp_blocklist:" .. fp)
    end
end

return _M
