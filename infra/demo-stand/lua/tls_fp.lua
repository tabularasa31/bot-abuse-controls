-- L3 tls_fp: the soft rules and the informational tags.
--
-- The blocking half of the stage stays inline in verdict.lua because it
-- short-circuits the cascade; everything here is observe-only and never exits.
--
-- Soft rules accumulate a flag, and L5 decides what to do with it:
--   * tls_fp_impersonator — the UA claims a browser, but the fingerprint
--     matches a known automation signature.
--   * tls_fp_suspicious_ciphers — the UA claims a browser, but the cipher count
--     is not the one that family offers.
--
-- Tags emit no verdict and never stop the cascade: tls_fp:automation_ua,
-- tls_fp:no_sni, and tls_fp:dc_browser, which combines this layer with L2 — a
-- browser-shaped fingerprint arriving from a datacenter ASN.
--
-- The catalogs arrive over Channel C and are rebuilt per worker on a generation
-- flip. Until the first pull lands there is a small static fallback, described
-- at COLD_START_PROFILES.
--
-- Staged catalog entries are kept out of the active tables entirely and
-- compiled into parallel ones. A staged match is recorded into staging_match
-- and never becomes a verdict, so the promotion decision has data before
-- anything blocks.

local fp_state = require "tls_fp_blocklist_state"

local _M = {
    enabled  = true,
    catalog  = {},   -- { [hash_b] = automation_family } (active entries only)
    profiles = {},   -- { [browser_family] = expected_cipher_cnt } (active only)
    -- Staging counterparts (status=staging), matched-but-never-verdict:
    catalog_staging   = {},   -- { [hash_b] = automation_family }
    profiles_staging  = {},   -- { [browser_family] = expected_cipher_cnt }
    blocklist_staging = {},   -- { [fp] = true }
}

-- Browser families we classify a UA into. Automation tools and anything else
-- collapse to "other" (no profile, never an impersonation victim).
local BROWSER_FAMILIES = {
    chrome = true, firefox = true, safari = true, edge = true,
}

-- Lowercased substrings that mark an automation client UA. Matched with plain
-- (non-pattern) find against ua:lower(), so this stays pure Lua — no ngx.re —
-- and is unit-testable under bare luajit (tests/tls_fp_test.lua).
local AUTOMATION_MARKERS = {
    "curl/", "python-requests", "python-urllib", "urllib", "go-http-client",
    "okhttp", "wget/", "libwww", "java/", "apache-httpclient", "node-fetch",
    "axios/", "scrapy", "aiohttp", "httpx", "guzzle", "postmanruntime",
}

-- Order matters: browser UA tokens nest, with Edge carrying both Chrome and
-- Safari and Chrome carrying Safari, so the most specific marker wins.
-- Lowercased first, or a lowercased spoof would slip past the soft rules.
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

-- pure: does the UA carry an explicit automation marker? (tls_fp:automation_ua)
function _M.is_automation_ua(ua)
    if type(ua) ~= "string" or ua == "" then return false end
    local low = ua:lower()
    for _, marker in ipairs(AUTOMATION_MARKERS) do
        if low:find(marker, 1, true) then return true end
    end
    return false
end

-- Anchored on the second segment rather than the whole string, so it survives
-- the fingerprint growing more segments.
function _M.hash_b(fp)
    if type(fp) ~= "string" then return nil end
    return fp:match("^[^_]+_([^_]+)_")
end

-- pure: cipher_count from the fp prefix "L<ver><sni><cipher_cnt><alpn>_…"
-- (same parse as bac_log.set_tls_fp). Matches only as far as the cipher-count
-- digits so it tolerates changes to the alpn suffix. Returns a number or nil.
function _M.cipher_count(fp)
    if type(fp) ~= "string" then return nil end
    local cc = fp:match("^L%d%d[di](%d%d)")
    return cc and tonumber(cc) or nil
end

-- Splits the wire map into active and staging tables. Malformed entries are
-- skipped: a partial payload must never break the request path.
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

-- pure: parse wire-format map { [family] = "<status>:<expected_cipher_cnt>" }
-- into two tables: active family → cipher_cnt, staging family → cipher_cnt.
-- A non-numeric or non-positive cipher_cnt is skipped (backend Validate
-- enforces > 0, but parser stays robust to corrupted wire payloads).
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

-- Only the staged fingerprints, as a membership set: the active ones are
-- blocked in verdict.lua straight off the same dict.
function _M.build_blocklist(wire)
    local staging = {}
    for fp, raw in pairs(wire or {}) do
        if type(raw) == "string" and fp_state.parse_value(raw) == "staging" then
            staging[fp] = true
        end
    end
    return staging
end

-- pure: tls_fp_impersonator decision. Fires when the UA claims a browser
-- family AND the fp's hash_b is a known automation signature in the catalog.
-- An automation/other UA matching its own automation fp is honest, not an
-- impersonation, so a non-browser ua_family never fires.
function _M.is_impersonator(ua_family, hb, catalog)
    if not BROWSER_FAMILIES[ua_family] then return false end
    if not hb then return false end
    return catalog[hb] ~= nil
end

-- The cold-start fallback: without it the stage would be blind for the first
-- 30 s after a restart, and for the whole of any backend outage.
--
-- It applies only until the first successful pull. After that the catalog is
-- the only source of truth — an always-on fallback would mask a deliberate
-- change, such as a browser's expected cipher count moving.
local COLD_START_PROFILES = {
    chrome  = 15,
    firefox = 16,
    safari  = 20,
    edge    = 15,
}

-- Whether a pull has ever landed. Afterwards the catalog is authoritative even
-- when it is empty.
local function profiles_landed()
    local g = _M._cached_gen_profiles
    return type(g) == "number" and g > 0
end

-- The fallback is allowed only for the active call. Applying it to the staging
-- one would emit staging_match events for signatures that do not exist yet and
-- poison the promotion metrics.
function _M.is_suspicious_ciphers(ua_family, cc, profiles, allow_fallback)
    local expected = profiles[ua_family]
    if not expected and allow_fallback and not profiles_landed() then
        expected = COLD_START_PROFILES[ua_family]
    end
    if not expected then return false end
    if not cc then return false end
    return cc ~= expected
end

-- pure: is the fp browser-shaped? Used for the tls_fp:dc_browser cross-layer
-- tag — the L3 half of the signal. We treat "cipher_count matches some browser
-- profile" as browser-shaped: it's a property of the TLS stack (the fp), not
-- of the spoofable UA, which is what "the fingerprint looks like a browser" means.
function _M.fp_looks_like_browser(cc, profiles)
    if not cc then return false end
    for _, expected in pairs(profiles) do
        if cc == expected then return true end
    end
    -- The fallback applies ONLY on a cold start (before the first Channel C pull). After a
    -- successful pull the dynamic table is final; an empty dynamic table
    -- means "the backend deliberately profiles no browser at all", and not a
    -- single true match should occur.
    if not profiles_landed() then
        for _, expected in pairs(COLD_START_PROFILES) do
            if cc == expected then return true end
        end
    end
    return false
end

-- pure: membership test over the (small) tags array.
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

    -- Stage off via the shared kill-switch helper (config-templates.md
    -- kill_switch; defaults.conf [kill_switch.*]). The block path
    -- (tls_fp_blocklist in verdict.lua) is governed separately; this toggle
    -- gates only the soft rules + tags this module owns.
    _M.enabled = require("config").stage_enabled(config.defaults or {}, "tls_fp")

    -- Per-worker gen-cache reset (init_by_lua runs before fork, but a worker
    -- restart re-runs this code on the new master too). nil means "first
    -- refresh in this worker will rebuild from current dict gen".
    _M._cached_gen_catalog   = nil
    _M._cached_gen_profiles  = nil
    _M._cached_gen_blocklist = nil

    -- The staged tables are empty at init (no pull has run yet); their counters
    -- appear in /metrics and in bac_log staging_match after the first
    -- catalog_pull tick (≤ 30 s). build() returns nothing but the module —
    -- init.lua calls it purely for the side effects.
    return _M
end

-- Rebuilds the per-worker tables when the generation moved; in steady state
-- this is one dict read and a comparison. Called from run(), so the stage needs
-- no pub/sub with the pull.
--
-- The rebuild scans the dict under a lock, which is why it happens per
-- generation rather than per request. At these catalog sizes the lock is
-- microseconds; past ~10K entries this would need a key index per generation
-- instead.
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

-- Keeps the staging counters honest across a generation flip: a new staged
-- entry is primed at zero, so "landed but no traffic" is distinguishable from
-- "never arrived", and an entry that left staging has its counter dropped so no
-- phantom stays behind.
local function reconcile_staging_metrics(catalog_name, prev_staging, new_staging)
    local m = ngx.shared.metrics
    if not m then return end
    local prefix = "staging:" .. catalog_name .. ":"

    -- The first few failures are logged individually, which is what makes a
    -- non-memory error debuggable; the rest are aggregated so shm pressure
    -- cannot flood the log.
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
    -- promotion decision was made from, and is left for the operator to clear.
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
        -- Swap before reconciling: afterwards a concurrent request can no
        -- longer see the removed pattern, so it cannot increment a counter that
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

    -- Only the staging set is rebuilt here; verdict.lua blocks the active
    -- entries straight off the same dict.
    local bl_gen = meta:get(fp_state.META_GEN_KEY) or 0
    if bl_gen ~= _M._cached_gen_blocklist then
        local staging = rebuild_from_dict("tls_fp_blocklist", bl_gen, _M.build_blocklist)
        local prev_staging = _M.blocklist_staging
        _M.blocklist_staging     = staging
        _M._cached_gen_blocklist = bl_gen
        reconcile_staging_metrics("tls_fp_blocklist", prev_staging, staging)
    end
end

-- Accumulates the flag and nothing else. A soft signal never decides a
-- challenge here; L5 does, weighing Strictness and attack mode.
local function fire_soft(bac_log, rule)
    bac_log.add_flag(rule)
end

-- Called per request from verdict.lua, after the tls_fp_blocklist check (a
-- blocklisted fp has already ngx.exit'd, so we only see non-blocked fps).
-- `fp` is the computed fingerprint string. Observe-only: never blocks, never
-- short-circuits.
function _M.run(fp)
    if not _M.enabled then return end

    -- Pull-in latest Channel C snapshot for tls_fp_catalog / tls_fp_browser_profiles.
    -- Cheap in steady state (one meta:get per gen-key, compare to cached
    -- worker-local int); rebuilds Lua tables only when gen flips (≈ pull
    -- interval, 30 s by default).
    _M.refresh()

    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local ctx = ngx.ctx.bac
    if not ctx then return end

    local ua        = ngx.var.http_user_agent or ""
    local ua_family = _M.classify_ua(ua)
    local cc        = ctx.tls_cipher_count or _M.cipher_count(fp)

    -- Informational tags first — evaluated unconditionally so they are
    -- recorded regardless of any rule (tags accumulate independent of verdict).
    if _M.is_automation_ua(ua) then
        bac_log.add_tag("tls_fp:automation_ua")
    end
    -- no_sni: bac_log.set_tls_fp parsed tls_sni_present from the fp prefix.
    -- Only a parsed false (SNI absent) flags; nil (malformed fp) does not.
    if ctx.tls_sni_present == false then
        bac_log.add_tag("tls_fp:no_sni")
    end
    -- dc_browser: browser-shaped fp (L3) + datacenter ASN (L2). reputation.lua
    -- ran earlier in the cascade and added reputation:asn_dc when the IP's ASN
    -- is in asn_datacenters.conf. Check the cheap asn_dc tag FIRST so the
    -- (rare) DC case is the only one that pays for the profile scan.
    if _M.has_tag(ctx.tags, "reputation:asn_dc")
       and _M.fp_looks_like_browser(cc, _M.profiles) then
        bac_log.add_tag("tls_fp:dc_browser")
    end

    -- Both may fire and both flags accumulate; the later one wins the terminal
    -- rule. hash_b is parsed only for a browser UA, since nothing else can
    -- match anyway.
    local hb = BROWSER_FAMILIES[ua_family] and _M.hash_b(fp) or nil
    if _M.is_impersonator(ua_family, hb, _M.catalog) then
        fire_soft(bac_log, "tls_fp_impersonator")
    end
    if _M.is_suspicious_ciphers(ua_family, cc, _M.profiles, true) then
        fire_soft(bac_log, "tls_fp_suspicious_ciphers")
    end

    -- Matched with the same predicate as the active entries, so the count
    -- reflects what promotion would do — but it only ever writes staging_match.
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
