-- L3 tls_fp soft-rule + tag stage (rules-reference L3 #11/#12 + tags T2–T4;
-- phase2-spec "Правила этапа"; vision §"UA-family ↔ fp mismatch").
--
-- This module owns the NON-blocking part of the tls_fp stage. The blocking
-- part (tls_fp_blocklist → ngx.exit(403)) stays inline in verdict.lua because
-- it short-circuits the cascade; everything here is observe-only and never
-- exits, so it lives as its own stage module alongside hygiene/reputation.
--
-- Naming note: the A9 ticket body sketched this as `ua_fp_consistency.lua`
-- with a per-request sidecar `/__score` round-trip (RFC §В2 grey-verdict
-- path). That path is explicitly retired in the current architecture — see
-- docs/architecture/edge-lua-vs-sidecar.md (terminology note, 2026-05-18:
-- "§В2 ... not used in the current design (no heavy/grey-verdict scoring)").
-- So A9 reduces to the doc-aligned tls_fp stage: two soft rules + three
-- informational tags, all evaluated in Lua, all observe-only. Hence the
-- stage name `tls_fp` rather than `ua_fp_consistency` (which would not cover
-- suspicious_ciphers or the tags).
--
-- Soft rules (category soft → log verdict=challenge, accumulate into `flags`):
--   * tls_fp_impersonator       — UA claims a browser family, but the fp's
--                                 hash_b matches a known automation signature
--                                 in tls_fp_catalog (UA Chrome + fp = curl/
--                                 python-requests/Go/okhttp ⇒ masquerade).
--   * tls_fp_suspicious_ciphers — UA claims a browser family, but the fp's
--                                 cipher_count differs from that family's
--                                 expected count in tls_fp_browser_profiles
--                                 (chrome=15, firefox=16, safari=20, edge=15).
--
-- Informational tags (NOT rules — emit no verdict, never stop the cascade,
-- accumulate in `tags` independent of the verdict):
--   * tls_fp:automation_ua — UA carries explicit automation markers
--                            (curl/python-requests/Go/okhttp/…). Duplicates
--                            what ua_blacklist will catch once populated; a
--                            primary automation signal until then.
--   * tls_fp:no_sni        — client sent no SNI in the TLS handshake.
--   * tls_fp:dc_browser    — cross-layer (L3 fp + L2 reputation): the fp is
--                            browser-shaped (cipher_count matches a browser
--                            profile) AND the IP is in a datacenter ASN (the
--                            reputation:asn_dc tag set upstream this request).
--
-- Observe-only (phase2-spec "Каскад в MVP только наблюдает"): run() records
-- the would-be verdict/flags/tags via bac_log but NEVER ngx.exit and NEVER
-- short-circuits. A soft challenge must NOT downgrade an already-recorded
-- block (e.g. an observe-only reputation ip_blocklist that did not exit on the
-- stand): vision.md's example keeps the terminal block as `rule` while the
-- soft flag persists in `flags`. run() therefore only writes verdict=challenge
-- when the current verdict is not already "block"; the flag is always added.
--
-- Config model. Like hygiene/reputation: tls_fp_catalog.conf and
-- tls_fp_browser_profiles.conf are parsed once in init_by_lua (config.lua) and
-- compiled into per-process lookup tables by build() — in the master before
-- workers fork, so every worker inherits them for free (no shared dict;
-- hot-reload over Channel C is a later task). Phase 3 swaps the data source to
-- the catalog pull without changing rule names, stage, category or the log
-- contract.
--
-- Staging: catalog entries with status=staging are excluded from the active
-- lookup tables (mirrors hygiene's ua_blacklist, reputation's IP lists and
-- init.lua's fp seeding). Recording staged matches into the `staging_match`
-- log slot is a separate task (A11); bac_log.add_staging_match stays a no-op
-- producer until then.

local _M = {
    enabled  = true,
    catalog  = {},   -- { [hash_b] = automation_family } (active entries only)
    profiles = {},   -- { [browser_family] = expected_cipher_cnt } (active only)
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

-- pure: classify a UA into a browser family or "other". Order matters because
-- browser UA tokens nest: Edge carries "Chrome" and "Safari"; Chrome carries
-- "Safari". Check the most specific marker first.
--   Edge   : edg/ (desktop), edga/ (android), edgios/ (ios)
--   Chrome : chrome/ (desktop/android), crios/ (ios) — and not Edge
--   Firefox: firefox/, fxios/ (ios)
--   Safari : safari/ + version/ — and not Chrome (genuine Safari has no Chrome)
-- Matched against the lowercased UA (like is_automation_ua), so a spoof that
-- lowercases the tokens still classifies and can't slip past the soft rules.
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

-- pure: extract hash_b (the sorted-cipher hash) from an fp string. Layout
-- (ja4_compute.lua): "L<prefix>_<hash_b>_<hash_c>". Anchored only on the
-- second underscore-delimited segment, not the whole string, so it keeps
-- working if the fp ever grows trailing segments. Returns nil for a
-- malformed/absent fp so callers fall through without a catalog lookup.
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

-- pure: build the active hash_b → family map from parsed tls_fp_catalog.conf
-- (config_loader.parse_ini output: { [hash_b] = { family=, status=, … } }).
-- Excludes status=staging; an entry with no family is skipped.
function _M.build_catalog(catalog_cfg)
    local out = {}
    for hb, attrs in pairs(catalog_cfg or {}) do
        if type(attrs) == "table" and attrs.family and attrs.status ~= "staging" then
            out[hb] = attrs.family
        end
    end
    return out
end

-- pure: build the active family → expected_cipher_cnt map from parsed
-- tls_fp_browser_profiles.conf. Excludes status=staging; an entry whose
-- expected_cipher_cnt is missing/non-numeric is skipped.
function _M.build_profiles(profiles_cfg)
    local out = {}
    for family, attrs in pairs(profiles_cfg or {}) do
        if type(attrs) == "table" and attrs.status ~= "staging" then
            local n = tonumber(attrs.expected_cipher_cnt)
            if n then out[family] = n end
        end
    end
    return out
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

-- pure: tls_fp_suspicious_ciphers decision. Fires when the UA claims a browser
-- family with a known profile AND the observed cipher_count differs from it.
-- Unknown family (no profile) or an unparseable cipher_count never fires.
function _M.is_suspicious_ciphers(ua_family, cc, profiles)
    local expected = profiles[ua_family]
    if not expected then return false end
    if not cc then return false end
    return cc ~= expected
end

-- pure: is the fp browser-shaped? Used for the tls_fp:dc_browser cross-layer
-- tag — the L3 half of the signal. We treat "cipher_count matches some browser
-- profile" as browser-shaped: it's a property of the TLS stack (the fp), not
-- of the spoofable UA, which is what "fp выглядит как браузер" means.
function _M.fp_looks_like_browser(cc, profiles)
    if not cc then return false end
    for _, expected in pairs(profiles) do
        if cc == expected then return true end
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

-- Called once in init_by_lua, after config.load(). Compiles the on-disk
-- catalogs into the per-process lookup tables run() reads.
function _M.build(config)
    _M.catalog  = _M.build_catalog(config.tls_fp_catalog)
    _M.profiles = _M.build_profiles(config.tls_fp_browser_profiles)

    -- Stage off via the shared kill-switch helper (config-templates.md
    -- kill_switch; defaults.conf [kill_switch.*]). The block path
    -- (tls_fp_blocklist in verdict.lua) is governed separately; this toggle
    -- gates only the soft rules + tags this module owns.
    _M.enabled = require("config").stage_enabled(config.defaults or {}, "tls_fp")

    -- Active entry counts for the startup log.
    local cat_n, prof_n = 0, 0
    for _ in pairs(_M.catalog)  do cat_n  = cat_n  + 1 end
    for _ in pairs(_M.profiles) do prof_n = prof_n + 1 end
    return _M, cat_n, prof_n
end

-- Record a soft challenge flag. The flag is always accumulated (vision.md:
-- flags = every soft signal seen along the path). The terminal verdict is set
-- to challenge only when it is not already a block, so a soft signal never
-- downgrades a recorded block — the block stays the terminal `rule`.
local function fire_soft(bac_log, ctx, rule)
    bac_log.add_flag(rule)
    if ctx.verdict ~= "block" then
        bac_log.set_verdict("tls_fp", "challenge", rule)
    end
end

-- Called per request from verdict.lua, after the tls_fp_blocklist check (a
-- blocklisted fp has already ngx.exit'd, so we only see non-blocked fps).
-- `fp` is the computed fingerprint string. Observe-only: never blocks, never
-- short-circuits.
function _M.run(fp)
    if not _M.enabled then return end

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
    -- is in asn_datacenters.conf.
    if _M.fp_looks_like_browser(cc, _M.profiles)
       and _M.has_tag(ctx.tags, "reputation:asn_dc") then
        bac_log.add_tag("tls_fp:dc_browser")
    end

    -- Soft rules. Both may fire; both flags accumulate (flags = all soft
    -- signals). impersonator is evaluated first, so suspicious_ciphers wins the
    -- terminal `rule` when both fire — `rule` is the last/terminal rule, the
    -- full set lives in `flags`.
    if _M.is_impersonator(ua_family, _M.hash_b(fp), _M.catalog) then
        fire_soft(bac_log, ctx, "tls_fp_impersonator")
    end
    if _M.is_suspicious_ciphers(ua_family, cc, _M.profiles) then
        fire_soft(bac_log, ctx, "tls_fp_suspicious_ciphers")
    end
end

return _M
