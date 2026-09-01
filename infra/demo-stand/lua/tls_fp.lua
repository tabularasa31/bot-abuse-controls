-- L3 tls_fp soft-rule + tag stage (rules-reference L3 #11/#12 + tags T2–T4;
-- phase2-spec "Rules of the stage"; vision §"A UA family ↔ fingerprint mismatch").
--
-- This module owns the NON-blocking part of the tls_fp stage. The blocking
-- part (tls_fp_blocklist → ngx.exit(403)) stays inline in verdict.lua because
-- it short-circuits the cascade; everything here is observe-only and never
-- exits, so it lives as its own stage module alongside hygiene/reputation.
--
-- Naming note: the A9 ticket body sketched this as `ua_fp_consistency.lua`
-- with a per-request sidecar `/__score` round-trip (RFC §C2 grey-verdict
-- path). That path is explicitly retired in the current architecture — see
-- docs/architecture/edge-lua-vs-sidecar.md (terminology note, 2026-05-18:
-- "§C2 ... not used in the current design (no heavy/grey-verdict scoring)").
-- So A9 reduces to the doc-aligned tls_fp stage: two soft rules + three
-- informational tags, all evaluated in Lua, all observe-only. Hence the
-- stage name `tls_fp` rather than `ua_fp_consistency` (which would not cover
-- suspicious_ciphers or the tags).
--
-- Soft rules (the soft category → they accumulate a flag in `flags`; the final verdict
-- is decided by L5/verification.lua from Strictness plus attack_mode, see C4):
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
-- Observe-only (phase2-spec, "in the MVP the cascade only observes"): run() records
-- flags and tags through bac_log, never calls ngx.exit and never
-- short-circuits. Before C4 this is also where verdict=challenge was set for soft
-- signals; after C4 that is gone — L5/verification.lua takes the decision,
-- honouring Strictness and attack_mode. A terminal block is still
-- not clobbered by a soft flag (the block stays in `rule` and the soft flag lives in
-- `flags`) — verification.decide() guarantees that: with verdict=="block"
-- it silently returns nil and leaves the terminal untouched.
--
-- Config model. After PR2 (ADR-006) tls_fp_catalog and tls_fp_browser_profiles
-- live in the `catalogs/` git repo and arrive over Channel C: the backend reads the
-- YAML into the catalog server, the edge polls through catalog_pull.lua plus an atomic swap into a
-- shared_dict. refresh() is a gen-cached per-worker rebuild, cheap on every
-- run(), rebuilding only on a flip. Until the first pull, the cold-start
-- fallback applies (COLD_START_PROFILES); after profiles_landed() → the fallback goes OFF and the
-- backend is the single source of truth. The pre-PR2 INI parsing in config.lua was removed.
--
-- Staging (A11, phase2-spec §"Staged rollout for PR catalogs"). Catalog
-- entries with status=staging are kept OUT of the active lookup tables (so they
-- never produce a verdict/rule even in active mode) and instead compiled into
-- parallel *_staging tables. When a staged entry matches the same way its
-- active counterpart would, run() records the fact into the `staging_match` log
-- slot ("<catalog>:<pattern_id>") via bac_log.add_staging_match — pure
-- observation for the promotion workflow (staging → active in a separate PR, or
-- revert). pattern_id per catalog: tls_fp_blocklist = the fp token,
-- tls_fp_catalog = hash_b, tls_fp_browser_profiles = browser_family. The
-- blocklist staging set lives here too (not in init.lua's active tls_fp_blocklist
-- seed) so the whole stage's staging detection is in one place; a staged fp is
-- absent from the active dict, so verdict.lua never exits on it and the request
-- always reaches run().
--
-- A11 follow-up (86exrtjpc): blocklist_staging is now built from the Channel C
-- snapshot in refresh() (the tls_fp_blocklist shared_dict, where staged fps
-- arrive as "staging:block" — see store.buildTLSFPBlocklist / parse_value),
-- not from the local tls_fp_blocklist.conf. The .conf stays the cold-start
-- seed for ACTIVE fps only (init.lua); staged observation is delivered live by
-- Channel C, symmetric with tls_fp_catalog / tls_fp_browser_profiles staging.

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

-- pure: parse wire-format map { [hash_b] = "<status>:<family>" } (composite
-- string per Channel C contract — symmetric to verified_bot_ips) into two
-- tables: active hash_b → family, staging hash_b → family. Empty family or
-- unknown status is skipped (defense-in-depth — backend validates these,
-- but a partial Channel C payload should never blow up the request path).
-- Used by refresh() to rebuild the per-process lookup tables after a
-- Channel C gen flip; also tested standalone (pure, no ngx deps).
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

-- pure: build the staging fp set from a Channel C wire map { [fp] =
-- "<status>:block" } (store.buildTLSFPBlocklist). Keeps only status=staging
-- fps as a membership set; active fps are NOT kept here (verdict.lua blocks
-- those directly off the same dict). A legacy bare "block" value (no colon)
-- is treated as active and thus skipped. Symmetric to build_catalog, but the
-- blocklist's verdict is implicit (block), so we keep only membership.
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

-- pure: tls_fp_suspicious_ciphers decision. Fires when the UA claims a browser
-- family with a known profile AND the observed cipher_count differs from it.
-- Unknown family (no profile) or an unparseable cipher_count never fires.
-- The cold-start fallback for is_suspicious_ciphers / fp_looks_like_browser:
-- a small static map of families → expected_cipher_cnt. Before PR2
-- (ADR-006) these values lived in infra/demo-stand/config/tls_fp_browser_profiles.conf
-- and were parsed in init_by_lua, so the cascade worked from the first second and
-- kept working even with the backend unavailable. After PR2 the catalog
-- arrives over Channel C, leaving a ~30 s cold-start window after a restart
-- plus an unbounded outage while the backend is unavailable. The fallback covers
-- both scenarios.
--
-- IMPORTANT (from re-review): the fallback is active ONLY until the first successful
-- Channel C pull (`profiles_landed()` below). Once the gen has flipped
-- at least once (gen >= 1), Channel C is the only source of truth:
-- if the backend deliberately removed or changed a profile (chrome moved from 15 → 16,
-- or it was deleted entirely), the edge MUST follow the backend rather than sticking to
-- the old hardcoded value. Without that condition an always-on fallback
-- would mask real catalog updates.
local COLD_START_PROFILES = {
    chrome  = 15,
    firefox = 16,
    safari  = 20,
    edge    = 15,
}

-- profiles_landed — true if at least one successful Channel C pull
-- delivered tls_fp_browser_profiles into the shared_dict (refresh() moved
-- _cached_gen_profiles to a number > 0). Until then the fallback is legitimate;
-- afterwards the backend is authoritative even if it sent an empty catalog.
--
-- If `_M._cached_gen_profiles` is empty (tests call the is_* helpers
-- directly without refresh), we treat it as a cold start (fallback on), to
-- keep the unit tests deterministic regardless of ngx initialisation.
local function profiles_landed()
    local g = _M._cached_gen_profiles
    return type(g) == "number" and g > 0
end

-- is_suspicious_ciphers: returns true if `cc` doesn't match the expected
-- cipher count for `ua_family`. `profiles` is the table to check (active
-- OR staging). `allow_fallback` (default false) decides whether the cold-start
-- fallback to COLD_START_PROFILES is permitted when the dict is empty and Channel C has not yet
-- landed. From review: apply the fallback ONLY for the active call (where the
-- goal is baseline detection before the first pull). For the staging call it is
-- forbidden: otherwise an empty staging table plus a not-landed gen emits
-- phantom `staging_match` events for every browser with a non-standard
-- cipher_count, poisoning the promotion metrics with signatures that do not exist.
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

-- Called once in init_by_lua, after config.load(). After PR2 (ADR-006)
-- tls_fp_catalog / tls_fp_browser_profiles are no longer INI files on the edge —
-- Channel C pulls them from the catalogs/ git repo through the backend (see
-- the catalog_pull.lua descriptors). Only the cold start happens here: we set empty
-- lookup tables; the first successful pull in catalog_pull.fetch fills the
-- shared_dict, and refresh() in run() builds the per-worker Lua tables from
-- that snapshot. blocklist_staging is Channel C-based too:
-- refresh() builds it from the tls_fp_blocklist shared_dict; at init the table is empty and
-- staged fingerprints arrive with the first pull. The local tls_fp_blocklist.conf remains
-- only a cold-start seed for ACTIVE fingerprints (init.lua), and staging is no longer
-- observed through it.
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

-- refresh — reads the current gen from meta:get(gen_key) and, if it differs
-- from the one cached for this worker, rebuilds the Lua tables
-- _M.catalog / _M.catalog_staging (and likewise the profiles) from the shared_dict.
-- Cheap in steady state: one meta:get per catalog plus a number comparison.
-- A rebuild happens only when Channel C delivered a new snapshot (≈ every 30 s).
-- It is called at the start of run(), so that the cascade works from the current catalog
-- with no explicit pub/sub between catalog_pull and tls_fp.
--
-- The per-request dict:get_keys(0) variant was rejected: for tls_fp_catalog
-- the size is small (dozens), but dict:get_keys locks the shared_dict for the
-- duration of the scan, which adds per-request latency variance. A per-gen rebuild
-- amortises that down to one lock per pull.
--
-- The performance trade-off (from review): `dict:get_keys(0)` locks the whole
-- shared_dict for the scan. For tls_fp_catalog (<100 entries) and
-- tls_fp_browser_profiles (≈5 entries) the lock is measured in microseconds —
-- acceptable. If a catalog grows past ~10K entries we will need a
-- "keys-of-gen-N" side index in the `meta` shared_dict and iterate over it
-- (the same plan is left open for fp_blocklist / verified_bot_ips,
-- see the comment in the catalog_pull.lua sweep).
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

-- reconcile_staging_metrics — on every gen flip of a Channel C catalog:
--   1) It seeds the counter `staging:<catalog>:<pattern_id>` with 0 in
--      the metrics shared_dict for every entry of the new staging table. That
--      lets promotion dashboards see "a staged signature is declared, zero
--      matches" instead of "metric absent" (telling "the PR landed but there was no
--      traffic" from "the PR never arrived").
--   2) It deletes the counter keys for entries that WERE in the previous
--      staging table but are gone from the new one (promoted to active or
--      removed). Without that a stale counter lives in the metrics dict until LRU
--      eviction, and the dashboard shows a phantom "staged, zero traffic"
--      entry for a signature product has already promoted (from review).
--
-- With an unsupported metrics dict (no declaration in nginx.conf) it is a silent
-- no-op. On a write error (no_memory under shm pressure) it logs a WARN: the fix
-- for the silent failure found in review (safe_add returns nil without an exception and does not
-- LRU-evict — the counter simply never appears and the dashboard sees "metric
-- absent" against the contract).
local function reconcile_staging_metrics(catalog_name, prev_staging, new_staging)
    local m = ngx.shared.metrics
    if not m then return end
    local prefix = "staging:" .. catalog_name .. ":"

    -- Add a zero counter for the new entries. Under shm pressure safe_add can
    -- return (nil, "no memory") for every entry. A hybrid log policy
    -- (from review): the first VERBOSE_LIMIT failures are logged with the pattern_id
    -- (which matters for debugging non-OOM errors like "key too long" or a unique
    -- collision); the rest are aggregated into a single WARN. That keeps the log readable
    -- under high-volume failures and attributable under low-volume ones.
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

    -- Delete the counter for entries that are no longer in new (promoted to active
    -- or removed). But ONLY when value == 0 — otherwise we erase the
    -- accumulated match count (the history of a staging→active promotion, which the
    -- promotion dashboard needs). The trade-off from review: phantom entries (always 0)
    -- are cleaned; entries with real history are left as "zombies" — an operator
    -- can clear them by hand, but we do not lose data.
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
        -- From review: swap before reconcile, so that log_event.incr from a
        -- parallel request does not race with reconcile's delete-if-zero
        -- (after the swap, run() no longer sees a promoted/removed pattern in the
        -- staging table → it never calls incr → the delete is safe).
        -- `prev_staging` is still reachable through the local reference to the
        -- previously assigned table (Lua tables are by reference).
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

    -- tls_fp_blocklist (86exrtjpc): staged fps arrive over Channel C in the
    -- tls_fp_blocklist shared_dict as "staging:block". verdict.lua blocks the
    -- ACTIVE ones directly off this dict; here we rebuild only the staging
    -- membership set so run() can record staging_match for them. Same gen-cached
    -- rebuild + metric reconcile as the two catalogs above. The gen key is the
    -- blocklist's own (fp_state.META_GEN_KEY), bumped by catalog_pull's
    -- tls_fp_blocklist descriptor.
    local bl_gen = meta:get(fp_state.META_GEN_KEY) or 0
    if bl_gen ~= _M._cached_gen_blocklist then
        local staging = rebuild_from_dict("tls_fp_blocklist", bl_gen, _M.build_blocklist)
        local prev_staging = _M.blocklist_staging
        _M.blocklist_staging     = staging
        _M._cached_gen_blocklist = bl_gen
        reconcile_staging_metrics("tls_fp_blocklist", prev_staging, staging)
    end
end

-- Record a soft challenge flag. The flag is always accumulated (vision.md:
-- flags = every soft signal seen along the path). C4: the terminal verdict is
-- NO LONGER set here — the soft signals only ACCUMULATE, and the decision
-- to "issue a challenge" is taken at L5 (verification.lua), honouring the
-- per-resource Strictness and attack_mode. Before C4 this function wrote
-- verdict=challenge directly, which broke rules-reference §"the L3/L4 flags
-- ... never issue a challenge themselves at L3/L4; they only mark the request, and the
-- single point where the decision is taken is this call at L5".
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

    -- Soft rules. Both may fire; both flags accumulate (flags = all soft
    -- signals). impersonator is evaluated first, so suspicious_ciphers wins the
    -- terminal `rule` when both fire — `rule` is the last/terminal rule, the
    -- full set lives in `flags`.
    -- Only parse hash_b for a browser-family UA — is_impersonator rejects
    -- non-browser UAs anyway, so the common case skips the string.match.
    local hb = BROWSER_FAMILIES[ua_family] and _M.hash_b(fp) or nil
    if _M.is_impersonator(ua_family, hb, _M.catalog) then
        fire_soft(bac_log, "tls_fp_impersonator")
    end
    if _M.is_suspicious_ciphers(ua_family, cc, _M.profiles, true) then
        fire_soft(bac_log, "tls_fp_suspicious_ciphers")
    end

    -- Staged patterns (A11). A staged entry is matched with the SAME predicate
    -- its active counterpart uses, so the recorded count reflects what would
    -- fire after promotion — but it only writes to staging_match, never to
    -- verdict/rule/flags. Gated by _M.enabled (above) like the rest of the
    -- stage, so the tls_fp kill-switch silences staging observation too.
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
