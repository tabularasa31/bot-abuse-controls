-- Demo-stand init (init_by_lua). Loads the cascade config files, seeds the
-- tls_fp_blocklist shared_dict from tls_fp_blocklist.conf, primes the metrics
-- shared_dict with zero-valued counter keys (so /metrics shows them from the
-- very first scrape), and records the start time for /__version uptime.
--
-- The tls_fp_blocklist dict is the one config the request path consumes today
-- (verdict.lua). The other catalogs (ip/ua/asn lists, tls_fp catalog/
-- profiles, defaults) are parsed and held on the `config` module for the
-- cascade-rule tasks that will read them — they are not wired into a
-- verdict here (rules are out of scope for the A3 config-files task).

local config = require "config"
config.load()

-- Compile the L1 hygiene stage (method whitelist + ua_blacklist combined
-- regex) from the loaded config. Done here in the master so every worker
-- inherits the compiled state on fork — see hygiene.lua.
local hygiene = require("hygiene").build(config)

-- Compile the L2 reputation stage (ip_whitelist / ip_blocklist CIDR matchers)
-- from the loaded config — also in the master so workers inherit the matchers
-- on fork (see reputation.lua). Returns the active entry counts for the
-- startup log below.
local reputation, rep_wl, rep_bl = require("reputation").build(config)

-- Compile the L2.2 verified-bot fastpath (B8: bot_verified /
-- bot_verified_pending). build() reads the searchbot UA alternation from
-- defaults.conf [allow.bot_verified].ua_pattern and stashes the split list;
-- the verified_bots shared_dict is filled by catalog_pull (Channel C
-- `verified_bot_ips`) and is empty on a stand without backend, so all
-- searchbot-UA requests resolve to provisional fastpath until the rDNS
-- worker (B7) publishes a status. Returns the active UA-alt count.
local _, vb_alts_n = require("verified_bots").build(config)

-- Compile the L4 rate_limits stage (GCRA profiles from defaults.conf
-- [blocking.rate_*] thresholds) — also in the master so workers inherit the
-- profile list on fork (see rate_limit.lua; the shared dict holds only per-key
-- TAT state). Returns the active profile count for the startup log.
local _, rate_n = require("rate_limit").build(config)

-- Compile the L3 tls_fp soft-rule stage. After PR2 (ADR-006)
-- all three staged catalogs (tls_fp_blocklist / tls_fp_catalog /
-- tls_fp_browser_profiles) arrive over Channel C, so
-- build() only sets up the cold-start state plus the kill-switch flag; the staging tables
-- are empty at init and are filled in tls_fp.refresh() after the first pull.
require("tls_fp").build(config)

-- Open the GeoLite2 databases (country + asn) once in the master so workers
-- inherit the handles on fork. Fail-open: if the license-gated .mmdb files (or
-- libmaxminddb) are absent the stand still starts and geo is simply
-- undetermined — geoip.init() logs the reason. Feeds the reputation:asn_dc tag
-- and the geo_country/asn log fields (A6).
require("geoip").init()

-- [B6] Channel C mTLS client cert — parse in the master (pre-privilege-drop)
-- so 0600 root-owned PEMs are readable. Workers inherit the parsed cdata on
-- fork, so catalog_pull.fetch() in init_worker_by_lua never re-opens the file
-- (codex review: workers run as nobody and can't read 0600 root keys).
-- Both paths must be set + parse cleanly; otherwise mTLS stays disabled and
-- catalog_pull falls into the existing fail-stale path.
require("catalog_pull").preload_mtls(
    os.getenv("ANTIBOT_BACKEND_CLIENT_CERT"),
    os.getenv("ANTIBOT_BACKEND_CLIENT_KEY"))

-- [C1] The Phase 4 HMAC secret for the clearance cookie (vision §"The HMAC secret for the
-- clearance cookie", §Channel A). Delivery on the demo stand is a file mount
-- (the ./certs bind mount), and rotation is `openresty -s reload`. C3/C5 are not yet
-- implemented — load() runs here so that when they arrive the secret is
-- already in the shared_dict; until then a missing file is a WARN, not fatal
-- (Phase 1-3 requests keep working).
require("challenge_secret").load(
    os.getenv("CHALLENGE_HMAC_SECRET_FILE")
        or "/etc/nginx/certs/challenge_secret.key")

-- [C2] The Phase 4 challenge page asset (the HTML+JS template, vision §5.2 "Branch A").
-- Delivery on the demo is a file mount (Channel A on the demo), at the path
-- /etc/nginx/challenge/page.html. preload() reads the template plus CASCADE_VERSION
-- once and compares the template's meta tag with the contents of the version file — a mismatch
-- fails init_by_lua and the container does not start. That is the version-pin
-- invariant: the cascade and the template can diverge only through a deliberate
-- simultaneous bump of both. Serving the page itself (tied to
-- verdict=challenge) is C5; only the preload and the check happen here.
local cascade_version = require("challenge").preload()

-- Seed the tls_fp_blocklist shared_dict from tls_fp_blocklist.conf. Entries are
-- active unless explicitly status=staging — staged fps match-but-don't-block
-- and are held in tls_fp.blocklist_staging (recorded into staging_match by the
-- tls_fp stage, A11), never seeded here. An empty file => SHADOW mode.
--
-- Keys are written under generation 0 (`fp .. ":" .. 0`, §C1 format) and
-- tls_fp_blocklist_gen is published as 0 so verdict.lua's §A1 read resolves them.
-- The static seed IS generation 0; when the Channel C catalog pull lands
-- (task 86exmk08u) it bumps to gen 1+ and atomically swaps the set.
--
-- Reload survival. The `meta` and `tls_fp_blocklist` shared_dicts
-- survive `nginx -s reload`. If in a previous life Channel C delivered gen=N
-- with an extended fingerprint set (50 versus 10 in the local .conf, say), a force reset to
-- gen=0 plus a re-seed under `:0` HIDES those 40 extra fingerprints until the next payload
-- change on the backend (a 304 on the first pull → the gen stays 0). So we seed
-- (as a cold-start fallback) ONLY when the gen key is absent from meta
-- (a completely fresh start). If the key is already there, the Channel C state survived, the data
-- shared_dict survived too, and readers in verdict.lua will find the `:N` records as before.
local fp_state    = require "tls_fp_blocklist_state"
local catalog_pull = require "catalog_pull"
local fp_dict = ngx.shared.tls_fp_blocklist
local meta    = ngx.shared.meta

-- seed_blocklist_cold — writes the local fallback under `:0`. Used
-- on the cold-start path (the key was just created through meta:add). On that
-- path the data dict is guaranteed to be empty or to hold only ghost keys from a
-- previous worker generation, which are read correctly (gen=0); there is no need to clear the
-- ghosts — we are about to overwrite them under that same `:0` suffix.
-- The record wire format (A11, store.buildTLSFPBlocklist) is "<status>:block".
-- The cold-start seed carries active records as "active:block" (verdict.lua blocks
-- only active ones). We do NOT put staged fingerprints into the seed: staging observation is delivered
-- live over Channel C (tls_fp.refresh builds blocklist_staging from the pulled snapshot),
-- symmetrically with tls_fp_catalog / tls_fp_browser_profiles staging.
local function seed_blocklist_cold()
    local seeded = 0
    for _, entry in ipairs(config.tls_fp_blocklist) do
        if entry.attrs.status ~= "staging" then
            local ok, err = fp_dict:set(fp_state.key(entry.value, 0), "active:block")
            if ok then
                seeded = seeded + 1
            else
                ngx.log(ngx.ERR, "tls_fp_blocklist:set failed: ", err)
            end
        end
    end
    return seeded
end

-- seed_blocklist_after_meta_failure — writes the fallback under `:0` and clears
-- the previous generation's ghost keys before writing. Used ONLY on the
-- meta:add ERR path (no_memory), where we force-set gen=0 over an
-- unknown previous value N. The data dict may hold `:N`
-- keys that nobody reads any more (we have just reset the gen)
-- while occupying slots — the clear frees them. On safety: fp_dict is an
-- exclusive writer zone for the blocklist (init plus catalog_pull, both ours);
-- if a future PR adds an admin override or a co-tenant
-- writer, this function will wipe their keys too — switch it to a typed
-- filter `fp_state.match(k, anything)` OR forbid third-party writers with a
-- comment in tls_fp_blocklist_state.lua.
local function seed_blocklist_after_meta_failure()
    for _, k in ipairs(fp_dict:get_keys(0)) do
        fp_dict:delete(k)
    end
    return seed_blocklist_cold()
end

-- meta_add_gen — a shared helper: meta:add(gen_key, 0) plus error recognition.
-- It returns (status, cur_gen_for_logging) where status ∈ {"cold_start",
-- "reload", "err"}. "err" is a meta:add failure other than "exists" (no_memory). On
-- "err" it calls meta:set(gen_key, 0) — best effort. verdict.lua and
-- friends are guarded everywhere with `meta:get(...) or 0`, so even if the set
-- also fails, readers see gen=0 through the nil default.
-- From audit: extracted out of tls_fp_blocklist into a shared helper, so that the
-- three sibling catalogs (verified_bots / tls_fp_catalog / tls_fp_browser_profiles)
-- get the same diagnostics plus force-set fallback instead of a silent SHADOW.
local function meta_add_gen(gen_key)
    local was_added, add_err = meta:add(gen_key, 0)
    if was_added then return "cold_start" end
    if add_err == "exists" then return "reload" end
    ngx.log(ngx.ERR, "[demo] meta:add ", gen_key, " failed (",
        tostring(add_err), ") — forcing gen=0; readers fall back via `or 0`")
    meta:set(gen_key, 0)
    return "err"
end

local blocklist_status = meta_add_gen(fp_state.META_GEN_KEY)
local n = 0
if blocklist_status == "cold_start" then
    -- A fresh start: the data dict holds nothing of ours, so seed it directly.
    n = seed_blocklist_cold()
elseif blocklist_status == "err" then
    -- meta:add failed: we force-set gen=0 but do not know the previous gen.
    -- Clear the ghosts before re-seeding.
    n = seed_blocklist_after_meta_failure()
else
    -- Reload survival: meta:add is a no-op because the key exists. We do not touch the data
    -- shared_dict — the Channel C `:N` entries are already there and verdict.lua will find them by
    -- meta:get(gen)=N. We count the surviving entries under the current gen for the
    -- blocklist_entries gauge plus the ACTIVE/SHADOW log (analyze.py parses
    -- "tls_fp_blocklist loaded: N"). We use the typed fp_state.match() rather than a
    -- bare suffix string — symmetrically with catalog_pull.sweep (a review guard
    -- against sharing the dict with another writer).
    local cur_gen = meta:get(fp_state.META_GEN_KEY) or 0
    -- `n` counts only ACTIVE records (for "loaded: N active entries" plus the gauge);
    -- `total` counts all of them (active+staging) for divergence detection (gen=N but the dict
    -- is empty). A11: the dict now also holds staging records ("staging:block"),
    -- so we count by status, so that staged fingerprints do not inflate the active count.
    local total = 0
    for _, k in ipairs(fp_dict:get_keys(0)) do
        if fp_state.match(k, cur_gen) then
            total = total + 1
            if fp_state.parse_value(fp_dict:get(k)) == "active" then
                n = n + 1
            end
        end
    end
    -- Detect divergence: meta:gen=N>0 + data dict empty. PR-62 round-8 audit:
    -- An INTENTIONALLY empty backend catalog and an operator wiping the data dict
    -- are indistinguishable from init.lua. If we re-seeded locally we would override
    -- the product intent for the legitimate empty case. The decision: only drop the etag
    -- (forcing the next pull to make a full 200 GET) plus a WARN. The next tick of
    -- catalog_pull brings the actual backend state: if it is empty, it stays empty;
    -- if there was a resize or a wipe, the backend redelivers the entries. The window "between the reload
    -- and the next pull" (≤30 s) leaves the catalog empty; for the rare situations
    -- where the backend is ALSO down, the operator sees the WARN and decides by hand.
    if cur_gen > 0 and total == 0 then
        ngx.log(ngx.WARN, "[demo] tls_fp_blocklist: meta says gen=", cur_gen,
            " but data dict has no matching entries — possibly zone wipe or ",
            "intentionally-empty Channel C payload. Dropping etag to force next ",
            "pull to verify; NOT re-seeding (preserves product intent if empty ",
            "was deliberate). Recover via catalog_pull within ≤30s if backend ",
            "reachable; see infra/demo-stand/README.md «Divergence WARN triage».")
        meta:delete(fp_state.META_ETAG_KEY)
    else
        ngx.log(ngx.NOTICE, "[demo] tls_fp_blocklist: reload detected, preserving Channel C state (gen=", cur_gen, ", entries=", total, " incl. ", n, " active)")
    end
end

-- verified_bots / tls_fp_catalog / tls_fp_browser_profiles — no static
-- seed (the catalogs arrive over Channel C). Initially (a cold start) the
-- gen keys are absent from `meta`; the meta shared_dict survives `nginx -s
-- reload` (the zone is preserved while the name and size are unchanged), so we use
-- `meta:add(key, 0)` — an assignment ONLY when the key does not exist.
--
-- check_data_dict_divergence — the same detection semantics as above for
-- tls_fp_blocklist (from audit, B1): meta:gen=N plus an empty data dict means
-- either an operator resized the zone or the backend published an empty catalog. Drop the etag and
-- WARN. With no re-seed (these three catalogs have no file fallback —
-- they arrive only over Channel C, and an intentional empty is
-- indistinguishable from a divergence).
--
-- It takes a catalog descriptor from catalog_pull.lua (the single source of truth
-- for dict_name/gen_key/etag_key — which removes the sync-drift trap that an
-- earlier fix closed for the blocklist; from audit: the same
-- trap must not be reintroduced for the siblings). A missing dict → an ERR
-- log plus a return (rather than silence — so that a typo in a catalog name is caught).
local function check_data_dict_divergence(cat)
    local dict = ngx.shared[cat.dict_name]
    if not dict then
        ngx.log(ngx.ERR, "[demo] check_data_dict_divergence: shared_dict ",
            cat.dict_name, " not declared (catalog ", cat.name,
            ") — declare in nginx.conf or remove from divergence check list")
        return
    end
    local cur_gen = meta:get(cat.gen_key)
    if not cur_gen or cur_gen <= 0 then return end
    -- A bare suffix match: the writer everywhere stores `<key>:<gen>` with the gen as the
    -- LAST `:` segment (catalog_pull.lua apply: `key .. ":" .. new_gen`).
    -- A ghost from an old gen=M (M≠N) ends in `:M` and does NOT match `:N`. IPv6 keys
    -- (verified_bots) were checked: the gen is always the last segment, so a false positive
    -- is impossible while the writer-side contract holds. If it ever changes
    -- to a content-hash gen, add a typed per-catalog match.
    local suffix = ":" .. cur_gen
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-#suffix) == suffix then return end
    end
    -- Reached: cur_gen > 0 + no matching entry → divergence.
    ngx.log(ngx.WARN, "[demo] ", cat.name, ": meta says gen=", cur_gen,
        " but data dict has no matching entries — possibly zone wipe or ",
        "intentionally-empty Channel C payload. Dropping etag to force next ",
        "pull to verify (recover ≤30s if backend reachable); see ",
        "infra/demo-stand/README.md «Divergence WARN triage».")
    meta:delete(cat.etag_key)
end

-- gen=0 seeding plus divergence detection for the three Channel-C-only catalogs.
-- meta_add_gen uses the shared ERR handling (no_memory is not
-- masked as a reload; force-set plus a log). The catalog descriptors come
-- from catalog_pull.catalogs — the single source of truth for the dict/gen/etag
-- names (so the literals are not duplicated between init.lua and the descriptors).
for _, cat_name in ipairs({"verified_bot_ips", "tls_fp_catalog", "tls_fp_browser_profiles", "policy"}) do
    local cat = catalog_pull.catalogs[cat_name]
    if not cat then
        ngx.log(ngx.ERR, "[demo] catalog_pull.catalogs[", cat_name,
            "] missing — divergence detection skipped")
    else
        meta_add_gen(cat.gen_key)
        check_data_dict_divergence(cat)
    end
end

-- ua_blacklist / ip_blocklist (A11, 86exrtjpc): file-seeded Channel C catalogs,
-- same model as tls_fp_blocklist. Generation 0 is the STATIC FALLBACK seeded
-- from the local conf (so the cascade matches from the first request, even with
-- no backend / before the first pull); Channel C then lands gen 1+ from
-- catalogs/*.yaml and the per-worker hygiene.refresh() / reputation.refresh()
-- swap to it.
--
-- Reload semantics (codex P2): the `meta` shared_dict survives `nginx -s
-- reload`, so meta_add_gen returns "reload". We must distinguish two cases by
-- the CURRENT gen, not just "reload":
--   * gen == 0 — still on the static fallback (no Channel C yet). Re-seed from
--     conf so an operator's `edit conf → nginx -s reload` actually takes effect
--     (otherwise the new workers' first refresh() rebuilds from the stale `:0`
--     entries and the edit is silently ignored until a full restart).
--   * gen  > 0 — real Channel C state survived; DON'T clobber it, just run the
--     divergence check.
local ua_dict  = ngx.shared.antibot_ua_blacklist
local ip_dict  = ngx.shared.antibot_ip_blocklist
local wl_dict  = ngx.shared.antibot_ip_whitelist
local asn_dict = ngx.shared.antibot_asn_datacenters

-- Delete all `:0` keys in a dict (the static-fallback generation) so a re-seed
-- drops entries removed from the conf. gen > 0 keys are Channel C state and are
-- left untouched.
local function clear_gen0(dict)
    if not dict then return end
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-2) == ":0" then dict:delete(k) end
    end
end

-- ua_blacklist seed: two keys under gen 0 — `active:0` (combined regex) and
-- `staging:0` (cjson array of staged patterns) — matching the Channel C layout
-- that hygiene.refresh() reads. The two keys are fixed, so a plain overwrite is
-- a complete re-seed (no stale entries possible).
local function seed_ua_blacklist_cold()
    if not ua_dict then return 0, 0 end
    -- Log set() failures loudly: refresh() rebuilds active_re from this gen-0
    -- dict on the first request, so a silently-dropped seed would disable the
    -- ua_blacklist rule below what build() compiled from conf (matches the
    -- load-or-die ethos of seed_blocklist_cold).
    local active = hygiene.build_combined(config.ua_blacklist) or ""
    local ok1, e1 = ua_dict:set("active:0", active)
    if not ok1 then
        ngx.log(ngx.ERR, "[demo] ua_blacklist seed active:0 failed: ", tostring(e1),
            " — edge may under-block until the first Channel C pull")
    end
    local _, staging_pats = hygiene.build_staging(config.ua_blacklist)
    staging_pats = staging_pats or {}
    local ok2, e2 = ua_dict:set("staging:0", require("cjson.safe").encode(staging_pats))
    if not ok2 then
        ngx.log(ngx.ERR, "[demo] ua_blacklist seed staging:0 failed: ", tostring(e2))
    end
    return (active ~= "" and 1 or 0), #staging_pats
end

-- ip_blocklist seed: `<cidr>:0` → "<status>:block" for every conf entry
-- (active and staging), matching the Channel C per-key layout. Clears prior
-- gen-0 keys first so a re-seed on reload drops CIDRs removed from the conf.
local function seed_ip_blocklist_cold()
    if not ip_dict then return 0, 0 end
    clear_gen0(ip_dict)
    local act, stg = 0, 0
    for _, e in ipairs(config.blocklist_ip) do
        if e.value and e.value ~= "" then
            local status = (e.attrs and e.attrs.status == "staging") and "staging" or "active"
            local ok, err = ip_dict:set(e.value .. ":0", status .. ":block")
            if ok then
                if status == "active" then act = act + 1 else stg = stg + 1 end
            else
                -- Loud: refresh() rebuilds the matcher from this gen-0 dict on
                -- the first request; a dropped CIDR would silently narrow the
                -- ip_blocklist rule until the first Channel C pull.
                ngx.log(ngx.ERR, "[demo] ip_blocklist seed ", e.value,
                    ":0 failed: ", tostring(err),
                    " — edge may under-block until the first Channel C pull")
            end
        end
    end
    return act, stg
end

-- ip_whitelist seed (B12): `<cidr>:0` → "1" for every conf entry, matching the
-- Channel C flat-list layout (no status — the allow list has no staging). Uses
-- reputation.active_values so the seeded set matches the matcher build()
-- compiled. Clears prior gen-0 keys first so a re-seed on reload drops CIDRs
-- removed from the conf.
local function seed_ip_whitelist_cold()
    if not wl_dict then return 0 end
    clear_gen0(wl_dict)
    local seeded = 0
    for _, v in ipairs(reputation.active_values(config.whitelist_ip)) do
        local ok, err = wl_dict:set(v .. ":0", "1")
        if ok then
            seeded = seeded + 1
        else
            -- Loud: refresh_whitelist() rebuilds the allow matcher from this
            -- gen-0 dict on the first request; a dropped CIDR would silently
            -- narrow the ip_whitelist allow until the first Channel C pull.
            ngx.log(ngx.ERR, "[demo] ip_whitelist seed ", v,
                ":0 failed: ", tostring(err),
                " — edge may under-allow until the first Channel C pull")
        end
    end
    return seeded
end

-- asn_datacenters seed (B12): `<asn>:0` → "1" for every conf entry, matching the
-- Channel C flat-list layout. Feeds the reputation:asn_dc tag (analytics-only,
-- no verdict), so a dropped entry is a missing tag rather than an allow/block
-- gap — logged at WARN, not ERR.
local function seed_asn_datacenters_cold()
    if not asn_dict then return 0 end
    clear_gen0(asn_dict)
    local seeded = 0
    for _, v in ipairs(reputation.active_values(config.asn_datacenters)) do
        local ok, err = asn_dict:set(v .. ":0", "1")
        if ok then
            seeded = seeded + 1
        else
            ngx.log(ngx.WARN, "[demo] asn_datacenters seed ", v,
                ":0 failed: ", tostring(err),
                " — reputation:asn_dc tag may miss this ASN until the first pull")
        end
    end
    return seeded
end

for _, spec in ipairs({
    { name = "ua_blacklist",    seed = seed_ua_blacklist_cold },
    { name = "ip_blocklist",    seed = seed_ip_blocklist_cold },
    { name = "ip_whitelist",    seed = seed_ip_whitelist_cold },
    { name = "asn_datacenters", seed = seed_asn_datacenters_cold },
}) do
    local cat = catalog_pull.catalogs[spec.name]
    if not cat then
        ngx.log(ngx.ERR, "[demo] catalog_pull.catalogs[", spec.name,
            "] missing — Channel C seed/divergence skipped")
    else
        local status = meta_add_gen(cat.gen_key)
        local cur_gen = meta:get(cat.gen_key) or 0
        if status ~= "reload" or cur_gen == 0 then
            -- cold_start / err / reload-still-on-static-fallback → (re)seed gen 0.
            spec.seed()
        else
            -- gen > 0: Channel C state survived the reload; preserve + verify.
            check_data_dict_divergence(cat)
        end
    end
end

-- One line per catalog so a reviewer can confirm at start that every config
-- loaded (acceptance: "Lua successfully loads every config").
ngx.log(ngx.NOTICE, "[demo] configs loaded from ", config.dir, ": ",
    "tls_fp_blocklist=", #config.tls_fp_blocklist,
    " ip_blocklist=", #config.blocklist_ip,
    " ip_whitelist=", #config.whitelist_ip,
    " ua_blacklist=", #config.ua_blacklist,
    " asn_datacenters=", #config.asn_datacenters)
-- Marker text is a contract: scripts/analyze.py INIT_RE parses the
-- blocklist size out of "[demo] tls_fp_blocklist loaded: N". Do not reword
-- without updating that regex, or daily reports mislabel the stand SHADOW.
ngx.log(ngx.NOTICE, "[demo] tls_fp_blocklist loaded: ", n, " active entries")
-- Reputation matchers: active (non-staging) entry counts compiled into the
-- ipmatcher objects. Empty whitelist/blocklist => that check is a no-op.
local asn_dc_n = 0
for _ in pairs(reputation.asn_dc_set) do asn_dc_n = asn_dc_n + 1 end
ngx.log(ngx.NOTICE, "[demo] reputation matchers: ip_whitelist=", rep_wl,
    " active, ip_blocklist=", rep_bl, " active, asn_dc=", asn_dc_n,
    " (geo_blocklist dormant — per-resource policy source is Phase 3)")
ngx.log(ngx.NOTICE, "[demo] verified-bot fastpath: ua_alts=", vb_alts_n,
    " (verified_bots dict empty until Channel C `verified_bot_ips`",
    " catalog pull lands — searchbot UAs get bot_verified_pending)")
-- Loud signal when the rule is enabled but its UA list is empty: looks_like_bot
-- would return false for every UA, so bot_verified / bot_verified_pending
-- never emits and every searchbot IP silently falls through to ip_blocklist.
-- A common cause is an accidental edit to [allow.bot_verified].ua_pattern in
-- defaults.conf (review #6 on PR #55).
if (require "verified_bots").enabled and vb_alts_n == 0 then
    ngx.log(ngx.WARN, "[demo] verified-bot fastpath: rule is ENABLED but",
        " ua_alts is EMPTY — check [allow.bot_verified].ua_pattern in",
        " defaults.conf; the fastpath will NEVER fire")
end
ngx.log(ngx.NOTICE, "[demo] rate_limits profiles: ", rate_n,
    " active (observe-only — verdict logged, no 429/delay in Phase 1)")
-- PR2 (ADR-006): tls_fp_catalog / tls_fp_browser_profiles moved from
-- local INI files to Channel C, and at init they are not there yet (the pull ticks after
-- init_worker_by_lua). External monitoring watches the metrics
-- `antibot_tls_fp_catalog_gen` / `antibot_tls_fp_browser_profiles_gen`
-- (metrics.lua) rather than the init log — no post-pull log marker
-- is printed here deliberately, so that dashboards do not confuse "a zero
-- gen at startup" with "the catalog never landed". For tls_fp_blocklist staging
-- (still file-based) we keep the traditional stand line.
ngx.log(ngx.NOTICE, "[demo] tls_fp staged catalogs: all three (blocklist / ",
    "catalog / browser_profiles) — Channel C-based; the staging tables are empty at ",
    "init and are filled in tls_fp.refresh() after the first pull (see /metrics ",
    "antibot_staging_match_total and *_gen)")
ngx.log(ngx.NOTICE, "[demo] challenge page template loaded, cascade_version=",
    cascade_version, " (C2 — preload only; serving wires up in C5)")

-- Prime metrics counters so they're visible at zero rather than absent.
local metrics = ngx.shared.metrics
for _, key in ipairs({
    "requests_total",
    "verdict_pass_total",
    "verdict_block_total",
    "verdict_challenge_total",
    "verdict_allow_total",
    "cache_hit_total",
    "cache_miss_total",
    "fp_unique",
    -- Known soft flags + informational tags, primed so /metrics shows them at
    -- zero from the first scrape (stable schema) instead of only after the
    -- first match. log_event.lua increments these per request; metrics.lua
    -- discovers them from the dict. New flag/tag codes still appear lazily.
    "flag:tls_fp_impersonator",
    "flag:tls_fp_suspicious_ciphers",
    "tag:tls_fp:automation_ua",
    "tag:tls_fp:no_sni",
    "tag:tls_fp:dc_browser",
    "tag:reputation:asn_dc",
    "tag:hygiene:header_anomaly",
    -- The BAC_LOG shipper (log_shipper.lua, B6 edge-side): the counters live
    -- here so that /metrics shows them at zero from the first scrape
    -- rather than lazily after the first line. enqueued is how much arrived in the
    -- queue from bac_log.emit; dropped is overflow or the shipper being off;
    -- shipped is how many lines left successfully for the backend; failed counts
    -- failed POSTs (the batch is lost); batches_ok counts successful
    -- POSTs (which helps tell "1 batch × 1000 lines" from "1000 batches
    -- × 1 line" when analysing throughput).
    "bac_log_enqueued_total",
    "bac_log_dropped_overflow_total",
    "bac_log_dropped_disabled_total",
    "bac_log_shipped_total",
    "bac_log_ship_failed_total",
    "bac_log_batches_ok_total",
    -- A 0/1 gauge: 0 if log_shipper.lua did not load (broken syntax,
    -- a missing dependency, an init_worker ERR that never reached start()); 1 after a
    -- successful start(). The dashboard alerts on `bac_log_shipper_loaded == 0`
    -- — otherwise a regression in log_shipper.lua fails silently.
    "bac_log_shipper_loaded",
    -- [C3/C7] L2.1 clearance cookie verify. Outcomes from clearance.verify
    -- (metric labels match clearance.RESULT_*; metrics.lua emits the labelled
    -- antibot_clearance_verify_total counter). Primed so /metrics shows them
    -- at zero from the first scrape — dashboards distinguish «no fastpath
    -- traffic yet» from «metric missing» without staring at NaN.
    "clearance_verify_valid_total",
    "clearance_verify_invalid_total",
    "clearance_verify_expired_total",
    "clearance_verify_missing_total",
    "clearance_verify_malformed_total",
    "clearance_verify_wrong_site_total",
    "clearance_verify_no_secret_total",
    -- [C7] attack_mode=on plus a cookie issued before the attack started (a long TTL) →
    -- it does not fastpath and goes to the L5 challenge.
    "clearance_verify_stale_pre_attack_total",
    -- [C5] Phase 4 L5.2 challenge issuance + verify endpoint.
    -- challenge_issued_total — render of Branch A challenge page;
    -- challenge_solved_total — successful POST /__challenge/verify (cookie
    -- issued); challenge_invalid_<reason>_total — fail reasons (bad_nonce,
    -- expired, replay, bad_token, wrong_version, bad_body, bad_method,
    -- no_secret); challenge_branch_b_total / challenge_branch_c_total —
    -- Branch B/C dispatches at L5 dispatch (non_browser_blocked /
    -- unchallengeable_request). Primed at zero so /metrics shows the
    -- shape from the first scrape; dashboards distinguish «no challenge
    -- traffic» from «metric missing».
    "challenge_issued_total",
    "challenge_solved_total",
    "challenge_invalid_bad_nonce_total",
    "challenge_invalid_expired_total",
    "challenge_invalid_replay_total",
    "challenge_invalid_bad_token_total",
    "challenge_invalid_wrong_version_total",
    "challenge_invalid_bad_body_total",
    "challenge_invalid_bad_method_total",
    "challenge_invalid_no_secret_total",
    "challenge_branch_b_total",
    "challenge_branch_c_total",
}) do
    metrics:safe_add(key, 0)
end

-- Prime a staging_match counter per staged pattern so /metrics shows it at zero
-- from the first scrape — the promotion workflow watches these to decide
-- staging→active. Key shape "staging:<catalog>:<pattern_id>" (log_event.lua
-- increments, metrics.lua parses). Pattern_ids are dynamic (depend on which
-- patterns are staged), so unlike the fixed flag/tag list above they are
-- primed from the compiled staging tables rather than hard-coded.
--
-- All three staged tls_fp catalogs (blocklist / catalog /
-- browser_profiles) are now Channel C-based — their staging tables are empty at init
-- and are filled after the first pull. Priming the staging counters is done by
-- `reconcile_staging_metrics` in tls_fp.refresh() on every gen flip
-- (together with deleting stale counters), so there are no priming loops
-- for tls_fp_* here any more. ua_blacklist / ip_blocklist staging is file-based
-- (hygiene / reputation), and their counters are primed here from the compiled staging branches,
-- so that /metrics shows the staged patterns at zero from the first scrape.
for _, pat in ipairs(hygiene.staging_patterns or {}) do
    metrics:safe_add("staging:ua_blacklist:" .. pat, 0)
end
for _, cidr in ipairs(reputation.blocklist_staging_values or {}) do
    metrics:safe_add("staging:ip_blocklist:" .. cidr, 0)
end

metrics:set("start_time", ngx.time())
metrics:set("blocklist_entries", n)

if n == 0 then
    ngx.log(ngx.NOTICE, "[demo] mode: SHADOW (empty fp blocklist — nothing blocked)")
else
    ngx.log(ngx.NOTICE, "[demo] mode: ACTIVE blocking on ", n, " fp(s) (ngx.exit(403) on block)")
end

-- On-demand TLS for tenant custom domains (lua-resty-auto-ssl, 86exrefdz
-- follow-up). pcall-guarded: a missing module or init error must NEVER brick
-- nginx start — ssl_certificate() then no-ops and the static fallback cert is
-- served (current behaviour). Logs loud so a broken setup is visible.
local autossl_ok, autossl_err = pcall(function()
    require("tls_autossl").setup()
end)
if autossl_ok then
    ngx.log(ngx.NOTICE, "[demo] on-demand TLS: lua-resty-acme active (staging=",
        tostring((os.getenv("AUTO_SSL_STAGING") or "") == "true"),
        ", base_domain=", os.getenv("STAND_BASE_DOMAIN") or "example.com", ")")
else
    ngx.log(ngx.ERR, "[demo] on-demand TLS: setup failed — serving static fallback ",
        "cert only (custom-domain tenants won't get a cert): ", tostring(autossl_err))
end
