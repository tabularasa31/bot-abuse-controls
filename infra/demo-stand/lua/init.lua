-- init_by_lua: loads the cascade config, seeds the shared dicts and primes the
-- counters so every metric exists from the first scrape rather than appearing
-- lazily on first use.

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

-- The catalog itself arrives over Channel C, so without a backend every
-- searchbot UA resolves to the provisional fastpath until the rDNS worker
-- publishes a status.
local _, vb_alts_n = require("verified_bots").build(config)

-- Compile the L4 rate_limits stage (GCRA profiles from defaults.conf
-- [blocking.rate_*] thresholds) — also in the master so workers inherit the
-- profile list on fork (see rate_limit.lua; the shared dict holds only per-key
-- TAT state). Returns the active profile count for the startup log.
local _, rate_n = require("rate_limit").build(config)

-- Only the cold-start state: the catalogs arrive over Channel C, so the staging
-- tables stay empty until the first pull.
require("tls_fp").build(config)

-- Opened in the master so workers inherit the handles. Fail-open: without the
-- licence-gated databases the stand still starts and geo stays undetermined.
require("geoip").init()

-- Parsed in the master, before privileges are dropped: the workers run as
-- nobody and could not open a 0600 root-owned key. They inherit the parsed
-- objects on fork.
require("catalog_pull").preload_mtls(
    os.getenv("ANTIBOT_BACKEND_CLIENT_CERT"),
    os.getenv("ANTIBOT_BACKEND_CLIENT_KEY"))

-- A missing secret is a warning rather than fatal: the cookie paths go dark,
-- but the rest of the cascade keeps working.
require("challenge_secret").load(
    os.getenv("CHALLENGE_HMAC_SECRET_FILE")
        or "/etc/nginx/certs/challenge_secret.key")

-- The template's version is compared against CASCADE_VERSION and a mismatch
-- fails the start. That is the pin: template and cascade can only diverge
-- through a deliberate bump of both.
local cascade_version = require("challenge").preload()

-- Seeds the local fallback as generation 0, which the pull later replaces with
-- generation 1 and up.
--
-- Only on a genuinely fresh start. The dicts survive a reload, so re-seeding
-- unconditionally would reset the generation and hide a larger set the pull had
-- already delivered — until the backend's payload happened to change, since a
-- 304 would leave the generation at zero.
local fp_state    = require "tls_fp_blocklist_state"
local catalog_pull = require "catalog_pull"
local fp_dict = ngx.shared.tls_fp_blocklist
local meta    = ngx.shared.meta

-- The cold-start path, where the data dict is empty or holds only ghosts that
-- this write overwrites. Staged fingerprints are deliberately not seeded: they
-- arrive live over Channel C.
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

-- Only for the path where the generation was force-reset over an unknown
-- previous value: the old keys are now unreachable and just occupy slots.
--
-- This assumes we are the dict's only writer. A future third-party writer would
-- have its keys wiped too, and would need a typed filter here.
local function seed_blocklist_after_meta_failure()
    for _, k in ipairs(fp_dict:get_keys(0)) do
        fp_dict:delete(k)
    end
    return seed_blocklist_cold()
end

-- Returns "cold_start", "reload" or "err". Readers default a missing generation
-- to zero, so even a failed force-set degrades predictably.
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
    -- The surviving entries are left alone and merely counted for the gauge.
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
    -- A non-zero generation over an empty dict is ambiguous: the backend may
    -- have published an empty catalog on purpose, or the zone may have been
    -- wiped. Re-seeding would override the first case, so we only drop the etag
    -- to force a full fetch and warn. The next pull settles it either way.
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

-- These three have no file fallback at all — they exist only over Channel C.
-- The same divergence check applies, and for the same reason it never
-- re-seeds.
--
-- The descriptor comes from catalog_pull, so the dict and key names have one
-- owner and cannot drift apart.
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
    -- The generation is always the last `:` segment, which is what makes this
    -- safe for IPv6 keys too.
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

-- Generation seeding and divergence detection for the Channel-C-only catalogs.
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

-- File-seeded catalogs: generation 0 comes from the local config so the cascade
-- matches from the first request, and the pull replaces it.
--
-- On a reload the current generation decides what to do. Still at zero means
-- nothing has been pulled, so re-seed — otherwise an operator's config edit
-- would be silently ignored until a full restart. Above zero means real pulled
-- state survived and must not be clobbered.
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

-- Prior generation-0 keys are cleared first, so a re-seed drops CIDRs that were
-- removed from the config.
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
-- An enabled rule with an empty UA list matches nothing, so every searchbot
-- would silently fall through to the blocklist.
if (require "verified_bots").enabled and vb_alts_n == 0 then
    ngx.log(ngx.WARN, "[demo] verified-bot fastpath: rule is ENABLED but",
        " ua_alts is EMPTY — check [allow.bot_verified].ua_pattern in",
        " defaults.conf; the fastpath will NEVER fire")
end
ngx.log(ngx.NOTICE, "[demo] rate_limits profiles: ", rate_n,
    " active (observe-only — verdict logged, no 429/delay in Phase 1)")
-- These two are empty at init by construction, so nothing is logged for them:
-- a startup line would read as "the catalog never landed". Monitoring watches
-- their generation counters instead.
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
    -- batches_ok alongside the line counters is what separates one batch of a
    -- thousand lines from a thousand batches of one.
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
    -- One per clearance.verify outcome.
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
    -- Challenge issuance, solves, and one counter per rejection reason.
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

-- Staged pattern ids are dynamic, so unlike the fixed lists above these are
-- primed from the compiled staging tables. Only the file-seeded catalogs are
-- primed here; the Channel C ones are handled on each generation flip.
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
