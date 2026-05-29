-- L2 reputation stage — system IP lists (rules-reference L2, vision §2.3–2.4).
--
-- Two source-IP checks via lua-resty-ipmatcher (CIDR-aware, IPv4 + IPv6):
--   1. ip_whitelist (category allow)    — our monitoring / check services.
--   2. ip_blocklist (category blocking) — known-bad IPs/CIDRs.
-- Whitelist is checked FIRST (vision §2.3 before §2.4): a whitelisted IP wins
-- and the blocklist is not consulted.
--
-- Runs AFTER hygiene, BEFORE tls_fp (cascade order hygiene → reputation →
-- tls_fp → rate_limits → verification).
--
-- Mode-gated enforcement (B11 / 86exr05q7). The block-side rules
-- (ip_blocklist and the dormant geo_blocklist) record the would-be
-- verdict via bac_log and then call policy.enforce(403). For a host
-- with policy.mode=active that means ngx.exit(403) right here (cascade
-- dies, later stages do not run). For mode=shadow (pool default) the
-- enforce is a no-op: run returns true, verdict.lua keeps going to
-- tls_fp / rate_limit so their would-be verdicts and tags still
-- accumulate. Last-writer-wins on the verdict matches phase1-spec
-- "финальное сработавшее правило" (a later tls_fp block can still
-- overwrite the reputation rule in the shadow log).
--
-- The allow-side (ip_whitelist match, verified_bots verified/pending)
-- still does NOT short-circuit the cascade — in either mode. Production
-- would fastpass past L3-L5 here, but the stand keeps going so a later
-- tls_fp block can still demonstrate (and so an active-mode whitelisted
-- IP can't accidentally skip a real tls_fp_blocklist hit downstream).
-- Switching the allow-side to a real fastpass is a separate task (paired
-- with per-host policy.ip_whitelist application, 86exr05xt).
--
-- Data. ip_whitelist: static whitelist_ip.conf, parsed once in init_by_lua
-- (config.lua) and compiled into an ipmatcher by build() (master pre-fork; no
-- shared dict yet — its Channel C migration is a follow-up). ip_blocklist
-- follows the production Channel C model (A11, 86exrtjpc): build() seeds the
-- cold-start matcher from blocklist_ip.conf, init.lua seeds gen 0 into the
-- antibot_ip_blocklist shared_dict, and refresh() (per request, gen-cached)
-- swaps to the Channel C snapshot (gen 1+, sourced from catalogs/
-- ip_blocklist.yaml). The rule names, stage, category and log contract are
-- unchanged — only the data source changes. The per-host policy.ip_blocklist
-- is a separate catalog applied via policy_matchers and is unaffected.
--
-- Staging (A11, 86exrtjpc): blocklist entries with status=staging are excluded
-- from the active matcher and compiled into a parallel staging matcher
-- (blocklist_staging, value-map so match returns the CIDR). run() records
-- staging_match: ["ip_blocklist:<cidr>"] for them and NEVER blocks — pure
-- observation for the staging→active promotion workflow, symmetric with
-- hygiene's ua_blacklist staging and tls_fp's blocklist staging.
--
-- A6 additions (geo/ASN, rules-reference L2 #9 + tag T1):
--   * geo_country / asn log fields — filled every request from a GeoLite2
--     lookup (geoip.lua) via bac_log.set_source.
--   * reputation:asn_dc — informational TAG (not a rule, emits no verdict):
--     request ASN is in asn_datacenters.conf. Accumulates in `tags` like
--     hygiene:header_anomaly, independent of the verdict.
--   * geo_blocklist — blocking rule, country NOT in the allowed-countries
--     whitelist. Source is per-resource policy[host].geo_whitelist; there
--     is no system-wide country list (geo-allow is a per-resource choice).
--     Live as of 86exr05xt — fires when the host's policy has a non-empty
--     geo_whitelist and the request country is outside it.
--
-- Per-host policy lists (86exr05xt). For each request the stage also
-- matches against policy[host].{ip_whitelist, ip_blocklist, asn_block,
-- geo_whitelist} pulled from antibot_policy shared_dict and compiled
-- through policy_matchers.lua (lrucache by (host, gen) — see that
-- module's header). Rule names in the log are namespaced so analytics
-- can split per-host hits from system-list hits:
--   * `ip_whitelist`        / `policy.ip_whitelist`
--   * `ip_blocklist`        / `policy.ip_blocklist`
--   * (no system asn rule)  / `policy.asn_block`
--   * (no system geo rule)  / `policy.geo_blocklist`
-- Empty per-host lists (pool default, untouched dashboard) are the
-- backwards-compatible no-op: policy_matchers returns the EMPTY
-- sentinel and every per-host check short-circuits at the first guard.
-- The verified-bot fastpath (B8) lives in verified_bots.lua and is
-- invoked inline below between the whitelist allow-checks and the
-- blocklist block-checks.

local policy          = require "policy"
local policy_matchers = require "policy_matchers"
local staging_metrics = require "staging_metrics"

local _M = {
    enabled        = true,
    whitelist      = nil,   -- ipmatcher or nil when no active entries
    blocklist      = nil,   -- ipmatcher or nil when no active entries
    blocklist_staging = nil, -- ipmatcher (new_with_value: match→cidr) or nil; A11 observe-only
    asn_dc_set     = {},    -- { ["24940"] = true, ... } from asn_datacenters.conf
    geo_enabled    = true,  -- [blocking.geo_blocklist].enabled (dormant: no source yet)
    demo_geo_header = false, -- honour X-Demo-IP override (stand testing); env-gated
}

-- pure: array of `value` strings from a parsed list (config_loader.parse_list
-- output: { { value = "<ip-or-cidr>", attrs = { status = ... } }, ... }),
-- excluding status=staging entries. Returns {} when the list is nil/empty/
-- all-staging. No ngx / ipmatcher dependency so it is unit-testable under bare
-- luajit (tests/reputation_test.lua).
function _M.active_values(list)
    local out = {}
    for _, e in ipairs(list or {}) do
        local v = e.value
        local status = e.attrs and e.attrs.status
        if v and v ~= "" and status ~= "staging" then
            out[#out + 1] = v
        end
    end
    return out
end

-- pure: array of `value` strings with status=staging (A11). The staging
-- counterpart of active_values — used to build the observe-only staging
-- matcher. No ngx / ipmatcher dependency (unit-tested in reputation_test.lua).
function _M.staging_values(list)
    local out = {}
    for _, e in ipairs(list or {}) do
        local v = e.value
        local status = e.attrs and e.attrs.status
        if v and v ~= "" and status == "staging" then
            out[#out + 1] = v
        end
    end
    return out
end

-- pure: array of strings -> lookup set { [v] = true }. Used for the
-- asn_datacenters set (membership test for the reputation:asn_dc tag). No
-- ngx dependency — unit-tested in tests/reputation_test.lua.
function _M.to_set(values)
    local set = {}
    for _, v in ipairs(values or {}) do
        if v ~= nil and v ~= "" then set[v] = true end
    end
    return set
end

-- pure: geo_blocklist decision. Block when an allowed-countries whitelist is
-- configured AND the request country is known AND it is NOT in the whitelist
-- (rules-reference #9 inverted logic). An empty/absent whitelist (the Phase 1
-- stand reality — no per-resource policy yet) or an unknown country never
-- blocks. No ngx dependency — unit-tested.
function _M.country_blocked(allow, cc)
    if not allow or not next(allow) then return false end
    if not cc or cc == "" then return false end
    return not allow[cc]
end

-- IP used for the GeoLite2 lookup only. Production: the real remote_addr.
-- Stand testing: when BAC_DEMO_GEO_HEADER=on, an X-Demo-IP request header
-- overrides it so a reviewer can simulate a public IP (a local/private client
-- IP has no GeoIP entry). The toggle defaults off, so on a live VM the header
-- is inert. The override applies ONLY to geo enrichment — the ip_whitelist /
-- ip_blocklist matchers always use the real remote_addr, so a caller-supplied
-- header can never rewrite a reputation verdict or skew rule metrics.
local function geo_lookup_ip(remote_addr)
    if _M.demo_geo_header then
        local override = ngx.var.http_x_demo_ip
        if override and override ~= "" then return override end
    end
    return remote_addr
end

-- Called once in init_by_lua, after config.load(). Compiles the on-disk IP
-- lists into the per-process ipmatcher objects the request path reads.
--
-- Empty active list => nil matcher (run() skips it); an empty blocklist is the
-- Phase 1 default and must not error.
--
-- A malformed IP/CIDR is FATAL, not fail-open: ipmatcher.new returns nil on a
-- bad entry, and we error out of init_by_lua (aborting the start) rather than
-- log-and-nil the whole list. Silently disabling all of ip_whitelist or
-- ip_blocklist on one bad line is a hard-to-notice protection gap; failing
-- loudly on a config typo matches config.lua's load-or-die contract ("fail
-- loudly rather than run a half-configured cascade").
--
-- A rule can also be disabled via defaults.conf ([blocking.ip_blocklist] /
-- [allow.ip_whitelist] enabled=false) — a runtime toggle for rollback /
-- incident handling, mirroring how hygiene.lua honours blocking.ua_blacklist.
-- A disabled rule yields a nil matcher (count 0); absent flag means enabled.
function _M.build(config)
    local ipmatcher = require "resty.ipmatcher"
    local defaults  = config.defaults or {}

    -- enabled unless the rule's defaults.conf section sets enabled=false.
    local function rule_enabled(section, name)
        local rule = (defaults[section] or {})[name] or {}
        return rule.enabled ~= false
    end

    local function matcher(list, label, enabled)
        if not enabled then return nil, 0 end
        local values = _M.active_values(list)
        if #values == 0 then return nil, 0 end
        local m, err = ipmatcher.new(values)
        if not m then
            error("reputation: invalid IP/CIDR in " .. label .. ": " .. tostring(err))
        end
        return m, #values
    end

    -- Toggle flags are stored separately from the matchers because the
    -- per-host equivalents (policy[host].ip_whitelist / ip_blocklist
    -- via policy_matchers) must also honour the kill-switch — an
    -- operator disabling ip_blocklist for incident rollback expects no
    -- IP-based blocking ANYWHERE, system or per-host (codex P1 on PR
    -- #71). matcher-nil collapses "disabled" and "no entries"; we can't
    -- distinguish them in run() without the explicit flag.
    _M.ip_whitelist_enabled = rule_enabled("allow", "ip_whitelist")
    _M.ip_blocklist_enabled = rule_enabled("blocking", "ip_blocklist")

    -- Staging matcher (A11): value-map (cidr → cidr) so match() returns the
    -- matched CIDR, needed for the staging_match pattern_id
    -- (["ip_blocklist:<cidr>"]). Gated on the same ip_blocklist_enabled
    -- kill-switch as the active matcher — disabling the rule for rollback
    -- silences observe-only staging too. A malformed staged CIDR is FATAL
    -- (same load-or-die contract as the active matcher).
    local function staging_matcher(list, label, enabled)
        if not enabled then return nil, {} end
        local values = _M.staging_values(list)
        if #values == 0 then return nil, {} end
        local vmap = {}
        for _, c in ipairs(values) do vmap[c] = c end
        local m, err = ipmatcher.new_with_value(vmap)
        if not m then
            error("reputation: invalid staging IP/CIDR in " .. label .. ": " .. tostring(err))
        end
        return m, values
    end

    local wl_n, bl_n
    _M.whitelist, wl_n = matcher(config.whitelist_ip, "whitelist_ip.conf",
                                 _M.ip_whitelist_enabled)
    _M.blocklist, bl_n = matcher(config.blocklist_ip, "blocklist_ip.conf",
                                 _M.ip_blocklist_enabled)
    _M.blocklist_staging, _M.blocklist_staging_values =
        staging_matcher(config.blocklist_ip, "blocklist_ip.conf (staging)",
                        _M.ip_blocklist_enabled)

    -- asn_datacenters.conf -> membership set for the reputation:asn_dc tag.
    -- Reuses active_values (drops blanks/staging). The tag has no enable flag
    -- of its own (config-templates tags carry no toggle); the per-stage
    -- kill-switch below disables it along with the rest of the stage.
    _M.asn_dc_set = _M.to_set(_M.active_values(config.asn_datacenters))

    -- geo_blocklist runtime toggle (rollback/incident), mirroring the IP rules.
    -- Dormant regardless in Phase 1 — there is no country whitelist source yet.
    _M.geo_enabled = rule_enabled("blocking", "geo_blocklist")

    -- Stand-only X-Demo-IP override, off unless explicitly enabled.
    _M.demo_geo_header = (os.getenv("BAC_DEMO_GEO_HEADER") == "on")

    -- Stage off via the shared kill-switch helper (config-templates.md
    -- kill_switch; defaults.conf [kill_switch.*]).
    _M.enabled = require("config").stage_enabled(defaults, "reputation")

    -- Per-worker gen cache for the Channel C ip_blocklist refresh (A11,
    -- 86exrtjpc). nil = "first refresh rebuilds from current gen". The matchers
    -- above (from the local conf) are the cold-start state; refresh() takes over
    -- once init.lua seeds gen 0 (conf) and Channel C lands gen 1+ (yaml).
    _M._cached_gen_ip = nil

    return _M, wl_n, bl_n
end

-- refresh — gen-cached rebuild of the active + staging ip_blocklist matchers
-- from the Channel C snapshot (A11, 86exrtjpc). antibot_ip_blocklist holds
-- `<cidr>:<gen>` → "<status>:block"; on a gen flip we scan the current gen,
-- split active vs staging, and rebuild the two ipmatcher objects. Cheap in
-- steady state (one meta:get + int compare). Honours the ip_blocklist
-- kill-switch. Fail-soft: a matcher that fails to rebuild keeps the previous
-- one (backend validates CIDRs, so this is defence-in-depth). When the gen key
-- is absent (catalog never seeded/pulled) it keeps the build()-time conf state.
function _M.refresh()
    if not ngx or not ngx.shared then return end
    local meta = ngx.shared.meta
    if not meta then return end
    local gen = meta:get("ip_blocklist_gen")
    if gen == nil or gen == _M._cached_gen_ip then return end
    local dict = ngx.shared.antibot_ip_blocklist
    if not dict then return end

    if not _M.ip_blocklist_enabled then
        local prev = _M.blocklist_staging_values
        _M.blocklist                = nil
        _M.blocklist_staging        = nil
        _M.blocklist_staging_values = {}
        _M._cached_gen_ip           = gen
        staging_metrics.reconcile("ip_blocklist", prev, {})
        return
    end

    local ipmatcher = package.loaded["resty.ipmatcher"] or require "resty.ipmatcher"
    local suffix = ":" .. gen
    local active, staging_vmap, staging_list = {}, {}, {}
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-#suffix) == suffix then
            local cidr = k:sub(1, -#suffix - 1)
            local val  = dict:get(k)
            local status = (type(val) == "string") and val:match("^([^:]+):") or nil
            if status == "active" then
                active[#active + 1] = cidr
            elseif status == "staging" then
                staging_vmap[cidr] = cidr
                staging_list[#staging_list + 1] = cidr
            end
        end
    end

    -- Active matcher: empty → nil (rule is a no-op); build error → keep previous.
    if #active == 0 then
        _M.blocklist = nil
    else
        local m, err = ipmatcher.new(active)
        if m then
            _M.blocklist = m
        else
            ngx.log(ngx.ERR, "reputation: ip_blocklist active matcher rebuild ",
                "failed, keeping previous: ", tostring(err))
        end
    end

    -- Staging matcher (value-map so match() returns the CIDR for pattern_id).
    local prev = _M.blocklist_staging_values
    if next(staging_vmap) == nil then
        _M.blocklist_staging        = nil
        _M.blocklist_staging_values = {}
    else
        local m, err = ipmatcher.new_with_value(staging_vmap)
        if m then
            _M.blocklist_staging        = m
            _M.blocklist_staging_values = staging_list
        else
            ngx.log(ngx.ERR, "reputation: ip_blocklist staging matcher rebuild ",
                "failed, keeping previous: ", tostring(err))
        end
    end

    _M._cached_gen_ip = gen
    staging_metrics.reconcile("ip_blocklist", prev, _M.blocklist_staging_values)
end

-- Called per request from verdict.lua, after bac_log.init(). Records the
-- would-be verdict via bac_log; on a block-side match (ip_blocklist /
-- geo_blocklist) it then calls policy.enforce(403), which 403s the
-- request for mode=active hosts and is a no-op for mode=shadow. The
-- allow-side (ip_whitelist, verified_bots verified/pending) stays
-- non-short-circuiting in either mode — see the header comment. The
-- boolean return (true when any rule matched, including allow) is
-- informational only; verdict.lua does not branch on it.
function _M.run()
    if not _M.enabled then return false end

    -- Pull the latest Channel C ip_blocklist snapshot (A11). Cheap in steady
    -- state (gen compare); rebuilds the matchers only on a gen flip.
    _M.refresh()

    local ip = ngx.var.remote_addr
    if not ip then return false end

    -- bac_log / geoip required lazily (keeps the pure helpers unit-testable
    -- without ngx); the package.loaded fast-path avoids the require() call
    -- overhead on the per-request hot path after the first lookup in a worker.
    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local geoip   = package.loaded["geoip"]   or require "geoip"

    -- Source enrichment + asn_dc tag run for EVERY request, independent of the
    -- verdict (tags accumulate even when a blocking rule fires; the log fields
    -- must be populated regardless). geo is fail-open: nil cc/asn just leaves
    -- the fields null and the tag unset. The lookup IP may be an X-Demo-IP
    -- override (stand testing); the matchers below still use the real ip.
    local cc, asn = geoip.lookup(geo_lookup_ip(ip))
    bac_log.set_source(asn, cc)
    if asn and _M.asn_dc_set[asn] then
        bac_log.add_tag("reputation:asn_dc")
    end

    -- Per-host policy matchers (86exr05xt). Compiled once per (host, gen)
    -- and lru-cached; the call below is a constant-time dictionary lookup
    -- after the first hit per worker. EMPTY sentinel means the host has
    -- no per-host lists at all — every `if pm.x then ...` guard then
    -- short-circuits and the stage runs at pre-PR cost.
    local host = ngx.var.host
    local pm   = policy_matchers.get(host)

    -- Verdict rules, first match wins within the stage (allow before blocking,
    -- vision §2.3 → §2.4 → geo). A match returns so a later same-stage rule
    -- doesn't overwrite it under bac_log's last-writer-wins. System lists
    -- are checked alongside per-host lists in each category — rule name
    -- distinguishes them in the log (`ip_whitelist` vs `policy.ip_whitelist`)
    -- so analytics can attribute hits to the right source.
    if _M.whitelist and _M.whitelist:match(ip) then
        bac_log.set_verdict("reputation", "allow", "ip_whitelist")
        return true
    end
    if _M.ip_whitelist_enabled and pm.whitelist and pm.whitelist:match(ip) then
        bac_log.set_verdict("reputation", "allow", "policy.ip_whitelist")
        return true
    end

    -- B8 verified-bot fastpath (rules-reference rules 4 + 5). Runs AFTER
    -- ip_whitelist (rule 2) per the rules-reference order, BEFORE
    -- ip_blocklist (rule 6) so a "verified" / "pending" allow always wins
    -- over a block on the same stage. "rejected" emits no verdict and we
    -- fall through to ip_blocklist (and the rest of the cascade) — that
    -- 3-state behaviour is the whole point of the catalog. Like
    -- ip_whitelist above, the stand stays observe-only: production would
    -- short-circuit L3-L5 here, but on the stand we keep going so a later
    -- tls_fp block can still demonstrate (last-writer-wins on the log).
    local verified_bots = package.loaded["verified_bots"]
                         or require "verified_bots"
    local vb_outcome = verified_bots.run(ip, ngx.var.http_user_agent)
    -- Use the SHORT_CIRCUIT set rather than a literal `vb_outcome ==
    -- "verified" or "pending"` chain so a future outcome added to
    -- verified_bots cannot accidentally short-circuit by being copy-pasted
    -- into this condition (review #3 on PR #55). "rejected" is deliberately
    -- absent from SHORT_CIRCUIT: rejected IPs must continue through
    -- ip_blocklist / tls_fp / rate_limits / L5 — that is the entire point
    -- of the 3-state catalog.
    if verified_bots.SHORT_CIRCUIT[vb_outcome] then
        return true
    end

    if _M.blocklist and _M.blocklist:match(ip) then
        bac_log.set_verdict("reputation", "block", "ip_blocklist")
        -- mode-gate: active → ngx.exit(403); shadow → no-op, cascade
        -- continues so later stages still tag/verdict (header comment).
        policy.enforce(403)
        return true
    end
    if _M.ip_blocklist_enabled and pm.blocklist and pm.blocklist:match(ip) then
        bac_log.set_verdict("reputation", "block", "policy.ip_blocklist")
        policy.enforce(403)
        return true
    end

    -- Per-host asn_block. The asn_dc tag above is system-level
    -- (analytics-only); the per-host block is a separate rule the client
    -- opts into via policy. Reads asn from the geoip lookup we already
    -- did; tostring matches policy_matchers.to_set which keys by string.
    if asn and pm.asn_block and pm.asn_block[asn] then
        bac_log.set_verdict("reputation", "block", "policy.asn_block")
        policy.enforce(403)
        return true
    end

    -- geo_blocklist. Per vision.md geo gating is per-resource — there is
    -- no system-wide country whitelist (geo-allow is a client choice).
    -- When pm.geo_whitelist is nil the rule never fires; when set, any
    -- country not in the set blocks. The `_M.geo_enabled` toggle stays as
    -- a master kill-switch (incident rollback for the whole rule).
    if _M.geo_enabled and pm.geo_whitelist then
        if _M.country_blocked(pm.geo_whitelist, cc) then
            bac_log.set_verdict("reputation", "block", "policy.geo_blocklist")
            policy.enforce(403)
            return true
        end
    end

    -- Staged ip_blocklist CIDRs (A11, 86exrtjpc). Observe-only: matched with
    -- the same predicate as the active matcher but records only staging_match
    -- (["ip_blocklist:<cidr>"]) — never a verdict, never a 403, never a
    -- short-circuit. Reached only when no allow/block rule matched above
    -- (those return), so it records what WOULD fire after promotion to active.
    -- new_with_value returns the matched CIDR, which is the pattern_id.
    if _M.blocklist_staging then
        local cidr = _M.blocklist_staging:match(ip)
        if cidr then
            bac_log.add_staging_match("ip_blocklist:" .. cidr)
        end
    end

    return false
end

return _M
