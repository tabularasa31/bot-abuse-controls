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
-- Data. Phase 1: static whitelist_ip.conf / blocklist_ip.conf, parsed once in
-- init_by_lua (config.lua) and compiled into ipmatcher objects by build()
-- below — done in the master before workers fork, so every worker inherits the
-- matchers for free (no shared dict; hot-reload is out of scope). Phase 3: the
-- same data arrives as the ip_whitelist / ip_blocklist catalogs over Channel C
-- into shared dicts antibot_ip_whitelist / antibot_ip_blocklist
-- (config-distribution.md); the rule names, stage, category and log contract
-- are unchanged across the phase boundary — only the data source changes.
--
-- Staging: blocklist entries with status=staging are excluded from the active
-- matcher (mirrors hygiene's ua_blacklist and init.lua's fp seeding). A11
-- implemented staging_match for the three tls_fp catalogs (tls_fp.lua);
-- recording staged ip_blocklist matches is the "и далее" follow-up to that task.
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

local _M = {
    enabled        = true,
    whitelist      = nil,   -- ipmatcher or nil when no active entries
    blocklist      = nil,   -- ipmatcher or nil when no active entries
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

    local wl_n, bl_n
    _M.whitelist, wl_n = matcher(config.whitelist_ip, "whitelist_ip.conf",
                                 rule_enabled("allow", "ip_whitelist"))
    _M.blocklist, bl_n = matcher(config.blocklist_ip, "blocklist_ip.conf",
                                 rule_enabled("blocking", "ip_blocklist"))

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

    return _M, wl_n, bl_n
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
    if pm.whitelist and pm.whitelist:match(ip) then
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
    if pm.blocklist and pm.blocklist:match(ip) then
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

    return false
end

return _M
