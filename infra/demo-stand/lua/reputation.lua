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
-- Phase 1 is OBSERVE-ONLY, exactly like hygiene.lua: run() records the
-- would-be verdict via bac_log but NEVER ngx.exit and NEVER short-circuits the
-- cascade. In particular an ip_whitelist match does NOT fastpass here. In
-- production an allow short-circuits L3–L5 and a block returns 403; on the
-- stand it must not, because skipping the later stages would let a whitelisted
-- IP bypass an active tls_fp block (the same trap hygiene.lua documents). The
-- bac_log verdict is last-writer-wins, so a later tls_fp block overwrites the
-- reputation verdict; otherwise the reputation verdict stands ("финальное
-- сработавшее правило"). Production fastpass/403 enforcement is a future
-- per-rule-enforce task, not Phase 1.
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
-- matcher (mirrors hygiene's ua_blacklist and init.lua's fp seeding). Recording
-- staged matches for promotion analytics lands with its own task (A11).
--
-- A6 additions (geo/ASN, rules-reference L2 #9 + tag T1):
--   * geo_country / asn log fields — filled every request from a GeoLite2
--     lookup (geoip.lua) via bac_log.set_source.
--   * reputation:asn_dc — informational TAG (not a rule, emits no verdict):
--     request ASN is in asn_datacenters.conf. Accumulates in `tags` like
--     hygiene:header_anomaly, independent of the verdict.
--   * geo_blocklist — blocking rule, country NOT in the allowed-countries
--     whitelist. Its only source is per-resource policy[host].geo_whitelist
--     (Phase 3); there is no system-wide country list (geo-allow is a
--     per-resource choice, not global). With no policy catalog on the stand
--     yet the rule is DORMANT: wired + unit-tested, but its allow-set is empty
--     so it never fires. Phase 3 supplies the per-host whitelist; the code
--     here is unchanged. (Same "rule wired, data empty" shape as ua_blacklist
--     / ip_blocklist.)
--
-- Per-resource policy ip_whitelist and verified-bot fastpath are separate
-- tasks (B8) and are intentionally not handled here.

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

-- Resolve the client IP the stage reasons about. Production: the real
-- remote_addr. Stand testing: when BAC_DEMO_GEO_HEADER=on, an X-Demo-IP
-- request header overrides it so a reviewer can simulate a public IP (the
-- local/private client IP has no GeoIP entry). The toggle defaults off, so on
-- a live VM the header is inert and the real remote_addr is always used. See
-- the A6 plan / README for why a single env toggle (no IP allowlist) suffices:
-- the stage is observe-only, so a spoofed IP only mislabels one log line.
local function client_ip()
    if _M.demo_geo_header then
        local override = ngx.var.http_x_demo_ip
        if override and override ~= "" then return override end
    end
    return ngx.var.remote_addr
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

    -- Stage off when the global kill-switch or the per-stage reputation switch
    -- is set (config-templates.md kill_switch; defaults.conf [kill_switch.*]).
    local ks = defaults.kill_switch or {}
    _M.enabled = not ((ks.global or {}).enabled == true
                      or (ks.per_stage or {}).reputation == true)

    return _M, wl_n, bl_n
end

-- Called per request from verdict.lua, after bac_log.init(). Records the
-- would-be verdict via bac_log. Never blocks and never stops the cascade
-- (observe-only); the boolean return (true when a rule matched) is
-- informational only.
function _M.run()
    if not _M.enabled then return false end

    local ip = client_ip()
    if not ip then return false end

    -- bac_log / geoip required lazily (keeps the pure helpers unit-testable
    -- without ngx); the package.loaded fast-path avoids the require() call
    -- overhead on the per-request hot path after the first lookup in a worker.
    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local geoip   = package.loaded["geoip"]   or require "geoip"

    -- Source enrichment + asn_dc tag run for EVERY request, independent of the
    -- verdict (tags accumulate even when a blocking rule fires; the log fields
    -- must be populated regardless). geo is fail-open: nil cc/asn just leaves
    -- the fields null and the tag unset.
    local cc, asn = geoip.lookup(ip)
    bac_log.set_source(asn, cc)
    if asn and _M.asn_dc_set[asn] then
        bac_log.add_tag("reputation:asn_dc")
    end

    -- Verdict rules, first match wins within the stage (allow before blocking,
    -- vision §2.3 → §2.4 → geo). A match returns so a later same-stage rule
    -- doesn't overwrite it under bac_log's last-writer-wins.
    if _M.whitelist and _M.whitelist:match(ip) then
        bac_log.set_verdict("reputation", "allow", "ip_whitelist")
        return true
    end

    if _M.blocklist and _M.blocklist:match(ip) then
        bac_log.set_verdict("reputation", "block", "ip_blocklist")
        return true
    end

    -- geo_blocklist — dormant in Phase 1: the allowed-countries whitelist comes
    -- from per-resource policy[host].geo_whitelist (Phase 3), which the stand
    -- has no source for yet, so `allow` is empty and country_blocked is always
    -- false. When the policy catalog lands this resolves the per-host set; the
    -- check below is unchanged.
    if _M.geo_enabled then
        local allow = nil  -- Phase 3: policy[host].geo_whitelist for ngx.var.host
        if _M.country_blocked(allow, cc) then
            bac_log.set_verdict("reputation", "block", "geo_blocklist")
            return true
        end
    end

    return false
end

return _M
