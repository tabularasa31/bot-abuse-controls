-- L2 reputation: source IP, ASN and geo.
--
-- Allow rules run before blocking ones, so a whitelisted IP wins. The allow
-- side deliberately does not short-circuit the cascade on the stand, so a later
-- fingerprint block still shows up in the log.
--
-- The system lists are compiled from local config at startup and swapped to the
-- Channel C snapshot on a generation flip; staged entries compile into a
-- parallel matcher that only records and never blocks.
--
-- Each request is also matched against the host's own lists, under namespaced
-- rule names so hits stay attributable.
--
-- asn_dc is a tag, not a rule. geo_blocklist is per-host only: geo gating is a
-- customer choice, so there is no system-wide country list.

local policy          = require "policy"
local policy_matchers = require "policy_matchers"
local staging_metrics = require "staging_metrics"

local _M = {
    enabled        = true,
    whitelist      = nil,   -- ipmatcher or nil when no active entries
    blocklist      = nil,   -- ipmatcher or nil when no active entries
    blocklist_staging = nil, -- ipmatcher (new_with_value: match→cidr) or nil; A11 observe-only
    asn_dc_set     = {},    -- { ["24940"] = true, ... }; cold-start from asn_datacenters.conf, then Channel C via refresh_asn ()
    geo_enabled    = true,  -- [blocking.geo_blocklist].enabled (dormant: no source yet)
    demo_geo_header = false, -- honour X-Demo-IP override (stand testing); env-gated
}

-- The active values of a parsed list, with staged entries excluded.
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

-- The staged counterpart of active_values.
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

function _M.to_set(values)
    local set = {}
    for _, v in ipairs(values or {}) do
        if v ~= nil and v ~= "" then set[v] = true end
    end
    return set
end

-- Blocks only when a whitelist is configured and the country is outside it.
function _M.country_blocked(allow, cc)
    if not allow or not next(allow) then return false end
    if not cc or cc == "" then return false end
    return not allow[cc]
end

-- For the geo lookup only. The IP matchers always use the real remote_addr, so
-- the testing header override can never move a verdict.
local function geo_lookup_ip(remote_addr)
    if _M.demo_geo_header then
        local override = ngx.var.http_x_demo_ip
        if override and override ~= "" then return override end
    end
    return remote_addr
end

-- A malformed CIDR aborts the start rather than nilling the list: one bad line
-- silently disabling a whole list is a gap nobody would notice.
function _M.build(config)
    local ipmatcher = require "resty.ipmatcher"
    local defaults  = config.defaults or {}

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

    -- Kept separate from the matchers, which cannot distinguish "disabled" from
    -- "no entries". The per-host lists honour the same switch.
    _M.ip_whitelist_enabled = rule_enabled("allow", "ip_whitelist")
    _M.ip_blocklist_enabled = rule_enabled("blocking", "ip_blocklist")

    -- A value map, so a match returns the CIDR recorded in staging_match.
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

    -- The tag has no toggle of its own; the per-stage kill switch covers it.
    _M.asn_dc_set = _M.to_set(_M.active_values(config.asn_datacenters))

    -- Dormant: there is no country whitelist source yet.
    _M.geo_enabled = rule_enabled("blocking", "geo_blocklist")

    _M.demo_geo_header = (os.getenv("BAC_DEMO_GEO_HEADER") == "on")

    _M.enabled = require("config").stage_enabled(defaults, "reputation")

    -- nil means the first refresh rebuilds from the cold-start state.
    _M._cached_gen_ip  = nil
    _M._cached_gen_wl  = nil
    _M._cached_gen_asn = nil

    return _M, wl_n, bl_n
end

-- Rebuilds both matchers on a generation flip. Fail-soft: a failed rebuild
-- keeps the previous matcher.
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

-- Same as refresh, for the whitelist. A flat list with no status, so there is
-- no staging matcher here.
function _M.refresh_whitelist()
    if not ngx or not ngx.shared then return end
    local meta = ngx.shared.meta
    if not meta then return end
    local gen = meta:get("ip_whitelist_gen")
    if gen == nil or gen == _M._cached_gen_wl then return end
    local dict = ngx.shared.antibot_ip_whitelist
    if not dict then return end

    if not _M.ip_whitelist_enabled then
        _M.whitelist      = nil
        _M._cached_gen_wl = gen
        return
    end

    local ipmatcher = package.loaded["resty.ipmatcher"] or require "resty.ipmatcher"
    local suffix = ":" .. gen
    local active = {}
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-#suffix) == suffix then
            active[#active + 1] = k:sub(1, -#suffix - 1)
        end
    end

    if #active == 0 then
        _M.whitelist = nil
    else
        local m, err = ipmatcher.new(active)
        if m then
            _M.whitelist = m
        else
            ngx.log(ngx.ERR, "reputation: ip_whitelist matcher rebuild ",
                "failed, keeping previous: ", tostring(err))
        end
    end

    _M._cached_gen_wl = gen
end

-- Same as refresh, for the datacenter ASN set behind the asn_dc tag. Keys are
-- strings, matching what the geo lookup returns.
function _M.refresh_asn()
    if not ngx or not ngx.shared then return end
    local meta = ngx.shared.meta
    if not meta then return end
    local gen = meta:get("asn_datacenters_gen")
    if gen == nil or gen == _M._cached_gen_asn then return end
    local dict = ngx.shared.antibot_asn_datacenters
    if not dict then return end

    local suffix = ":" .. gen
    local set = {}
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-#suffix) == suffix then
            set[k:sub(1, -#suffix - 1)] = true
        end
    end

    -- Empty set is a valid state (backend published an empty asn_datacenters):
    -- the tag simply never fires. Unlike the matchers there is no "keep
    -- previous on build error" — set construction can't fail.
    _M.asn_dc_set      = set
    _M._cached_gen_asn = gen
end

-- The boolean return is informational; the caller does not branch on it.
function _M.run()
    if not _M.enabled then return false end

    -- Each rebuilds only on its own generation flip.
    _M.refresh()
    _M.refresh_whitelist()
    _M.refresh_asn()

    local ip = ngx.var.remote_addr
    if not ip then return false end

    -- bac_log / geoip required lazily (keeps the pure helpers unit-testable
    -- without ngx); the package.loaded fast-path avoids the require() call
    -- overhead on the per-request hot path after the first lookup in a worker.
    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local geoip   = package.loaded["geoip"]   or require "geoip"

    -- Runs for every request: the log fields must be populated whatever the
    -- verdict. Fail-open — an unresolved lookup just leaves them null.
    local cc, asn = geoip.lookup(geo_lookup_ip(ip))
    bac_log.set_source(asn, cc)
    if asn and _M.asn_dc_set[asn] then
        bac_log.add_tag("reputation:asn_dc")
    end

    -- A constant-time lookup after the first hit per worker. The empty sentinel
    -- means the host has no lists, and every guard below short-circuits.
    local host = ngx.var.host
    local pm   = policy_matchers.get(host)

    -- First match wins, allow before blocking. Each match returns, so a later
    -- rule in the same stage cannot overwrite it.
    if _M.whitelist and _M.whitelist:match(ip) then
        bac_log.set_verdict("reputation", "allow", "ip_whitelist")
        return true
    end
    if _M.ip_whitelist_enabled and pm.whitelist and pm.whitelist:match(ip) then
        bac_log.set_verdict("reputation", "allow", "policy.ip_whitelist")
        return true
    end

    -- Placed between the whitelist and the blocklist, so a verified or pending
    -- bot outranks a block in this stage, while a rejected one falls through to
    -- the blocklist and the rest of the cascade.
    local verified_bots = package.loaded["verified_bots"]
                         or require "verified_bots"
    local vb_outcome = verified_bots.run(ip, ngx.var.http_user_agent)
    -- The set rather than an inline comparison, so a new outcome cannot
    -- short-circuit by being copy-pasted into this condition.
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

    -- Per-host only: with no whitelist the rule never fires, and with one any
    -- country outside it blocks.
    if _M.geo_enabled and pm.geo_whitelist then
        if _M.country_blocked(pm.geo_whitelist, cc) then
            bac_log.set_verdict("reputation", "block", "policy.geo_blocklist")
            policy.enforce(403)
            return true
        end
    end

    -- Observe-only, and only reached when nothing above matched — so it records
    -- what promotion to active would have done.
    if _M.blocklist_staging then
        local cidr = _M.blocklist_staging:match(ip)
        if cidr then
            bac_log.add_staging_match("ip_blocklist:" .. cidr)
        end
    end

    return false
end

return _M
