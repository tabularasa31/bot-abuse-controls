-- L2.2 verified-bot fastpath: a read-only lookup against the catalog the rDNS
-- worker publishes. Three states.
--
--   verified  → allow.
--   rejected  → no verdict; the cascade continues. A UA claiming Googlebot
--               whose rDNS was rejected is what the cascade exists for.
--   absent    → provisional allow, on every request from that IP. The edge
--               keeps no state; the backend sees the event and queues the
--               check. Never block a searchbot we have not confirmed yet.
--
-- No DNS on the hot path, only the membership lookup.
local _M = {
    enabled     = true,
    ua_alts     = {},   -- array of plain substrings split from ua_pattern
    provisional = true, -- emit bot_verified_pending on absent
}

_M.GEN_KEY = "verified_bots_gen"

-- "rejected" must stay out: those IPs keep going through the cascade.
_M.SHORT_CIRCUIT = { verified = true, pending = true }

-- plain=true, so an alternative with regex metacharacters matches literally.
function _M.looks_like_bot(ua, alts)
    if not ua or ua == "" or not alts then return false end
    for _, a in ipairs(alts) do
        if a and a ~= "" and ua:find(a, 1, true) then return true end
    end
    return false
end

-- Empty input leaves the rule dormant rather than crashing.
function _M.split_ua_pattern(pattern)
    local out = {}
    if not pattern or pattern == "" then return out end
    for a in string.gmatch(pattern, "[^|]+") do
        local t = a:gsub("^%s+", ""):gsub("%s+$", "")
        if t ~= "" then out[#out + 1] = t end
    end
    return out
end

-- An unknown status yields nil, so a malformed entry cannot upgrade a request.
function _M.parse_entry(val)
    if type(val) ~= "string" or val == "" then return nil, nil end
    local status, family = val:match("^([^:]+):(.+)$")
    if status ~= "verified" and status ~= "rejected" then
        return nil, nil
    end
    return status, family
end

-- The kill switch is checked at the stage boundary, covering every L2 rule.
function _M.build(config)
    local defaults = config.defaults or {}
    local rule     = (defaults.allow or {}).bot_verified or {}

    _M.enabled     = rule.enabled ~= false
    _M.provisional = rule.provisional_pending ~= false
    _M.ua_alts     = _M.split_ua_pattern(rule.ua_pattern or "")

    return _M, #_M.ua_alts
end

-- Catalog trouble reads as absent: never block a searchbot over our plumbing.
function _M.classify(ip)
    if not ip or ip == "" then return "absent", nil end
    local dict = ngx.shared.verified_bots
    local meta = ngx.shared.meta
    if not dict or not meta then return "absent", nil end
    -- A missing generation must not collapse into a legitimate 0, which would
    -- quietly make everything pending with no signal. Logged once per worker.
    local gen, gen_err = meta:get(_M.GEN_KEY)
    if gen == nil and gen_err == nil then
        if meta:add("verified_bots_gen_missing_logged", 1) then
            ngx.log(ngx.WARN, "verified_bots: ", _M.GEN_KEY,
                " missing from `meta` dict — init_by_lua ordering bug or",
                " meta was cleared post-init; classify will treat all IPs as absent")
        end
        gen = 0
    elseif gen == nil then
        if meta:add("verified_bots_gen_error_logged", 1) then
            ngx.log(ngx.ERR, "verified_bots: meta:get(", _M.GEN_KEY,
                ") failed: ", tostring(gen_err))
        end
        return "absent", nil
    end
    local val = dict:get(ip .. ":" .. gen)
    if val == nil then return "absent", nil end
    local status, family = _M.parse_entry(val)
    if not status then
        -- Falling back to absent is safe but would hide a backend bug forever,
        -- so surface it once per (ip, value).
        if ngx.shared.metrics then
            ngx.shared.metrics:incr("verified_bots_malformed_total", 1, 0)
        end
        if meta:add("verified_bots_malformed:" .. ip .. ":" .. tostring(val), 1) then
            ngx.log(ngx.WARN, "verified_bots: malformed entry for ip=", ip,
                " val=", tostring(val), " — treating as absent")
        end
        return "absent", nil
    end
    return status, family
end

-- Called between the ip_whitelist and ip_blocklist checks. Returns
-- "verified" / "pending" (both short-circuit), "rejected" (keep going), or nil.
function _M.run(ip, ua)
    if not _M.enabled then return nil end
    if not _M.looks_like_bot(ua, _M.ua_alts) then return nil end

    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local status = _M.classify(ip)

    if status == "verified" then
        bac_log.set_verdict("reputation", "allow", "bot_verified")
        return "verified"
    elseif status == "rejected" then
        -- No verdict: rejected IPs fall through to the later stages.
        return "rejected"
    end

    if _M.provisional then
        bac_log.set_verdict("reputation", "allow", "bot_verified_pending")
        return "pending"
    end
    return nil
end

return _M
