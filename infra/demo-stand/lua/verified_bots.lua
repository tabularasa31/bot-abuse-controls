-- L2.2 verified-bot fastpath (B8; rules-reference rules 4 + 5).
--
-- Read-only lookup against the `verified_bots` shared_dict that the
-- Channel C catalog pull (catalog_pull.lua) fills from
-- `/catalog/verified_bot_ips`. THREE states per IP-with-searchbot-UA, per
-- vision §"Шаг 2.2" / entities-reference `bot_verified*`:
--
--   verified  → bac_log.set_verdict("reputation", "allow", "bot_verified")
--               whitelist fastpath (production short-circuits L3-L5; the
--               stand stays observe-only — see comment in reputation.lua).
--   rejected  → NO verdict, cascade continues (tls_fp / rate_limits / L5 may
--               still fire). This is the point of the 3-state catalog: a UA
--               claiming "Googlebot" with a rejected rDNS is exactly the
--               case the cascade is for.
--   absent    → provisional fastpath: bac_log.set_verdict("reputation",
--               "allow", "bot_verified_pending"). Fires on EVERY request
--               with that IP — the proxy keeps no per-IP state; backend's
--               log receiver sees the pending event and queues rDNS (B7).
--               SEO-safe by design: never block a searchbot UA just because
--               we have not yet confirmed it. When B7 publishes the final
--               status, subsequent requests resolve to verified/rejected.
--
-- DNS does NOT run on the hot path — only the set-membership lookup. rDNS
-- lives in the backend worker (B7).
--
-- Data shape on the wire (config-distribution §"The 'catalog' concept"):
--   map(ip → "<status>:<family>")
-- where status ∈ {verified, rejected}, family ∈ {google, bing, yandex, ddg}.
-- The absent state is just a missing key.
--
-- Storage shape inside the shared_dict mirrors `fp_blocklist`'s §В1 atomic
-- swap: keys are `<ip>:<gen>` so two generations can coexist during the
-- write→flip→sweep window, and readers compose the key with the gen they
-- read from `ngx.shared.meta:get("verified_bots_gen")`. catalog_pull's
-- descriptor (apply/sweep) keeps this contract symmetric with fp_blocklist.
--
-- The UA "looks like a searchbot" test is a plain-substring alternation
-- compiled from defaults.conf `[allow.bot_verified].ua_pattern` ("Googlebot|
-- bingbot|YandexBot|DuckDuckBot"). The four documented families decompose
-- cleanly into literal substrings, so we use string.find with the plain
-- flag — no PCRE dependency, no escaping foot-guns, and the helper stays
-- unit-testable under bare luajit. A future pattern that needs real regex
-- syntax must migrate to ngx.re.match (with a build-time validation step).

local _M = {
    enabled     = true,
    ua_alts     = {},   -- array of plain substrings split from ua_pattern
    provisional = true, -- emit bot_verified_pending on absent
}

_M.GEN_KEY = "verified_bots_gen"

-- pure: does `ua` contain ANY of the searchbot-family substrings? Empty UA
-- or empty alternatives → false. plain=true on string.find so a future
-- alternative with `.`/`?`/etc. matches literally (the regex `Googlebot`
-- also matches literally — the alternation in ua_pattern is the only
-- regex feature we actually use). No ngx dependency — unit-testable.
function _M.looks_like_bot(ua, alts)
    if not ua or ua == "" or not alts then return false end
    for _, a in ipairs(alts) do
        if a and a ~= "" and ua:find(a, 1, true) then return true end
    end
    return false
end

-- pure: split the ua_pattern on `|` into a trimmed list of alternatives.
-- Empty input → empty list (which makes looks_like_bot always-false, i.e.
-- the rule is dormant rather than crashing). Exposed for unit tests.
function _M.split_ua_pattern(pattern)
    local out = {}
    if not pattern or pattern == "" then return out end
    for a in string.gmatch(pattern, "[^|]+") do
        local t = a:gsub("^%s+", ""):gsub("%s+$", "")
        if t ~= "" then out[#out + 1] = t end
    end
    return out
end

-- pure: parse a catalog entry "<status>:<family>" into (status, family).
-- Unknown status / missing colon → (nil, nil) — treated as "absent" by the
-- caller so a malformed entry can never UPGRADE a request to verified. No
-- ngx dependency — unit-testable.
function _M.parse_entry(val)
    if type(val) ~= "string" or val == "" then return nil, nil end
    local status, family = val:match("^([^:]+):(.+)$")
    if status ~= "verified" and status ~= "rejected" then
        return nil, nil
    end
    return status, family
end

-- Called once in init_by_lua, after config.load(). Compiles the UA pattern
-- and reads the per-rule defaults (enabled + provisional_pending). The
-- per-stage kill-switch is checked at the reputation stage boundary
-- (config.stage_enabled in reputation.build), not here — that keeps the
-- single global toggle for "the L2 stage is off" applying to bot_verified
-- alongside ip_whitelist/ip_blocklist.
function _M.build(config)
    local defaults = config.defaults or {}
    local rule     = (defaults.allow or {}).bot_verified or {}

    _M.enabled     = rule.enabled ~= false
    _M.provisional = rule.provisional_pending ~= false
    _M.ua_alts     = _M.split_ua_pattern(rule.ua_pattern or "")

    return _M, #_M.ua_alts
end

-- Read the catalog generation + lookup the IP-keyed entry. Returns one of
-- "verified" / "rejected" / "absent" + the family (verified/rejected only).
-- Missing dict / missing meta → "absent" (fail-open into provisional fastpath
-- if UA is a searchbot — never blocks a searchbot because of catalog
-- plumbing trouble; the static-seed default for verified_bots_gen is 0 so
-- an empty dict reads cleanly).
function _M.classify(ip)
    if not ip or ip == "" then return "absent", nil end
    local dict = ngx.shared.verified_bots
    local meta = ngx.shared.meta
    if not dict or not meta then return "absent", nil end
    local gen = meta:get(_M.GEN_KEY) or 0
    local val = dict:get(ip .. ":" .. gen)
    if val == nil then return "absent", nil end
    local status, family = _M.parse_entry(val)
    if not status then return "absent", nil end
    return status, family
end

-- Per-request entry point, called from reputation.run() between the
-- ip_whitelist and ip_blocklist checks (rules-reference order: allow rules
-- 1-5 before block rule 6/8). Returns one of:
--   "verified" — bot_verified verdict set, caller should stop reputation rules
--   "pending"  — bot_verified_pending verdict set, caller should stop too
--   "rejected" — no verdict, caller should KEEP going through ip_blocklist
--                etc. (the 3-state catalog's whole point)
--   nil        — not enabled / UA does not look like a searchbot / nothing
--                to record, caller proceeds normally.
function _M.run(ip, ua)
    if not _M.enabled then return nil end
    if not _M.looks_like_bot(ua, _M.ua_alts) then return nil end

    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local status = _M.classify(ip)

    if status == "verified" then
        bac_log.set_verdict("reputation", "allow", "bot_verified")
        return "verified"
    elseif status == "rejected" then
        -- No verdict written: rejected IPs fall through so a later stage
        -- (tls_fp / rate_limits / L5) can fire on them. Returning the
        -- token lets the caller distinguish "rejected" from "no match" if
        -- it ever wants to count rejected-but-cascade-clean later; today
        -- both shapes result in the same fallthrough.
        return "rejected"
    end

    if _M.provisional then
        bac_log.set_verdict("reputation", "allow", "bot_verified_pending")
        return "pending"
    end
    return nil
end

return _M
