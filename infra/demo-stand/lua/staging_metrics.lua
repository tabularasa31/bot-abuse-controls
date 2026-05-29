-- Shared staging_match metric reconcile for the file-seeded Channel C catalogs
-- (ua_blacklist via hygiene, ip_blocklist via reputation; A11, 86exrtjpc).
--
-- On each catalog gen flip the stage calls reconcile(catalog, prev, new):
--   * prime a zero counter for every NEW staged pattern_id, so /metrics shows
--     "staged, zero traffic" from the first scrape instead of a missing metric;
--   * drop the counter for ids that LEFT staging (promoted to active or removed)
--     but ONLY when still zero — a non-zero counter is accumulated match history
--     the promotion dashboard needs, so we leave it as a zombie for the operator.
--
-- Key shape "staging:<catalog>:<pattern_id>" (log_event.lua increments per
-- match, metrics.lua parses). Missing metrics dict → silent noop (unit tests
-- that don't wire a metrics dict). tls_fp.lua keeps its own richer variant
-- (set-keyed tables + verbose per-pattern failure logging from the PR-62 audit);
-- this array-based helper covers the two stages whose staged ids are plain lists.

local _M = {}

-- prev / new are ARRAYS of pattern_ids (regex patterns for ua_blacklist, CIDRs
-- for ip_blocklist). Either may be nil (treated as empty).
function _M.reconcile(catalog, prev, new)
    local m = ngx.shared.metrics
    if not m then return end
    local prefix = "staging:" .. catalog .. ":"

    local newset = {}
    for _, id in ipairs(new or {}) do
        newset[id] = true
        m:safe_add(prefix .. id, 0)
    end
    for _, id in ipairs(prev or {}) do
        if not newset[id] then
            local key = prefix .. id
            if (m:get(key) or 0) == 0 then m:delete(key) end
        end
    end
end

return _M
