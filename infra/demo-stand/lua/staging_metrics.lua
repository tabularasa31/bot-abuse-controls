-- Reconciles staging_match counters on a catalog generation flip.
--
-- A new staged pattern is primed at zero, so it reads as "staged, no traffic"
-- rather than as a missing metric. A pattern leaving staging is dropped only
-- while still zero: a non-zero counter is match history the promotion decision
-- needs, and is left for the operator to clear.

local _M = {}

-- prev and new are arrays of pattern ids; either may be nil.
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
