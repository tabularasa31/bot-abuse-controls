-- Recent-requests ring buffer for the /__admin live view. Lua analogue of
-- the vanilla sidecar's observe.RecentStore, scoped to what a single edge
-- can do with a shared_dict (no per-fp aggregation store — that's a bigger
-- task; this gives the "what's happening right now" sample the thin admin
-- page was missing).
--
-- Stores the last CAP request records as JSON in ngx.shared.recent, indexed
-- by a monotonic head counter modulo CAP. snapshot() returns newest-first.

local cjson = require "cjson.safe"

local _M = {}

local CAP  = 50
local dict = ngx.shared.recent

-- Record one pipeline request. `rec` is a small flat table; UA is capped so
-- a pathological User-Agent can't blow the shared_dict value limit. host and
-- flags (C6) are kept so the /__admin recovery widget can show enough context
-- to recognise a false positive and dispatch the correct per-resource
-- whitelist call (host → which policy, flags → why it blocked).
function _M.record(rec)
    if not dict then return end
    if rec.ua and #rec.ua > 160 then rec.ua = rec.ua:sub(1, 160) end
    if rec.host and #rec.host > 253 then rec.host = rec.host:sub(1, 253) end
    local line = cjson.encode(rec)
    if not line then return end
    local idx = dict:incr("head", 1, 0)        -- 1 on first call (init 0 + 1)
    dict:set("e:" .. (idx % CAP), line)
end

-- Return up to `limit` most-recent records, newest first.
function _M.snapshot(limit)
    if not dict then return {} end
    local head = dict:get("head") or 0
    limit = math.min(limit or CAP, CAP)
    local out = {}
    for i = 0, limit - 1 do
        local idx = head - i
        if idx < 1 then break end
        local v = dict:get("e:" .. (idx % CAP))
        if v then
            local rec = cjson.decode(v)
            if rec then out[#out + 1] = rec end
        end
    end
    return out
end

return _M
