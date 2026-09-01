-- Ring buffer of the last CAP requests, as JSON in a shared_dict indexed by a
-- monotonic head counter modulo CAP. Written by log_event; its reader was
-- removed with the public admin surface and is kept for a private one.

local cjson = require "cjson.safe"

local _M = {}

local CAP  = 50
local dict = ngx.shared.recent

-- UA and host are capped so a pathological header cannot exceed the
-- shared_dict value limit.
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
