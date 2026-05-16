-- Runs in init_by_lua_block. Loads the static blocklist into the
-- shared dict so workers don't each parse the table on first hit.

local blocklist = require "blocklist"
local dict = ngx.shared.fp_blocklist

for fp, verdict in pairs(blocklist.entries) do
    local ok, err = dict:set(fp, verdict)
    if not ok then
        ngx.log(ngx.ERR, "fp_blocklist:set failed: ", err)
    end
end

ngx.log(ngx.NOTICE, "fp_blocklist loaded: ", dict:get_keys(0) and #dict:get_keys(0) or 0, " entries")
