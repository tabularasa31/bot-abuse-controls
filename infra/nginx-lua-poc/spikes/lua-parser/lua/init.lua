-- Spike 2 init: same as PoC #2, load static blocklist into shared dict.
local blocklist = require "blocklist"
local dict = ngx.shared.fp_blocklist
for fp, verdict in pairs(blocklist.entries) do
    local ok, err = dict:set(fp, verdict)
    if not ok then ngx.log(ngx.ERR, "fp_blocklist:set failed: ", err) end
end
ngx.log(ngx.NOTICE, "fp_blocklist loaded: ",
        dict:get_keys(0) and #dict:get_keys(0) or 0, " entries")
