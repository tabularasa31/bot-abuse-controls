local blocklist = require "blocklist"
local dict = ngx.shared.fp_blocklist
for fp, verdict in pairs(blocklist.entries) do dict:set(fp, verdict) end
