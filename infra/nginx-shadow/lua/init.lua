-- Shadow-mode init. Same as PoC #2: load blocklist into shared dict at
-- worker startup so the verdict path doesn't pay the parse cost per
-- request.
--
-- For shadow mode, the blocklist is typically EMPTY (we're observing,
-- not blocking) — but populating it with known scraper fps is also
-- useful because verdict.lua still records what it *would* have done,
-- so we get ground-truth counts of "how many requests would we have
-- blocked" with the current ruleset.

local blocklist = require "blocklist"
local dict = ngx.shared.fp_blocklist
for fp, verdict in pairs(blocklist.entries) do
    local ok, err = dict:set(fp, verdict)
    if not ok then
        ngx.log(ngx.ERR, "fp_blocklist:set failed: ", err)
    end
end
ngx.log(ngx.NOTICE, "[shadow] fp_blocklist loaded: ",
        dict:get_keys(0) and #dict:get_keys(0) or 0, " entries")
ngx.log(ngx.NOTICE, "[shadow] mode active — verdicts will be logged but NOT enforced")
