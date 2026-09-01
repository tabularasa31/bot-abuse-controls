-- Read-only effective-policy JSON for the private :9090 management plane.
--
-- Empty policy list fields must encode as `[]`, not `{}`: cjson.decode drops the
-- empty_array_mt metatable, so re-encoding through the global cjson would break
-- the wire contract. Hence a module-local encoder, leaving the global untouched.

local _M = {}

-- Built on first use, so the module stays require-able under the bare-luajit
-- unit runner, which has no cjson.
local _cjson

-- An explicit `?host=<name>` wins over the request's own Host.
function _M.pick_host(arg_host, req_host)
    if arg_host and arg_host ~= "" then return arg_host end
    return req_host
end

function _M.encode(host, policy)
    if not _cjson then
        _cjson = require("cjson").new()
        _cjson.encode_empty_table_as_object(false)
    end
    return _cjson.encode({ host = host, policy = policy })
end

function _M.handle()
    local policy = require "policy"
    local host = _M.pick_host(ngx.var.arg_host, ngx.var.host)
    ngx.say(_M.encode(host, policy.get(host)))
end

return _M
