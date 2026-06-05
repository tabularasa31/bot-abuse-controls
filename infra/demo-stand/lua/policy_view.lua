-- policy_view — read-only effective-policy JSON for the private :9090 mgmt plane.
--
-- Extracted from an inline content_by_lua_block in nginx.demo.conf (code-review
-- on PR #147) so the host-fallback logic is unit-testable and the empty-list
-- wire contract lives in ONE named place instead of buried in nginx config.
--
-- Wire contract: the dashboard / backend PoolDefault model requires empty Policy
-- list fields (ua_blacklist / ip_whitelist / ip_blocklist / asn_block /
-- geo_whitelist / rate_rules) to encode as JSON arrays `[]`. cjson.decode of an
-- empty array drops the empty_array_mt metatable, so a re-encode via the GLOBAL
-- cjson would emit `{}` — wire-incompatible. A module-local cjson with
-- encode_empty_table_as_object(false) preserves the array shape without changing
-- the global cjson other modules use.

local _M = {}

-- Lazy module-local array-preserving encoder. Built on first use rather than at
-- module load so policy_view is require-able under the bare-luajit unit runner,
-- which ships no cjson (all unit tests stub it). pick_host() below stays
-- cjson-free and is the part with real branching to cover in tests.
local _cjson

-- pure: choose which host to inspect. An explicit `?host=<name>` override wins;
-- otherwise the request's own Host. No ngx/cjson dep → unit-testable.
function _M.pick_host(arg_host, req_host)
    if arg_host and arg_host ~= "" then return arg_host end
    return req_host
end

-- encode the {host, policy} view as JSON with the array-preserving cjson.
function _M.encode(host, policy)
    if not _cjson then
        _cjson = require("cjson").new()
        _cjson.encode_empty_table_as_object(false)
    end
    return _cjson.encode({ host = host, policy = policy })
end

-- handler for `location = /__policy` on the :9090 mgmt server.
function _M.handle()
    local policy = require "policy"
    local host = _M.pick_host(ngx.var.arg_host, ngx.var.host)
    ngx.say(_M.encode(host, policy.get(host)))
end

return _M
