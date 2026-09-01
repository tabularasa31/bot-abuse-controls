-- Rewrites the hostname inside the upstream URL to the tenant's origin IP.
--
-- A tenant's public hostname points at this edge, so letting nginx resolve it
-- for `proxy_pass $origin` returns the edge's own IP and the request proxies
-- into itself until the headers grow past the limit. /etc/hosts does not help:
-- the variable-driven resolver path ignores it. Substituting the IP here
-- short-circuits the lookup. Host and SNI sent upstream are set separately, so
-- the backend still sees the public hostname.
local _M = {}

-- Returns `origin` with its hostname replaced by `origin_ip`, preserving
-- scheme, port and path. Any empty input, or a hostname that does not match
-- `loop_host`, returns `origin` unchanged. Gating on the hostname inside
-- `origin` rather than on the incoming Host header is what makes this
-- loop-safe for scanners that connect by IP.
function _M.resolve(origin, origin_ip, loop_host)
    if not origin    or origin    == "" then return origin end
    if not origin_ip or origin_ip == "" then return origin end
    if not loop_host or loop_host == "" then return origin end

    local origin_host = origin:match("^https?://%[([^%]]+)%]")
                     or origin:match("^https?://([^:/]+)")
    if origin_host ~= loop_host then return origin end

    local formatted_ip = origin_ip
    if origin_ip:find(":", 1, true) and not origin_ip:find("^%[") then
        formatted_ip = "[" .. origin_ip .. "]"
    end

    -- `%` is a capture reference in a gsub replacement. ValidateOriginIP
    -- rejects zone-scoped IPv6, but a value written straight to the database
    -- could still carry one and would corrupt the URL at request time.
    local repl = formatted_ip:gsub("%%", "%%%%")

    -- Bracketed IPv6 first: the IPv4 pattern stops at the first `:` inside
    -- `[2001:db8::1]`. A zero count means no scheme, so return the input.
    local rewritten, n = origin:gsub("^(https?://)%[[^%]]+%]", "%1" .. repl)
    if n == 0 then
        rewritten, n = origin:gsub("^(https?://)[^:/]+", "%1" .. repl)
    end
    if n == 0 then
        return origin
    end
    return rewritten
end

return _M
