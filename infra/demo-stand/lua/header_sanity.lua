-- Header sanity checks (RFC §A2, edge-lua-vs-sidecar.md).
--
-- Kept as a pure function over already-extracted request attributes so the
-- decision is unit-testable without nginx protocol negotiation (Test::Nginx /
-- luajit cannot synthesise an HTTP/2 connection): hygiene.lua passes the
-- relevant ngx.var values in and the rules are exercised here directly.
--
-- check() returns a short reason string when the request should be flagged,
-- or nil when it passes.
--
-- Built-in rule (always on): HTTP/2 with no Accept header. Real browsers
-- always send Accept on a navigation; an HTTP/2 client that omits it is a
-- strong automation signal. Additional rules (e.g. HTTP/1.1 with no
-- Accept-Language) are configurable and OFF by default — flip `enabled` once
-- the rule has been calibrated against real traffic.
--
-- NB: header_sanity is specified by RFC §A2 but is not (yet) one of the
-- Phase 1 rule codes in docs/product/rules-reference.md. It is recorded with
-- rule="header_sanity"; promote it into the rules catalogue if it stays.

local _M = {}

-- Ordered rules. Each match(ctx) -> true when suspicious.
-- ctx = { protocol =, accept =, accept_language = }.
_M.rules = {
    {
        reason = "http2_no_accept",
        enabled = true,
        match = function(ctx)
            return ctx.protocol == "HTTP/2.0" and not ctx.accept
        end,
    },
    {
        reason = "http1_no_accept_language",
        enabled = false,  -- configurable; calibrate before enabling
        match = function(ctx)
            return ctx.protocol == "HTTP/1.1" and not ctx.accept_language
        end,
    },
}

function _M.check(protocol, accept, accept_language)
    local ctx = {
        protocol = protocol,
        accept = accept,
        accept_language = accept_language,
    }
    for _, rule in ipairs(_M.rules) do
        if rule.enabled and rule.match(ctx) then
            return rule.reason
        end
    end
    return nil
end

return _M
