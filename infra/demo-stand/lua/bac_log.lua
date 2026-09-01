-- One structured JSON record per request, emitted in log_by_lua. Stages
-- record their outcome as they run and the last rule to fire wins.

local cjson      = require "cjson.safe"
local cjson_base = require "cjson"   -- empty_array_mt + null sentinels
local policy     = require "policy"  -- per-host mode/strictness (B11)

local _M = {}

local EDGE_ID = os.getenv("EDGE_ID") or "stand-bac"


-- permissive suppresses the challenge, so it maps to pass.
local VERDICT_TO_ACTION = {
    pass = "pass", block = "block", challenge = "challenge",
    allow = "allow", permissive = "pass",
}

local VALID_STAGES = {
    hygiene = true, reputation = true, tls_fp = true,
    rate_limits = true, verification = true,
    egress = true, cold_start = true,
}
local VALID_VERDICTS = {
    pass = true, block = true, challenge = true,
    allow = true, permissive = true,
}

-- Call once, as early as possible, so latency_ms covers the whole cascade.
function _M.init()
    -- The metatable is what makes an empty array encode as [] rather than {}.
    local tags = setmetatable({}, cjson_base.empty_array_mt)
    local staging_match = setmetatable({}, cjson_base.empty_array_mt)
    local flags = setmetatable({}, cjson_base.empty_array_mt)

    -- resource_id stays null here: the backend fills it in on ingest.
    local ctx = {
        request_id    = ngx.var.request_id,     -- nginx built-in: 32 hex, unique
        t_start       = ngx.now(),               -- float seconds, for latency_ms
        stage         = "egress",
        verdict       = "pass",
        rule          = nil,
        tags          = tags,
        flags         = flags,                   -- soft-rule challenge flags (A9 tls_fp); [] when none fire
        staging_match = staging_match,           -- populated once staged catalogs land (A11)
        asn           = nil,                     -- filled by reputation stage (A6)
        geo_country   = nil,                     -- filled by reputation stage (A6)
        tls_fp        = nil,                     -- set by the tls_fp stage (set_tls_fp)
        tls_cipher_count = nil,                  -- parsed from the fp prefix (set_tls_fp)
        tls_alpn         = nil,                  -- parsed from the fp prefix (set_tls_fp)
        tls_sni_present  = nil,                  -- parsed from the fp prefix (set_tls_fp)
    }
    ngx.ctx.bac = ctx
    return ctx
end

-- Separates cascade time from origin and delivery time. Blocked requests exit
-- before this and fall back to the full window, which for them is the same.
function _M.mark_cascade_end()
    local ctx = ngx.ctx.bac
    if ctx and not ctx.t_cascade_end then
        -- ngx.now() is cached and only refreshed on a yield; the cascade never
        -- yields, so without this the two stamps would be identical.
        ngx.update_time()
        ctx.t_cascade_end = ngx.now()
    end
end

-- Empty with no upstream; otherwise one component per try or redirect, with
-- failures as "-". Sum the numbers and ignore the rest.
local function sum_upstream_time(v)
    if not v or v == "" then return nil end
    local total, found = 0, false
    for num in v:gmatch("%d+%.?%d*") do
        total = total + (tonumber(num) or 0)
        found = true
    end
    if not found then return nil end
    return total
end

-- The last call wins. An invalid enum is logged and ignored.
function _M.set_verdict(stage, verdict, rule)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    if not VALID_STAGES[stage] then
        ngx.log(ngx.ERR, "bac_log: invalid stage '", tostring(stage), "'")
        return
    end
    if not VALID_VERDICTS[verdict] then
        ngx.log(ngx.ERR, "bac_log: invalid verdict '", tostring(verdict), "'")
        return
    end
    ctx.stage   = stage
    ctx.verdict = verdict
    ctx.rule    = rule
end

-- Tags accumulate across stages and never affect the verdict.
function _M.add_tag(tag)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.tags[#ctx.tags + 1] = tag
end

-- Flags accumulate too: only a blocking or allow rule short-circuits, so every
-- soft signal seen on the way is kept.
function _M.add_flag(flag)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.flags[#ctx.flags + 1] = flag
end

-- A staged match, recorded without affecting the verdict.
function _M.add_staging_match(entry)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.staging_match[#ctx.staging_match + 1] = entry
end

function _M.set_source(asn, geo_country)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.asn         = asn
    ctx.geo_country = geo_country
end

-- Parsed back out of the fingerprint rather than re-read from $ssl_*, so the
-- two cannot disagree.
-- The browser fingerprint from the solver. It plays no part in verification.
function _M.set_challenge_fp(fp)
    local ctx = ngx.ctx.bac
    if ctx and type(fp) == "table" then
        ctx.challenge_fp = fp
    end
end

function _M.set_tls_fp(fp)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.tls_fp = fp

    if type(fp) == "string" then
        local ver, sni, cc, alpn = fp:match("^L(%d%d)([di])(%d%d)(..)_")
        if ver then
            ctx.tls_cipher_count = tonumber(cc)
            ctx.tls_sni_present  = (sni == "d")
            -- "00" = no ALPN negotiated → null, not the literal token.
            ctx.tls_alpn = (alpn ~= "00") and alpn or nil
        end
    end
end

local function iso8601_ms(now)
    local secs = math.floor(now)
    local ms   = math.floor((now - secs) * 1000 + 0.5)
    if ms > 999 then ms = 999 end
    return string.format("%s.%03dZ", os.date("!%Y-%m-%dT%H:%M:%S", secs), ms)
end

-- Requests that bypassed the cascade have no context and produce no record.
function _M.emit()
    local ctx = ngx.ctx.bac
    if not ctx then return end

    local now = ngx.now()

    -- An explicit branch: `cond and false or null` would collapse a valid
    -- false into null and lose the difference from "unknown".
    local sni_present = cjson_base.null
    if ctx.tls_sni_present ~= nil then
        sni_present = ctx.tls_sni_present
    end

    -- latency_ms is the whole request, dominated by the download tail for a slow
    -- client. cascade_ms is our part, proxy_ms adds the origin round trip.
    local cascade_ms = ctx.t_start and ((ctx.t_cascade_end or now) - ctx.t_start) * 1000 or nil
    local up_total = sum_upstream_time(ngx.var.upstream_response_time)
    local upstream_response_ms = up_total and up_total * 1000 or nil
    -- Null with no upstream: reporting it equal to cascade_ms would mislead.
    local proxy_ms = (cascade_ms and upstream_response_ms)
        and (cascade_ms + upstream_response_ms) or nil

    -- Keeps the line under PIPE_BUF so the single stdout write below stays
    -- atomic across workers.
    local ua = ngx.var.http_user_agent
    if ua and #ua > 2048 then ua = ua:sub(1, 2048) end

    local p = policy.get(ngx.var.host)

    -- Absent fields become explicit nulls, so every record has the full key set.
    local record = {
        request_id    = ctx.request_id,
        timestamp     = iso8601_ms(ctx.t_start or now),
        edge_id       = EDGE_ID,
        resource_id   = cjson_base.null,   -- backend-enriched on ingest; null on edge
        host          = ngx.var.host or cjson_base.null,
        -- $request_uri survives internal redirects, so a challenged request logs
        -- what the client asked for rather than the internal target.
        path          = (ngx.var.request_uri and ngx.var.request_uri:match("^([^?]*)"))
                          or ngx.var.uri or cjson_base.null,
        method        = ngx.var.request_method or cjson_base.null,
        status        = tonumber(ngx.var.status) or cjson_base.null,
        ip            = ngx.var.remote_addr or cjson_base.null,
        asn           = ctx.asn or cjson_base.null,
        geo_country   = ctx.geo_country or cjson_base.null,
        ua            = ua or cjson_base.null,
        tls_fp           = ctx.tls_fp or cjson_base.null,
        tls_cipher_count = ctx.tls_cipher_count or cjson_base.null,
        tls_alpn         = ctx.tls_alpn or cjson_base.null,
        tls_sni_present  = sni_present,
        stage         = ctx.stage,
        verdict       = ctx.verdict,
        rule          = ctx.rule or cjson_base.null,
        action        = VERDICT_TO_ACTION[ctx.verdict] or "pass",
        mode          = p.mode,
        -- Attack-mode challenges must be excluded from the solve rate: under
        -- attack it reflects the host's posture, not the fingerprint.
        attack_mode   = p.attack_mode == nil and cjson_base.null or p.attack_mode,
        strictness    = p.strictness,
        latency_ms    = ctx.t_start and (now - ctx.t_start) * 1000 or cjson_base.null,
        cascade_ms           = cascade_ms or cjson_base.null,
        upstream_response_ms = upstream_response_ms or cjson_base.null,
        proxy_ms             = proxy_ms or cjson_base.null,
        tags          = ctx.tags,
        flags         = ctx.flags,
        staging_match = ctx.staging_match,
        challenge_fp  = ctx.challenge_fp or cjson_base.null,
    }

    local line = cjson.encode(record)
    if not line then
        ngx.log(ngx.ERR, "bac_log: cjson encode failed for request ",
            tostring(ctx.request_id))
        return
    end

    -- Straight to stdout: ngx.log would append its request context and corrupt
    -- the JSON. The flush matters — a pipe is fully buffered, so without it lines
    -- split at buffer boundaries and interleave across workers.
    io.stdout:write("BAC_LOG ", line, "\n")
    io.stdout:flush()

    -- Never blocks, and is a no-op when the shipper is unconfigured. Read from
    -- package.loaded because a miss is a deploy bug, not something to fall back
    -- from, and a pcall would cost on every request.
    local shipper = package.loaded["log_shipper"]
    if shipper and shipper.enqueue then
        shipper.enqueue(line)
    end
end

return _M
