-- The structured request log: exactly one JSON record per request, emitted in
-- log_by_lua.
--
-- Cascade stages record their outcome through set_verdict() and add_tag(); the
-- last rule to fire wins, which is the "final rule that fired" the schema asks
-- for.
--
-- The field set and the enums are stable. Consumers key on them, so fields are
-- added rather than renamed or reordered, and arrays stay present and empty
-- when nothing fills them.

local cjson      = require "cjson.safe"
local cjson_base = require "cjson"   -- empty_array_mt + null sentinels
local policy     = require "policy"  -- per-host mode/strictness (B11)

local _M = {}

-- Edge identifier. Defaults to the stand value; override via the
-- EDGE_ID env var (must be listed in nginx.conf `env EDGE_ID;`).
local EDGE_ID = os.getenv("EDGE_ID") or "stand-bac"

-- Per-request business mode/strictness come from policy[ngx.var.host]
-- (B11). Unregistered host falls back to POOL_DEFAULT (shadow/standard)
-- inside policy.get. Both fields are stable enum strings.

-- action = the effective action the final rule's category implies, kept
-- separate from verdict so analytics can distinguish "what was decided"
-- (verdict) from "what would be done" (action). In Phase 1 they line up;
-- permissive suppresses the challenge, so it maps to pass.
local VERDICT_TO_ACTION = {
    pass = "pass", block = "block", challenge = "challenge",
    allow = "allow", permissive = "pass",
}

-- Carries the documented future values too, so a stage landing later is not
-- rejected by its own log call.
local VALID_STAGES = {
    hygiene = true, reputation = true, tls_fp = true,
    rate_limits = true, verification = true,
    egress = true, cold_start = true,
}
local VALID_VERDICTS = {
    pass = true, block = true, challenge = true,
    allow = true, permissive = true,
}

-- Stamp a fresh per-request context. Call once, as early as possible
-- (access phase), so latency_ms covers the whole cascade. Defaults
-- describe a request that passed every stage untouched.
function _M.init()
    -- Force empty arrays to encode as JSON [] rather than an object {}.
    local tags = setmetatable({}, cjson_base.empty_array_mt)
    local staging_match = setmetatable({}, cjson_base.empty_array_mt)
    local flags = setmetatable({}, cjson_base.empty_array_mt)

    -- NB: resource_id is intentionally NOT set here. The edge works from
    -- Host only; the backend enriches the record with resource_id from
    -- its DB on log ingest (vision.md Step 7, ADR-005, config-distribution).
    -- The field is emitted as null so the column stays stable.
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

-- Stamped when the cascade hands the request to proxy_pass, so cascade_ms can
-- be separated from the origin and delivery time. Blocked requests exit before
-- this and fall back to the full window, which is the same thing for them.
function _M.mark_cascade_end()
    local ctx = ngx.ctx.bac
    -- Only the first stamp wins (the real cascade end); later calls are no-ops.
    if ctx and not ctx.t_cascade_end then
        -- ngx.now() returns a CACHED time updated only at phase boundaries /
        -- on yields. The cascade runs synchronously without yielding, so
        -- without this the start (t_start) and end timestamps would be
        -- identical and cascade_ms would always be 0.
        ngx.update_time()
        ctx.t_cascade_end = ngx.now()
    end
end

-- $upstream_response_time is empty with no upstream, and otherwise carries one
-- component per try or internal redirect, with failures as "-". Sum the numbers
-- and ignore the rest.
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

-- Record a triggered rule. Stages call this in cascade order; the last
-- call wins. Invalid enum values are logged and ignored rather than
-- corrupting the record.
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

-- Append an informational tag (namespace-prefixed, e.g. reputation:asn_dc).
-- Tags accumulate across stages and never affect the verdict.
function _M.add_tag(tag)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.tags[#ctx.tags + 1] = tag
end

-- Flags accumulate independently of the terminal verdict: only a blocking or
-- allow rule short-circuits, and every soft signal seen on the way is kept.
function _M.add_flag(flag)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.flags[#ctx.flags + 1] = flag
end

-- A staged pattern that matched without affecting the verdict, as
-- "<catalog>:<pattern_id>". This is what the promotion decision reads.
function _M.add_staging_match(entry)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.staging_match[#ctx.staging_match + 1] = entry
end

-- Set the source attributes the reputation stage resolves (MaxMind).
function _M.set_source(asn, geo_country)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.asn         = asn
    ctx.geo_country = geo_country
end

-- The sub-columns are parsed back out of the fingerprint prefix rather than
-- re-read from $ssl_*, so they cannot disagree with the fingerprint itself.
-- Layout: 2-digit version, SNI flag, 2-digit cipher count, 2-char ALPN.
-- The browser fingerprint the JS solver collected. It plays no part in
-- verification — the cookie is a bearer token — and is stored as-is, as a
-- dataset for analytics.
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

-- ISO 8601 with millisecond precision, UTC, e.g. 2026-05-18T14:30:00.123Z
local function iso8601_ms(now)
    local secs = math.floor(now)
    local ms   = math.floor((now - secs) * 1000 + 0.5)
    if ms > 999 then ms = 999 end
    return string.format("%s.%03dZ", os.date("!%Y-%m-%dT%H:%M:%S", secs), ms)
end

-- Build and emit the single final record. Call in log_by_lua. Requests
-- that bypass the cascade (infra endpoints that never called init) have
-- no ctx and produce no record.
function _M.emit()
    local ctx = ngx.ctx.bac
    if not ctx then return end

    local now = ngx.now()

    -- Explicit branch, not an `and/or` ternary: tls_sni_present is a
    -- boolean, and `cond and false or null` would collapse a valid false
    -- ("SNI absent") into null, making it indistinguishable from "unknown
    -- / malformed fp". Only nil (never parsed) becomes null.
    local sni_present = cjson_base.null
    if ctx.tls_sni_present ~= nil then
        sni_present = ctx.tls_sni_present
    end

    -- latency_ms covers the whole request, so for a slow client it is dominated
    -- by the download tail rather than by our work. The split isolates the
    -- parts that are ours: cascade_ms is the access-phase overhead,
    -- upstream_response_ms the origin round trip, and proxy_ms their sum —
    -- everything up to holding the full response, with no delivery tail.
    local cascade_ms = ctx.t_start and ((ctx.t_cascade_end or now) - ctx.t_start) * 1000 or nil
    local up_total = sum_upstream_time(ngx.var.upstream_response_time)
    local upstream_response_ms = up_total and up_total * 1000 or nil
    -- proxy_ms is null unless an upstream was actually contacted — for
    -- blocked/challenge requests there's no origin response, so reporting
    -- proxy_ms == cascade_ms would be misleading.
    local proxy_ms = (cascade_ms and upstream_response_ms)
        and (cascade_ms + upstream_response_ms) or nil

    -- Cap the UA so a pathological multi-KB User-Agent can't push the log
    -- line past PIPE_BUF (4 KB on Linux) and break the atomicity of the
    -- single stdout write below. Legitimate UAs are well under this; the
    -- other fields are bounded, so this keeps the whole line atomic.
    local ua = ngx.var.http_user_agent
    if ua and #ua > 2048 then ua = ua:sub(1, 2048) end

    -- Per-host policy for mode/strictness. Reader is null-safe: unregistered
    -- host or absent shared_dict → POOL_DEFAULT (shadow/standard). Done once
    -- per emit so a slow shared_dict miss doesn't double-count.
    local p = policy.get(ngx.var.host)

    -- Optional/absent fields fall back to a JSON null sentinel so every
    -- record carries the full key set — a stable schema for the sink.
    local record = {
        request_id    = ctx.request_id,
        timestamp     = iso8601_ms(ctx.t_start or now),
        edge_id       = EDGE_ID,
        resource_id   = cjson_base.null,   -- backend-enriched on ingest; null on edge
        host          = ngx.var.host or cjson_base.null,
        -- $request_uri survives internal redirects, so a challenged request
        -- logs what the client asked for rather than the internal target. The
        -- query string is stripped to keep the field comparable.
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
        -- The solve-rate signal has to exclude attack-mode challenges: under
        -- attack almost everyone is challenged, so a low solve rate reflects the
        -- host's posture rather than the fingerprint. Guarded on nil, since
        -- `false or null` would log the common case as null.
        attack_mode   = p.attack_mode == nil and cjson_base.null or p.attack_mode,
        strictness    = p.strictness,
        latency_ms    = ctx.t_start and (now - ctx.t_start) * 1000 or cjson_base.null,
        cascade_ms           = cascade_ms or cjson_base.null,
        upstream_response_ms = upstream_response_ms or cjson_base.null,
        proxy_ms             = proxy_ms or cjson_base.null,
        tags          = ctx.tags,
        flags         = ctx.flags,
        staging_match = ctx.staging_match,
        -- [C5] challenge-pass browser fingerprint (set_challenge_fp); null
        -- on every non-challenge-verify request — kept as a stable field
        -- so the sink schema is uniform.
        challenge_fp  = ctx.challenge_fp or cjson_base.null,
    }

    local line = cjson.encode(record)
    if not line then
        ngx.log(ngx.ERR, "bac_log: cjson encode failed for request ",
            tostring(ctx.request_id))
        return
    end

    -- Straight to stdout, not through ngx.log: during the log phase nginx
    -- appends its request context to the message, which would corrupt the JSON.
    -- The prefix lets the sink separate this stream from the access lines
    -- sharing the same pipe.
    --
    -- The flush is required. Stdout to a pipe is fully buffered, so without it
    -- lines are split at arbitrary buffer boundaries and interleave across
    -- workers. Writing the whole line and flushing makes it one write, atomic
    -- as long as the line stays under PIPE_BUF — hence the UA cap.
    io.stdout:write("BAC_LOG ", line, "\n")
    io.stdout:flush()

    -- enqueue never blocks, and is a no-op when the shipper is unconfigured.
    -- stdout stays the ground truth; this is a second channel to the backend.
    --
    -- Read from package.loaded rather than pcall(require): the module is loaded
    -- in init_worker, so a miss here is a deploy bug rather than something to
    -- fall back from, and the pcall would cost on every request.
    local shipper = package.loaded["log_shipper"]
    if shipper and shipper.enqueue then
        shipper.enqueue(line)
    end
end

return _M
