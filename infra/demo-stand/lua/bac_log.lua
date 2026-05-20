-- Phase 1 structured-log contract for the BAC stand.
--
-- Emits exactly one JSON record per request in log_by_lua. The cascade
-- stages (hygiene / reputation / rate_limits — each a separate task)
-- record their outcome through set_verdict()/add_tag(); the final
-- triggering rule wins (last writer), which is the "финальное
-- сработавшее правило" the schema asks for.
--
-- Forward-compatibility: the field set and enums are stable. The Phase 2
-- TLS-fp data columns (tls_fp, tls_cipher_count, tls_alpn, tls_sni_present)
-- and the Phase 2/3 optional fields (rule_source, client_rule_name) are
-- NOT emitted here — they land with their own tasks without renaming or
-- reordering these keys.

local cjson      = require "cjson.safe"
local cjson_base = require "cjson"   -- empty_array_mt + null sentinels

local _M = {}

-- Edge identifier. Defaults to the stand value; override via the
-- EDGE_ID env var (must be listed in nginx.conf `env EDGE_ID;`).
local EDGE_ID = os.getenv("EDGE_ID") or "stand-bac"

-- Per-resource business mode (shadow / active). Phase 1 has no policy
-- catalog, and the product stance is observe-only, so the stand emits a
-- single uniform mode — "shadow" by default, override via BAC_MODE (must
-- be listed in nginx.conf `env BAC_MODE;`). Per-resource modes arrive
-- with the policy catalog (Phase 3); the field name does not change.
local MODE = os.getenv("BAC_MODE") or "shadow"
if MODE ~= "shadow" and MODE ~= "active" then
    MODE = "shadow"
end

-- action = the effective action the final rule's category implies, kept
-- separate from verdict so analytics can distinguish "what was decided"
-- (verdict) from "what would be done" (action). In Phase 1 they line up;
-- permissive suppresses the challenge, so it maps to pass.
local VERDICT_TO_ACTION = {
    pass = "pass", block = "block", challenge = "challenge",
    allow = "allow", permissive = "pass",
}

-- Stage / verdict enums. Forward-compatible per phase1-spec: the enum
-- carries the documented future values (tls_fp Phase 2, cold_start
-- Phase 3, verification Phase 4; verdict permissive Phase 4) so a later
-- cascade stage calling set_verdict() isn't rejected. Existing codes are
-- never renamed or reordered.
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
        staging_match = staging_match,           -- populated once staged catalogs land (A11)
        asn           = nil,                     -- filled by reputation stage (A6)
        geo_country   = nil,                     -- filled by reputation stage (A6)
    }
    ngx.ctx.bac = ctx
    return ctx
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

-- Record a staged-catalog pattern that matched but did not affect the
-- verdict (for promotion analytics). Format "<catalog>:<pattern_id>".
-- No-op in Phase 1 — staged catalogs arrive with A11.
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
    local record = {
        request_id  = ctx.request_id,
        timestamp   = iso8601_ms(ctx.t_start or now),
        edge_id     = EDGE_ID,
        resource_id = cjson_base.null,   -- backend-enriched on ingest; null on edge
        host        = ngx.var.host,
        path        = ngx.var.uri,
        method      = ngx.var.request_method,
        status      = tonumber(ngx.var.status),
        ip          = ngx.var.remote_addr,
        asn         = ctx.asn or cjson_base.null,
        geo_country = ctx.geo_country or cjson_base.null,
        ua          = ngx.var.http_user_agent,
        stage         = ctx.stage,
        verdict       = ctx.verdict,
        rule          = ctx.rule,
        action        = VERDICT_TO_ACTION[ctx.verdict] or "pass",
        mode          = MODE,
        latency_ms    = ctx.t_start and (now - ctx.t_start) * 1000 or nil,
        tags          = ctx.tags,
        staging_match = ctx.staging_match,
    }

    local line = cjson.encode(record)
    if not line then
        ngx.log(ngx.ERR, "bac_log: cjson encode failed for request ",
            tostring(ctx.request_id))
        return
    end

    -- Write straight to stdout rather than via ngx.log: a message logged
    -- through the error_log during the log phase gets nginx's request
    -- context ("while logging request, client: ...") appended, which
    -- would corrupt the JSON line. A direct write keeps every line a
    -- clean, jq-parseable object for the telemetry sink (separate task).
    -- The "BAC_LOG " prefix lets the sink grep the structured stream out
    -- of the access/error lines that share docker stdout. One write +
    -- flush keeps the sub-PIPE_BUF line atomic across workers.
    io.stdout:write("BAC_LOG ", line, "\n")
    io.stdout:flush()
end

return _M
