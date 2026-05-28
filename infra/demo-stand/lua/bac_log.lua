-- Phase 1 structured-log contract for the BAC stand.
--
-- Emits exactly one JSON record per request in log_by_lua. The cascade
-- stages (hygiene / reputation / rate_limits — each a separate task)
-- record their outcome through set_verdict()/add_tag(); the final
-- triggering rule wins (last writer), which is the "финальное
-- сработавшее правило" the schema asks for.
--
-- Forward-compatibility: the field set and enums are stable. `tls_fp` and
-- its three sub-columns (tls_cipher_count, tls_alpn, tls_sni_present,
-- parsed from the fp prefix in set_tls_fp) are emitted; the stand's daily
-- analyzer keys on them. The `flags` array (soft-rule challenge flags,
-- vision.md v0.5 Step 7) is populated by the tls_fp soft rules (A9) and
-- stays a stable [] when none fire.
-- The Phase 2/3 optional fields (rule_source, client_rule_name) still land
-- with their own tasks, without renaming or reordering these keys.

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

-- mark_cascade_end — stamp the end of the access-phase cascade. Called at the
-- tail of verdict.lua (the pass path), i.e. the moment we've finished checking
-- and hand the request to proxy_pass. Lets emit() split cascade_ms (our own
-- intake+check overhead) from the upstream/origin time and the client-delivery
-- tail. For block/challenge requests verdict.lua exits before this, so
-- t_cascade_end stays nil and cascade_ms falls back to the full window (which
-- is fine — those never reach an upstream).
function _M.mark_cascade_end()
    local ctx = ngx.ctx.bac
    -- Only the first stamp wins (the real cascade end); later calls are no-ops.
    if ctx and not ctx.t_cascade_end then
        -- ngx.now() returns a CACHED time updated only at phase boundaries /
        -- on yields. The cascade runs synchronously without yielding, so
        -- without this the start (t_start) and end timestamps would be
        -- identical and cascade_ms would always be 0 (gemini review on PR #97).
        ngx.update_time()
        ctx.t_cascade_end = ngx.now()
    end
end

-- sum_upstream_time — parse nginx $upstream_response_time into seconds.
-- The var is nil/""/"-" when no upstream was contacted (blocked, landing), or
-- one-or-more numbers separated by ", " (multiple upstream tries) / " : "
-- (internal redirects); failed tries appear as "-". We sum every numeric
-- component and ignore the rest. Returns nil when there's no numeric value.
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

-- Append a soft-rule challenge flag (e.g. tls_fp_impersonator). Flags
-- accumulate across stages independently of the terminal verdict/rule:
-- the cascade short-circuits only on a blocking/allow rule, while soft
-- flags seen along the way are all kept for analytics (vision.md Step 7).
-- Producers: the tls_fp soft rules (A9, tls_fp.lua). The field stays a
-- stable [] when no soft rule fires, so the sink schema is unchanged.
function _M.add_flag(flag)
    local ctx = ngx.ctx.bac
    if not ctx then return end
    ctx.flags[#ctx.flags + 1] = flag
end

-- Record a staged-catalog pattern that matched but did not affect the
-- verdict (for promotion analytics). Format "<catalog>:<pattern_id>".
-- Producers: the tls_fp stage (A11, tls_fp.run) for tls_fp_blocklist /
-- tls_fp_catalog / tls_fp_browser_profiles. Stays a stable [] when nothing
-- staged matched.
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

-- Record the computed TLS fingerprint (tls_fp stage) and the three TLS
-- sub-columns derived from it. We parse them straight out of the fp
-- prefix rather than re-reading $ssl_* or calling compute() again: the
-- prefix layout "L<ver><sni><cipher_cnt><alpn>" (ja4_compute.lua) already
-- encodes them, so the log values are guaranteed consistent with tls_fp
-- (same source of truth the daily analyzer keys on, scripts/analyze.py).
--   <ver>        2 digits  (e.g. 13)
--   <sni>        d = SNI present, i = absent
--   <cipher_cnt> 2 digits  (%02d, GREASE-stripped, capped at 99)
--   <alpn>       2 chars   (h2 / h1 / 00 = none)
-- A malformed/absent fp leaves the sub-columns nil → null in the record.
-- set_challenge_fp(table). [C5] Browser fingerprint, собранный JS solver'ом
-- на challenge-странице (canvas/audio/screen/UA/etc.), приехавший в payload
-- POST /__challenge/verify. Пишется в BAC_LOG отдельным полем
-- `challenge_fp` для challenge-pass события (vision §5.2). НЕ участвует
-- в верификации запроса (bearer cookie без fp-binding); это датасет под
-- аналитику и будущие L6 ML-модели. Сохраняем как-есть, чтобы backend
-- мог нормализовать поля по своему usage (поля типа `ua/languages/
-- screen/timezone/hwc/platform` — см. challenge/page.html `fingerprint()`).
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

    -- Timing decomposition. latency_ms (below) is the WHOLE request lifetime
    -- ($request_time-like): cascade + origin + delivery to the end user — so
    -- for a slow client it's dominated by the download tail, not our work.
    -- The fields here isolate the parts we care about:
    --   cascade_ms  — our access-phase overhead (intake + cascade check),
    --                 stamped by verdict.lua mark_cascade_end(). Exact for
    --                 pass; for block/challenge (no upstream) ≈ latency_ms.
    --   upstream_response_ms — $upstream_response_time: upstream connect → last
    --                 byte of the origin response (origin round-trip incl. the
    --                 origin's own think-time), EXCLUDING delivery to the user.
    --                 null when no upstream was contacted (blocked / landing).
    --   proxy_ms    — cascade_ms + upstream_response_ms: request arrival → we
    --                 hold the full origin response ready to hand to the user.
    --                 This is the proxy path that adds overhead, WITHOUT the
    --                 slow-client delivery tail (what latency_ms − proxy_ms is).
    local cascade_ms = ctx.t_start and ((ctx.t_cascade_end or now) - ctx.t_start) * 1000 or nil
    local up_total = sum_upstream_time(ngx.var.upstream_response_time)
    local upstream_response_ms = up_total and up_total * 1000 or nil
    -- proxy_ms is null unless an upstream was actually contacted — for
    -- blocked/landing requests there's no origin response, so reporting
    -- proxy_ms == cascade_ms would be misleading (gemini review on PR #97).
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
        -- $request_uri preserves the ORIGINAL request path through
        -- internal rewrites (the catch-all-to-BAC model uses
        -- `rewrite ^ /__landing last` for unknown Hosts; without this
        -- $uri-vs-$request_uri swap, every unknown-Host record would
        -- log path=/__landing and we'd lose visibility into what
        -- scanners actually asked for). Query string is stripped so
        -- the field stays comparable to its pre-change shape — the
        -- sink already has separate observability for query patterns
        -- if needed.
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

    -- Write straight to stdout rather than via ngx.log: a message logged
    -- through the error_log during the log phase gets nginx's request
    -- context ("while logging request, client: ...") appended, which
    -- would corrupt the JSON line. A direct write keeps every line a
    -- clean, jq-parseable object for the telemetry sink (separate task).
    -- The "BAC_LOG " prefix lets the sink grep the structured stream out
    -- of the access/error lines that share docker stdout.
    --
    -- The flush is required, not optional: stdout to a docker pipe is
    -- fully buffered (not line-buffered), so without it lines accumulate
    -- and get split at arbitrary BUFSIZ boundaries, interleaving across
    -- workers. Writing the whole line then flushing emits it as one
    -- write() at the line boundary; with the line kept under PIPE_BUF
    -- (see UA cap) that write is atomic. The per-request syscall is fine
    -- for the stand; the telemetry-sink task swaps this for a batched
    -- async shipper.
    io.stdout:write("BAC_LOG ", line, "\n")
    io.stdout:flush()

    -- Ship to antibot-backend /v1/logs via per-worker async queue. enqueue
    -- никогда не блокирует и не аллоцирует heavy (см. log_shipper.lua);
    -- если shipper не сконфигурирован (ANTIBOT_BACKEND_URL не задан) — это
    -- no-op. На стенде stdout-эмит остаётся как ground truth для analyze.py
    -- daily-report'a; shipper — отдельный канал для backend-receiver'а.
    --
    -- Прямой доступ через package.loaded, а не pcall(require, ...): require
    -- кэширует, но pcall + table-lookup на каждый запрос — заметный шум
    -- на хот-пасе log_by_lua. Модуль точно загружен в init_worker (см.
    -- nginx.demo.conf), если он там не зарегистрировался — это deploy-bug,
    -- а не runtime-fallback. PR #54 gemini review.
    local shipper = package.loaded["log_shipper"]
    if shipper and shipper.enqueue then
        shipper.enqueue(line)
    end
end

return _M
