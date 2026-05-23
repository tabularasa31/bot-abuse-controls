-- Channel C client on the edge (B5, RFC §В1).
--
-- Background ngx.timer.every per catalog: conditional GET against
-- antibot-backend, atomic generation swap into the catalog's
-- lua_shared_dict, explicit cleanup of the old generation. Fail-stale:
-- any transport / status / decode / version error is logged and skipped;
-- the previous generation stays in the dict, the timer keeps ticking.
--
-- Layout:
--   _M.catalogs     — per-catalog descriptors (endpoint, dict name, apply +
--                     sweep functions, meta-key names).
--   _M.handle_response(cat, dict, meta, res, err)
--                   — pure-ish response handler used both by fetch() and by
--                     tests. Returns "ok" / "not_modified" / "skip".
--   _M.fetch(name)  — one tick: build httpc, request, dispatch to
--                     handle_response.
--   _M.start(opts)  — wire ngx.timer.every per catalog in
--                     init_worker_by_lua_block. Guarded to worker 0 so a
--                     pool with N workers does N× fewer pulls, not N×.
--
-- Today the only catalog wired in is fp_blocklist — verdict.lua is the only
-- request-path reader that consumes a Channel C catalog through the §A1
-- gen-keyed lookup (`fp:gen`). The other seven catalogs from
-- docs/architecture/config-distribution.md §"The 'catalog' concept" migrate
-- to Channel C in [B12] (hot-reload of static configs) — adding them here
-- without a consumer would write to a dict nobody reads.

local cjson        = require "cjson.safe"
local fp_state     = require "fp_blocklist_state"

local _M = {}

-- Major version of the X-Catalog-Version header we accept. Bump in lockstep
-- with backend B3 payload-shape changes; an incompatible major keeps the
-- previous generation and bumps edge_sidecar_version_mismatch_total.
_M.SUPPORTED_VERSION_MAJOR = "1"

-- Per-catalog payload writers / sweepers. `apply` writes the decoded body
-- into the dict under the NEW generation; `sweep` deletes the OLD gen's keys
-- after the gen flip (RFC §В1 explicit cleanup — per-entry TTL is wrong here
-- because the 304 short-circuit means entries never get re-written and would
-- silently age out, see §В1 "Why explicit cleanup instead of per-entry TTL").
_M.catalogs = {
    fp_blocklist = {
        endpoint    = "/catalog/fp_blocklist",
        dict_name   = "fp_blocklist",
        gen_key     = fp_state.META_GEN_KEY,   -- "fp_blocklist_gen"
        etag_key    = "fp_blocklist_etag",
        version_key = "fp_blocklist_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for fp, verdict in pairs(entries) do
                local ok, err = dict:set(fp_state.key(fp, new_gen), verdict)
                if ok then
                    n = n + 1
                else
                    ngx.log(ngx.ERR, "fp_blocklist:set failed: ", err)
                end
            end
            return n
        end,
        sweep = function(dict, old_gen)
            -- old_gen == 0 is the static seed from init.lua; sweeping it on
            -- the first pull is intentional — once the live catalog lands,
            -- the seed becomes redundant.
            if old_gen < 0 then return 0 end
            local suffix = ":" .. old_gen
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if k:sub(-#suffix) == suffix then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },
}

-- bump_metric — best-effort counter increment on the `metrics` shared_dict.
-- Same convention as log_event.lua; missing dict is silent so this module
-- still works in tests that don't wire a metrics dict.
local function bump_metric(key)
    local m = ngx.shared.metrics
    if m then m:incr(key, 1, 0) end
end

-- version_compatible — single-major check. Accepts "1", "1.x", "1.x.y". An
-- empty / missing header is treated as compatible: older backend builds may
-- not set the header, and a missing header is an operator concern (visible
-- in logs), not a correctness one.
function _M.version_compatible(version)
    if not version or version == "" then return true end
    local major = version:match("^(%d+)")
    if not major then return false end
    return major == _M.SUPPORTED_VERSION_MAJOR
end

-- handle_response — process one HTTP result and apply it (or skip) under
-- the catalog descriptor. Returns one of:
--   "ok"           — 200 applied, gen flipped, old gen swept.
--   "not_modified" — 304, nothing touched (regression guard from round-3
--                    review: NEVER zero entries on 304).
--   "skip"         — anything else (transport error, non-200 status,
--                    decode failure, wrong decoded type, version
--                    mismatch). Previous generation stays in the dict.
function _M.handle_response(cat, dict, meta, res, err)
    -- Transport error: timeout, connection refused — lua-resty-http returns
    -- res=nil with err set.
    if res == nil then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, " fetch failed: ",
            tostring(err))
        return "skip"
    end

    if res.status == 304 then
        -- Round-3 regression: do NOT touch dict, do NOT bump gen. The 304
        -- short-circuit is the steady state — without this guard a catalog
        -- that hasn't changed for an hour would silently empty out.
        return "not_modified"
    end

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, ": HTTP ", res.status)
        return "skip"
    end

    local version = res.headers and res.headers["X-Catalog-Version"]
    if not _M.version_compatible(version) then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, ": version mismatch ",
            tostring(version), " vs major=", _M.SUPPORTED_VERSION_MAJOR)
        bump_metric("edge_sidecar_version_mismatch_total:" .. cat.dict_name)
        return "skip"
    end

    -- cjson.safe returns nil + err on malformed JSON. The RFC §В1 pcall+
    -- type-check is collapsed into one decode (.safe never throws) plus
    -- one type check. The type check guards against decoded-but-not-a-table
    -- (a top-level JSON string/number is valid JSON but would crash pairs).
    local body = res.body or ""
    local entries, derr = cjson.decode(body)
    if entries == nil then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint,
            ": decode failed: ", tostring(derr))
        return "skip"
    end
    if type(entries) ~= "table" then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint,
            ": decoded value is ", type(entries), ", expected table")
        return "skip"
    end

    -- Order matters: write the new gen first, then flip the gen counter,
    -- then sweep the old gen. A reader that read meta:gen before the flip
    -- still resolves to old_gen and finds its entries; a reader that reads
    -- after the flip resolves to new_gen and finds those. See RFC §В1
    -- "Atomically flip readers" and verdict.lua's `fp:gen` lookup.
    local old_gen = meta:get(cat.gen_key) or 0
    local new_gen = old_gen + 1
    cat.apply(dict, entries, new_gen)
    meta:set(cat.gen_key, new_gen)

    local etag = res.headers and res.headers["ETag"]
    if etag then meta:set(cat.etag_key, etag) end
    if version then meta:set(cat.version_key, version) end

    cat.sweep(dict, old_gen)

    -- Last-successful-pull timestamp drives edge_catalog_staleness_seconds
    -- in metrics.lua (gauge = now - last). Recorded only on "ok", so a long
    -- run of skips/304s makes the gauge grow.
    local m = ngx.shared.metrics
    if m then m:set("catalog_last_pull_ts:" .. cat.dict_name, ngx.time()) end

    return "ok"
end

-- fetch — one tick for one catalog. Resolves shared dicts, builds the
-- httpc, sends the conditional GET, hands the result to handle_response.
-- Any uncaught error inside is swallowed by the pcall in tick() so the
-- ngx.timer keeps running.
function _M.fetch(catalog_name)
    local cat = _M.catalogs[catalog_name]
    if not cat then
        ngx.log(ngx.ERR, "catalog_pull: unknown catalog ", tostring(catalog_name))
        return
    end
    local dict = ngx.shared[cat.dict_name]
    local meta = ngx.shared.meta
    if not dict or not meta then
        ngx.log(ngx.ERR, "catalog_pull: missing shared_dict for ", catalog_name)
        return
    end

    local httpc_mod = _M.http_module
    if not httpc_mod then
        ngx.log(ngx.ERR, "catalog_pull: http module not configured")
        return
    end
    local httpc = httpc_mod.new()
    httpc:set_timeout(_M.timeout_ms)

    local etag = meta:get(cat.etag_key)
    local headers = { ["If-None-Match"] = etag or "" }
    if _M.backend_host_header then
        headers["Host"] = _M.backend_host_header
    end

    local req_opts = {
        method   = "GET",
        headers  = headers,
        ssl_verify = _M.ssl_verify,
    }
    local res, err = httpc:request_uri(_M.backend_url .. cat.endpoint, req_opts)

    _M.handle_response(cat, dict, meta, res, err)
end

-- start — call from init_worker_by_lua_block. Wires one ngx.timer.every per
-- requested catalog, guarded to worker 0 so an N-worker pool issues N×
-- fewer pulls (each catalog has one timer per machine, not per worker;
-- shared dicts are process-wide so a single writer suffices).
function _M.start(opts)
    opts = opts or {}
    _M.backend_url         = opts.backend_url
                             or os.getenv("ANTIBOT_BACKEND_URL")
                             or "http://antibot-backend:8080"
    _M.backend_host_header = opts.backend_host_header
                             or os.getenv("ANTIBOT_BACKEND_HOST")
    _M.timeout_ms          = opts.timeout_ms or 5000
    if opts.ssl_verify ~= nil then
        _M.ssl_verify = opts.ssl_verify
    else
        _M.ssl_verify = true
    end
    _M.interval            = opts.interval or 30
    local catalogs         = opts.catalogs or { "fp_blocklist" }

    if not _M.http_module then
        local ok, mod = pcall(require, "resty.http")
        if not ok then
            ngx.log(ngx.ERR, "catalog_pull: lua-resty-http not available, ",
                "Channel C disabled — running on static seed only")
            return
        end
        _M.http_module = mod
    end

    if ngx.worker and ngx.worker.id() ~= 0 then
        -- Only worker 0 pulls; other workers read the shared_dict that
        -- worker 0 populates.
        return
    end

    for _, name in ipairs(catalogs) do
        local function tick(premature)
            if premature then return end
            local ok, e = pcall(_M.fetch, name)
            if not ok then
                ngx.log(ngx.ERR, "catalog_pull ", name, " tick failed: ", e)
            end
        end
        -- Cold-start: immediate first fetch (don't make the edge wait the
        -- full interval to leave the static seed), then steady cadence.
        local ok1, e1 = ngx.timer.at(0, tick)
        if not ok1 then
            ngx.log(ngx.ERR, "catalog_pull ", name,
                ": ngx.timer.at failed: ", e1)
        end
        local ok2, e2 = ngx.timer.every(_M.interval, tick)
        if not ok2 then
            ngx.log(ngx.ERR, "catalog_pull ", name,
                ": ngx.timer.every failed: ", e2)
        end
    end
end

return _M
