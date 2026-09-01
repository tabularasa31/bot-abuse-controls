-- The Channel C client: pulls the catalogs from the backend.
--
-- One background timer per catalog does a conditional GET, writes the payload
-- under a new generation, flips the generation and sweeps the old one.
-- Fail-stale throughout: any transport, status, decode or version error is
-- logged and skipped, leaving the previous generation in place.
--
-- Each catalog is a descriptor holding its endpoint, dict and apply/sweep
-- functions. `name` is kept separate from `dict_name` because the metrics are
-- keyed by catalog name, and the two differ for some catalogs.

local cjson        = require "cjson.safe"
local fp_state     = require "tls_fp_blocklist_state"

local _M = {}

-- Major version of the X-Catalog-Version header we accept. Bump in lockstep
-- with backend B3 payload-shape changes; an incompatible major keeps the
-- previous generation and bumps edge_sidecar_version_mismatch_total.
_M.SUPPORTED_VERSION_MAJOR = "1"

-- Cleanup is explicit rather than a per-entry TTL: the 304 short-circuit means
-- entries are never rewritten, so a TTL would silently age out a catalog that
-- simply had not changed.
_M.catalogs = {
    tls_fp_blocklist = {
        name        = "tls_fp_blocklist",
        endpoint    = "/catalog/tls_fp_blocklist",
        dict_name   = "tls_fp_blocklist",
        gen_key     = fp_state.META_GEN_KEY,   -- "tls_fp_blocklist_gen"
        etag_key    = fp_state.META_ETAG_KEY,
        version_key = "tls_fp_blocklist_version",
        -- A single failed write fails the whole apply, so the caller can roll
        -- back before the flip rather than sweep the old generation and leave a
        -- half-written catalog behind.
        apply = function(dict, entries, new_gen)
            local n = 0
            for fp, verdict in pairs(entries) do
                local ok, err = dict:set(fp_state.key(fp, new_gen), verdict)
                if not ok then
                    ngx.log(ngx.ERR, "tls_fp_blocklist:set failed: ", err,
                        " (fp=", fp, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        -- The scan locks the dict; at these catalog sizes that is microseconds,
        -- but past tens of thousands of keys it would need an index per
        -- generation instead.
        --
        -- Matched through the typed inverse of key() rather than a raw suffix,
        -- so that a future second writer's keys cannot be deleted by an
        -- accidental tail match.
        sweep = function(dict, old_gen)
            -- old_gen == 0 is the static seed from init.lua; sweeping it on
            -- the first pull is intentional — once the live catalog lands,
            -- the seed becomes redundant.
            if old_gen < 0 then return 0 end
            local n = 0
            for _, k in ipairs(dict:get_keys(0)) do
                if fp_state.match(k, old_gen) then
                    dict:delete(k)
                    n = n + 1
                end
            end
            return n
        end,
    },

    -- map(ip → "<status>:<family>"). An empty dict means every searchbot UA
    -- gets the provisional fastpath, which is the SEO-safe default.
    verified_bot_ips = {
        name        = "verified_bot_ips",
        endpoint    = "/catalog/verified_bot_ips",
        dict_name   = "verified_bots",
        gen_key     = "verified_bots_gen",
        etag_key    = "verified_bots_etag",
        version_key = "verified_bots_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for ip, val in pairs(entries) do
                local ok, err = dict:set(ip .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "verified_bots:set failed: ", err,
                        " (ip=", ip, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        -- A suffix match is safe here because this catalog is the dict's only
        -- writer. This is the dict sized for tens of thousands of entries, so
        -- it is the first that would need a per-generation index instead of a
        -- full scan.
        sweep = function(dict, old_gen)
            -- The suffix match only holds for numeric generations. Asserted so
            -- that switching to, say, a content hash fails here rather than
            -- silently shadowing IP-shaped keys.
            assert(type(old_gen) == "number",
                "verified_bot_ips.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
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

    -- map(hash_b → "<status>:<family>"), the automation signatures behind
    -- tls_fp_impersonator.
    tls_fp_catalog = {
        name        = "tls_fp_catalog",
        endpoint    = "/catalog/tls_fp_catalog",
        dict_name   = "tls_fp_catalog",
        gen_key     = "tls_fp_catalog_gen",
        etag_key    = "tls_fp_catalog_etag",
        version_key = "tls_fp_catalog_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for hb, val in pairs(entries) do
                local ok, err = dict:set(hb .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "tls_fp_catalog:set failed: ", err,
                        " (hash_b=", hb, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        -- The same suffix-match approach as verified_bot_ips: the gen is numeric and
        -- hash_b is hex without a `:`. We keep the contract explicit with an assert, in case
        -- somebody later decides to make the gen a string (a content hash).
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "tls_fp_catalog.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
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

    -- map(family → "<status>:<expected_cipher_cnt>"). A handful of entries, but
    -- it follows the same swap model as the rest.
    tls_fp_browser_profiles = {
        name        = "tls_fp_browser_profiles",
        endpoint    = "/catalog/tls_fp_browser_profiles",
        dict_name   = "tls_fp_browser_profiles",
        gen_key     = "tls_fp_browser_profiles_gen",
        etag_key    = "tls_fp_browser_profiles_etag",
        version_key = "tls_fp_browser_profiles_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for family, val in pairs(entries) do
                local ok, err = dict:set(family .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "tls_fp_browser_profiles:set failed: ", err,
                        " (family=", family, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "tls_fp_browser_profiles.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
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

    -- An object rather than a per-key map: the active side is one combined
    -- regex, and the staging side a list matched per pattern for attribution.
    -- So this stores two keys per generation.
    ua_blacklist = {
        name        = "ua_blacklist",
        endpoint    = "/catalog/ua_blacklist",
        dict_name   = "antibot_ua_blacklist",
        gen_key     = "ua_blacklist_gen",
        etag_key    = "ua_blacklist_etag",
        version_key = "ua_blacklist_version",
        apply = function(dict, entries, new_gen)
            -- entries = { active = "<combined>", staging = { ... } }. A missing
            -- field is tolerated (treated as empty) so a partial payload can't
            -- crash the pull — handle_response already type-checked `entries`
            -- is a table.
            local active = entries.active
            if type(active) ~= "string" then active = "" end
            local ok1, err1 = dict:set("active:" .. new_gen, active)
            if not ok1 then
                ngx.log(ngx.ERR, "ua_blacklist:set active failed: ", err1,
                    " (gen=", new_gen, ")")
                return false, 0
            end
            local staging = entries.staging
            if type(staging) ~= "table" then staging = {} end
            local encoded, eerr = cjson.encode(staging)
            if not encoded then
                ngx.log(ngx.ERR, "ua_blacklist:encode staging failed: ",
                    tostring(eerr), " (gen=", new_gen, ")")
                return false, 1
            end
            local ok2, err2 = dict:set("staging:" .. new_gen, encoded)
            if not ok2 then
                ngx.log(ngx.ERR, "ua_blacklist:set staging failed: ", err2,
                    " (gen=", new_gen, ")")
                return false, 1
            end
            return true, 2
        end,
        -- Fixed two-key layout per gen, so sweep just deletes the old gen's
        -- `active:` and `staging:` keys (no get_keys scan needed).
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "ua_blacklist.sweep: old_gen must be a number, got " ..
                type(old_gen))
            if old_gen < 0 then return 0 end
            local n = 0
            if dict:get("active:" .. old_gen) ~= nil then
                dict:delete("active:" .. old_gen); n = n + 1
            end
            if dict:get("staging:" .. old_gen) ~= nil then
                dict:delete("staging:" .. old_gen); n = n + 1
            end
            return n
        end,
    },

    -- map(cidr → "<status>:block"). An IPv6 CIDR contains colons, but the
    -- generation is always the last segment, so the suffix sweep still holds.
    -- The per-host list is a separate catalog and is not merged here.
    ip_blocklist = {
        name        = "ip_blocklist",
        endpoint    = "/catalog/ip_blocklist",
        dict_name   = "antibot_ip_blocklist",
        gen_key     = "ip_blocklist_gen",
        etag_key    = "ip_blocklist_etag",
        version_key = "ip_blocklist_version",
        apply = function(dict, entries, new_gen)
            local n = 0
            for cidr, val in pairs(entries) do
                local ok, err = dict:set(cidr .. ":" .. new_gen, val)
                if not ok then
                    ngx.log(ngx.ERR, "ip_blocklist:set failed: ", err,
                        " (cidr=", cidr, ", gen=", new_gen, ")")
                    return false, n
                end
                n = n + 1
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "ip_blocklist.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
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

    -- A flat array: an allow list has no per-entry status, since staged rollout
    -- makes no sense for it. Stored per key anyway, to match the others.
    ip_whitelist = {
        name        = "ip_whitelist",
        endpoint    = "/catalog/ip_whitelist",
        dict_name   = "antibot_ip_whitelist",
        gen_key     = "ip_whitelist_gen",
        etag_key    = "ip_whitelist_etag",
        version_key = "ip_whitelist_version",
        apply = function(dict, entries, new_gen)
            -- entries is a JSON array → a Lua sequence; iterate with ipairs.
            -- A non-string element (malformed payload) is skipped rather than
            -- crashing the pull — handle_response already type-checked the
            -- top-level value is a table.
            local n = 0
            for _, cidr in ipairs(entries) do
                if type(cidr) == "string" and cidr ~= "" then
                    local ok, err = dict:set(cidr .. ":" .. new_gen, "1")
                    if not ok then
                        ngx.log(ngx.ERR, "ip_whitelist:set failed: ", err,
                            " (cidr=", cidr, ", gen=", new_gen, ")")
                        return false, n
                    end
                    n = n + 1
                end
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "ip_whitelist.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
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

    -- The datacenter ASNs behind the asn_dc tag. Only key membership matters,
    -- so the wire value is dropped.
    asn_datacenters = {
        name        = "asn_datacenters",
        endpoint    = "/catalog/asn_datacenters",
        dict_name   = "antibot_asn_datacenters",
        gen_key     = "asn_datacenters_gen",
        etag_key    = "asn_datacenters_etag",
        version_key = "asn_datacenters_version",
        apply = function(dict, entries, new_gen)
            -- entries is a map(asn → 1); iterate keys with pairs. cjson decodes
            -- the string keys as Lua strings, which is exactly the type the
            -- reputation:asn_dc membership test uses (geoip.lookup returns asn
            -- as a string).
            local n = 0
            for asn, _ in pairs(entries) do
                if type(asn) == "string" and asn ~= "" then
                    local ok, err = dict:set(asn .. ":" .. new_gen, "1")
                    if not ok then
                        ngx.log(ngx.ERR, "asn_datacenters:set failed: ", err,
                            " (asn=", asn, ", gen=", new_gen, ")")
                        return false, n
                    end
                    n = n + 1
                end
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "asn_datacenters.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
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

    -- The whole host → policy map in one pull. Each value is re-encoded so the
    -- reader does exactly one decode per request.
    --
    -- Hosts go through the same normalisation the reader uses. The backend
    -- preserves case, so without it a mixed-case row would never be found and
    -- the customer would silently fall back to the pool default.
    policy = {
        name        = "policy",
        endpoint    = "/catalog/policy",
        dict_name   = "antibot_policy",
        gen_key     = "antibot_policy_gen",
        etag_key    = "antibot_policy_etag",
        version_key = "antibot_policy_version",
        apply = function(dict, entries, new_gen)
            local canonical_host = require("policy").canonical_host
            -- Two rows differing only in case collapse to one key here, and
            -- iteration order is unspecified — so "first wins" would pick a
            -- different mode on different pulls. Detect every collision before
            -- writing anything and keep the previous generation instead.
            local seen = {}
            local collided = false
            for host, _ in pairs(entries) do
                local key_host = canonical_host(host)
                if key_host then
                    if seen[key_host] then
                        ngx.log(ngx.ERR, "antibot_policy: host case collision: '",
                            host, "' and '", seen[key_host],
                            "' both canonicalize to '", key_host,
                            "' — failing the pull; collapse the duplicate at the backend")
                        collided = true
                    else
                        seen[key_host] = host
                    end
                end
            end
            if collided then
                return false, 0
            end
            local n = 0
            for host, p in pairs(entries) do
                local key_host = canonical_host(host)
                if not key_host then
                    ngx.log(ngx.WARN, "antibot_policy: skipping empty host key")
                else
                    local encoded, eerr = cjson.encode(p)
                    if not encoded then
                        ngx.log(ngx.ERR, "antibot_policy:encode failed: ",
                            tostring(eerr), " (host=", host, ", gen=", new_gen, ")")
                        return false, n
                    end
                    local ok, err = dict:set(key_host .. ":" .. new_gen, encoded)
                    if not ok then
                        ngx.log(ngx.ERR, "antibot_policy:set failed: ", err,
                            " (host=", host, ", gen=", new_gen, ")")
                        return false, n
                    end
                    n = n + 1
                end
            end
            return true, n
        end,
        sweep = function(dict, old_gen)
            assert(type(old_gen) == "number",
                "policy.sweep: old_gen must be a number, got " ..
                type(old_gen) .. " — sweep relies on numeric `:<gen>` suffix")
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

-- Keyed by catalog name, not dict name: the two differ for some catalogs, and
-- using the wrong one leaves the staleness gauge stuck at -1.
local function bump_last_pull_ts(cat)
    local m = ngx.shared.metrics
    if m then m:set("catalog_last_pull_ts:" .. cat.name, ngx.time()) end
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

-- Returns "ok" when a new generation was applied, "not_modified" on a 304, and
-- "skip" for anything else — in which case the previous generation stays.
function _M.handle_response(cat, dict, meta, res, err)
    -- Transport error: timeout, connection refused — lua-resty-http returns
    -- res=nil with err set.
    if res == nil then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, " fetch failed: ",
            tostring(err))
        return "skip"
    end

    if res.status == 304 then
        -- Touch nothing: a 304 is the steady state, and emptying the catalog
        -- here would wipe anything that had not changed recently.
        --
        -- The timestamp is still bumped. It measures time since successful
        -- contact, not since the last data change — otherwise a catalog that
        -- legitimately changes once a week would keep the staleness alert
        -- firing around the clock.
        bump_last_pull_ts(cat)
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
        -- Same naming contract as bump_last_pull_ts: keyed by the catalog
        -- NAME (descriptor key), which is what metrics.lua reads back.
        bump_metric("edge_sidecar_version_mismatch_total:" .. cat.name)
        return "skip"
    end

    -- cjson.safe returns nil + err on malformed JSON. The RFC §C1 pcall+
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

    -- Write, then flip, then sweep. A reader that saw the old generation still
    -- finds its entries, and one that sees the new generation finds those; no
    -- reader ever looks at a generation that is not fully written.
    local old_gen = meta:get(cat.gen_key) or 0
    local new_gen = old_gen + 1

    -- On a partial write, roll back the new generation and stay on the previous
    -- one; the next tick tries again.
    local apply_ok, written = cat.apply(dict, entries, new_gen)
    if not apply_ok then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint,
            ": apply failed after ", written, " writes — keeping gen=", old_gen)
        cat.sweep(dict, new_gen)
        return "skip"
    end

    -- The flip itself. A meta:set on a 1m shared_dict with a single int practically never fails,
    -- but if it did, the new gen's catalog is already in the dict while readers still resolve
    -- the old one. We reduce that to the same fail-stale: clean up the new gen and keep the old.
    local ok_flip, flip_err = meta:set(cat.gen_key, new_gen)
    if not ok_flip then
        ngx.log(ngx.ERR, "catalog ", cat.endpoint, ": gen flip failed: ",
            tostring(flip_err), " — rolling back, keeping gen=", old_gen)
        cat.sweep(dict, new_gen)
        return "skip"
    end

    local etag = res.headers and res.headers["ETag"]
    if etag then meta:set(cat.etag_key, etag) end
    if version then meta:set(cat.version_key, version) end

    cat.sweep(dict, old_gen)

    -- A long run of skips lets this age, which is the alert condition.
    bump_last_pull_ts(cat)

    return "ok"
end

-- The timer fires on schedule whether or not the previous tick finished. Two
-- concurrent ticks would interleave apply, flip and sweep: one tick's sweep can
-- delete the other's just-written entries while requests are mid-lookup,
-- briefly falling through to allow. A plain flag suffices, since the Lua VM is
-- single-threaded per worker.
local in_flight = {}

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

    -- In-flight guard: skip this tick if the previous one for the same
    -- catalog is still inside httpc:request_uri / handle_response. The
    -- skipped tick is just lost cadence — next ngx.timer.every firing
    -- will retry. No mutex contention because of single-threaded Lua.
    if in_flight[catalog_name] then
        ngx.log(ngx.NOTICE, "catalog_pull ", catalog_name,
            ": previous tick still in flight — skipping this one")
        return
    end
    in_flight[catalog_name] = true

    local dict = ngx.shared[cat.dict_name]
    local meta = ngx.shared.meta
    if not dict or not meta then
        ngx.log(ngx.ERR, "catalog_pull: missing shared_dict for ", catalog_name)
        in_flight[catalog_name] = nil
        return
    end

    local httpc_mod = _M.http_module
    if not httpc_mod then
        ngx.log(ngx.ERR, "catalog_pull: http module not configured")
        in_flight[catalog_name] = nil
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
    -- Either both or neither. Without them the backend refuses the handshake,
    -- which the fail-stale path already handles.
    if _M.parsed_cert and _M.parsed_key then
        req_opts.ssl_client_cert = _M.parsed_cert
        req_opts.ssl_client_priv_key = _M.parsed_key
    end
    local res, err = httpc:request_uri(_M.backend_url .. cat.endpoint, req_opts)

    -- pcall — handle_response can throw from cat.apply/cat.sweep
    -- (through ngx.log with an exotic argument, for instance). In that case
    -- in_flight would stay raised forever and the catalog would silently get stuck.
    local ok, perr = pcall(_M.handle_response, cat, dict, meta, res, err)
    in_flight[catalog_name] = nil
    if not ok then
        ngx.log(ngx.ERR, "catalog_pull ", catalog_name,
            ": handle_response raised: ", perr)
    end
end

-- Parses the PEM files into the form the HTTP client expects. Any failure
-- leaves mTLS disabled and surfaces as a handshake error plus a stalling
-- staleness gauge.
local function read_file(path)
    local f, ferr = io.open(path, "rb")
    if not f then return nil, ferr end
    local data, rerr = f:read("*a")
    f:close()
    if not data then return nil, rerr end
    return data
end

-- Called from the master before privileges are dropped, because the worker
-- phase runs as nobody and could not read a 0600 root-owned key. Workers
-- inherit the parsed material on fork.
function _M.preload_mtls(cert_path, key_path)
    if _M.parsed_cert and _M.parsed_key then return end
    _M.parsed_cert, _M.parsed_key = _M.load_mtls_material(cert_path, key_path)
end

function _M.load_mtls_material(cert_path, key_path)
    if not cert_path or cert_path == "" or not key_path or key_path == "" then
        return nil, nil
    end
    local ok_ssl, ssl = pcall(require, "ngx.ssl")
    if not ok_ssl then
        ngx.log(ngx.ERR, "catalog_pull: ngx.ssl not available — mTLS disabled")
        return nil, nil
    end

    local cert_pem, cerr = read_file(cert_path)
    if not cert_pem then
        ngx.log(ngx.ERR, "catalog_pull: read client cert ", cert_path, " failed: ", cerr)
        return nil, nil
    end
    local key_pem, kerr = read_file(key_path)
    if not key_pem then
        ngx.log(ngx.ERR, "catalog_pull: read client key ", key_path, " failed: ", kerr)
        return nil, nil
    end

    local parsed_cert, perr = ssl.parse_pem_cert(cert_pem)
    if not parsed_cert then
        ngx.log(ngx.ERR, "catalog_pull: parse_pem_cert failed: ", perr)
        return nil, nil
    end
    local parsed_key, kperr = ssl.parse_pem_priv_key(key_pem)
    if not parsed_key then
        ngx.log(ngx.ERR, "catalog_pull: parse_pem_priv_key failed: ", kperr)
        return nil, nil
    end
    return parsed_cert, parsed_key
end

-- One timer per catalog, on worker 0 only: the dicts are process-wide, so one
-- writer is enough and an N-worker pool does not multiply the pulls.
-- Empty strings count as nil. Compose substitutes an empty string for an unset
-- variable, and an empty URL is truthy in Lua — which would send every stand
-- without a backend into a bad-uri loop every 30 seconds.
local function nonempty(s)
    if s == nil or s == "" then return nil end
    return s
end

-- Coerces an env string to a boolean, so the certificate-verification toggle
-- lives in .env rather than in an edited nginx config on the host.
local function truthy_env(s, default)
    s = nonempty(s)
    if s == nil then return default end
    s = s:lower()
    if s == "false" or s == "0" or s == "no" or s == "off" then return false end
    return true
end

function _M.start(opts)
    opts = opts or {}
    -- Applied to the options too: a caller passing an empty string should fall
    -- through to the default rather than loop on a bad uri.
    _M.backend_url         = nonempty(opts.backend_url)
                             or nonempty(os.getenv("ANTIBOT_BACKEND_URL"))
                             or "http://antibot-backend:8080"
    _M.backend_host_header = nonempty(opts.backend_host_header)
                             or nonempty(os.getenv("ANTIBOT_BACKEND_HOST"))
    _M.timeout_ms          = opts.timeout_ms or 5000
    if opts.ssl_verify ~= nil then
        _M.ssl_verify = opts.ssl_verify
    else
        _M.ssl_verify = truthy_env(os.getenv("ANTIBOT_BACKEND_SSL_VERIFY"), true)
    end
    _M.interval            = opts.interval or 30
    local catalogs         = opts.catalogs or { "tls_fp_blocklist" }

    -- [B6] mTLS material: preferred to be preloaded by init_by_lua (so 0600
    -- root-owned keys are readable before privilege drop). preload_mtls is
    -- idempotent; this call is a safety net for callers that wire start()
    -- without a preload step.
    local cert_path = nonempty(opts.client_cert_path)
                      or nonempty(os.getenv("ANTIBOT_BACKEND_CLIENT_CERT"))
    local key_path  = nonempty(opts.client_priv_key_path)
                      or nonempty(os.getenv("ANTIBOT_BACKEND_CLIENT_KEY"))
    _M.preload_mtls(cert_path, key_path)
    if _M.parsed_cert and _M.parsed_key then
        ngx.log(ngx.NOTICE, "catalog_pull: mTLS client cert active",
            cert_path and (" (cert=" .. cert_path .. ")") or "")
    end

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
