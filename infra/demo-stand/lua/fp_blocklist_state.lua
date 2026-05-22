-- Per-worker generation cursor for the tls_fp blocklist catalog.
--
-- Modelled on §A2's `ua_blacklist_state` (docs/architecture/edge-lua-vs-sidecar.md):
-- a `require`'d module table is cached per worker, so `_M.gen` is stable
-- across requests on the same worker and we can mutate it in place.
--
-- The blocklist shared_dict is keyed by `fp .. ":" .. gen` (§A1 read /
-- §В1 atomic write). Keying by generation lets the catalog pull swap the
-- whole set atomically — it writes the new generation's keys, flips
-- `meta:fp_blocklist_gen`, then drops the old generation — so every reader
-- moves to the new catalog at once without a per-key race.
--
-- On the demo stand there is no Channel C pull yet (that is task 86exmk08u):
-- init.lua seeds the static blocklist under generation 0 and publishes
-- `fp_blocklist_gen = 0`, so `gen` stays 0 until the pull lands. Reading
-- through the generation key today keeps the request path forward-compatible
-- with the pull bumping it to 1+ with no verdict.lua change.

local _M = { gen = 0 }

-- Pure key builder shared by the §A1 read (verdict.lua) and the static seed
-- (init.lua) so both sides always agree on the format.
function _M.key(fp, gen)
    return fp .. ":" .. gen
end

-- Advance the per-worker cursor to the generation currently published in
-- ngx.shared.meta by the catalog pull (§В1). Returns the generation to use
-- for this request's lookup. The shared_dict read happens in the caller; this
-- keeps the cursor as the single place that tracks generation transitions.
function _M.sync(cur_gen)
    if _M.gen ~= cur_gen then
        _M.gen = cur_gen
    end
    return cur_gen
end

return _M
