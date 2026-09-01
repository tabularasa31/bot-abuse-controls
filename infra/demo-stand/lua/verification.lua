-- L5 verification stage — should_challenge() decision (C4).
--
-- L3 (tls_fp) and L4 (rate_limits) no longer issue verdict=challenge
-- directly: they only ACCUMULATE soft signals through bac_log.add_flag, and
-- the decision "issue verification or not" is taken at exactly one point —
-- this module at L5. The contract is rules-reference §"should_challenge()":
--
--   * attack_mode[host]=on            → a challenge for any request that reached
--                                       L5 (it overrides Strictness and the flags).
--   * A customer rate rule with action=challenge → always a challenge, even under
--                                       Strictness=Permissive (an explicit customer
--                                       setting is respected). The source is
--                                       ctx.client_challenge_flags, written by L4
--                                       when a client rate rule fires
--                                       (Phase 3+, rate_custom). It is always empty
--                                       for now.
--   * A system challenge flag + Strictness=Standard   → a challenge.
--   * A system challenge flag + Strictness=Permissive → verdict=permissive
--                                       (logged only; the request physically goes
--                                       to the origin).
--   * Otherwise                        → we do nothing and the verdict stays
--                                       as the earlier stages left it.
--
-- The system flags are a fixed whitelist (SYSTEM_FLAGS below). That
-- protects Strictness=Permissive from being bypassed by a client flag mistakenly
-- marked as a system one (and vice versa). When L4 gains system
-- rate rules with action=challenge we will add them here; entities-reference
-- lists "system L4 rate rules with action=challenge" among the system
-- signals, but in Phase 1 every system profile is blocking, so it is empty for now.
--
-- If the verdict is already block/allow we write nothing (block > allow > challenge
-- in the verdict hierarchy; clearance, ip_blocklist, hygiene and a rate block must all
-- survive to log_event). That matches tls_fp.fire_soft before
-- C4 — "a soft signal never downgrades a recorded block" — but the rule now
-- applies to the L5 decision rather than to every soft firing.
--
-- The attack_mode rule. When a challenge is issued because of attack_mode, the log
-- records rule="attack_mode" (with no accumulated flags) or the name of the last
-- system flag (which would have produced a challenge anyway; attack_mode merely
-- guarantees it on top of Strictness). A client flag, if there was one, would be
-- preferable, but under attack_mode=on the client path has already run
-- above.
--
-- C7 (a cookie under attack). A cookie_valid that survived to L5 with attack_mode=on
-- is a during-attack cookie (the short under_attack TTL): a pre-attack cookie was
-- already discarded by L2.1 as RESULT_STALE_PRE_ATTACK (clearance.verify), without
-- setting verdict=allow. So attack_mode here does NOT overwrite
-- verdict=allow — all three allow outcomes (a during-attack cookie_valid /
-- ip_whitelist / bot_verified) fastpath, and the challenge is forced only for
-- non-allow. That is what gives "a real user solves one challenge per attack".

local _M = {}

local bac_log = require "bac_log"
local policy  = require "policy"

-- The system challenge flags (see the module header). They are listed explicitly, so
-- that Permissive cannot be bypassed by a custom flag marked as a
-- system one. tls_fp_impersonator / tls_fp_suspicious_ciphers are the only
-- ones today (rules-reference L3 #11/#12). When this is extended (Phase 3+ system
-- L4 rate rules with action=challenge), add them here.
local SYSTEM_FLAGS = {
    tls_fp_impersonator       = true,
    tls_fp_suspicious_ciphers = true,
}

_M.SYSTEM_FLAGS = SYSTEM_FLAGS

-- pure: the should_challenge() decision. It returns (verdict, rule), or nil,nil
-- if the cascade should not touch the verdict. A pure function: the inputs are the bac ctx and
-- the per-host policy; no side effects and no ngx.* — so unit tests
-- (tests/verification_test.lua).
function _M.decide(ctx, p)
    if not ctx or not p then return nil, nil end

    -- block is terminal and is never overridden (not even by attack_mode):
    -- a blocking rule won at L1/L2/L4, and the client has already left with a 403
    -- (mode=active) or with a block recorded in the log (mode=shadow). Asking for a
    -- challenge on top of a block is meaningless.
    if ctx.verdict == "block" then return nil, nil end

    -- The last system flag — for the rule in the Standard/Permissive branch.
    local last_system
    for _, f in ipairs(ctx.flags or {}) do
        if SYSTEM_FLAGS[f] then last_system = f end
    end

    -- A customer rate rule with action=challenge (Phase 3+). Always empty today,
    -- but the contract is already fixed: a client flag always beats Permissive.
    -- Defensive type-check (gemini PR #86 review): client_challenge_flags
    -- is set by a future L4 rate_custom; while there is no concrete caller, the explicit
    -- type=="table" check keeps an accidental non-table assignment (a bool or
    -- string) from breaking L5 on `#client` (a Lua runtime error).
    local client = ctx.client_challenge_flags
    local last_client
    if type(client) == "table" and #client > 0 then
        last_client = client[#client]
    end

    -- attack_mode (C7) overrides Strictness. Everything that reached L5 without
    -- verdict=allow is forced to a challenge (rules-reference §attack_mode:
    -- "everything that reaches L5 → branches A/B/C"). verdict=allow under attack
    -- fastpaths — the semantics differ by rule, and all the filtering has already
    -- been done AT L2, before us:
    --   * ip_whitelist / bot_verified fastpath under attack by design
    --     (SEO and trusted integrations are unaffected, vision §5.3);
    --   * cookie_valid at L5 MEANS a during-attack cookie. A pre-attack
    --     cookie was already discarded by L2.1 (clearance.verify under attack_mode) as
    --     RESULT_STALE_PRE_ATTACK — it never set verdict=allow,rule=
    --     cookie_valid, so such a request arrived here without an allow and will go to a
    --     challenge below. So any cookie_valid that survives to L5 under
    --     attack was issued during the attack and must fastpath (vision §2.1:
    --     "the user solves one challenge per attack").
    -- So we do NOT distinguish allow by rule here — a fastpass for all three.
    if p.attack_mode and ctx.verdict ~= "allow" then
        return "challenge", last_client or last_system or "attack_mode"
    end

    -- verdict=allow (cookie_valid / ip_whitelist / bot_verified) — fastpass,
    -- L5 leaves alone (with attack_mode=on too, see above).
    if ctx.verdict == "allow" then return nil, nil end

    -- A client rate-rule challenge — always honoured, even under Permissive.
    if last_client then
        return "challenge", last_client
    end

    -- A system flag — gated by Strictness.
    if last_system then
        if p.strictness == "permissive" then
            return "permissive", last_system
        end
        return "challenge", last_system
    end

    return nil, nil
end

-- Branch classification (C5, vision §5.2 "Stage 5.2"). When decide()
-- returned verdict=challenge, the routing into branches A/B/C happens HERE
-- — a pure function with no side effects: the input is `req` (UA / method / Accept
-- / Upgrade) and the output is "A" | "B" | "C". The caller (verdict.lua) interprets it:
--   A — render the challenge page (branch A);
--   B — verdict=block, rule=non_browser_blocked (branch B);
--   C — verdict=block, rule=unchallengeable_request (branch C).
--
-- The order of checks: vision §5.2 frames branch B as "the UA is plainly not
-- a browser" and branch C as "protocol-incompatible with a challenge (the UA may
-- well be a browser one)". We cut the non-browser UA first — branch B is
-- more specific to the client (a curl with a POST → B, not C). Then we check
-- protocol compatibility (branch C). Otherwise → A.
--
-- Browser detection reuses `tls_fp.classify_ua` (the same table
-- as tls_fp_impersonator / suspicious_ciphers): "other" → not a
-- browser. A divergence between those two classifiers would make possible the
-- situation "the L3 soft rule did not fire because UA=other, while at L5
-- branch A served it a challenge" — hence one source of truth.
--
-- The unchallengeable signals (vision §5.2, "Property of the request"):
--   * the method is outside {GET, HEAD} — POST/PUT/PATCH/DELETE break on
--     `window.location = url` (a 303 drops the body);
--   * `Upgrade: websocket` — the client is waiting for `101 Switching Protocols`, and
--     an HTML page breaks the upgrade;
--   * Accept does not contain `text/html` (or is missing, or is `*/*`) —
--     a non-browser client expecting JSON/binary would render the HTML as garbage.
local tls_fp = require "tls_fp"

function _M.classify_branch(req)
    req = req or {}

    -- Branch B: a non-browser UA. classify_ua returns {edge|chrome|
    -- firefox|safari|other}; "other" — non-browser.
    local family = tls_fp.classify_ua(req.user_agent or "")
    if family == "other" then
        return "B"
    end

    -- Branch C signals — any of the three switches it on.
    local method = req.method or ""
    if method ~= "GET" and method ~= "HEAD" then
        return "C"
    end

    local upgrade = req.upgrade
    if type(upgrade) == "string" and upgrade ~= "" then
        if upgrade:lower():find("websocket", 1, true) then
            return "C"
        end
    end

    local accept = req.accept
    -- vision §5.2: "the default with no Accept is */* → unchallengeable".
    -- Real browsers always send an Accept with text/html for a top-level GET,
    -- so the strict check does not produce false positives on legitimate users.
    if type(accept) ~= "string" or accept == ""
        or not accept:lower():find("text/html", 1, true) then
        return "C"
    end

    return "A"
end

-- The per-request entry point. It reads ctx plus the policy, calls decide() and writes
-- the verdict through bac_log. No physical exit: the physical issuance
-- (the branch A/B/C dispatch) happens in verdict.lua after this returns,
-- so that the mode-gating policy (policy.enforce) lives in one place.
function _M.run()
    local ctx = ngx.ctx.bac
    if not ctx then return end
    local p = policy.get(ngx.var.host or "")
    local verdict, rule = _M.decide(ctx, p)
    if verdict then
        bac_log.set_verdict("verification", verdict, rule)
    end
end

return _M
