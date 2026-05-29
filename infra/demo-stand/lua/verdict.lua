-- Demo-stand access_by_lua handler.
--
-- Responsibilities:
--   1. Initialise the per-request BAC log context (request_id, start
--      time, resource_id) so latency_ms covers the whole cascade and
--      log_event.lua can emit the final structured record.
--   2. Run the L1 `hygiene` stage (hygiene.lua: method_not_allowed /
--      ua_blacklist + the hygiene:header_anomaly tag) — observe-only.
--   3. Run the L2 `reputation` stage (reputation.lua: ip_whitelist /
--      ip_blocklist via lua-resty-ipmatcher) — observe-only.
--   4. Run the existing TLS-fingerprint block decision (compute_fp +
--      cache + blocklist), identical to production.
--   5. Run the tls_fp soft rules + tls_fp:* tags (tls_fp.lua: A9) — the
--      observe-only, non-blocking half of the tls_fp stage.
--
-- The fp-based block is the Phase 2 `tls_fp` stage; it is recorded
-- through the same bac_log contract as hygiene/reputation. The remaining
-- Phase 1 stages (rate_limits) are separate tasks.
--
-- Mode-gated enforcement (B11): the only physical exit in the cascade —
-- tls_fp_blocklist hit below — goes through policy.enforce(403). For
-- clients with policy[host].mode=shadow (pool default), the would-be
-- verdict is still recorded via bac_log.set_verdict and the request
-- passes through to origin. For clients with mode=active, ngx.exit(403)
-- fires. Future enforcement points (rate_limit 429, per-host
-- ip_blocklist, challenge) MUST go through the same helper — see
-- policy.lua header for the convention.

local ja4        = require "ja4_compute"
local bac_log    = require "bac_log"
local hygiene    = require "hygiene"
local reputation = require "reputation"
local tls_fp     = require "tls_fp"
local rate_limit = require "rate_limit"
local fp_state   = require "tls_fp_blocklist_state"
local config     = require "config"
local policy     = require "policy"
local clearance  = require "clearance"
local verification = require "verification"

-- Global kill-switch (A12). When set, the whole cascade is a no-op: we return
-- before bac_log.init so the request proxies straight to the origin and emits
-- NO BAC_LOG record (log_event.lua skips when ngx.ctx.bac is unset). This is
-- the catastrophe lever from vision.md §"Аварийные рычаги" — protection must
-- never take the site down. Toggled via the gitignored kill_switch.local.conf
-- (config.lua), applied on `nginx -s reload`, no container recreate.
if config.global_kill(config.defaults) then
    return
end

bac_log.init()

-- L1 hygiene (method_not_allowed / ua_blacklist + hygiene:header_anomaly tag).
-- Mode-gated: hygiene.run records the would-be verdict and informational
-- tag via bac_log; on a blocking rule it then calls policy.enforce(403) so
-- a mode=active host gets 403 right inside run (ngx.exit, cascade dies).
-- For mode=shadow (pool default) enforce is a no-op and run returns
-- normally, so the cascade continues to tls_fp / rate_limit and their
-- would-be verdicts/tags still accumulate — last-writer-wins matches
-- phase1-spec "финальное сработавшее правило" (e.g., a later tls_fp
-- block overwrites the hygiene verdict in the log).
hygiene.run()

-- L2 reputation (ip_whitelist / ip_blocklist / dormant geo_blocklist).
-- Mode-gated like hygiene: ip_blocklist / geo_blocklist call
-- policy.enforce(403) so mode=active hosts get 403 right inside run; for
-- mode=shadow the would-be verdict is logged and the cascade continues.
-- The allow-side (ip_whitelist, verified_bots) still does NOT short-
-- circuit the cascade — a whitelisted IP that is also tls_fp_blocklisted
-- must still hit tls_fp downstream, regardless of mode. Real allow-side
-- fastpass is paired with per-host policy.ip_whitelist application
-- (86exr05xt), not this stage.
reputation.run()

-- L2.1 clearance cookie verify (C3). vision §2.1 / rules-reference rule
-- `cookie_valid`. HMAC-stateless: secret загружен через C1, никаких
-- сетевых вызовов. Валидный cookie → verdict=allow,rule=cookie_valid +
-- skip-flag `ngx.ctx.clearance_valid`, который L3 (tls_fp ниже) и L5
-- (challenge, C5+ ещё не реализован) уважают и пропускают себя; L4
-- (rate_limit) применяется к держателю cookie как обычно (vision §2.1
-- «пропускает L3 и L5, но НЕ L4»).
--
-- Порядок относительно hygiene/reputation. clearance.run идёт ПОСЛЕ них,
-- так что last-writer-wins работает в нашу пользу: L1 hygiene block
-- (method/ua_blacklist) выставит verdict=block ДО нас — мы поверх не
-- пишем (см. ниже `ctx.verdict ~= "block"` guard), и block корректно
-- доживёт до log_event. Аналогично reputation ip_blocklist: записан до
-- clearance, мы его не затираем. Если ничего блокирующего не сработало
-- → clearance ставит verdict=allow, который потом может быть переписан
-- L4 rate_limit (тоже by design — vision §2.1 «если сработал rate-лимит
-- → выигрывает правило L4»).
--
-- Все исходы (valid/invalid/expired/missing/wrong_site/malformed/no_secret)
-- идут в метрику `antibot_clearance_verify_total{result=...}` (metrics.lua).
-- Counter инкрементится здесь, а не в clearance.verify(), чтобы verify
-- осталась чистой функцией для unit-тестов (та же логика, что у policy
-- и rate_limit: модуль решает «что», caller — «что с этим сделать»).
--
-- ASYMMETRY WARN — метрика отражает только запросы, дошедшие до этой
-- точки в access_by_lua. В mode=active hygiene/reputation block через
-- `policy.enforce(403)` делает `ngx.exit(403)` ВЫШЕ — clearance.run для
-- них не выполняется. Поэтому сумма шести clearance_verify_* counter'ов
-- НЕ равна requests_total для active-mode хостов; она равна
-- (requests_total - active_mode_early_blocks). Дашборды, считающие
-- «cookie funnel coverage», должны нормировать на post-L1/L2.2-blocks
-- baseline, не на сырой requests_total (review on PR #85).
--
-- Per-stage kill-switch (A12). clearance — отдельная per-stage точка
-- выключения, чтобы при regression в clearance.verify / lua-resty-openssl
-- оператор мог потушить только L2.1 без обнуления всего каскада через
-- global A12. Гейт чекается через config.stage_enabled — тот же протокол,
-- что у hygiene/reputation/tls_fp/rate_limits/verification.
if config.stage_enabled(config.defaults, "clearance") then
    local host = ngx.var.host or ""
    -- attack_mode pre-attack gate (C7). Под attack_mode=on для host'a
    -- передаём в verify порог under_attack TTL: cookie с длинным (normal)
    -- TTL = выдан ДО начала атаки → verify вернёт RESULT_STALE_PRE_ATTACK,
    -- мы его НЕ фастпасим (clearance_valid не ставим, verdict не трогаем) —
    -- запрос идёт по каскаду до L5 на challenge. During-attack cookie
    -- (короткий TTL) фастпасит как обычно. Различение по типу TTL — vision
    -- §5.3, см. clearance.lua header. ip_whitelist/verified_bot фастпас при
    -- атаке не трогаем — он на L2 (reputation выше), не здесь.
    local opts
    -- policy.get контрактно non-nil (POOL_DEFAULT fallback), но guard'имся
    -- `p and` для консистентности с challenge_verify.lua / verification.lua —
    -- единый паттерн чтения policy на эдже (gemini review on PR #92).
    local p = policy.get(host)
    if p and p.attack_mode then
        local max_ttl
        local allow = config.defaults and config.defaults.allow
        if type(allow) == "table" and type(allow.cookie_valid) == "table" then
            max_ttl = tonumber(allow.cookie_valid.ttl_seconds_under_attack)
        end
        opts = { attack_mode = true, max_under_attack_ttl = max_ttl }
    end
    local result = clearance.verify(host, opts)
    ngx.shared.metrics:incr("clearance_verify_" .. result .. "_total", 1, 0)
    if result == clearance.RESULT_VALID then
        local ctx = ngx.ctx.bac
        -- Не затираем уже сработавший block (hygiene/reputation выше).
        -- Per rules-reference: cookie_valid пропускает L3 и L5, но L1 и
        -- L2.2/2.3 (включая ip_blocklist) всё равно применяются — их
        -- блок > наш allow. Если block уже выставлен:
        --   * verdict в логе НЕ перетираем;
        --   * clearance_valid НЕ ставим — L3 soft rules (tls_fp:*-tags +
        --     impersonator/suspicious_ciphers flags) должны прогнаться,
        --     чтобы shadow-mode log сохранил полную «would-be»-картину
        --     для блокированного-но-cookie-holding запроса (review on
        --     PR #85). Без этого guard'а L3 observability silently
        --     теряется для именно того профиля — украденный cookie + bad
        --     fp — против которого soft rules и проектировались.
        if ctx and ctx.verdict ~= "block" then
            ngx.ctx.clearance_valid = true
            bac_log.set_verdict("reputation", "allow", "cookie_valid")
        end
    end
end

-- Per-stage kill-switch for tls_fp (A12). This gate covers the fp compute +
-- blocklist block-path that live inline here (not in tls_fp.lua, which gates
-- its own soft rules via _M.enabled). When killed, fp stays nil — which is the
-- same "fp not computed" signal rate_limit.run treats as a graceful skip of the
-- rate_tls_fp profile (A10), so the per-IP profiles keep working.
--
-- [C3] Clearance fastpath skips ONLY the L3 decision (blocklist hit + soft
-- rules + tls_fp:* tags), NOT the fp compute. rate_tls_fp is part of L4
-- (rate_limits), and per vision §2.1 / rules-reference rule 3 cookie_valid
-- «пропускает L3 и L5, но НЕ L4» — including rate_tls_fp. Если бы fp
-- оставался nil под cookie, rate_limit.run скипал бы rate_tls_fp_profile
-- (rate_limit.lua `fp_ok`-guard), и держатель cookie получил бы бесплатный
-- bypass per-fp лимита на 24 часа TTL (codex review on PR #85). Поэтому
-- fp всё равно считаем + кладём в bac_log, но `if not clearance_valid`
-- оборачивает только cache/blocklist check и `tls_fp.run(fp)`.
local fp
if config.stage_enabled(config.defaults, "tls_fp") then
    fp = ja4.compute()
    bac_log.set_tls_fp(fp)

    if not ngx.ctx.clearance_valid then
        -- §A1 read: pin the generation the catalog pull (§В1) last published and
        -- key BOTH the verdict cache and the blocklist by `fp:gen`. Sharing the
        -- generation key makes a catalog swap atomic for the cache too: when gen
        -- bumps, old-gen cache entries become unreachable and age out on their TTL,
        -- so the flip takes effect immediately instead of being masked by a stale
        -- bare-fp entry for up to 60s. No pull on the stand yet, so gen stays at
        -- the 0 init.lua seeds.
        local gen = ngx.shared.meta:get(fp_state.META_GEN_KEY) or 0
        local key = fp_state.key(fp, gen)

        local cache  = ngx.shared.verdict_cache
        local cached = cache:get(key)
        local cache_hit = (cached ~= nil)

        local verdict
        if cached == "block" or cached == "allow" then
            verdict = cached
        else
            -- §A1 + A11: the Channel C value carries status ("<status>:block").
            -- Only an ACTIVE entry blocks here; a staged fp resolves to "allow"
            -- so the request falls through to tls_fp.run(), which records
            -- staging_match from tls_fp.blocklist_staging (built from the same
            -- snapshot in refresh()). parse_value tolerates the legacy bare
            -- "block" seed (treated as active).
            local status = fp_state.parse_value(ngx.shared.tls_fp_blocklist:get(key))
            verdict = (status == "active") and "block" or "allow"
            cache:set(key, verdict, 60)
        end

        -- Cache outcome is metrics-only; stash it for log_event.lua's counters.
        ngx.ctx.bac_cache_hit = cache_hit

        if verdict == "block" then
            bac_log.set_verdict("tls_fp", "block", "tls_fp_blocklist")
            -- B11: active → ngx.exit(403) below; shadow → enforce is a no-op,
            -- we then `return` from access_by_lua to short-circuit the rest of
            -- the cascade so a later stage (tls_fp soft / rate_limit) can't
            -- overwrite the "block" verdict via last-writer-wins. The log
            -- reflects the same final state the active path would have
            -- emitted (verdict=block, rule=tls_fp_blocklist), the only
            -- difference being that the request still proxies to origin.
            -- Stamp cascade end BEFORE enforce: in shadow this returns and the
            -- request still proxies to origin, so cascade_ms must capture only
            -- the cascade, not the upstream/client tail (gemini review #97).
            bac_log.mark_cascade_end()
            policy.enforce(403)
            return
        end

        -- tls_fp soft rules + tls_fp:* tags (A9). Observe-only: records the would-be
        -- challenge verdict and the soft flags / informational tags via bac_log but
        -- never blocks or short-circuits. Runs after the blocklist check (a
        -- blocklisted fp has already exited above) and after reputation, so the
        -- cross-layer tls_fp:dc_browser tag can see reputation:asn_dc.
        tls_fp.run(fp)
    end
end

-- L4 rate_limits (rate_ip / rate_ip_ua / rate_api / rate_tls_fp /
-- rate_scan_urls). Runs last in the cascade. Mode-gated: a fired
-- profile calls policy.enforce(429, {Retry-After=...}) — mode=active
-- hosts get a real 429 with the Retry-After header (window size as
-- upper bound); mode=shadow records the would-be verdict and lets the
-- request reach origin. last-writer-wins on the verdict, so a rate
-- block overwrites the egress default. `fp` is passed so rate_tls_fp
-- can key on it (and skip gracefully when the fp was not computed
-- for this request).
rate_limit.run(fp)

-- L5 verification — should_challenge() (C4). Решение про challenge — ровно
-- здесь. До C4 verdict=challenge выставлял сам tls_fp soft-блок, что
-- нарушало rules-reference («L3/L4 flags only mark, decision happens at L5»)
-- и игнорировало per-resource Strictness. Теперь tls_fp лишь копит flag'и,
-- а verification.decide() читает (flags, policy.strictness, policy.attack_mode)
-- и пишет verdict=challenge / verdict=permissive / ничего. Observe-only:
-- physical challenge issuance (Branch A — JS challenge, Branch B/C — block)
-- — отдельный ticket C5; сейчас вердикт идёт только в bac_log.
--
-- Гейтится per-stage kill-switch'ем `verification` (defaults.conf
-- [kill_switch.per_stage]). При выключении системные soft-флаги остаются
-- в `flags` (для аналитики), но не превращаются ни в challenge, ни в
-- permissive — verdict остаётся таким, каким его оставил L4 (pass /
-- block / allow).
if config.stage_enabled(config.defaults, "verification") then
    verification.run()

    -- L5.2 — physical dispatch (C5). verification.run() выставил
    -- verdict=challenge в bac_log; physically делаем разводку по веткам
    -- здесь, чтобы policy.enforce был единой точкой mode-gating'a (то же
    -- соглашение, что и у tls_fp_blocklist выше + rate_limit). decide()
    -- chooses verdict; classify_branch() chooses ветку A/B/C; этот блок —
    -- единственная точка physical issue/block в L5.
    --
    -- Mode-gating:
    --   * Branch A в mode=active → render challenge page, ngx.exit(200).
    --     В shadow — НЕ серверим страницу: would-be-verdict уже в логе
    --     (`verdict=challenge`), запрос идёт к origin как обычно. Это
    --     сохраняет observe-only контракт shadow-режима: edge не меняет
    --     ответ пользователю, пока клиент не переключился в active.
    --   * Branch B/C — пишем block в лог (вне зависимости от mode) и
    --     зовём policy.enforce(403): active → 403, shadow → no-op,
    --     запрос продолжает идти к origin. Та же схема, что у
    --     tls_fp_blocklist.
    local ctx = ngx.ctx.bac
    if ctx and ctx.verdict == "challenge" then
        local branch = verification.classify_branch({
            user_agent = ngx.var.http_user_agent,
            method     = ngx.var.request_method,
            accept     = ngx.var.http_accept,
            upgrade    = ngx.var.http_upgrade,
        })
        if branch == "B" then
            bac_log.set_verdict("verification", "block", "non_browser_blocked")
            ngx.shared.metrics:incr("challenge_branch_b_total", 1, 0)
            bac_log.mark_cascade_end()   -- shadow proxies on; stamp before enforce (review #97)
            policy.enforce(403)
            return
        elseif branch == "C" then
            bac_log.set_verdict("verification", "block", "unchallengeable_request")
            ngx.shared.metrics:incr("challenge_branch_c_total", 1, 0)
            bac_log.mark_cascade_end()   -- shadow proxies on; stamp before enforce (review #97)
            policy.enforce(403)
            return
        else
            -- Branch A — JS challenge. Только в active mode, иначе
            -- shadow ломает «edge не меняет ответ». В shadow verdict
            -- challenge остаётся в логе, запрос идёт к origin.
            --
            -- ngx.exec в internal `@challenge_page` (а не ngx.print
            -- здесь) — стандартный паттерн §A8 edge-lua-vs-sidecar:
            -- access_by_lua переключает запрос на content_by_lua-
            -- handler, который и пишет body. URL клиента сохраняется
            -- (важно: после window.location.reload() браузер уходит на
            -- исходный URL с новым cookie, не на «/_challenge»).
            -- policy.get guarantees a non-nil POOL_DEFAULT fallback, но
            -- хранение в локальной переменной убирает повторный
            -- shared_dict lookup (policy.get кеширует в ngx.ctx, но
            -- читать `.mode` дважды через две вложенные индексации —
            -- читается хуже) + защищает от теоретической поломки
            -- контракта policy.get (gemini review on PR #87).
            local p = policy.get(ngx.var.host or "")
            if p and p.mode == "active" then
                return ngx.exec("@challenge_page")
            end
        end
    end
end

-- End of the access-phase cascade for the PASS path: stamp it so bac_log can
-- split cascade_ms (our intake + check overhead) from the upstream/origin time
-- and the client-delivery tail. block/challenge paths exit earlier via
-- ngx.exit/ngx.exec and never reach here — fine, they have no upstream.
bac_log.mark_cascade_end()

-- Fall through. If no rate profile fired and L5 не дал challenge/permissive,
-- the context keeps its defaults (stage=egress, verdict=pass).
