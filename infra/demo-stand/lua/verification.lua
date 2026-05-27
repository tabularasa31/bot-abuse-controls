-- L5 verification stage — should_challenge() decision (C4).
--
-- L3 (tls_fp) и L4 (rate_limits) больше не выдают verdict=challenge
-- напрямую: soft-сигналы они только КОПЯТ через bac_log.add_flag, а
-- решение «выдавать верификацию или нет» принимает ровно одна точка —
-- этот модуль на L5. Контракт — rules-reference §"should_challenge()":
--
--   * attack_mode[host]=on            → challenge для любого запроса, дошедшего
--                                       до L5 (override Strictness и флагов).
--   * Клиентское rate-rule action=challenge → всегда challenge, даже при
--                                       Strictness=Permissive (явная настройка
--                                       клиента уважается). Источник —
--                                       ctx.client_challenge_flags, пишется L4
--                                       при срабатывании client rate-rule
--                                       (Phase 3+, rate_custom). Сейчас всегда
--                                       пусто.
--   * Системный challenge-flag + Strictness=Standard   → challenge.
--   * Системный challenge-flag + Strictness=Permissive → verdict=permissive
--                                       (только в лог; физически запрос идёт
--                                       к origin).
--   * Иначе                            → ничего не делаем, verdict остаётся
--                                       тем, что выставили предыдущие стадии.
--
-- Системные flag'и — фиксированный whitelist (SYSTEM_FLAGS ниже). Это
-- защищает Strictness=Permissive от обхода через client-flag, ошибочно
-- помеченный как системный (и наоборот). Когда L4 заведёт системные
-- rate-rules с action=challenge — допишем их сюда; entities-reference
-- говорит «L4 системные rate-rules с action=challenge» в списке системных
-- сигналов, в Phase 1 все системные профили blocking, поэтому пока пусто.
--
-- Если verdict уже block/allow — ничего не пишем (block > allow > challenge
-- в иерархии вердиктов; clearance ip_blocklist hygiene rate-block — все
-- они должны дожить до log_event). Это совпадает с tls_fp.fire_soft'ом до
-- C4: «soft signal never downgrades a recorded block», но теперь правило
-- применяется к L5-решению, а не к каждому soft-выстрелу.
--
-- attack_mode rule. Когда challenge выдан из-за attack_mode, в лог
-- пишется rule="attack_mode" (нет накопленных flag'ов) или имя последнего
-- системного flag'a (он бы и так дал challenge, attack_mode лишь
-- гарантирует это поверх Strictness). Клиентский flag, если был —
-- предпочтительнее, но при attack_mode=on путь через client уже отрабатывает
-- выше. Точный формат поля rule под attack_mode уточняется в C7
-- (там же добавится сам polulation attack_mode из per-host policy и
-- iat-проверка cookie); для C4 важно лишь то, что attack_mode=on
-- однозначно → verdict=challenge.

local _M = {}

local bac_log = require "bac_log"
local policy  = require "policy"

-- Системные challenge-flag'и (см. модульный заголовок). Перечислены явно,
-- чтобы Permissive нельзя было обойти кастомным flag'ом, помеченным как
-- системный. tls_fp_impersonator / tls_fp_suspicious_ciphers — единственные
-- сейчас (rules-reference L3 #11/#12). При расширении (Phase 3+ системные
-- L4 rate-rules action=challenge) добавлять сюда.
local SYSTEM_FLAGS = {
    tls_fp_impersonator       = true,
    tls_fp_suspicious_ciphers = true,
}

_M.SYSTEM_FLAGS = SYSTEM_FLAGS

-- pure: should_challenge() decision. Возвращает (verdict, rule) или nil,nil
-- если каскад не должен трогать verdict. Чистая функция: вход — bac ctx и
-- per-host policy; никаких side-effects, никаких ngx.* — для unit-тестов
-- (tests/verification_test.lua).
function _M.decide(ctx, p)
    if not ctx or not p then return nil, nil end

    -- block — терминал, никогда не override'им (даже attack_mode'ом):
    -- блокирующее правило выиграло L1/L2/L4, физически клиент уже ушёл с 403
    -- (mode=active) или с записью block в логе (mode=shadow). Просить
    -- challenge поверх блокировки бессмысленно.
    if ctx.verdict == "block" then return nil, nil end

    -- Последний системный flag — для rule в Standard/Permissive ветке.
    local last_system
    for _, f in ipairs(ctx.flags or {}) do
        if SYSTEM_FLAGS[f] then last_system = f end
    end

    -- Клиентское rate-rule action=challenge (Phase 3+). Сейчас всегда пусто,
    -- но контракт уже зафиксирован: client-flag всегда побеждает Permissive.
    -- Defensive type-check (gemini PR #86 review): client_challenge_flags
    -- ставится будущим L4 rate_custom; пока конкретного caller'a нет, явная
    -- проверка type=="table" не даёт случайной non-table присваиванию (bool/
    -- string) уронить L5 на `#client` (runtime error в Lua).
    local client = ctx.client_challenge_flags
    local last_client
    if type(client) == "table" and #client > 0 then
        last_client = client[#client]
    end

    -- attack_mode (C7) — override Strictness и cookie_valid allow.
    -- ip_whitelist / verified_bot fastpath остаются (rules-reference
    -- §attack_mode: «verified-bot и IP-whitelist продолжают фастпасить»).
    -- cookie_valid под атакой → challenge (rule 3: cookie_valid действует
    -- ТОЛЬКО при attack_mode=off; пре-атакные cookie не должны фастпасить).
    -- Различаем по `rule`: cookie_valid override'им, остальные allow — нет.
    -- Carve-out для cookie, выданных ВО ВРЕМЯ атаки (rules-reference §145:
    -- «выданные во время атаки — фастпасят»), живёт в clearance.lua + C7
    -- (iat vs attack_started_at) — там cookie_valid просто не выставится для
    -- пре-атакных cookie, и эта ветка переписывания не сработает. До C7
    -- здесь чрезмерно строго: ВСЕ cookie_valid под attack_mode идут в
    -- challenge — это безопасно (false-positive на cookie issued during
    -- attack), и C7 это сузит. Если verdict=allow с другим rule (ip_whitelist,
    -- bot_verified, …) — отдаём fastpass (codex PR #86 review).
    if p.attack_mode then
        local cookie_allow = (ctx.verdict == "allow" and ctx.rule == "cookie_valid")
        if ctx.verdict ~= "allow" or cookie_allow then
            return "challenge", last_client or last_system or "attack_mode"
        end
    end

    -- Без attack_mode: любой verdict=allow (cookie_valid / ip_whitelist /
    -- bot_verified) — fastpass, L5 не трогает.
    if ctx.verdict == "allow" then return nil, nil end

    -- Client rate-rule challenge — всегда честим, даже при Permissive.
    if last_client then
        return "challenge", last_client
    end

    -- Системный flag — гейтится Strictness.
    if last_system then
        if p.strictness == "permissive" then
            return "permissive", last_system
        end
        return "challenge", last_system
    end

    return nil, nil
end

-- Branch classification (C5, vision §5.2 «Этап 5.2»). Когда decide()
-- вернул verdict=challenge, разводка по веткам A/B/C делается ЗДЕСЬ
-- — чистая функция, без side-effects: вход `req` (UA / method / Accept
-- / Upgrade), выход — "A" | "B" | "C". Caller (verdict.lua) интерпретирует:
--   A — render challenge page (Ветка A);
--   B — verdict=block, rule=non_browser_blocked (Ветка B);
--   C — verdict=block, rule=unchallengeable_request (Ветка C).
--
-- Порядок проверок: vision §5.2 формулирует Branch B как «UA явно не
-- браузер», Branch C как «протокольно не подходит под challenge (UA может
-- быть браузерным)». Сначала отсекаем non-browser UA — Branch B
-- специфичнее по клиенту (curl с POST → B, не C). Потом проверяем
-- протокольную совместимость (Branch C). Иначе → A.
--
-- Browser-detection переиспользует `tls_fp.classify_ua` (та же таблица,
-- что и для tls_fp_impersonator / suspicious_ciphers): "other" → не
-- браузер. Расхождение этих двух классификаторов сделало бы возможной
-- ситуацию «soft-rule на L3 не сработал, потому что UA=other, а на L5
-- Branch A отдал ему challenge» — поэтому держим один источник истины.
--
-- Unchallengeable signals (vision §5.2 «Признак запроса»):
--   * method не из {GET, HEAD} — POST/PUT/PATCH/DELETE ломаются на
--     `window.location = url` (303 сбросит body);
--   * `Upgrade: websocket` — клиент ждёт `101 Switching Protocols`,
--     HTML-страница ломает upgrade;
--   * Accept не содержит `text/html` (или отсутствует, или `*/*`) —
--     не-браузерный клиент с JSON/binary, HTML отрендерит как мусор.
local tls_fp = require "tls_fp"

function _M.classify_branch(req)
    req = req or {}

    -- Branch B: non-browser UA. classify_ua возвращает {edge|chrome|
    -- firefox|safari|other}; "other" — non-browser.
    local family = tls_fp.classify_ua(req.user_agent or "")
    if family == "other" then
        return "B"
    end

    -- Branch C signals — любой из трёх включает.
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
    -- vision §5.2: «Дефолт при отсутствии Accept — */* → unchallengeable».
    -- Реальные браузеры всегда шлют Accept с text/html для top-level GET,
    -- так что строгий чек не false-positive'ит на легитимных пользователях.
    if type(accept) ~= "string" or accept == ""
        or not accept:lower():find("text/html", 1, true) then
        return "C"
    end

    return "A"
end

-- Per-request entry point. Читает ctx + policy, вызывает decide(), пишет
-- verdict через bac_log. Никакого physical exit: physical issuance
-- (Branch A/B/C dispatch) делается в verdict.lua после возврата отсюда,
-- чтобы политика mode-gating (policy.enforce) была в одной точке.
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
