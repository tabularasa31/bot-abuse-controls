-- L3 tls_fp soft-rule + tag stage (rules-reference L3 #11/#12 + tags T2–T4;
-- phase2-spec "Правила этапа"; vision §"UA-family ↔ fp mismatch").
--
-- This module owns the NON-blocking part of the tls_fp stage. The blocking
-- part (tls_fp_blocklist → ngx.exit(403)) stays inline in verdict.lua because
-- it short-circuits the cascade; everything here is observe-only and never
-- exits, so it lives as its own stage module alongside hygiene/reputation.
--
-- Naming note: the A9 ticket body sketched this as `ua_fp_consistency.lua`
-- with a per-request sidecar `/__score` round-trip (RFC §В2 grey-verdict
-- path). That path is explicitly retired in the current architecture — see
-- docs/architecture/edge-lua-vs-sidecar.md (terminology note, 2026-05-18:
-- "§В2 ... not used in the current design (no heavy/grey-verdict scoring)").
-- So A9 reduces to the doc-aligned tls_fp stage: two soft rules + three
-- informational tags, all evaluated in Lua, all observe-only. Hence the
-- stage name `tls_fp` rather than `ua_fp_consistency` (which would not cover
-- suspicious_ciphers or the tags).
--
-- Soft rules (category soft → накапливают флаг в `flags`; финальный verdict
-- решает L5/verification.lua по Strictness + attack_mode, см. C4):
--   * tls_fp_impersonator       — UA claims a browser family, but the fp's
--                                 hash_b matches a known automation signature
--                                 in tls_fp_catalog (UA Chrome + fp = curl/
--                                 python-requests/Go/okhttp ⇒ masquerade).
--   * tls_fp_suspicious_ciphers — UA claims a browser family, but the fp's
--                                 cipher_count differs from that family's
--                                 expected count in tls_fp_browser_profiles
--                                 (chrome=15, firefox=16, safari=20, edge=15).
--
-- Informational tags (NOT rules — emit no verdict, never stop the cascade,
-- accumulate in `tags` independent of the verdict):
--   * tls_fp:automation_ua — UA carries explicit automation markers
--                            (curl/python-requests/Go/okhttp/…). Duplicates
--                            what ua_blacklist will catch once populated; a
--                            primary automation signal until then.
--   * tls_fp:no_sni        — client sent no SNI in the TLS handshake.
--   * tls_fp:dc_browser    — cross-layer (L3 fp + L2 reputation): the fp is
--                            browser-shaped (cipher_count matches a browser
--                            profile) AND the IP is in a datacenter ASN (the
--                            reputation:asn_dc tag set upstream this request).
--
-- Observe-only (phase2-spec "Каскад в MVP только наблюдает"): run() записывает
-- флаги/теги через bac_log, никогда не делает ngx.exit и никогда не
-- short-circuit'ит. До C4 здесь же ставился verdict=challenge для soft-
-- сигналов; после C4 это убрано — L5/verification.lua принимает решение,
-- уважая Strictness и attack_mode. Терминальный block по-прежнему
-- не затирается soft-флагом (block остаётся `rule`, soft-флаг живёт в
-- `flags`) — это гарантирует verification.decide(): при verdict=="block"
-- он молча возвращает nil и оставляет терминал нетронутым.
--
-- Config model. After PR2 (ADR-006) tls_fp_catalog and tls_fp_browser_profiles
-- live in git-репо `catalogs/` и приезжают через Channel C: backend читает
-- YAML в catalog server, edge polls via catalog_pull.lua + atomic-swap в
-- shared_dict. refresh() — gen-cached rebuild per-worker, дёшево на каждом
-- run(), rebuild только при flip'е. До первого pull действует cold-start
-- fallback (COLD_START_PROFILES); после profiles_landed() → fallback OFF,
-- backend single source of truth. Pre-PR2 INI-парсинг в config.lua удалён.
--
-- Staging (A11, phase2-spec §"Staged rollout для PR-каталогов"). Catalog
-- entries with status=staging are kept OUT of the active lookup tables (so they
-- never produce a verdict/rule even in active mode) and instead compiled into
-- parallel *_staging tables. When a staged entry matches the same way its
-- active counterpart would, run() records the fact into the `staging_match` log
-- slot ("<catalog>:<pattern_id>") via bac_log.add_staging_match — pure
-- observation for the promotion workflow (staging → active in a separate PR, or
-- revert). pattern_id per catalog: tls_fp_blocklist = the fp token,
-- tls_fp_catalog = hash_b, tls_fp_browser_profiles = browser_family. The
-- blocklist staging set lives here too (not in init.lua's active tls_fp_blocklist
-- seed) so the whole stage's staging detection is in one place; a staged fp is
-- absent from the active dict, so verdict.lua never exits on it and the request
-- always reaches run().
--
-- A11 follow-up (86exrtjpc): blocklist_staging is now built from the Channel C
-- snapshot in refresh() (the tls_fp_blocklist shared_dict, where staged fps
-- arrive as "staging:block" — see store.buildTLSFPBlocklist / parse_value),
-- not from the local tls_fp_blocklist.conf. The .conf stays the cold-start
-- seed for ACTIVE fps only (init.lua); staged observation is delivered live by
-- Channel C, symmetric with tls_fp_catalog / tls_fp_browser_profiles staging.

local fp_state = require "tls_fp_blocklist_state"

local _M = {
    enabled  = true,
    catalog  = {},   -- { [hash_b] = automation_family } (active entries only)
    profiles = {},   -- { [browser_family] = expected_cipher_cnt } (active only)
    -- Staging counterparts (status=staging), matched-but-never-verdict:
    catalog_staging   = {},   -- { [hash_b] = automation_family }
    profiles_staging  = {},   -- { [browser_family] = expected_cipher_cnt }
    blocklist_staging = {},   -- { [fp] = true }
}

-- Browser families we classify a UA into. Automation tools and anything else
-- collapse to "other" (no profile, never an impersonation victim).
local BROWSER_FAMILIES = {
    chrome = true, firefox = true, safari = true, edge = true,
}

-- Lowercased substrings that mark an automation client UA. Matched with plain
-- (non-pattern) find against ua:lower(), so this stays pure Lua — no ngx.re —
-- and is unit-testable under bare luajit (tests/tls_fp_test.lua).
local AUTOMATION_MARKERS = {
    "curl/", "python-requests", "python-urllib", "urllib", "go-http-client",
    "okhttp", "wget/", "libwww", "java/", "apache-httpclient", "node-fetch",
    "axios/", "scrapy", "aiohttp", "httpx", "guzzle", "postmanruntime",
}

-- pure: classify a UA into a browser family or "other". Order matters because
-- browser UA tokens nest: Edge carries "Chrome" and "Safari"; Chrome carries
-- "Safari". Check the most specific marker first.
--   Edge   : edg/ (desktop), edga/ (android), edgios/ (ios)
--   Chrome : chrome/ (desktop/android), crios/ (ios) — and not Edge
--   Firefox: firefox/, fxios/ (ios)
--   Safari : safari/ + version/ — and not Chrome (genuine Safari has no Chrome)
-- Matched against the lowercased UA (like is_automation_ua), so a spoof that
-- lowercases the tokens still classifies and can't slip past the soft rules.
function _M.classify_ua(ua)
    if type(ua) ~= "string" or ua == "" then return "other" end
    local low = ua:lower()
    local function has(s) return low:find(s, 1, true) ~= nil end

    if has("edg/") or has("edga/") or has("edgios/") then return "edge" end
    if has("chrome/") or has("crios/") then return "chrome" end
    if has("firefox/") or has("fxios/") then return "firefox" end
    if has("safari/") and has("version/") then return "safari" end
    return "other"
end

-- pure: does the UA carry an explicit automation marker? (tls_fp:automation_ua)
function _M.is_automation_ua(ua)
    if type(ua) ~= "string" or ua == "" then return false end
    local low = ua:lower()
    for _, marker in ipairs(AUTOMATION_MARKERS) do
        if low:find(marker, 1, true) then return true end
    end
    return false
end

-- pure: extract hash_b (the sorted-cipher hash) from an fp string. Layout
-- (ja4_compute.lua): "L<prefix>_<hash_b>_<hash_c>". Anchored only on the
-- second underscore-delimited segment, not the whole string, so it keeps
-- working if the fp ever grows trailing segments. Returns nil for a
-- malformed/absent fp so callers fall through without a catalog lookup.
function _M.hash_b(fp)
    if type(fp) ~= "string" then return nil end
    return fp:match("^[^_]+_([^_]+)_")
end

-- pure: cipher_count from the fp prefix "L<ver><sni><cipher_cnt><alpn>_…"
-- (same parse as bac_log.set_tls_fp). Matches only as far as the cipher-count
-- digits so it tolerates changes to the alpn suffix. Returns a number or nil.
function _M.cipher_count(fp)
    if type(fp) ~= "string" then return nil end
    local cc = fp:match("^L%d%d[di](%d%d)")
    return cc and tonumber(cc) or nil
end

-- pure: parse wire-format map { [hash_b] = "<status>:<family>" } (composite
-- string per Channel C contract — symmetric to verified_bot_ips) into two
-- tables: active hash_b → family, staging hash_b → family. Empty family or
-- unknown status is skipped (defense-in-depth — backend validates these,
-- but a partial Channel C payload should never blow up the request path).
-- Used by refresh() to rebuild the per-process lookup tables after a
-- Channel C gen flip; also tested standalone (pure, no ngx deps).
function _M.build_catalog(wire)
    local active, staging = {}, {}
    for hb, raw in pairs(wire or {}) do
        if type(raw) == "string" then
            local status, family = raw:match("^([^:]+):(.+)$")
            if family and family ~= "" then
                if status == "active" then
                    active[hb] = family
                elseif status == "staging" then
                    staging[hb] = family
                end
            end
        end
    end
    return active, staging
end

-- pure: parse wire-format map { [family] = "<status>:<expected_cipher_cnt>" }
-- into two tables: active family → cipher_cnt, staging family → cipher_cnt.
-- A non-numeric or non-positive cipher_cnt is skipped (backend Validate
-- enforces > 0, but parser stays robust to corrupted wire payloads).
function _M.build_profiles(wire)
    local active, staging = {}, {}
    for family, raw in pairs(wire or {}) do
        if type(raw) == "string" then
            local status, cnt = raw:match("^([^:]+):(.+)$")
            local n = tonumber(cnt)
            if n and n > 0 then
                if status == "active" then
                    active[family] = n
                elseif status == "staging" then
                    staging[family] = n
                end
            end
        end
    end
    return active, staging
end

-- pure: build the staging fp set from a Channel C wire map { [fp] =
-- "<status>:block" } (store.buildTLSFPBlocklist). Keeps only status=staging
-- fps as a membership set; active fps are NOT kept here (verdict.lua blocks
-- those directly off the same dict). A legacy bare "block" value (no colon)
-- is treated as active and thus skipped. Symmetric to build_catalog, but the
-- blocklist's verdict is implicit (block), so we keep only membership.
function _M.build_blocklist(wire)
    local staging = {}
    for fp, raw in pairs(wire or {}) do
        if type(raw) == "string" and fp_state.parse_value(raw) == "staging" then
            staging[fp] = true
        end
    end
    return staging
end

-- pure: tls_fp_impersonator decision. Fires when the UA claims a browser
-- family AND the fp's hash_b is a known automation signature in the catalog.
-- An automation/other UA matching its own automation fp is honest, not an
-- impersonation, so a non-browser ua_family never fires.
function _M.is_impersonator(ua_family, hb, catalog)
    if not BROWSER_FAMILIES[ua_family] then return false end
    if not hb then return false end
    return catalog[hb] ~= nil
end

-- pure: tls_fp_suspicious_ciphers decision. Fires when the UA claims a browser
-- family with a known profile AND the observed cipher_count differs from it.
-- Unknown family (no profile) or an unparseable cipher_count never fires.
-- Cold-start fallback для is_suspicious_ciphers / fp_looks_like_browser:
-- маленькая статичная карта семейств → expected_cipher_cnt. До PR2
-- (ADR-006) эти значения жили в infra/demo-stand/config/tls_fp_browser_profiles.conf
-- и парсились в init_by_lua, поэтому каскад работал с первой секунды и
-- продолжал работать даже при недоступном backend. После PR2 каталог
-- приезжает через Channel C, есть ~30 сек cold-start window после рестарта
-- + неограниченный простой при недоступном backend. Fallback закрывает
-- оба сценария.
--
-- ВАЖНО (PR-62 re-review): fallback активен ТОЛЬКО до первого успешного
-- Channel C pull (`profiles_landed()` ниже). После того как gen флипнулся
-- хотя бы один раз (gen >= 1), Channel C — единственный source of truth:
-- если backend намеренно убрал/изменил профиль (chrome ушёл с 15 → 16,
-- или удалили целиком), edge ДОЛЖЕН follow'ить backend, не залипать на
-- старом захардкоженном значении. Без этого условия always-on fallback
-- маскировал бы реальные обновления каталога.
local COLD_START_PROFILES = {
    chrome  = 15,
    firefox = 16,
    safari  = 20,
    edge    = 15,
}

-- profiles_landed — true если хотя бы один успешный Channel C pull
-- доставил tls_fp_browser_profiles в shared_dict (refresh() сдвинул
-- _cached_gen_profiles в число > 0). До этого момента fallback легитимен;
-- после — backend авторитетен даже если прислал пустой каталог.
--
-- Если `_M._cached_gen_profiles` пуст (тесты вызывают is_*-helpers
-- напрямую без refresh) — считаем как cold start (fallback on), чтобы
-- сохранить детерминизм юнит-тестов независимо от ngx-инициализации.
local function profiles_landed()
    local g = _M._cached_gen_profiles
    return type(g) == "number" and g > 0
end

-- is_suspicious_ciphers: returns true if `cc` doesn't match the expected
-- cipher count for `ua_family`. `profiles` — таблица для проверки (active
-- ИЛИ staging). `allow_fallback` (default false) — разрешать ли cold-start
-- fallback к COLD_START_PROFILES, когда дикт пуст и Channel C ещё не
-- landed. PR-62 round-6: fallback применять ТОЛЬКО для active-call (где
-- цель — детекция baseline до первого pull). Для staging-call —
-- запрещено: иначе пустая staging-таблица + не-landed gen эмитят
-- фантомные `staging_match` для каждого браузера с нестандартным
-- cipher_count, отравляя promotion-метрики несуществующими signatures.
function _M.is_suspicious_ciphers(ua_family, cc, profiles, allow_fallback)
    local expected = profiles[ua_family]
    if not expected and allow_fallback and not profiles_landed() then
        expected = COLD_START_PROFILES[ua_family]
    end
    if not expected then return false end
    if not cc then return false end
    return cc ~= expected
end

-- pure: is the fp browser-shaped? Used for the tls_fp:dc_browser cross-layer
-- tag — the L3 half of the signal. We treat "cipher_count matches some browser
-- profile" as browser-shaped: it's a property of the TLS stack (the fp), not
-- of the spoofable UA, which is what "fp выглядит как браузер" means.
function _M.fp_looks_like_browser(cc, profiles)
    if not cc then return false end
    for _, expected in pairs(profiles) do
        if cc == expected then return true end
    end
    -- Fallback ТОЛЬКО на cold start (до первого Channel C pull). После
    -- успешного pull dynamic-table — окончательный источник; пустой dynamic
    -- значит «backend намеренно не профилирует ни одного браузера», ни
    -- одного истинного match быть не должно.
    if not profiles_landed() then
        for _, expected in pairs(COLD_START_PROFILES) do
            if cc == expected then return true end
        end
    end
    return false
end

-- pure: membership test over the (small) tags array.
function _M.has_tag(tags, want)
    for _, t in ipairs(tags or {}) do
        if t == want then return true end
    end
    return false
end

-- Called once in init_by_lua, after config.load(). После PR2 (ADR-006)
-- tls_fp_catalog / tls_fp_browser_profiles больше не INI-файлы на эдже —
-- их Channel C тащит из git-репо catalogs/ через backend (см.
-- catalog_pull.lua descriptors). Здесь только cold-start: ставим пустые
-- lookup-таблицы; первая успешная pull в catalog_pull.fetch заполнит
-- shared_dict, а refresh() в run() построит per-worker Lua-таблицы по
-- этому snapshot'у. blocklist_staging тоже Channel C-based (86exrtjpc):
-- refresh() строит его из tls_fp_blocklist shared_dict; на init таблица пуста,
-- staged fps приедут с первым pull. Локальный tls_fp_blocklist.conf остаётся
-- только cold-start seed для ACTIVE fps (init.lua), staging через него больше
-- не наблюдается.
function _M.build(config)
    _M.catalog          = {}
    _M.profiles         = {}
    _M.catalog_staging  = {}
    _M.profiles_staging = {}
    _M.blocklist_staging = {}

    -- Stage off via the shared kill-switch helper (config-templates.md
    -- kill_switch; defaults.conf [kill_switch.*]). The block path
    -- (tls_fp_blocklist in verdict.lua) is governed separately; this toggle
    -- gates only the soft rules + tags this module owns.
    _M.enabled = require("config").stage_enabled(config.defaults or {}, "tls_fp")

    -- Per-worker gen-cache reset (init_by_lua runs before fork, but a worker
    -- restart re-runs this code on the new master too). nil means "first
    -- refresh in this worker will rebuild from current dict gen".
    _M._cached_gen_catalog   = nil
    _M._cached_gen_profiles  = nil
    _M._cached_gen_blocklist = nil

    -- Staged-таблицы пусты на init (pull ещё не запускался); их счётчики
    -- видны в /metrics и в bac_log staging_match после первого тика
    -- catalog_pull (≤ 30 сек). build() ничего не возвращает кроме модуля —
    -- init.lua вызывает его только ради side-effects.
    return _M
end

-- refresh — читает текущий gen из meta:get(gen_key) и, если он отличается
-- от закешированного для этого worker'а, пересобирает Lua-таблицы
-- _M.catalog / _M.catalog_staging (и аналогично profiles) из shared_dict.
-- Дешево в steady state: один meta:get на катаолог + сравнение чисел.
-- Rebuild — только когда Channel C доставил новый snapshot (≈ раз в 30с).
-- Вызывается в начале run(), чтобы каскад работал на актуальном catalog'е
-- без явного pub/sub между catalog_pull и tls_fp.
--
-- Вариант с per-request dict:get_keys(0) был отвергнут: для tls_fp_catalog
-- размер маленький (десятки), но dict:get_keys лочит shared_dict на время
-- скана, что добавляет latency-вариативности per-request. Per-gen rebuild
-- амортизирует это до одного lock'а на pull.
--
-- Performance trade-off (PR-62 gemini high): `dict:get_keys(0)` лочит весь
-- shared_dict на время скана. Для tls_fp_catalog (<100 записей) и
-- tls_fp_browser_profiles (≈5 записей) лок измеряется микросекундами —
-- допустимо. Если каталог вырастет за ~10K записей, нужно завести
-- side-index «keys-of-gen-N» в `meta` shared_dict и итерировать по нему
-- (тот же план оставлен открытым для fp_blocklist / verified_bot_ips,
-- см. комментарий в catalog_pull.lua sweep).
local function rebuild_from_dict(dict_name, cur_gen, builder)
    local dict = ngx.shared[dict_name]
    if not dict then return {}, {} end
    local suffix = ":" .. cur_gen
    local wire   = {}
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-#suffix) == suffix then
            local base = k:sub(1, -#suffix - 1)
            local val  = dict:get(k)
            if val then wire[base] = val end
        end
    end
    return builder(wire)
end

-- reconcile_staging_metrics — на каждом gen flip Channel C-каталога:
--   1) Сидирует counter `staging:<catalog>:<pattern_id>` со значением 0 в
--      metrics shared_dict для всех entries новой staging-таблицы. Это
--      даёт promotion-дашбордам видеть «staged signature объявлена, ноль
--      матчей» вместо «metric absent» (отличает «PR landed, traffic не
--      было» от «PR не доехал»).
--   2) Удаляет counter ключи для entries, которые БЫЛИ в предыдущей
--      staging-таблице, но исчезли из новой (promoted-to-active или
--      удалены). Без этого stale counter живёт в metrics dict до LRU
--      eviction, и дашборд показывает фантомную «staged, zero traffic»
--      запись для signature, которую продакт уже promoted (PR-62 round 6).
--
-- При unsupported metrics dict (нет declaration в nginx.conf) — silent
-- noop. При ошибке записи (no_memory под shm pressure) — лог WARN: фикс
-- silent-failure от round-5 (safe_add возвращает nil без exception, не
-- делает LRU evict — counter просто не появится, дашборд увидит «metric
-- absent» вопреки контракту).
local function reconcile_staging_metrics(catalog_name, prev_staging, new_staging)
    local m = ngx.shared.metrics
    if not m then return end
    local prefix = "staging:" .. catalog_name .. ":"

    -- Add zero counter для новых entries. Под shm pressure safe_add может
    -- вернуть (nil, "no memory") для каждого entry. Hybrid log policy
    -- (PR-62 round-8): первые VERBOSE_LIMIT failures логируем с pattern_id
    -- (важно для дебага non-OOM ошибок типа «key too long», unique
    -- collision); остальные агрегируем в один WARN. Сохраняем читаемость
    -- лога под high-volume failures и attribution под low-volume.
    local VERBOSE_LIMIT = 3
    local fail_count, last_err = 0, nil
    for pattern_id in pairs(new_staging) do
        local ok, err = m:safe_add(prefix .. pattern_id, 0)
        if not ok and err ~= "exists" then
            fail_count = fail_count + 1
            last_err = err
            if fail_count <= VERBOSE_LIMIT then
                ngx.log(ngx.WARN, "tls_fp: ", catalog_name,
                    " staging-counter add failed (pattern=", pattern_id,
                    "): ", tostring(err))
            end
        end
    end
    if fail_count > VERBOSE_LIMIT then
        ngx.log(ngx.WARN, "tls_fp: ", catalog_name,
            " staging-counter priming: ", fail_count - VERBOSE_LIMIT,
            " additional failures elided (last err: ", tostring(last_err), ")")
    end

    -- Delete counter для entries, которых больше нет в new (promoted-to-active
    -- или удалены). Но ТОЛЬКО если value == 0 — иначе мы стираем
    -- accumulated match count (история staging→active промоута, нужна
    -- promotion-дашборду). PR-62 round-7 trade-off: phantom entries (всегда 0)
    -- чистим; entries с реальной историей оставляем «zombie» — operator
    -- может вычистить вручную, но мы не теряем данные.
    if prev_staging then
        for pattern_id in pairs(prev_staging) do
            if not new_staging[pattern_id] then
                local key = prefix .. pattern_id
                if (m:get(key) or 0) == 0 then
                    m:delete(key)
                end
            end
        end
    end
end

function _M.refresh()
    if not ngx or not ngx.shared then return end
    local meta = ngx.shared.meta
    if not meta then return end

    local cat_gen = meta:get("tls_fp_catalog_gen") or 0
    if cat_gen ~= _M._cached_gen_catalog then
        local active, staging = rebuild_from_dict(
            "tls_fp_catalog", cat_gen, _M.build_catalog)
        -- PR-62 round-8: swap до reconcile, чтобы log_event.incr из
        -- параллельного запроса не race'нул с reconcile.delete-if-zero
        -- (после swap run() уже не видит promoted/removed pattern в
        -- staging-таблице → не вызывает incr → delete безопасен).
        -- `prev_staging` всё ещё доступен через локальную ссылку на
        -- ранее присвоенную table (Lua table-by-reference).
        local prev_staging = _M.catalog_staging
        _M.catalog          = active
        _M.catalog_staging  = staging
        _M._cached_gen_catalog = cat_gen
        reconcile_staging_metrics("tls_fp_catalog", prev_staging, staging)
    end

    local prof_gen = meta:get("tls_fp_browser_profiles_gen") or 0
    if prof_gen ~= _M._cached_gen_profiles then
        local active, staging = rebuild_from_dict(
            "tls_fp_browser_profiles", prof_gen, _M.build_profiles)
        local prev_staging = _M.profiles_staging
        _M.profiles          = active
        _M.profiles_staging  = staging
        _M._cached_gen_profiles = prof_gen
        reconcile_staging_metrics("tls_fp_browser_profiles", prev_staging, staging)
    end

    -- tls_fp_blocklist (86exrtjpc): staged fps arrive over Channel C in the
    -- tls_fp_blocklist shared_dict as "staging:block". verdict.lua blocks the
    -- ACTIVE ones directly off this dict; here we rebuild only the staging
    -- membership set so run() can record staging_match for them. Same gen-cached
    -- rebuild + metric reconcile as the two catalogs above. The gen key is the
    -- blocklist's own (fp_state.META_GEN_KEY), bumped by catalog_pull's
    -- tls_fp_blocklist descriptor.
    local bl_gen = meta:get(fp_state.META_GEN_KEY) or 0
    if bl_gen ~= _M._cached_gen_blocklist then
        local staging = rebuild_from_dict("tls_fp_blocklist", bl_gen, _M.build_blocklist)
        local prev_staging = _M.blocklist_staging
        _M.blocklist_staging     = staging
        _M._cached_gen_blocklist = bl_gen
        reconcile_staging_metrics("tls_fp_blocklist", prev_staging, staging)
    end
end

-- Record a soft challenge flag. The flag is always accumulated (vision.md:
-- flags = every soft signal seen along the path). C4: терминальный verdict
-- больше НЕ выставляется здесь — soft-сигналы только КОПЯТСЯ, а решение
-- «выдавать challenge» принимает L5 (verification.lua) с учётом
-- per-resource Strictness и attack_mode. До C4 эта функция писала
-- verdict=challenge напрямую, что нарушало rules-reference §"L3/L4 флаги
-- ... сами на L3/L4 challenge не выдают — они только помечают запрос;
-- единственная точка, где принимается решение — этот вызов на L5".
local function fire_soft(bac_log, rule)
    bac_log.add_flag(rule)
end

-- Called per request from verdict.lua, after the tls_fp_blocklist check (a
-- blocklisted fp has already ngx.exit'd, so we only see non-blocked fps).
-- `fp` is the computed fingerprint string. Observe-only: never blocks, never
-- short-circuits.
function _M.run(fp)
    if not _M.enabled then return end

    -- Pull-in latest Channel C snapshot for tls_fp_catalog / tls_fp_browser_profiles.
    -- Cheap in steady state (one meta:get per gen-key, compare to cached
    -- worker-local int); rebuilds Lua tables only when gen flips (≈ pull
    -- interval, 30s по умолчанию).
    _M.refresh()

    local bac_log = package.loaded["bac_log"] or require "bac_log"
    local ctx = ngx.ctx.bac
    if not ctx then return end

    local ua        = ngx.var.http_user_agent or ""
    local ua_family = _M.classify_ua(ua)
    local cc        = ctx.tls_cipher_count or _M.cipher_count(fp)

    -- Informational tags first — evaluated unconditionally so they are
    -- recorded regardless of any rule (tags accumulate independent of verdict).
    if _M.is_automation_ua(ua) then
        bac_log.add_tag("tls_fp:automation_ua")
    end
    -- no_sni: bac_log.set_tls_fp parsed tls_sni_present from the fp prefix.
    -- Only a parsed false (SNI absent) flags; nil (malformed fp) does not.
    if ctx.tls_sni_present == false then
        bac_log.add_tag("tls_fp:no_sni")
    end
    -- dc_browser: browser-shaped fp (L3) + datacenter ASN (L2). reputation.lua
    -- ran earlier in the cascade and added reputation:asn_dc when the IP's ASN
    -- is in asn_datacenters.conf. Check the cheap asn_dc tag FIRST so the
    -- (rare) DC case is the only one that pays for the profile scan.
    if _M.has_tag(ctx.tags, "reputation:asn_dc")
       and _M.fp_looks_like_browser(cc, _M.profiles) then
        bac_log.add_tag("tls_fp:dc_browser")
    end

    -- Soft rules. Both may fire; both flags accumulate (flags = all soft
    -- signals). impersonator is evaluated first, so suspicious_ciphers wins the
    -- terminal `rule` when both fire — `rule` is the last/terminal rule, the
    -- full set lives in `flags`.
    -- Only parse hash_b for a browser-family UA — is_impersonator rejects
    -- non-browser UAs anyway, so the common case skips the string.match.
    local hb = BROWSER_FAMILIES[ua_family] and _M.hash_b(fp) or nil
    if _M.is_impersonator(ua_family, hb, _M.catalog) then
        fire_soft(bac_log, "tls_fp_impersonator")
    end
    if _M.is_suspicious_ciphers(ua_family, cc, _M.profiles, true) then
        fire_soft(bac_log, "tls_fp_suspicious_ciphers")
    end

    -- Staged patterns (A11). A staged entry is matched with the SAME predicate
    -- its active counterpart uses, so the recorded count reflects what would
    -- fire after promotion — but it only writes to staging_match, never to
    -- verdict/rule/flags. Gated by _M.enabled (above) like the rest of the
    -- stage, so the tls_fp kill-switch silences staging observation too.
    if _M.is_impersonator(ua_family, hb, _M.catalog_staging) then
        bac_log.add_staging_match("tls_fp_catalog:" .. hb)
    end
    if _M.is_suspicious_ciphers(ua_family, cc, _M.profiles_staging, false) then
        bac_log.add_staging_match("tls_fp_browser_profiles:" .. ua_family)
    end
    if type(fp) == "string" and _M.blocklist_staging[fp] then
        bac_log.add_staging_match("tls_fp_blocklist:" .. fp)
    end
end

return _M
