-- Demo-stand init (init_by_lua). Loads the cascade config files, seeds the
-- tls_fp_blocklist shared_dict from tls_fp_blocklist.conf, primes the metrics
-- shared_dict with zero-valued counter keys (so /metrics shows them from the
-- very first scrape), and records the start time for /__version uptime.
--
-- The tls_fp_blocklist dict is the one config the request path consumes today
-- (verdict.lua). The other catalogs (ip/ua/asn lists, tls_fp catalog/
-- profiles, defaults) are parsed and held on the `config` module for the
-- cascade-rule tasks that will read them — they are not wired into a
-- verdict here (rules are out of scope for the A3 config-files task).

local config = require "config"
config.load()

-- Compile the L1 hygiene stage (method whitelist + ua_blacklist combined
-- regex) from the loaded config. Done here in the master so every worker
-- inherits the compiled state on fork — see hygiene.lua.
require("hygiene").build(config)

-- Compile the L2 reputation stage (ip_whitelist / ip_blocklist CIDR matchers)
-- from the loaded config — also in the master so workers inherit the matchers
-- on fork (see reputation.lua). Returns the active entry counts for the
-- startup log below.
local reputation, rep_wl, rep_bl = require("reputation").build(config)

-- Compile the L2.2 verified-bot fastpath (B8: bot_verified /
-- bot_verified_pending). build() reads the searchbot UA alternation from
-- defaults.conf [allow.bot_verified].ua_pattern and stashes the split list;
-- the verified_bots shared_dict is filled by catalog_pull (Channel C
-- `verified_bot_ips`) and is empty on a stand without backend, so all
-- searchbot-UA requests resolve to provisional fastpath until the rDNS
-- worker (B7) publishes a status. Returns the active UA-alt count.
local _, vb_alts_n = require("verified_bots").build(config)

-- Compile the L4 rate_limits stage (GCRA profiles from defaults.conf
-- [blocking.rate_*] thresholds) — also in the master so workers inherit the
-- profile list on fork (see rate_limit.lua; the shared dict holds only per-key
-- TAT state). Returns the active profile count for the startup log.
local _, rate_n = require("rate_limit").build(config)

-- Compile the L3 tls_fp soft-rule stage. После PR2 (ADR-006)
-- tls_fp_catalog / tls_fp_browser_profiles приезжают через Channel C, так
-- что build() заводит только cold-start state + kill-switch flag; staging
-- counts для них всегда 0 на init (заполнятся после первого pull). Только
-- tls_fp_blocklist staging остаётся file-based — его counter `tls_stg_bl_n`
-- идёт в startup-log и в metrics:safe_add ниже.
local tls_fp, _, _, _, _, tls_stg_bl_n = require("tls_fp").build(config)

-- Open the GeoLite2 databases (country + asn) once in the master so workers
-- inherit the handles on fork. Fail-open: if the license-gated .mmdb files (or
-- libmaxminddb) are absent the stand still starts and geo is simply
-- undetermined — geoip.init() logs the reason. Feeds the reputation:asn_dc tag
-- and the geo_country/asn log fields (A6).
require("geoip").init()

-- [B6] Channel C mTLS client cert — parse in the master (pre-privilege-drop)
-- so 0600 root-owned PEMs are readable. Workers inherit the parsed cdata on
-- fork, so catalog_pull.fetch() in init_worker_by_lua never re-opens the file
-- (codex review: workers run as nobody and can't read 0600 root keys).
-- Both paths must be set + parse cleanly; otherwise mTLS stays disabled and
-- catalog_pull falls into the existing fail-stale path.
require("catalog_pull").preload_mtls(
    os.getenv("ANTIBOT_BACKEND_CLIENT_CERT"),
    os.getenv("ANTIBOT_BACKEND_CLIENT_KEY"))

-- [C1] Phase 4 HMAC secret для clearance cookie (vision §«HMAC secret для
-- clearance cookie», §Channel A). Доставка на демо-стенде = file/mount
-- (./certs bind-mount), ротация = `openresty -s reload`. C3/C5 ещё не
-- реализованы — load() выполняется здесь, чтобы когда они появятся, secret
-- уже лежал в shared_dict; до тех пор отсутствие файла — WARN, не fatal
-- (Phase 1-3 запросы продолжают работать).
require("challenge_secret").load(
    os.getenv("CHALLENGE_HMAC_SECRET_FILE")
        or "/etc/nginx/certs/challenge_secret.key")

-- [C2] Phase 4 challenge page asset (HTML+JS-шаблон, vision §5.2 «Ветка A»).
-- Доставка на демо = file/mount (Channel A на демо), путь
-- /etc/nginx/challenge/page.html. preload() читает шаблон + CASCADE_VERSION
-- один раз и сверяет meta-тег шаблона с содержимым файла версии — mismatch
-- валит init_by_lua, контейнер не стартует. Это и есть version-pin
-- инвариант: каскад и шаблон могут разъехаться только осознанным
-- одновременным bump'ом обоих. Сама выдача страницы (привязка к
-- verdict=challenge) — в C5; здесь только preload + проверка.
local cascade_version = require("challenge").preload()

-- Seed the tls_fp_blocklist shared_dict from tls_fp_blocklist.conf. Entries are
-- active unless explicitly status=staging — staged fps match-but-don't-block
-- and are held in tls_fp.blocklist_staging (recorded into staging_match by the
-- tls_fp stage, A11), never seeded here. An empty file => SHADOW mode.
--
-- Keys are written under generation 0 (`fp .. ":" .. 0`, §В1 format) and
-- tls_fp_blocklist_gen is published as 0 so verdict.lua's §A1 read resolves them.
-- The static seed IS generation 0; when the Channel C catalog pull lands
-- (task 86exmk08u) it bumps to gen 1+ and atomically swaps the set.
--
-- PR-62 audit round-6: reload-survive. `meta` и `tls_fp_blocklist` shared_dict
-- выживают `nginx -s reload`. Если в прошлой жизни Channel C доставил gen=N
-- с расширенным набором fp (например 50 vs 10 в локальном .conf), force-reset
-- gen=0 + re-seed под `:0` СКРЫВАЕТ те 40 extra fps до следующего payload
-- change на backend (304 на первом pull → gen остаётся 0). Поэтому: seed
-- (как cold-start fallback) делаем ТОЛЬКО когда gen-key отсутствует в meta
-- (полностью fresh start). Если key уже есть — Channel C state выжил, data
-- shared_dict тоже выжил, читатели verdict.lua найдут `:N` записи как раньше.
local fp_state    = require "tls_fp_blocklist_state"
local catalog_pull = require "catalog_pull"
local fp_dict = ngx.shared.tls_fp_blocklist
local meta    = ngx.shared.meta

-- seed_blocklist_cold — пишет локальный fallback под `:0`. Используется
-- на cold-start пути (key только что создан через meta:add). На этом
-- пути data dict гарантированно пуст или содержит только ghost-keys от
-- предыдущей worker-генерации, которые верно reader'ятся (gen=0); очищать
-- ghosts не нужно — мы их сейчас перепишем под тем же `:0` suffix.
local function seed_blocklist_cold()
    local seeded = 0
    for _, entry in ipairs(config.tls_fp_blocklist) do
        if entry.attrs.status ~= "staging" then
            local ok, err = fp_dict:set(fp_state.key(entry.value, 0), "block")
            if ok then
                seeded = seeded + 1
            else
                ngx.log(ngx.ERR, "tls_fp_blocklist:set failed: ", err)
            end
        end
    end
    return seeded
end

-- seed_blocklist_after_meta_failure — пишет fallback под `:0` + очищает
-- ghost-keys предыдущей генерации перед записью. Используется ТОЛЬКО на
-- meta:add ERR-пути (no_memory), когда мы force-set'нули gen=0 поверх
-- неизвестного предыдущего значения N. data dict может содержать `:N`
-- ключи, которые никто больше не читает (мы только что сбросили gen),
-- но занимают slots — clear освобождает. Безопасность: fp_dict —
-- exclusive writer-zone для blocklist (init + catalog_pull, оба нашего
-- авторства); если будущий PR добавит admin-override или co-tenant
-- writer, эта функция wipe'нет их keys тоже — переключи на typed
-- filter `fp_state.match(k, anything)` ИЛИ запрети сторонних writers
-- комментом в tls_fp_blocklist_state.lua.
local function seed_blocklist_after_meta_failure()
    for _, k in ipairs(fp_dict:get_keys(0)) do
        fp_dict:delete(k)
    end
    return seed_blocklist_cold()
end

-- meta_add_gen — общий helper: meta:add(gen_key, 0) + распознание err.
-- Возвращает (status, cur_gen_for_logging) где status ∈ {"cold_start",
-- "reload", "err"}. "err" — meta:add fail с не-"exists" (no_memory). На
-- "err" вызывает meta:set(gen_key, 0) — best-effort. verdict.lua и
-- friends везде защищены `meta:get(...) or 0`, так что даже если set
-- тоже fail'нет — readers увидят gen=0 через nil-default.
-- PR-62 round-9 audit: вынесено из tls_fp_blocklist в общий helper, чтобы
-- три sibling catalogs (verified_bots / tls_fp_catalog / tls_fp_browser_profiles)
-- получили те же diagnostics+force-set fallback вместо silent SHADOW.
local function meta_add_gen(gen_key)
    local was_added, add_err = meta:add(gen_key, 0)
    if was_added then return "cold_start" end
    if add_err == "exists" then return "reload" end
    ngx.log(ngx.ERR, "[demo] meta:add ", gen_key, " failed (",
        tostring(add_err), ") — forcing gen=0; readers fall back via `or 0`")
    meta:set(gen_key, 0)
    return "err"
end

local blocklist_status = meta_add_gen(fp_state.META_GEN_KEY)
local n = 0
if blocklist_status == "cold_start" then
    -- Свежий старт: data dict не содержит ничего нашего, seed напрямую.
    n = seed_blocklist_cold()
elseif blocklist_status == "err" then
    -- meta-add failed: force-set'нули gen=0 но не знаем предыдущего gen.
    -- Чистим ghost'ы перед re-seed.
    n = seed_blocklist_after_meta_failure()
else
    -- Reload-survive: meta:add no-op потому что key exists. Не трогаем data
    -- shared_dict — Channel C `:N` entries уже там, verdict.lua найдёт их по
    -- meta:get(gen)=N. Считаем выжившие entries под current gen для
    -- blocklist_entries gauge + ACTIVE/SHADOW лог (analyze.py парсит
    -- «tls_fp_blocklist loaded: N»). Используем typed fp_state.match() вместо
    -- bare suffix-string — симметрично catalog_pull.sweep (PR-55 review #5
    -- guard от sharing dict с другим writer'ом).
    local cur_gen = meta:get(fp_state.META_GEN_KEY) or 0
    for _, k in ipairs(fp_dict:get_keys(0)) do
        if fp_state.match(k, cur_gen) then
            n = n + 1
        end
    end
    -- Detect divergence: meta:gen=N>0 + data dict empty. PR-62 round-8 audit:
    -- ИНТЕНЦИОНАЛЬНО empty backend catalog и data-dict-wiped operator действие
    -- неотличимы из init.lua. Если бы мы re-seedили локально — overрode'нули бы
    -- product intent для legitimate empty case. Решение: только drop etag
    -- (заставить next pull сделать полный 200 GET) + WARN. catalog_pull
    -- следующего тика принесёт actual backend state: если empty — будет empty;
    -- если был resize/wipe — backend re-доставит entries. Окно «между reload
    -- и next pull» (≤30 сек) — каталог пуст; для тех редких ситуаций,
    -- когда backend ALSO down — operator увидит WARN и решит вручную.
    if cur_gen > 0 and n == 0 then
        ngx.log(ngx.WARN, "[demo] tls_fp_blocklist: meta says gen=", cur_gen,
            " but data dict has no matching entries — possibly zone wipe or ",
            "intentionally-empty Channel C payload. Dropping etag to force next ",
            "pull to verify; NOT re-seeding (preserves product intent if empty ",
            "was deliberate). Recover via catalog_pull within ≤30s if backend ",
            "reachable; see infra/demo-stand/README.md «Divergence WARN triage».")
        meta:delete(fp_state.META_ETAG_KEY)
    else
        ngx.log(ngx.NOTICE, "[demo] tls_fp_blocklist: reload detected, preserving Channel C state (gen=", cur_gen, ", entries=", n, ")")
    end
end

-- verified_bots / tls_fp_catalog / tls_fp_browser_profiles — no static
-- seed (catalogs приезжают через Channel C). Изначально (cold start)
-- gen-keys отсутствуют в `meta`; meta shared_dict выживает `nginx -s
-- reload` (zone сохраняется при неизменном name+size), поэтому используем
-- `meta:add(key, 0)` — присвоение ТОЛЬКО если ключ не существует.
--
-- check_data_dict_divergence — те же detection-семантики, что выше для
-- tls_fp_blocklist (round-8 audit, B1): meta:gen=N + data dict empty значит
-- либо operator resize zone, либо backend опубликовал empty. Drop etag,
-- WARN. Без re-seed (для этих трёх каталогов нет файлового fallback'а —
-- catalog'и приходят только через Channel C, и intentional-empty
-- неразличим от divergence).
--
-- Принимает catalog-descriptor из catalog_pull.lua (single source of truth
-- для dict_name/gen_key/etag_key — устраняет sync-drift trap, который
-- round-8 fix #5 закрыл для blocklist; round-9 audit B-R8-2: тот же
-- trap не должен reintroduce'иться для siblings). dict missing → ERR
-- log + return (вместо silent — чтобы typo в catalog name ловилась).
local function check_data_dict_divergence(cat)
    local dict = ngx.shared[cat.dict_name]
    if not dict then
        ngx.log(ngx.ERR, "[demo] check_data_dict_divergence: shared_dict ",
            cat.dict_name, " not declared (catalog ", cat.name,
            ") — declare in nginx.conf or remove from divergence check list")
        return
    end
    local cur_gen = meta:get(cat.gen_key)
    if not cur_gen or cur_gen <= 0 then return end
    -- Bare suffix-match: writer везде кладёт `<key>:<gen>` с gen как
    -- ПОСЛЕДНИЙ `:`-segment (catalog_pull.lua apply: `key .. ":" .. new_gen`).
    -- Ghost от старой gen=M (M≠N) ends `:M` — НЕ match `:N`. IPv6 ключи
    -- (verified_bots) проверены: gen всегда последний segment, false-positive
    -- невозможен пока writer-side контракт держится. Если когда-то поменяется
    -- на content-hash gen — добавить typed match per-catalog.
    local suffix = ":" .. cur_gen
    for _, k in ipairs(dict:get_keys(0)) do
        if k:sub(-#suffix) == suffix then return end
    end
    -- Reached: cur_gen > 0 + no matching entry → divergence.
    ngx.log(ngx.WARN, "[demo] ", cat.name, ": meta says gen=", cur_gen,
        " but data dict has no matching entries — possibly zone wipe or ",
        "intentionally-empty Channel C payload. Dropping etag to force next ",
        "pull to verify (recover ≤30s if backend reachable); see ",
        "infra/demo-stand/README.md «Divergence WARN triage».")
    meta:delete(cat.etag_key)
end

-- gen=0 seeding + divergence detection для трёх Channel-C-only каталогов.
-- meta_add_gen использует общий ERR-handling (fix B-R8-1: no_memory не
-- маскируется под reload, force-set + log). catalog descriptors берутся
-- из catalog_pull.catalogs — single source of truth для dict/gen/etag
-- имён (fix B-R8-2: literals не дублируются между init.lua и descriptors).
for _, cat_name in ipairs({"verified_bot_ips", "tls_fp_catalog", "tls_fp_browser_profiles", "policy"}) do
    local cat = catalog_pull.catalogs[cat_name]
    if not cat then
        ngx.log(ngx.ERR, "[demo] catalog_pull.catalogs[", cat_name,
            "] missing — divergence detection skipped")
    else
        meta_add_gen(cat.gen_key)
        check_data_dict_divergence(cat)
    end
end

-- One line per catalog so a reviewer can confirm at start that every config
-- loaded (acceptance: "Lua успешно подгружает все конфиги").
ngx.log(ngx.NOTICE, "[demo] configs loaded from ", config.dir, ": ",
    "tls_fp_blocklist=", #config.tls_fp_blocklist,
    " ip_blocklist=", #config.blocklist_ip,
    " ip_whitelist=", #config.whitelist_ip,
    " ua_blacklist=", #config.ua_blacklist,
    " asn_datacenters=", #config.asn_datacenters)
-- Marker text is a contract: scripts/analyze.py INIT_RE parses the
-- blocklist size out of "[demo] tls_fp_blocklist loaded: N". Do not reword
-- without updating that regex, or daily reports mislabel the stand SHADOW.
ngx.log(ngx.NOTICE, "[demo] tls_fp_blocklist loaded: ", n, " active entries")
-- Reputation matchers: active (non-staging) entry counts compiled into the
-- ipmatcher objects. Empty whitelist/blocklist => that check is a no-op.
local asn_dc_n = 0
for _ in pairs(reputation.asn_dc_set) do asn_dc_n = asn_dc_n + 1 end
ngx.log(ngx.NOTICE, "[demo] reputation matchers: ip_whitelist=", rep_wl,
    " active, ip_blocklist=", rep_bl, " active, asn_dc=", asn_dc_n,
    " (geo_blocklist dormant — per-resource policy source is Phase 3)")
ngx.log(ngx.NOTICE, "[demo] verified-bot fastpath: ua_alts=", vb_alts_n,
    " (verified_bots dict empty until Channel C `verified_bot_ips`",
    " catalog pull lands — searchbot UAs get bot_verified_pending)")
-- Loud signal when the rule is enabled but its UA list is empty: looks_like_bot
-- would return false for every UA, so bot_verified / bot_verified_pending
-- never emits and every searchbot IP silently falls through to ip_blocklist.
-- A common cause is an accidental edit to [allow.bot_verified].ua_pattern in
-- defaults.conf (review #6 on PR #55).
if (require "verified_bots").enabled and vb_alts_n == 0 then
    ngx.log(ngx.WARN, "[demo] verified-bot fastpath: rule is ENABLED but",
        " ua_alts is EMPTY — check [allow.bot_verified].ua_pattern in",
        " defaults.conf; the fastpath will NEVER fire")
end
ngx.log(ngx.NOTICE, "[demo] rate_limits profiles: ", rate_n,
    " active (observe-only — verdict logged, no 429/delay in Phase 1)")
-- PR2 (ADR-006): tls_fp_catalog / tls_fp_browser_profiles переехали с
-- локальных INI на Channel C, на init их ещё нет (pull тикает после
-- init_worker_by_lua). Внешний monitoring следит за метриками
-- `antibot_tls_fp_catalog_gen` / `antibot_tls_fp_browser_profiles_gen`
-- (metrics.lua), а не за init-логом — никакой post-pull лог-маркер
-- здесь не печатается специально, чтобы дашборды не путали «нулевая
-- gen на старте» с «catalog не landed». Для tls_fp_blocklist staging
-- (всё ещё file-based) сохраняем традиционную stand-line.
ngx.log(ngx.NOTICE, "[demo] tls_fp blocklist staged: ", tls_stg_bl_n,
    " (file-based; tls_fp_catalog / browser_profiles см. /metrics ",
    "*_gen после первого Channel C pull)")
ngx.log(ngx.NOTICE, "[demo] challenge page template loaded, cascade_version=",
    cascade_version, " (C2 — preload only; serving wires up in C5)")

-- Prime metrics counters so they're visible at zero rather than absent.
local metrics = ngx.shared.metrics
for _, key in ipairs({
    "requests_total",
    "verdict_pass_total",
    "verdict_block_total",
    "verdict_challenge_total",
    "verdict_allow_total",
    "cache_hit_total",
    "cache_miss_total",
    "fp_unique",
    -- Known soft flags + informational tags, primed so /metrics shows them at
    -- zero from the first scrape (stable schema) instead of only after the
    -- first match. log_event.lua increments these per request; metrics.lua
    -- discovers them from the dict. New flag/tag codes still appear lazily.
    "flag:tls_fp_impersonator",
    "flag:tls_fp_suspicious_ciphers",
    "tag:tls_fp:automation_ua",
    "tag:tls_fp:no_sni",
    "tag:tls_fp:dc_browser",
    "tag:reputation:asn_dc",
    "tag:hygiene:header_anomaly",
    -- BAC_LOG shipper (log_shipper.lua, B6 edge-side): счётчики живут
    -- здесь, чтобы /metrics показывал их at-zero с первого scrape'a,
    -- а не лениво после первой строки. enqueued — сколько прилетело в
    -- очередь от bac_log.emit; dropped — overflow / shipper выключен;
    -- shipped — сколько успешных строк уехало на backend; failed —
    -- провальные POST'ы (батч теряется); batches_ok — счётчик удачных
    -- POST'ов (помогает отличить «1 батч × 1000 строк» от «1000 батчей
    -- × 1 строка» при анализе пропускной способности).
    "bac_log_enqueued_total",
    "bac_log_dropped_overflow_total",
    "bac_log_dropped_disabled_total",
    "bac_log_shipped_total",
    "bac_log_ship_failed_total",
    "bac_log_batches_ok_total",
    -- Gauge 0/1: 0 если log_shipper.lua не загрузился (syntax broken,
    -- missing dep, init_worker ERR'нул и не дошёл до start()); 1 после
    -- успешного start(). Дашборд алертит на `bac_log_shipper_loaded == 0`
    -- — иначе silent-failure при regression в log_shipper.lua.
    "bac_log_shipper_loaded",
    -- [C3/C7] L2.1 clearance cookie verify. Outcomes from clearance.verify
    -- (metric labels match clearance.RESULT_*; metrics.lua emits the labelled
    -- antibot_clearance_verify_total counter). Primed so /metrics shows them
    -- at zero from the first scrape — dashboards distinguish «no fastpath
    -- traffic yet» from «metric missing» without staring at NaN.
    "clearance_verify_valid_total",
    "clearance_verify_invalid_total",
    "clearance_verify_expired_total",
    "clearance_verify_missing_total",
    "clearance_verify_malformed_total",
    "clearance_verify_wrong_site_total",
    "clearance_verify_no_secret_total",
    -- [C7] attack_mode=on + cookie выписан до начала атаки (длинный TTL) →
    -- не фастпасит, идёт на L5 challenge.
    "clearance_verify_stale_pre_attack_total",
    -- [C5] Phase 4 L5.2 challenge issuance + verify endpoint.
    -- challenge_issued_total — render of Branch A challenge page;
    -- challenge_solved_total — successful POST /__challenge/verify (cookie
    -- issued); challenge_invalid_<reason>_total — fail reasons (bad_nonce,
    -- expired, replay, bad_token, wrong_version, bad_body, bad_method,
    -- no_secret); challenge_branch_b_total / challenge_branch_c_total —
    -- Branch B/C dispatches at L5 dispatch (non_browser_blocked /
    -- unchallengeable_request). Primed at zero so /metrics shows the
    -- shape from the first scrape; dashboards distinguish «no challenge
    -- traffic» from «metric missing».
    "challenge_issued_total",
    "challenge_solved_total",
    "challenge_invalid_bad_nonce_total",
    "challenge_invalid_expired_total",
    "challenge_invalid_replay_total",
    "challenge_invalid_bad_token_total",
    "challenge_invalid_wrong_version_total",
    "challenge_invalid_bad_body_total",
    "challenge_invalid_bad_method_total",
    "challenge_invalid_no_secret_total",
    "challenge_branch_b_total",
    "challenge_branch_c_total",
}) do
    metrics:safe_add(key, 0)
end

-- Prime a staging_match counter per staged pattern so /metrics shows it at zero
-- from the first scrape — the promotion workflow watches these to decide
-- staging→active. Key shape "staging:<catalog>:<pattern_id>" (log_event.lua
-- increments, metrics.lua parses). Pattern_ids are dynamic (depend on which
-- patterns are staged), so unlike the fixed flag/tag list above they are
-- primed from the compiled staging tables rather than hard-coded.
--
-- PR-62 round-6: для двух Channel C-каталогов (tls_fp_catalog,
-- tls_fp_browser_profiles) на init соответствующие staging-таблицы пусты —
-- данные приедут только после первого pull. Priming для них делает
-- `reconcile_staging_metrics` в tls_fp.refresh() на каждом gen flip
-- (одновременно с удалением stale counters). Здесь оставляем только
-- file-based tls_fp_blocklist staging (его данные есть на init из
-- локального conf-файла).
for fp_tok in pairs(tls_fp.blocklist_staging) do
    metrics:safe_add("staging:tls_fp_blocklist:" .. fp_tok, 0)
end
-- Удалены no-op loops для tls_fp.catalog_staging / profiles_staging (после
-- PR2 они всегда пустые на init; priming живёт в tls_fp.refresh()).

metrics:set("start_time", ngx.time())
metrics:set("blocklist_entries", n)

if n == 0 then
    ngx.log(ngx.NOTICE, "[demo] mode: SHADOW (empty fp blocklist — nothing blocked)")
else
    ngx.log(ngx.NOTICE, "[demo] mode: ACTIVE blocking on ", n, " fp(s) (ngx.exit(403) on block)")
end

-- On-demand TLS for tenant custom domains (lua-resty-auto-ssl, 86exrefdz
-- follow-up). pcall-guarded: a missing module or init error must NEVER brick
-- nginx start — ssl_certificate() then no-ops and the static fallback cert is
-- served (current behaviour). Logs loud so a broken setup is visible.
local autossl_ok, autossl_err = pcall(function()
    require("tls_autossl").setup()
end)
if autossl_ok then
    ngx.log(ngx.NOTICE, "[demo] on-demand TLS: lua-resty-acme active (staging=",
        tostring((os.getenv("AUTO_SSL_STAGING") or "") == "true"),
        ", base_domain=", os.getenv("STAND_BASE_DOMAIN") or "example.com", ")")
else
    ngx.log(ngx.ERR, "[demo] on-demand TLS: setup failed — serving static fallback ",
        "cert only (custom-domain tenants won't get a cert): ", tostring(autossl_err))
end
