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
local fp_state = require "tls_fp_blocklist_state"
local fp_dict = ngx.shared.tls_fp_blocklist
-- ngx.shared.DICT:add returns (success, err, forcible). success=true ⇒
-- ключ только что создан (cold start); success=false + err="exists" ⇒
-- ключ уже существовал (reload-survive); любая другая ошибка
-- (err="no memory") — реальный fail, на котором мы НЕ должны идти в
-- reload-branch, иначе re-seed скипнется и стенд тихо станет SHADOW.
local was_added, add_err = ngx.shared.meta:add(fp_state.META_GEN_KEY, 0)
local is_cold_start = was_added or add_err ~= "exists"
if not was_added and add_err ~= "exists" then
    ngx.log(ngx.ERR, "[demo] meta:add tls_fp_blocklist_gen failed (",
        tostring(add_err), ") — forcing cold-start re-seed to avoid silent SHADOW")
    -- Force-set gen=0 чтобы verdict.lua резолвил наш сейчас-pisemый seed.
    ngx.shared.meta:set(fp_state.META_GEN_KEY, 0)
end
local n = 0
if is_cold_start then
    -- Cold start (или meta-add failed): gen-key создан/forсed в 0.
    -- Заводим entries под `:0` чтобы verdict.lua сразу видел seed до первого
    -- Channel C pull.
    for _, entry in ipairs(config.tls_fp_blocklist) do
        if entry.attrs.status ~= "staging" then
            local ok, err = fp_dict:set(fp_state.key(entry.value, 0), "block")
            if ok then
                n = n + 1
            else
                ngx.log(ngx.ERR, "tls_fp_blocklist:set failed: ", err)
            end
        end
    end
else
    -- Reload-survive: meta:add no-op потому что key exists. Не трогаем data
    -- shared_dict — Channel C `:N` entries уже там, verdict.lua найдёт их по
    -- meta:get(gen)=N. Считаем выжившие entries под current gen для
    -- blocklist_entries gauge + ACTIVE/SHADOW лог (analyze.py парсит
    -- «tls_fp_blocklist loaded: N»). Используем typed fp_state.match() вместо
    -- bare suffix-string — симметрично catalog_pull.sweep (PR-55 review #5
    -- guard от sharing dict с другим writer'ом).
    local cur_gen = ngx.shared.meta:get(fp_state.META_GEN_KEY) or 0
    for _, k in ipairs(fp_dict:get_keys(0)) do
        if fp_state.match(k, cur_gen) then
            n = n + 1
        end
    end
    -- Detect data-dict-resized-but-meta-survived divergence: если gen>0 говорит
    -- «Channel C доставил state», но n=0 значит data zone был wiped (например
    -- operator resize'нул tls_fp_blocklist zone в nginx.conf и сделал reload).
    -- В этом случае catalog_pull получит 304 (etag survived в meta) → gen
    -- остаётся N → каталог frozen forever. Lечим: force-reset gen=0 + drop
    -- etag, чтобы следующий pull сделал полный 200 GET и re-доставил данные.
    if cur_gen > 0 and n == 0 then
        ngx.log(ngx.WARN, "[demo] tls_fp_blocklist: meta says gen=", cur_gen,
            " but data dict is empty — assuming zone resize/wipe. ",
            "Forcing gen=0 + dropping etag so next Channel C pull re-delivers.")
        ngx.shared.meta:set(fp_state.META_GEN_KEY, 0)
        ngx.shared.meta:delete("tls_fp_blocklist_etag")
        -- Re-seed локальный fallback под `:0`.
        for _, entry in ipairs(config.tls_fp_blocklist) do
            if entry.attrs.status ~= "staging" then
                local ok, err = fp_dict:set(fp_state.key(entry.value, 0), "block")
                if ok then
                    n = n + 1
                else
                    ngx.log(ngx.ERR, "tls_fp_blocklist:set failed: ", err)
                end
            end
        end
    else
        ngx.log(ngx.NOTICE, "[demo] tls_fp_blocklist: reload detected, preserving Channel C state (gen=", cur_gen, ", entries=", n, ")")
    end
end

-- verified_bots / tls_fp_catalog / tls_fp_browser_profiles — no static
-- seed (catalogs приезжают через Channel C). Изначально (cold start)
-- gen-keys отсутствуют в `meta`; mета shared_dict выживает `nginx -s
-- reload` (zone сохраняется при неизменном name+size), поэтому используем
-- `meta:add(key, 0)` — присвоение ТОЛЬКО если ключ не существует. Это
-- закрывает PR-62 audit-bug: при reload meta:gen уже содержит реальное
-- значение (например 7), `add` не перетирает в 0; refresh() видит 7,
-- сканирует `:7` суффикс в data shared_dict (зона тоже выжила reload),
-- находит выжившие entries → каталог не залипает на 304.
-- Контракт: после первого вызова gen-key всегда существует, любой
-- читатель без `or 0`-защиты не nil-ошибётся.
ngx.shared.meta:add("verified_bots_gen", 0)
ngx.shared.meta:add("tls_fp_catalog_gen", 0)
ngx.shared.meta:add("tls_fp_browser_profiles_gen", 0)

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
