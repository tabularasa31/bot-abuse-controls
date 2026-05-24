-- 0003_logs.sql — приёмник телеметрии: таблица `logs` под BAC_LOG c эджей ([B9]).
--
-- vision.md §"Приёмник логов" / phase1-spec §"Открытые вопросы (приёмник
-- телеметрии)": Phase 1 sink — та же PostgreSQL, что держит каталоги (B1/B4);
-- при росте объёма граница «receiver→sink» вынесет хранилище в DuckDB/
-- ClickHouse без правок edge-стороны и без миграций схемы logs.
--
-- Forward-compatibility (acceptance B9: «добавление Phase 2/3 поля не требует
-- миграции»). Стратегия — гибрид: типизированные колонки под «горячие» поля
-- Phase 1 (entities-reference §"Поля JSON-лога"), которые нужны аналитике
-- сейчас, плюс одна JSONB-колонка `raw` с целой записью. Любое новое поле
-- Phase 2/3, появившееся в bac_log.lua, ЗАВЕДОМО попадает в `raw` без
-- миграции; типизированную колонку под него заведём отдельным ALTER'ом
-- только когда аналитика реально захочет индекс / GROUP BY (это уже
-- миграция «расширения», а не «приёма нового поля»).
--
-- Все типизированные колонки nullable: edge кэширует часть полей null'ом
-- (resource_id заполняется backend'ом на ingest, tls_*-поля появляются с
-- Phase 2, и т.д.) — entities-reference таблица это явно фиксирует.
-- Не валим всю строку из-за одного отсутствующего поля; жёсткие
-- check'и (stage/verdict enum) хранятся в самом edge bac_log.lua.
--
-- Идемпотентно: CREATE … IF NOT EXISTS — переприменение безопасно
-- (HA-пара backend стартует обе реплики, миграции под advisory lock).
CREATE TABLE IF NOT EXISTS logs (
    id               BIGSERIAL    PRIMARY KEY,
    request_id       TEXT         NOT NULL,
    ts               TIMESTAMPTZ  NOT NULL,
    edge_id          TEXT         NOT NULL,
    resource_id      TEXT,
    host             TEXT,
    path             TEXT,
    method           TEXT,
    status           INTEGER,
    ip               TEXT,
    asn              TEXT,
    geo_country      TEXT,
    ua               TEXT,
    tls_fp           TEXT,
    tls_cipher_count INTEGER,
    tls_alpn         TEXT,
    tls_sni_present  BOOLEAN,
    stage            TEXT,
    verdict          TEXT,
    rule             TEXT,
    action           TEXT,
    mode             TEXT,
    latency_ms       DOUBLE PRECISION,
    tags             TEXT[],
    flags            TEXT[],
    staging_match    TEXT[],
    rule_source      TEXT,
    client_rule_name TEXT,
    raw              JSONB        NOT NULL,
    ingested_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Индекс по ts — большинство запросов аналитики «за последние N часов».
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (ts DESC);

-- (host, ts) — daily-аналитика срезает по ресурсу. Без отдельного
-- идекса по host (он в композите ведущий) — экономим место.
CREATE INDEX IF NOT EXISTS idx_logs_host_ts ON logs (host, ts DESC);

-- (verdict, ts) — top-level дашборд «сколько block/challenge/pass за час».
CREATE INDEX IF NOT EXISTS idx_logs_verdict_ts ON logs (verdict, ts DESC);
