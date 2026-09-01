-- 0003_logs.sql — the telemetry sink: the `logs` table for BAC_LOG from the edges.
--
-- The sink is the same PostgreSQL that holds the catalogs;
-- as the volume grows, the "receiver→sink" boundary moves the storage to DuckDB/
-- ClickHouse with no edge-side changes and no migrations of the logs schema.
--
-- Forward compatibility ("adding a field must not require a
-- migration"). The strategy is a hybrid: typed columns for the hot fields
-- (entities-reference §"JSON log fields") that analytics needs
-- today, plus one JSONB `raw` column holding the whole record. Any new field
-- that appears in bac_log.lua CERTAINLY lands in `raw` with no
-- migration; we add a typed column for it in a separate ALTER
-- only when analytics really wants an index or a GROUP BY (which is then an
-- "extension" migration rather than "accepting a new field").
--
-- Every typed column is nullable: the edge leaves some fields null
-- (resource_id is filled in by the backend on ingest, the tls_* fields appear later) — the entities-reference table states this explicitly.
-- We do not fail a whole row because of one missing field; the strict
-- checks (the stage/verdict enums) live in the edge's bac_log.lua itself.
--
-- Idempotent: CREATE … IF NOT EXISTS — reapplying is safe
-- (the HA pair of backends starts both replicas, and the migrations run under an advisory lock).
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

-- An index on ts — most analytics queries are "over the last N hours".
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (ts DESC);

-- (host, ts) — the daily analytics slices by resource. There is no separate
-- index on host (it leads the composite) — we save space.
CREATE INDEX IF NOT EXISTS idx_logs_host_ts ON logs (host, ts DESC);

-- (verdict, ts) — the top-level dashboard, "how many block/challenge/pass in an hour".
CREATE INDEX IF NOT EXISTS idx_logs_verdict_ts ON logs (verdict, ts DESC);
