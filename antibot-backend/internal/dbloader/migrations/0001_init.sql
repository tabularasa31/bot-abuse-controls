-- 0001_init.sql — initial schema for Channel C catalogs and per-host policy.
--
-- Source of truth: docs/architecture/config-distribution.md
-- (§"The 'catalog' concept", §"Per-resource lookup — keyed by Host"). All
-- eight catalogs from that table land here in normal form, plus a single
-- `policy` row per Host carrying mode/strictness/attack_mode and the
-- per-resource lists.
--
-- Schema is intentionally minimal — backend reads everything in one shot
-- on each reload tick (config-distribution §Load: ~12 req/s peak across
-- the edge pool, dozens of rows per table). When tables grow past that
-- back-of-envelope, B9 moves logs to a separate store; this schema stays.
--
-- All tables use IF NOT EXISTS so this file is safe to re-run on a fresh
-- VM or after a partial earlier apply. B15 will introduce a proper
-- migration tool (golang-migrate) with a tracking table; until then the
-- minimal runner in internal/dbloader/migrate.go applies the file once
-- per startup and relies on IF NOT EXISTS for idempotence.

-- Singleton row carrying the semver that lands in X-Catalog-Version on
-- every Channel C response (data.go §defaultVersion). Operator bumps it
-- on schema-breaking changes; ETag tracks content changes independently.
CREATE TABLE IF NOT EXISTS catalog_version (
    id          SMALLINT PRIMARY KEY DEFAULT 1,
    version     TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT  catalog_version_singleton CHECK (id = 1)
);
INSERT INTO catalog_version (id, version)
    VALUES (1, '1.0.0')
    ON CONFLICT (id) DO NOTHING;

-- fp_blocklist: TLS-fingerprint → "block". status='staging' rows compile
-- into the *_staging shared_dict on the edge (A11), 'active' into the
-- enforcing one. Backend filters by status when materializing the
-- catalog payload.
CREATE TABLE IF NOT EXISTS fp_blocklist (
    fp          TEXT PRIMARY KEY,
    status      TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'staging')),
    note        TEXT,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ua_blacklist: regex patterns combined into one (?:p1)|(?:p2)|… string
-- on the build step. Validated through regexp.Compile at load time so a
-- broken row fails the whole reload rather than poisoning the edge.
CREATE TABLE IF NOT EXISTS ua_blacklist (
    pattern     TEXT PRIMARY KEY,
    status      TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'staging')),
    note        TEXT,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ip_blocklist / ip_whitelist: CIDR strings. We do not enforce CIDR
-- syntax in the DB (PostgreSQL `inet` is stricter than what lua-resty-
-- ipmatcher accepts in edge cases) — validation lives in the loader.
CREATE TABLE IF NOT EXISTS ip_blocklist (
    cidr        TEXT PRIMARY KEY,
    status      TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'staging')),
    note        TEXT,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_whitelist (
    cidr        TEXT PRIMARY KEY,
    note        TEXT,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- asn_datacenters: ASN numbers. BIGINT to accommodate 32-bit ASNs (RFC 6793).
CREATE TABLE IF NOT EXISTS asn_datacenters (
    asn         BIGINT PRIMARY KEY,
    note        TEXT,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- verified_bot_ips: populated by the rDNS worker, read by backend on
-- every reload. bot_name is the pipe-separated taxonomy from the catalog
-- contract ("google|bing|yandex|ddg").
CREATE TABLE IF NOT EXISTS verified_bot_ips (
    ip          TEXT PRIMARY KEY,
    bot_name    TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- policy: per-host JSON-ish bag, one row per Host. Hot columns
-- (mode/strictness/attack_mode) are typed; collections live in JSONB
-- because they are read whole every tick and rarely queried by content.
-- Default row values match the pool default the loader returns for
-- unregistered hosts (mode=shadow, strictness=standard) — so a row
-- inserted with only `host` produces the same payload as no row at all.
CREATE TABLE IF NOT EXISTS policy (
    host           TEXT PRIMARY KEY,
    mode           TEXT NOT NULL DEFAULT 'shadow'
                       CHECK (mode IN ('shadow', 'active')),
    strictness     TEXT NOT NULL DEFAULT 'standard'
                       CHECK (strictness IN ('standard', 'permissive')),
    attack_mode    BOOLEAN NOT NULL DEFAULT FALSE,
    ua_blacklist   JSONB NOT NULL DEFAULT '[]'::jsonb,
    ip_whitelist   JSONB NOT NULL DEFAULT '[]'::jsonb,
    ip_blocklist   JSONB NOT NULL DEFAULT '[]'::jsonb,
    asn_block      JSONB NOT NULL DEFAULT '[]'::jsonb,
    geo_whitelist  JSONB NOT NULL DEFAULT '[]'::jsonb,
    rate_rules     JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
