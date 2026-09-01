-- 0004_drop_slow_catalogs.sql — the slow catalogs moved into the catalogs/ git
-- repo. The database remains only for the runtime state that
-- changes automatically and does not suit files by nature: verified_bot_ips
-- (the rDNS worker) and policy (antibotapi from the dashboard).
--
-- catalog_version is dropped too — the version now comes from catalogs/version
-- (a singleton file with one semver line).
--
-- Before applying this on the stand: run scripts/seed-catalogs-from-db.sh
-- to dump the tables' current contents into catalogs/*.yaml so that no
-- state is lost. On an empty database (CI / a fresh stand) you can go
-- alembic-style "upgrade head".
--
-- Idempotent through IF EXISTS — the HA pair of backends starts both replicas,
-- the advisory_lock in Migrate serialises them, but a repeat apply on an already
-- migrated database must be harmless.

DROP TABLE IF EXISTS fp_blocklist;
DROP TABLE IF EXISTS ua_blacklist;
DROP TABLE IF EXISTS ip_blocklist;
DROP TABLE IF EXISTS ip_whitelist;
DROP TABLE IF EXISTS asn_datacenters;
DROP TABLE IF EXISTS catalog_version;
