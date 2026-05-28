-- 0005_policy_origin_ip.sql — per-host origin_ip on policy (ClickUp 86exrefdz).
--
-- Multi-tenant routing: the edge picks the upstream by the incoming Host,
-- proxying to the tenant's origin_ip (bare IPv4/IPv6). A host without a
-- non-empty origin_ip is not a proxied tenant — the edge routes it to BAC's
-- own surface. This replaces the single-tenant ORIGIN_URL / DASHBOARD_*
-- env model entirely.
--
-- Empty string (not NULL) is the "unset" value, matching the Policy
-- contract (all fields present, zero == absent; see catalog/data.go).
--
-- Идемпотентно через IF NOT EXISTS — Migrate сериализует HA-реплики через
-- advisory_lock, повторный apply на уже мигрированной БД безвреден.
-- downgrade намеренно отсутствует (house rule: никаких drop column).

ALTER TABLE policy ADD COLUMN IF NOT EXISTS origin_ip TEXT NOT NULL DEFAULT '';
