-- 0004_drop_slow_catalogs.sql — медленные каталоги переехали в git-репо
-- catalogs/ (см. ADR-006). БД остаётся только для runtime state, который
-- меняется автоматически и не подходит файлам по природе: verified_bot_ips
-- (rDNS-воркер) и policy (antibotapi из дашборда).
--
-- catalog_version тоже дропаем — версия теперь приходит из catalogs/version
-- (singleton-файл с одной строкой semver).
--
-- Перед накатом на стенд: запустите scripts/seed-catalogs-from-db.sh,
-- чтобы выгрузить текущее содержимое таблиц в catalogs/*.yaml и не
-- потерять состояние. На пустой БД (CI / fresh stand) можно сразу
-- alembic-style "upgrade head".
--
-- Идемпотентно через IF EXISTS — HA-пара backend стартует обе реплики,
-- advisory_lock в Migrate сериализует, но повторный apply на уже
-- мигрированной БД должен быть безвреден.

DROP TABLE IF EXISTS fp_blocklist;
DROP TABLE IF EXISTS ua_blacklist;
DROP TABLE IF EXISTS ip_blocklist;
DROP TABLE IF EXISTS ip_whitelist;
DROP TABLE IF EXISTS asn_datacenters;
DROP TABLE IF EXISTS catalog_version;
