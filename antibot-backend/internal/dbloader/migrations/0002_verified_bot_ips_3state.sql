-- 0002_verified_bot_ips_3state.sql — extend verified_bot_ips with the
-- three-state machine the rDNS worker writes ([B7]).
--
-- vision.md (Шаг 2.2 + §"Reverse-DNS воркер") + entities-reference.md row
-- `bot_verification_status`: edge на L2.2 различает три состояния IP с
-- поисковым UA — `verified` (полный fastpath), `rejected` (no fastpath,
-- идёт по каскаду), отсутствие записи (provisional fastpath). До B7 в
-- таблице лежал только positive исход (`verified`); rejected жил в виде
-- "нет записи", что неотличимо от "ещё не проверяли" — impersonator под
-- Googlebot получал бесплатный provisional на каждом запросе.
--
-- TTL — 1 час симметрично на оба исхода (vision §Шаг 2.2 v0.6, ранее
-- было 5 минут для rejected; короткий TTL давал impersonator-IP ~288
-- бесплатных provisional-проходов в сутки между ре-проверками). Edge
-- читает каталог через dbloader.Load с фильтром expires_at > NOW().
--
-- Idempotent через ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS —
-- HA-пара backend стартует обе реплики, advisory lock в Migrate
-- сериализует, но повторный apply на уже мигрированной БД тоже допустим.

ALTER TABLE verified_bot_ips
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'verified'
        CHECK (status IN ('verified', 'rejected'));

-- expires_at: добавляем без DEFAULT, отдельным UPDATE'ом раскидываем
-- по verified_at прошлых записей, и только потом ставим DEFAULT +
-- NOT NULL. Прямой `ADD COLUMN NOT NULL DEFAULT (NOW() + INTERVAL '1
-- hour')` забэкфилил бы ВСЕ строки одним и тем же T+1h — через час
-- dbloader.Load (`WHERE expires_at > NOW()`) выбросил бы их одним
-- разом, и edge потерял бы весь verified-набор разом → cold-start
-- storm на rDNS-резолвере. PR #53 review.
ALTER TABLE verified_bot_ips
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

UPDATE verified_bot_ips
    SET expires_at = verified_at + INTERVAL '1 hour'
    WHERE expires_at IS NULL;

ALTER TABLE verified_bot_ips
    ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '1 hour'),
    ALTER COLUMN expires_at SET NOT NULL;

-- Worker дёргает DELETE WHERE expires_at <= NOW() периодически, чтобы
-- таблица не росла бесконечно (запросы с фильтром expires_at > NOW()
-- иначе оплачивают полный seq scan). Partial-index'a нет — Postgres
-- не позволяет неимутабельные функции в predicate.
CREATE INDEX IF NOT EXISTS idx_verified_bot_ips_expires_at
    ON verified_bot_ips (expires_at);
