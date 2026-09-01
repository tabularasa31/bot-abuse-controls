-- 0002_verified_bot_ips_3state.sql — extend verified_bot_ips with the
-- three-state machine the rDNS worker writes ([B7]).
--
-- vision.md (stage 2.2 plus §"The reverse-DNS worker") and the entities-reference.md row
-- `bot_verification_status`: at L2.2 the edge distinguishes three states of an IP with a
-- search engine UA — `verified` (a full fastpath), `rejected` (no fastpath,
-- it walks the cascade) and no record (the provisional fastpath). Before B7 the
-- table held only the positive outcome (`verified`), while rejected existed as
-- "no record", which is indistinguishable from "not checked yet" — so an impersonator posing
-- as Googlebot got a free provisional pass on every request.
--
-- The TTL is 1 hour, symmetric across both outcomes (vision §Stage 2.2 v0.6; it used to
-- be 5 minutes for rejected, and that short TTL gave an impersonator IP ~288
-- free provisional passes a day between rechecks). The edge
-- reads the catalog through dbloader.Load with the filter expires_at > NOW().
--
-- Idempotent through ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS —
-- the HA pair of backends starts both replicas, the advisory lock in Migrate
-- serialises them, but a repeat apply on an already-migrated database must also be fine.

ALTER TABLE verified_bot_ips
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'verified'
        CHECK (status IN ('verified', 'rejected'));

-- expires_at: we add it without a DEFAULT, spread the values with a separate UPDATE
-- based on the verified_at of the existing rows, and only then set the DEFAULT plus
-- NOT NULL. A direct `ADD COLUMN NOT NULL DEFAULT (NOW() + INTERVAL '1
-- hour')` would backfill EVERY row with the same T+1h — an hour later
-- dbloader.Load (`WHERE expires_at > NOW()`) would drop them all at
-- once, the edge would lose its whole verified set in one go → a cold-start
-- storm on the rDNS resolver. From review.
ALTER TABLE verified_bot_ips
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

UPDATE verified_bot_ips
    SET expires_at = verified_at + INTERVAL '1 hour'
    WHERE expires_at IS NULL;

ALTER TABLE verified_bot_ips
    ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '1 hour'),
    ALTER COLUMN expires_at SET NOT NULL;

-- The worker runs DELETE WHERE expires_at <= NOW() periodically, so that
-- the table does not grow forever (queries filtering on expires_at > NOW()
-- would otherwise pay for a full seq scan). There is no partial index — Postgres
-- does not allow non-immutable functions in a predicate.
CREATE INDEX IF NOT EXISTS idx_verified_bot_ips_expires_at
    ON verified_bot_ips (expires_at);
