# Runbook — blocklist promotion (D1)

**Goal.** Take a TLS fingerprint from the morning report through to enforcement,
and retire a stale one — via a PR, with an audit trail, reversibly. The decision
logic (score, gates, purity, intent) is in
[blocklist-scoring.md](../blocklist-scoring.md); the process and SLA are in
[blocklist-promotion.md](../blocklist-promotion.md).

**SLA.** Email → production block in ≤4 h (including the staging observation and
two reviews). After the merge, the catalog reaches the edge within ≤15 min
([catalog-rollback.md](catalog-rollback.md)).

**Where to run it.** The analytics (`antibot-analytics`) and the scripts live on
the backend+obs VM (`ubuntu@<BACKEND_VM_IP>`), together with the git checkout and
`gh`. The artifacts are `state/candidates.json` / `staging-observation.json` /
`stale.json`. This depends on A11 staging delivery over Channel C, so that
staging entries really match on the edge and emit `staging_match`.

## Preconditions

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls

# A fresh analytics run (one-shot — writes the artifacts and sends the report;
# on schedule this is done by host cron at 08:00, see §Schedule):
docker compose -f infra/demo-backend/docker-compose.backend.yml --profile observability run --rm analytics
ls -l state/candidates.json state/staging-observation.json state/stale.json

# gh is authenticated (for the PR) and the git remote is reachable:
gh auth status
```

## Promotion (staging → observation → active)

```sh
# 1. A HIGH candidate from the email / candidates.json. Dry run first, to see the
#    diff and the PR body:
scripts/promote-fp.sh <fp> --reason "impersonator campaign, poses as Chrome + recon /.env" --dry-run

# 2. Open the PR (status=staging). Watch the gates: purity/allowlist is a hard veto.
scripts/promote-fp.sh <fp> --reason "..."

# 3. Review and merge. Within ≤15 min the staging entry reaches the edge: it
#    matches, writes staging_match: ["tls_fp_blocklist:<fp>"], and does NOT block.
#    Check that it matches:
python3 infra/demo-stand/scripts/analyze.py --staging-observation-json | \
  python3 -c "import sys,json;[print(o) for o in json.load(sys.stdin)['observations']]"
#    → n_matches grows for that fingerprint, human_share=0 → the verdict will be activate.

# 4. Observe for ≥48 h. Once verdict=activate (zero false positives, ≥10 matches):
scripts/promote-fp.sh <fp> --activate          # PR 2: staging → active

# 5. Review and merge. The edge starts emitting verdict=block, rule=tls_fp_blocklist.
```

If at step 3–4 you get `verdict=fp_caught` (the pattern touched a real browser or
an allowlisted client), **do not activate** — remove it:
`scripts/demote-fp.sh <fp> --remove`.

## Retiring an entry (reversible)

```sh
scripts/demote-fp.sh <fp> --reason "false positive: legitimate client with the same fp"   # active → staging
scripts/demote-fp.sh <fp> --reason "campaign over" --remove                                 # remove entirely
```

## The autopilot (cron, draft PRs in both directions)

```sh
# What it would propose, changing nothing:
scripts/blocklist-autopilot.sh --dry-run

# The real run (opens draft PRs ONLY; a human reviews and merges):
#   30 5 * * * cd ~/abuse-controls && ./scripts/blocklist-autopilot.sh >> ~/autopilot.log 2>&1
```

The autopilot collects every change that has matured during the run into **one
draft PR** (branch `blocklist-auto-YYYY-MM-DD`): auto-promote HIGH (≥1 day, gates
plus intent) → staging; activate staging entries whose verdict is activate;
auto-demote entries silent for >14 days (active→staging→remove). It is
idempotent: one branch per day, so a second run on the same day is a no-op. CI on
such a catalog-only PR runs `validate-catalogs` alone (the other jobs are
path-filtered, see `.github/workflows/ci.yml`).

## Schedule (cron on the backend VM)

The analytics is **cron-driven and one-shot** (the container does not loop): host
cron at 08:00 MSK does a single run — first `rotate-state.py` (D7: bounds the
growth of `seen-fps.json` / `ip-cache.json`, archiving into `state/archive/`),
then `analyze.py` (artifacts plus the report), then the autopilot reads the fresh
artifacts. Rotation is non-fatal — its failure does not block the report; the TTL
logic and env knobs are in
[`infra/demo-stand/scripts/README.md`](../../infra/demo-stand/scripts/README.md).
Runs on `ubuntu@<BACKEND_VM_IP>`. **Times are written in explicit UTC**: the host
runs UTC, and this cron (Debian) does NOT honour `CRON_TZ` (verified: `0 8` with
`CRON_TZ=Europe/Moscow` still fired at 08:00 UTC). Hence `05:00 UTC = 08:00 MSK`
(Moscow has no DST). `-T` because cron allocates no TTY; `PATH` so that cron finds
`git`/`gh` for the autopilot:

```cron
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# 05:00 UTC = 08:00 MSK — analytics run (Loki → state/*.json + email)
0 5 * * * cd /home/ubuntu/abuse-controls/infra/demo-backend && /usr/bin/docker compose -f docker-compose.backend.yml --profile observability run -T --rm analytics >> /home/ubuntu/analytics-cron.log 2>&1
# 05:30 UTC = 08:30 MSK — autopilot: one draft PR from the fresh artifacts
30 5 * * * cd /home/ubuntu/abuse-controls && ./scripts/blocklist-autopilot.sh >> /home/ubuntu/autopilot.log 2>&1
```

`run.sh` is the image's default entrypoint. Until the image on the VM is rebuilt
as one-shot, add `--entrypoint /opt/analytics/run.sh` to force a single pass
(otherwise the old looping image never exits).

The old edge-side `daily-report.sh` was deleted (the analytics moved to the
backend; on the edge, `analyze.py` remains a manual debugging tool with
`--source docker`).

## What to watch

- After the staging PR is merged: `staging_match` for the fingerprint grows on
  the edge while the `verdict` stays as it was (NOT block);
  `analyze.py --staging-observation-json` shows n_matches>0.
- After the activate PR is merged: `blocklist_entries` +1 (EDGE_STATS in Loki, or
  `:9090/__stats`), and requests carrying the fingerprint give
  `verdict=block,rule=tls_fp_blocklist` (Loki `{kind="bac_log"}`).
- After an auto-demote: the entry leaves active (silent for >14 days) and
  enforcement is lifted.

## Rollback

`scripts/demote-fp.sh <fp>` (targeted at one fingerprint) or `git revert` of the
whole PR ([catalog-rollback.md](catalog-rollback.md)). Both land within the
≤15 min delivery SLA.

## Verified on stand

2026-05-29 (D1 on main `2506c03`, A11 staging delivery `f984716` already in main).

- **Producer (backend/Loki).** The `antibot-analytics` container was brought up on
  the backend VM (observability profile), read **live Loki** and wrote
  `state/candidates.json` (**14 HIGH / 11 MEDIUM / 31 LOW**) plus `stale.json`
  and `staging-observation.json`.
  `infra/demo-stand/scripts/analyze.py --source loki` works end to end.
- **Promote → PR.** `scripts/promote-fp.sh L13d1300_69e852b66fc7_10d89aa70559 --reason "..."`
  opened a clean staging PR off main with an evidence passport (score 6 HIGH:
  impersonator go-http-client plus leakix recon, 13 IPs, datacenter,
  `human_share 0.0`, gates ✓); CI green.
- **Channel C staging delivery.** After that merge the edge (visible in
  `:9090/__stats` and the EDGE_STATS stream) showed
  `L13d1300_69e852b66fc7_10d89aa70559 → staging:block` — the entry arrived and
  loaded as match-but-observe (no 403, unlike the `active:block` entries the edge
  was blocking a live jitsi scanner with at that moment). This confirms staging
  really reaches the edge, closing the gap.
- **`staging_match`.** The `antibot_staging_match_total` metric (observe-only) is
  wired on the edge and increments on the next request carrying that fingerprint
  (it depends on the timing of live traffic for that specific fingerprint — at
  the time of the check it had not made a request since loading).
- **Activation.** Gated by the §E dwell hours (`staging-since.json`, default 48 h)
  plus a clean observation (`human_share=0`): it runs after the window through
  `scripts/promote-fp.sh <fp> --activate` (or `--force` for a demo) → a second PR
  moving it to `active`.

> The "at least one HIGH candidate carried through the flow" acceptance is closed
> on delivery: a live HIGH from Loki → promote PR → merge → loaded on the edge as
> staging. A real `verdict=block` follows activation (48 h dwell, or `--force`).
