# `infra/demo-stand/scripts/`

On-VM helper scripts for the abuse-controls stand. They resolve paths from their
own location and run out of the git checkout, so they track `main` with the
stand. State and report archives live under the repo root's `state/` and
`reports/` (both gitignored).

| Script | What it does |
| --- | --- |
| `analyze.py` | Daily traffic analyzer: reads `BAC_LOG` (Loki by default, `--source docker` for the local edge container), scores blocklist candidates, renders markdown / HTML / subject + the machine-readable JSON views the promotion tooling consumes. Lifetime state in `state/seen-fps.json` (by fp) and `state/ip-cache.json` (by IP). |
| `rotate-state.py` | Bounds the growth of that lifetime state — see **State rotation** below. |
| `blocklist-autopilot.sh`, `promote-fp.sh`, `demote-fp.sh` | Turn the analyzer's candidate/stale JSON into draft blocklist PRs (host-side; need the checkout + `gh`). |
| `update.sh`, `sync-demo-certs.sh`, `install-edge-client-cert.sh`, `generate-challenge-secret.sh`, `fetch-geoip.sh` | Deploy / cert / secret / GeoIP plumbing. |

## State rotation (`rotate-state.py`)

`seen-fps.json` and `ip-cache.json` record **every** fp / IP ever seen. On the
demo stand that is a few thousand records; on a production CDN operator edge
(millions of unique fp/IP per day) it would grow into gigabytes and slow
`analyze.py` down. `rotate-state.py` keeps the active files small without losing
history.

**Run order:** the scheduled daily run lives in the backend `antibot-analytics`
container ([`infra/demo-backend/analytics/run.sh`](../../demo-backend/analytics/run.sh)),
which runs `rotate-state.py` **before** `analyze.py`. The rotation step is
non-fatal (a hiccup never blocks the daily report).

The rotation logic itself lives in `analyze.rotate_state()` so the producer
(`rotate-state.py`) and the consumer (`analyze.py`'s lazy restore) share one
definition of "old". `rotate-state.py` is the thin CLI/cron wrapper.

### What happens to each record

For each store, keyed off the record's **last-seen day**:

- **Archive** — last seen longer ago than its TTL → moved out of the active file
  into a monthly shard `state/archive/YYYY-MM.json` (the month it was last seen).
  Nothing is deleted; the record is just parked.
- **Drop (compaction)** — `count < STATE_COMPACT_MIN_COUNT` **and** idle for more
  than 7 days → deleted outright. These are likely one-off probes not worth
  keeping. (The 7-day floor also guards a brand-new low-count fp from being
  culled the same week.)
- **Keep** — everything else stays active. A record with no resolvable last-seen
  day yet (e.g. a just-seeded IP the lifetime pass hasn't stamped) is left alone
  rather than guessed stale.

**fp** last-seen comes from `max(days_seen)` (the canonical clock, see
[`docs/blocklist-scoring.md`](../../../docs/blocklist-scoring.md)); **IP**
last-seen comes from the `last_seen` field the lifetime pass stamps. The IP TTL
is shorter than the fp TTL because ASN / reverse-DNS churns faster.

### Lazy restore

When a fp or IP that was archived **reappears** in the logs, `analyze.py` pulls
it back out of the monthly shard into the active state — counts and history
intact — before the new window accumulates onto it. A record is therefore either
active or archived, never both. (Dropped records are gone; nothing to restore.)

A key→month index at `state/archive-index.json` gates this: a lookup for a key
that was never archived — the common case, since brand-new fps/IPs appear every
run — returns immediately without opening a single shard, so restore cost does
**not** grow with the archive. The index is maintained as records are archived
and restored, and **rebuilt from the shards if it is missing or corrupt**. So to
hand-restore a record (e.g. the manual archive test), move it into the right
`state/archive/YYYY-MM.json` shard, `rm state/archive-index.json`, and the next
`analyze.py` run rebuilds the index and picks the record up.

> Note: because rotation runs *before* the daily analyze pass, an fp that aged
> out but reappears in the same window is archived by `rotate-state.py` and then
> immediately restored by `analyze.py` — correct, but one redundant shard write
> per such fp. Rare (only aged-out fps that resurface that day), so left as-is.

### Overriding the TTLs

Env vars (set in the backend `run.sh`, or exported before a manual run):

| Var | Default | Meaning |
| --- | --- | --- |
| `STATE_FP_TTL_DAYS` | `30` | archive an fp once last-seen is older than N days |
| `STATE_IP_TTL_DAYS` | `7` | archive an IP once last-seen is older than N days |
| `STATE_COMPACT_MIN_COUNT` | `3` | count below which an idle (>7d) record is dropped |
| `ABUSE_CONTROLS_ROOT` | repo checkout | repo root holding `state/` |

```sh
# Preview what would move, change nothing:
python3 infra/demo-stand/scripts/rotate-state.py --dry-run

# Rotate with custom TTLs:
STATE_FP_TTL_DAYS=14 STATE_IP_TTL_DAYS=3 \
  python3 infra/demo-stand/scripts/rotate-state.py
# (or the equivalent --fp-ttl-days / --ip-ttl-days / --min-count flags)
```

Tests for the rotation, archive, and lazy-restore logic are in
[`tests/test_analyze.py`](../../../tests/test_analyze.py) (`pytest -q`).
