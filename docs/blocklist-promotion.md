# Blocklist promotion — the operator's process

How to take a TLS fingerprint from the morning email into enforcement, and how to
retire one. The decision logic (score, gates, purity, intent, lifecycle) is in
[blocklist-scoring.md](blocklist-scoring.md). The on-VM procedure with the actual
commands is in [runbooks/blocklist-promotion.md](runbooks/blocklist-promotion.md).

## Why this exists

Previously the only way to add a fingerprint to `catalogs/tls_fp_blocklist.yaml`
was to edit the file by hand, and nobody ever retired a stale entry. The tooling
closes both ends: promotion in one command with an audit trail (an evidence
"passport" in the PR and in the entry's comment), and automatic retirement on
inactivity. Every automated action is a **draft PR that a human approves** — there
is no auto-merge.

## SLA

**From the morning email to a production block: ≤4 hours.** That budget covers
spotting a HIGH candidate → running `promote-fp.sh` → reviewing the staging PR →
merging → observing → the activate PR → merging. After the merge, the catalog
reaches the edge within ≤15 min (Channel C, see
[catalogs/README](../catalogs/README.md)).

## When to promote

- **impersonator** (UA says browser, fingerprint says tool) — the most reliable
  signal, promote it.
- **recon on an unknown or specific fingerprint** (not a generic curl/python one)
  — promote it.
- **HIGH with no intent** (an honest curl from a datacenter, even doing recon) —
  do **not** put it in `tls_fp_blocklist`: that fingerprint is shared by every
  user of the tool. This is a case for `ua_blacklist` / `ip_blocklist`.
- **purity veto** (`human_share > 0.05`) — do not promote: there are real browsers
  behind that fingerprint.

The autopilot opens draft PRs by itself for candidates that pass every gate plus
intent, leaving the operator the review. The email states why a HIGH candidate was
not auto-promoted.

## What to write in `--reason`

One line, to the point: what this is and why we block it. Good: `"impersonator
campaign, poses as Chrome + recon /.env"`, `"go scanner hitting Atlassian
endpoints, 8 datacenter IPs"`. Bad: `"bot"`, `"bad fp"`. The reason goes into the
PR and into the entry's passport comment — it is the answer to the future question
"why is this fingerprint on the blocklist".

## Lifecycle and commands

```sh
# 1. Promote to staging (matches, writes staging_match, does NOT block) — opens a PR
scripts/promote-fp.sh <fp> --reason "one line"

# 2. Observe for ≥48 h. Confirm the pattern only catches bots (see the runbook).

# 3. Activation (staging → active) — checks against the observation, opens PR 2
scripts/promote-fp.sh <fp> --activate

# Retirement (reversible):
scripts/demote-fp.sh <fp> --reason "why we retired it"      # active → staging
scripts/demote-fp.sh <fp> --reason "campaign over" --remove # remove entirely

# See what the autopilot would propose, changing nothing:
scripts/blocklist-autopilot.sh --dry-run
```

Useful promote flags: `--status active` (skip staging — against A11, do it
deliberately), `--ttl-days N` (an advisory review-by date in the passport),
`--force-low-volume` (override the volume gate), `--dry-run` (show the diff and
the PR body, change nothing), `--auto` (draft PR — the autopilot's mode).

## Reversibility

- **`demote-fp.sh`** — the standard way back, addressed by fingerprint key
  (surgical, no conflicts with other entries). By default it softly moves
  `active → staging`; `--remove` takes it out.
- **`git revert`** — the emergency rollback of a whole PR, within the same SLA.
  Use it when you need to undo the last PR quickly (see
  [runbooks/catalog-rollback.md](runbooks/catalog-rollback.md)).
- **auto-demote** — the autopilot opens a draft PR to retire a fingerprint that
  has been silent for more than 14 days. Nobody has to track inactive entries by
  hand.

## Where this runs

The analytics and its artifacts (`candidates.json` / `staging-observation.json` /
`stale.json`) live on the **backend+obs VM** (`antibot-analytics`, sourced from
Loki). The promote/demote/autopilot scripts run **there too, host-side** (they
need a git checkout and gh). The delivery path is git → backend → edge.
