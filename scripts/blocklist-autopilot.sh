#!/usr/bin/env bash
# blocklist-autopilot.sh — cron driver that turns the analytics artifacts into
# DRAFT PRs in both directions. It NEVER merges and NEVER opens a non-draft PR;
# a human reviews and merges. Idempotent: a deterministic branch name per fp +
# the promote/demote branch-exists guard means a re-run won't duplicate PRs.
#
#   blocklist-autopilot.sh [--dry-run] [--base BRANCH]
#
# Reads (written by the antibot-analytics container from Loki):
#   state/candidates.json          → auto-promote eligible HIGH (intent ✓, gates ✓)
#   state/staging-observation.json → staging entries whose verdict == activate
#   state/stale.json               → silent > ttl → auto-demote (active→staging, staging→remove)
# Entries with no observation history (unknown) are left for human review, not demoted.
#
# Cron (backend VM), after the analytics run writes the artifacts:
#   30 8 * * * /home/ubuntu/abuse-controls/scripts/blocklist-autopilot.sh >> ~/autopilot.log 2>&1
set -euo pipefail   # -e guards init (source/resolve); run() OR-lists keep a single
                    # skipped/failed fp from aborting the sweep.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/blocklist_common.sh
source "$HERE/lib/blocklist_common.sh"

DRY_FLAG=""; BASE="main"
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_FLAG="--dry-run"; shift;;
    --base) BASE="$2"; shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) bl_die "unknown option: $1";;
  esac
done
bl_resolve "$HERE"

_fps() {  # <json-file> <python expr returning list of fps from dict d>
  [ -f "$1" ] || return 0
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for fp in eval(sys.argv[2], {}, {"d": d}):
    print(fp)
PY
}

_pairs() {  # <json-file> <python expr returning list of [fp, status] from dict d>
  [ -f "$1" ] || return 0
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for fp, st in eval(sys.argv[2], {}, {"d": d}):
    print(fp, st)
PY
}

run() {  # log + invoke, never abort the sweep
  echo "autopilot> $*"
  "$@" || echo "autopilot: skipped/failed (exit $?): $*"
}

echo "=== blocklist-autopilot $(date -u +%FT%TZ) ${DRY_FLAG:+[dry-run]} ==="

echo "--- auto-promote (HIGH, intent ✓, gates ✓) ---"
_fps "$CANDIDATES" "[c['fp'] for c in d.get('high',[]) if c.get('auto_eligible')]" | while read -r fp; do
  run "$HERE/promote-fp.sh" "$fp" --reason "auto: stable HIGH, gates+intent passed" --auto --base "$BASE" $DRY_FLAG
done || true

echo "--- auto-activate (staging observation verdict=activate) ---"
_fps "$STAGING_OBS" "[o['fp'] for o in d.get('observations',[]) if o.get('verdict')=='activate']" | while read -r fp; do
  run "$HERE/promote-fp.sh" "$fp" --activate --reason "auto: staging clean, observation confirms" --auto --base "$BASE" $DRY_FLAG
done || true

echo "--- auto-demote (silent > ttl, confirmed only) ---"
# Two-stage demote: an active entry softens to staging; a STAGING entry that is
# still silent is removed (demote-fp.sh requires --remove to drop a staging
# entry — without it it would abort, so the second lifecycle stage must pass it).
_pairs "$STALE_JSON" "[[s['fp'], s['status']] for s in d.get('stale',[]) if s.get('stale')]" | while read -r fp st; do
  if [ "$st" = "staging" ]; then
    run "$HERE/demote-fp.sh" "$fp" --remove --reason "auto: staging silent > ttl, removing" --auto --base "$BASE" $DRY_FLAG
  else
    run "$HERE/demote-fp.sh" "$fp" --reason "auto: silent > ttl, threat appears gone" --auto --base "$BASE" $DRY_FLAG
  fi
done || true

# Entries with no observation history are NOT auto-demoted (stale=False); surface
# them so a human can check, since the autopilot deliberately won't act on them.
UNKNOWN="$(_fps "$STALE_JSON" "[s['fp'] for s in d.get('stale',[]) if s.get('unknown')]" | wc -l | tr -d ' ')"
if [ "${UNKNOWN:-0}" != 0 ]; then
  echo "note: $UNKNOWN catalog entr(y/ies) have no observation history — left for human review, not auto-demoted"
fi
echo "=== autopilot done ==="
