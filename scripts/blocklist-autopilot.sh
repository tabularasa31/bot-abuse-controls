#!/usr/bin/env bash
# blocklist-autopilot.sh — cron driver that turns the analytics artifacts into
# DRAFT PRs in both directions. It NEVER merges and NEVER opens a non-draft PR;
# a human reviews and merges. Idempotent: a deterministic branch name per fp +
# the promote/demote branch-exists guard means a re-run won't duplicate PRs.
#
#   blocklist-autopilot.sh [--dry-run] [--base BRANCH] [--include-unknown]
#
# Reads (written by the antibot-analytics container from Loki):
#   state/candidates.json          → auto-promote eligible HIGH (intent ✓, gates ✓)
#   state/staging-observation.json → staging entries whose verdict == activate
#   state/stale.json               → entries silent > ttl → auto-demote (active→staging)
#
# Cron (backend VM), after the analytics run writes the artifacts:
#   30 8 * * * /home/ubuntu/abuse-controls/scripts/blocklist-autopilot.sh >> ~/autopilot.log 2>&1
set -euo pipefail   # -e guards init (source/resolve); run() OR-lists keep a single
                    # skipped/failed fp from aborting the sweep.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/blocklist_common.sh
source "$HERE/lib/blocklist_common.sh"

DRY_FLAG=""; BASE="main"; INCLUDE_UNKNOWN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_FLAG="--dry-run"; shift;;
    --base) BASE="$2"; shift 2;;
    --include-unknown) INCLUDE_UNKNOWN=1; shift;;
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

echo "--- auto-demote (silent > ttl) ---"
if [ "$INCLUDE_UNKNOWN" = 1 ]; then
  STALE_EXPR="[s['fp'] for s in d.get('stale',[]) if s.get('stale')]"
else
  STALE_EXPR="[s['fp'] for s in d.get('stale',[]) if s.get('stale') and not s.get('unknown')]"
fi
_fps "$STALE_JSON" "$STALE_EXPR" | while read -r fp; do
  run "$HERE/demote-fp.sh" "$fp" --reason "auto: silent > ttl, threat appears gone" --auto --base "$BASE" $DRY_FLAG
done || true

# Surface what we deliberately skipped, so silent caps aren't invisible.
SKIPPED="$(_fps "$STALE_JSON" "[s['fp'] for s in d.get('stale',[]) if s.get('unknown')]" | wc -l | tr -d ' ')"
if [ "${SKIPPED:-0}" != 0 ] && [ "$INCLUDE_UNKNOWN" != 1 ]; then
  echo "note: $SKIPPED stale entr(y/ies) with no observations skipped (pass --include-unknown to demote them)"
fi
echo "=== autopilot done ==="
