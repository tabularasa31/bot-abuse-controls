#!/usr/bin/env bash
# blocklist-autopilot.sh — cron driver that turns the daily Loki-analysis
# artifacts into ONE DRAFT PR per run (all matured changes batched into a single
# branch/PR). It NEVER merges and NEVER opens a non-draft PR; a human reviews and
# merges. Idempotent: one branch per day (blocklist-auto-YYYY-MM-DD) — a re-run
# that day no-ops on the branch-exists guard.
#
#   blocklist-autopilot.sh [--dry-run] [--base BRANCH]
#
# Reads (written by the antibot-analytics container from Loki):
#   state/candidates.json          → auto-promote eligible HIGH (intent ✓, gates ✓)
#   state/staging-observation.json → staging entries whose verdict == activate
#   state/stale.json               → silent > ttl → demote (active→staging, staging→remove)
# Entries with no observation history (unknown) are left for human review, not demoted.
#
# Cron (backend VM), after the analytics run writes the artifacts:
#   30 8 * * * /home/ubuntu/abuse-controls/scripts/blocklist-autopilot.sh >> ~/autopilot.log 2>&1
set -euo pipefail
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

# Freshness guard: if the analytics artifacts are stale (the analytics container
# is down, or the catalog was unreadable so emit() left yesterday's files in
# place), do NOT act on old data. Each artifact carries generated_utc.
MAX_AGE_H="${BAC_ARTIFACT_MAX_AGE_HOURS:-26}"
_artifact_age_h() {  # <file> → whole hours since generated_utc; 99999 if absent/unparseable
  [ -f "$1" ] || { echo 99999; return; }
  python3 - "$1" <<'PY'
import json, sys, datetime
try:
    g = json.load(open(sys.argv[1]))["generated_utc"]
    t = datetime.datetime.fromisoformat(g.replace("Z", "+00:00"))
    print(int((datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() // 3600))
except Exception:
    print(99999)
PY
}
AGE="$(_artifact_age_h "$CANDIDATES")"
if [ "$AGE" -gt "$MAX_AGE_H" ]; then
  echo "autopilot: candidates.json missing or ${AGE}h old (> ${MAX_AGE_H}h) — analytics may be down; skipping to avoid acting on stale data"
  exit 0
fi

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

echo "=== blocklist-autopilot $(date -u +%FT%TZ) ${DRY_FLAG:+[dry-run]} ==="

# Collect the day's actions from the artifacts (one list each).
PROMOTE="$(_fps "$CANDIDATES" "[c['fp'] for c in d.get('high',[]) if c.get('auto_eligible')]")"
ACTIVATE="$(_fps "$STAGING_OBS" "[o['fp'] for o in d.get('observations',[]) if o.get('verdict')=='activate']")"
DEMOTE="$(_pairs "$STALE_JSON" "[[s['fp'], s.get('status','active')] for s in d.get('stale',[]) if s.get('stale') and s.get('fp')]")"
UNKNOWN="$(_fps "$STALE_JSON" "[s['fp'] for s in d.get('stale',[]) if s.get('unknown')]" | grep -c . || true)"
# `held` = silent past ttl, but the hash_b family is still live under a rotated
# hash_c. Not auto-demoted (the bot just moved to a sibling fp) — held for human.
HELD_LINES="$(_fps "$STALE_JSON" "['%s — %s' % (s['fp'], s.get('reason','')) for s in d.get('stale',[]) if s.get('held')]")"
HELD="$(printf '%s' "$HELD_LINES" | grep -c . || true)"
n_p="$(printf '%s' "$PROMOTE" | grep -c . || true)"
n_a="$(printf '%s' "$ACTIVATE" | grep -c . || true)"
n_d="$(printf '%s' "$DEMOTE" | grep -c . || true)"
echo "eligible: promote=$n_p activate=$n_a demote=$n_d (unknown skipped=$UNKNOWN, held=$HELD)"

if [ -z "${PROMOTE}${ACTIVATE}${DEMOTE}" ]; then
  echo "autopilot: nothing eligible — no PR"
  [ "${UNKNOWN:-0}" != 0 ] && echo "note: $UNKNOWN entr(y/ies) without observation history — left for human review"
  [ "${HELD:-0}" != 0 ] && { echo "note: $HELD silent entr(y/ies) held — hash_b family still live under a rotated hash_c:"; printf '%s\n' "$HELD_LINES" | sed 's/^/  - /'; }
  exit 0
fi

TODAY="$(date -u +%F)"
BRANCH="blocklist-auto-$TODAY"
TITLE="Blocklist auto-update $TODAY"
BODY="$(mktemp)"; trap 'rm -f "$BODY"' EXIT
# review-by = $TODAY (UTC) + TTL. Parse $TODAY in Python so we don't mix it with
# the local-tz date.today() (codex: off-by-one across the UTC/local boundary).
REVIEW_BY="$(python3 -c "import datetime;print((datetime.date.fromisoformat('$TODAY')+datetime.timedelta(days=${BAC_TTL_DAYS:-14})).isoformat())")"

# Promote passport (YAML comment) from pre-fetched candidate fields — caller
# passes them so we don't re-spawn Python + re-parse candidates.json per field.
mk_passport() {  # <score> <tier> <reasons> <human_share> <n_lifetime>
  printf 'promoted %s (auto) — reason: stable HIGH, gates+intent passed\nscore %s (%s) · %s\nhuman_share %s · events %s · review-by %s\n' \
    "$TODAY" "$1" "$2" "$3" "$4" "$5" "$REVIEW_BY"
}

# All evidence fields for one fp in a SINGLE Python call (tab-separated).
cand_fields() {  # <fp> → score\ttier\treasons\thuman_share\tn_lifetime
  python3 - "$CANDIDATES" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for c in d.get("high", []) + d.get("medium", []) + d.get("low", []):
    if c.get("fp") == sys.argv[2]:
        print("\t".join([str(c.get("score", "")), str(c.get("tier", "")),
                         " / ".join(c.get("reasons", [])),
                         str(c.get("human_share", "")), str(c.get("n_lifetime", ""))]))
        break
PY
}

# Apply every action to the catalog on the current branch and fill the PR body.
apply_all() {
  {
    echo "## $TITLE"
    echo
    echo "Automated by \`blocklist-autopilot.sh\` from the daily Loki analysis. **Draft** — review each line before merge."
  } > "$BODY"
  if [ -n "$PROMOTE" ]; then
    { echo; echo "### Promote → staging"; } >> "$BODY"
    while IFS= read -r fp; do [ -z "$fp" ] && continue
      IFS=$'\t' read -r score tier reasons hs life <<< "$(cand_fields "$fp")"
      python3 "$EDITOR_PY" --file "$CATALOG" add "$fp" staging --comment "$(mk_passport "$score" "$tier" "$reasons" "$hs" "$life")" >/dev/null
      echo "- \`$fp\` — score $score $tier · $reasons" >> "$BODY"
    done <<< "$PROMOTE"
  fi
  if [ -n "$ACTIVATE" ]; then
    { echo; echo "### Activate → active (staging observation clean)"; } >> "$BODY"
    while IFS= read -r fp; do [ -z "$fp" ] && continue
      python3 "$EDITOR_PY" --file "$CATALOG" set-status "$fp" active --note "auto-activated $TODAY: staging observation clean" >/dev/null
      echo "- \`$fp\` — staging → active" >> "$BODY"
    done <<< "$ACTIVATE"
  fi
  if [ -n "$DEMOTE" ]; then
    { echo; echo "### Demote (silent > ttl)"; } >> "$BODY"
    while IFS= read -r line; do [ -z "$line" ] && continue
      local fp="${line%% *}" st="${line##* }"
      if [ "$st" = "staging" ]; then
        python3 "$EDITOR_PY" --file "$CATALOG" remove "$fp" >/dev/null
        echo "- \`$fp\` — staging → remove (silent)" >> "$BODY"
      else
        python3 "$EDITOR_PY" --file "$CATALOG" set-status "$fp" staging --note "auto-demoted $TODAY: silent > ttl" >/dev/null
        echo "- \`$fp\` — active → staging (silent)" >> "$BODY"
      fi
    done <<< "$DEMOTE"
  fi
  [ "${UNKNOWN:-0}" != 0 ] && { echo; echo "_$UNKNOWN catalog entr(y/ies) without observation history left for human review (not demoted)._"; } >> "$BODY"
  if [ "${HELD:-0}" != 0 ]; then
    { echo; echo "### Held (silent, but hash_b family still live under a rotated hash_c)";
      printf '%s\n' "$HELD_LINES" | sed 's/^/- `/; s/ — /` — /';
      echo; echo "_Not auto-demoted — review whether the family needs a hash_b entry in tls_fp_catalog._"; } >> "$BODY"
  fi
  echo >> "$BODY"; echo "🤖 Generated with [Claude Code](https://claude.com/claude-code)" >> "$BODY"
}

if [ -n "$DRY_FLAG" ]; then
  echo "=== would open ONE draft PR ($BRANCH) ==="
  # Revert the in-place catalog edits even if apply_all aborts mid-loop, so a
  # dry run never leaves the working tree dirty.
  trap 'git -C "$REPO" checkout -- "$CATALOG" 2>/dev/null || true; rm -f "$BODY"' EXIT
  apply_all
  echo "--- catalog diff ---"; git -C "$REPO" --no-pager diff -- "$CATALOG" || true
  git -C "$REPO" checkout -- "$CATALOG"
  echo "--- PR body ---"; cat "$BODY"
  echo "=== (dry-run) nothing created ==="
  exit 0
fi

# Idempotency: skip only if an OPEN PR for today's branch already exists. A
# pushed branch alone is NOT proof — `git push` and `gh pr create` are separate
# steps in bl_open_pr, so a push that succeeded while pr-create failed must not
# block the day. Clear any stale branch (local residue, or pushed-without-PR on
# origin) so the retry starts clean.
if [ "$( ( cd "$REPO" && gh pr list --head "$BRANCH" --state open --json number -q 'length' ) 2>/dev/null || echo 0)" -gt 0 ]; then
  echo "autopilot: open PR for $BRANCH already exists — skipping"; exit 0
fi
git -C "$REPO" branch -D "$BRANCH" >/dev/null 2>&1 || true
git -C "$REPO" push origin --delete "$BRANCH" >/dev/null 2>&1 || true

# From here we mutate the worktree. On ANY failure, revert the catalog and
# return to base so the next run starts clean (the stale local branch is
# cleared above next time). On success this is harmless (worktree already clean).
trap 'st=$?; rm -f "$BODY"; git -C "$REPO" checkout -- "$CATALOG" 2>/dev/null || true; bl_restore_base "$BASE" 2>/dev/null || true; exit $st' EXIT
bl_start_branch "$BRANCH" "$BASE"
apply_all
bl_validate_catalog
bl_commit_catalog "blocklist: auto-update $TODAY ($n_p promote / $n_a activate / $n_d demote)" "$(cat "$BODY")"
bl_open_pr "$BRANCH" "$BASE" "$TITLE" "$BODY" true
echo "=== autopilot done: one draft PR for $BRANCH ==="
