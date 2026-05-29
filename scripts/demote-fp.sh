#!/usr/bin/env bash
# demote-fp.sh — the reverse of promote-fp.sh: soften or remove a TLS
# fingerprint from catalogs/tls_fp_blocklist.yaml via a reviewable PR.
#
#   scripts/demote-fp.sh <fp> --reason "X"            # active -> staging (default)
#   scripts/demote-fp.sh <fp> --reason "X" --remove   # delete the entry entirely
#
# Why not just `git revert`: revert targets a specific commit and conflicts once
# other fps were added after it. demote addresses the entry by fp key — surgical,
# conflict-free, audited. Default softens (active→staging, keep observing);
# --remove drops it. Used both by hand and by blocklist-autopilot.sh on stale fps.
#
# Options: --reason "X" (required) · --remove · --auto (draft PR) · --dry-run
#          · --base BRANCH (default main) · --force (demote even if already staging)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/blocklist_common.sh
source "$HERE/lib/blocklist_common.sh"

FP=""; REASON=""; REMOVE=0; AUTO=0; DRY=0; BASE="main"; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --reason) REASON="$2"; shift 2;;
    --remove) REMOVE=1; shift;;
    --auto) AUTO=1; shift;;
    --dry-run) DRY=1; shift;;
    --base) BASE="$2"; shift 2;;
    --force) FORCE=1; shift;;
    -h|--help) sed -n '2,17p' "$0"; exit 0;;
    -*) bl_die "unknown option: $1";;
    *) [ -z "$FP" ] && FP="$1" || bl_die "unexpected arg: $1"; shift;;
  esac
done
[ -n "$FP" ] || bl_die "usage: demote-fp.sh <fp> --reason \"X\" [--remove]"
[ -n "$REASON" ] || bl_die "--reason is required"
bl_resolve "$HERE"
bl_validate_fp "$FP"
TODAY="$(bl_today)"
SHORT="$(echo "$FP" | tr -cd 'A-Za-z0-9' | cut -c1-16)"
DRAFT=false; [ "$AUTO" = 1 ] && DRAFT=true
BODY="$(mktemp)"; trap 'rm -f "$BODY"' EXIT

cur="$(bl_catalog_status "$FP")"
[ -n "$cur" ] || bl_die "$FP not in catalog — nothing to demote"

if [ "$REMOVE" = 1 ]; then
  ACTION="remove (was $cur)"; SUBJECT="blocklist: remove $FP"; TITLE="Blocklist demote: $FP (remove)"
  EDITOR_ARGS=(remove "$FP")
else
  [ "$cur" = "active" ] || { [ "$FORCE" = 1 ] || bl_die "$FP is already '$cur'; use --remove to delete (or --force)"; }
  ACTION="active → staging (перестает блокировать, продолжает наблюдаться)"
  SUBJECT="blocklist: demote $FP (active→staging)"; TITLE="Blocklist demote: $FP (active→staging)"
  EDITOR_ARGS=(set-status "$FP" staging --note "demoted $TODAY: $REASON")
fi

cat > "$BODY" <<EOF
## Blocklist demote: \`$FP\`

**Action:** $ACTION
**Reason:** $REASON
**Trigger:** $([ "$AUTO" = 1 ] && echo "auto (stale/silent)" || echo "manual")

### Rollback
- Re-promote: \`scripts/promote-fp.sh $FP --reason "...":\` (staging) → \`--activate\`.
- Или git revert этого PR.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF

if [ "$DRY" = 1 ]; then
  python3 "$EDITOR_PY" --file "$CATALOG" "${EDITOR_ARGS[@]}" >/dev/null
  echo "=== catalog diff (dry-run) ==="; git -C "$REPO" --no-pager diff -- "$CATALOG" || true
  git -C "$REPO" checkout -- "$CATALOG"
  echo "=== PR body (dry-run) ==="; cat "$BODY"
  echo "=== (dry-run) no branch/commit/PR created ==="
  exit 0
fi
BRANCH="demote/fp-$SHORT-$TODAY"
bl_branch_exists "$BRANCH" && bl_die "branch $BRANCH already exists — PR likely open already"
python3 "$EDITOR_PY" --file "$CATALOG" "${EDITOR_ARGS[@]}"
bl_validate_catalog
bl_commit "$BRANCH" "$SUBJECT" "$(cat "$BODY")"
bl_open_pr "$BRANCH" "$BASE" "$TITLE" "$BODY" "$DRAFT"
