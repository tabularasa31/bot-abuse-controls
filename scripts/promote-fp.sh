#!/usr/bin/env bash
# promote-fp.sh — promote a TLS fingerprint into catalogs/tls_fp_blocklist.yaml
# via a reviewable PR, with an evidence "passport" in the entry comment.
#
#   scripts/promote-fp.sh <fp> --reason "one-liner" [opts]   # add as staging
#   scripts/promote-fp.sh <fp> --activate [--reason "..."]    # staging -> active
#
# Lifecycle (A11): promote defaults to status=staging (matches in staging_match,
# does NOT block) → observe → --activate flips to active after the staging
# observation confirms zero false positives. See docs/blocklist-scoring.md.
#
# Options:
#   --reason "X"        why (goes into the passport + PR; required unless --activate)
#   --status staging|active   target status for a fresh promote (default staging)
#   --activate          flip an existing staging entry to active (uses §D observation)
#   --ttl-days N        advisory review-by = today+N in the passport (default 14)
#   --force-low-volume  promote despite the volume gate (operator override)
#   --force             override safety guards: the staging-observation verdict
#                       guard on --activate, and the "fp absent from candidates.json
#                       → gates unverifiable" refusal on a fresh promote
#   --auto              open the PR as a draft (autopilot mode; never auto-merge)
#   --dry-run           show the catalog diff + PR body, change nothing
#   --base BRANCH       PR base branch (default main)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/blocklist_common.sh
source "$HERE/lib/blocklist_common.sh"

FP=""; REASON=""; STATUS="staging"; ACTIVATE=0; TTL_DAYS=14
FORCE_LOW_VOLUME=0; FORCE=0; AUTO=0; DRY=0; BASE="main"
while [ $# -gt 0 ]; do
  case "$1" in
    --reason) REASON="$2"; shift 2;;
    --status) STATUS="$2"; shift 2;;
    --activate) ACTIVATE=1; shift;;
    --ttl-days) TTL_DAYS="$2"; shift 2;;
    --force-low-volume) FORCE_LOW_VOLUME=1; shift;;
    --force) FORCE=1; shift;;
    --auto) AUTO=1; shift;;
    --dry-run) DRY=1; shift;;
    --base) BASE="$2"; shift 2;;
    -h|--help) sed -n '2,30p' "$0"; exit 0;;
    -*) bl_die "unknown option: $1";;
    *) if [ -z "$FP" ]; then FP="$1"; else bl_die "unexpected arg: $1"; fi; shift;;
  esac
done
[ -n "$FP" ] || bl_die "usage: promote-fp.sh <fp> --reason \"X\" [opts]"
bl_resolve "$HERE"
bl_validate_fp "$FP"
TODAY="$(bl_today)"
SHORT="$(echo "$FP" | tr -cd 'A-Za-z0-9' | cut -c1-16)"
DRAFT=false; [ "$AUTO" = 1 ] && DRAFT=true
BODY="$(mktemp)"; trap 'rm -f "$BODY"' EXIT

apply_and_open() {  # branch subject title passport_comment editor_cmd...
  local branch="$1" subject="$2" title="$3"; shift 3
  local editor_args=("$@")
  if [ "$DRY" = 1 ]; then
    python3 "$EDITOR_PY" --file "$CATALOG" "${editor_args[@]}" >/dev/null
    echo "=== catalog diff (dry-run) ==="; git -C "$REPO" --no-pager diff -- "$CATALOG" || true
    git -C "$REPO" checkout -- "$CATALOG"
    echo "=== PR body (dry-run) ==="; cat "$BODY"
    echo "=== (dry-run) no branch/commit/PR created ==="
    return 0
  fi
  bl_branch_exists "$branch" && bl_die "branch $branch already exists — PR likely open already"
  bl_start_branch "$branch" "$BASE"           # fork clean off origin/$BASE
  python3 "$EDITOR_PY" --file "$CATALOG" "${editor_args[@]}"
  bl_validate_catalog
  bl_commit_catalog "$subject" "$(cat "$BODY")"
  bl_open_pr "$branch" "$BASE" "$title" "$BODY" "$DRAFT"
  bl_restore_base "$BASE"
}

# ---------------------------------------------------------------------------
# Pull evidence from candidates.json (best-effort; "manual" if not present).
SCORE="$(bl_cand_field "$FP" "c['score']")"
TIER="$(bl_cand_field "$FP" "c['tier']")"
REASONS="$(bl_cand_field "$FP" "' / '.join(c['reasons'])")"
HS="$(bl_cand_field "$FP" "c['human_share']")"
IPS="$(bl_cand_field "$FP" "c['ips'][:5]")"
NDAYS="$(bl_cand_field "$FP" "len(c['days_seen'])")"
LIFE="$(bl_cand_field "$FP" "c['n_lifetime']")"
UA="$(bl_cand_field "$FP" "c['sample_ua']")"
PURITY_OK="$(bl_cand_field "$FP" "c['gates']['purity']")"
ALLOW_OK="$(bl_cand_field "$FP" "c['gates']['allowlist']")"
VOL_OK="$(bl_cand_field "$FP" "c['gates']['volume']")"
INTENT="$(bl_cand_field "$FP" "c['intent']")"
[ -n "$SCORE" ] && EVID="score $SCORE ($TIER) · $REASONS" || EVID="(manual — not in current candidate set)"

if [ "$ACTIVATE" = 1 ]; then
  # ---- staging -> active (confirmed by observation, §D) -------------------
  cur="$(bl_catalog_status "$FP")"
  [ "$cur" = "staging" ] || bl_die "cannot activate: $FP status is '${cur:-absent}', expected staging"
  VERDICT="$(bl_obs_field "$FP" "o['verdict']")"
  NMATCH="$(bl_obs_field "$FP" "o['n_matches']")"
  HS_OBS="$(bl_obs_field "$FP" "o['human_share']")"
  HOURS="$(bl_obs_field "$FP" "o['observed_hours']")"
  if [ "$FORCE" != 1 ]; then
    [ -n "$VERDICT" ] || bl_die "no staging observation for $FP (run analytics, or --force)"
    case "$VERDICT" in
      activate) ;;
      fp_caught) bl_die "staging caught legit traffic (human_share $HS_OBS / allowlist) — demote-fp.sh instead, do NOT activate";;
      *) bl_die "observation verdict '$VERDICT' — keep observing (need the activate verdict, or --force)";;
    esac
  fi
  NOTE="activated $TODAY: observed ${HOURS:-?}h / ${NMATCH:-?} matches / human_share ${HS_OBS:-?}${REASON:+ — $REASON}"
  cat > "$BODY" <<EOF
## Blocklist activate: \`$FP\` (staging → active)

**Action:** staging → active (starts emitting verdict=block)
**Reason:** ${REASON:-staging observation clean, promoting per A11}
**Observation (§D):** observed ${HOURS:-?}h · ${NMATCH:-?} matches · human_share ${HS_OBS:-?} · verdict \`${VERDICT:-forced}\`

### Lifecycle / rollback
- Rollback: \`scripts/demote-fp.sh $FP\` (active→staging) or git revert.
- Silent > ${TTL_DAYS}d → the automation will suggest a demote.
- SLA from the email to enforcement: ≤ 4 h.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
  apply_and_open "promote/fp-$SHORT-activate-$TODAY" \
    "blocklist: activate $FP (staging→active)" \
    "Blocklist activate: $FP (staging→active)" \
    set-status "$FP" active --note "$NOTE"
  exit 0
fi

# ---- fresh promote (default staging) --------------------------------------
[ -n "$REASON" ] || bl_die "--reason is required for a fresh promote"
[ "$STATUS" = "staging" ] || [ "$STATUS" = "active" ] || bl_die "--status must be staging|active"
cur="$(bl_catalog_status "$FP")"
[ -z "$cur" ] || bl_die "$FP already in catalog (status=$cur); use --activate or demote-fp.sh"

# Safety gates (vetoes hold even for a manual promote; volume is overridable).
if [ -n "$SCORE" ]; then
  [ "$PURITY_OK" = "false" ] && bl_die "purity veto: human_share $HS — fp has genuine-browser traffic, not safe to block"
  [ "$ALLOW_OK" = "false" ] && bl_die "allowlist/verified veto: fp touches whitelist/verified-bot — not safe to block"
  if [ "$VOL_OK" = "false" ] && [ "$FORCE_LOW_VOLUME" != 1 ]; then
    bl_die "volume gate: lifetime $LIFE / days $NDAYS below thresholds — pass --force-low-volume to override"
  fi
  [ "$INTENT" = "false" ] && bl_warn "no impersonator/recon intent — a shared tool fp may catch legitimate automation; consider ua_blacklist/ip_blocklist"
else
  # No candidate evidence → we cannot verify the purity/allowlist/volume vetoes.
  # Refuse by default so a real-browser fp can't be promoted unchecked; --force
  # is the explicit operator override.
  [ "$FORCE" = 1 ] || bl_die "fp not in candidates.json — cannot verify safety gates (purity/allowlist/volume). Re-run analytics so it appears, or pass --force to promote on operator judgement."
  bl_warn "fp not in candidates.json — promoting WITHOUT gate verification (--force, evidence: manual)"
fi

REVIEW_BY="$(python3 - "$TODAY" "$TTL_DAYS" <<'PY'
import sys, datetime
d = datetime.date.fromisoformat(sys.argv[1]) + datetime.timedelta(days=int(sys.argv[2]))
print(d.isoformat())
PY
)"
AUTO_TAG=""; [ "$AUTO" = 1 ] && AUTO_TAG=" (auto)"
PASSPORT="promoted ${TODAY}${AUTO_TAG} — reason: ${REASON}
${EVID}
human_share ${HS:-n/a} · events ${LIFE:-n/a} · review-by ${REVIEW_BY}"

cat > "$BODY" <<EOF
## Blocklist promote: \`$FP\` (→ $STATUS)

**Action:** add → status \`$STATUS\`$([ "$STATUS" = staging ] && echo "  (observation only, does not block)")
**Reason:** $REASON
**Score / Tier:** ${SCORE:-manual} / ${TIER:-—}
**Trigger:** $([ "$AUTO" = 1 ] && echo "auto" || echo "manual")

### Evidence chain
${REASONS:-(manual — not in current candidate set)}

### Promotion gates
- purity: human_share ${HS:-n/a} (≤ veto) → ${PURITY_OK:-n/a}
- volume: lifetime ${LIFE:-n/a}, days ${NDAYS:-n/a} → ${VOL_OK:-n/a}
- allowlist/verified → ${ALLOW_OK:-n/a}
- intent (impersonator|recon) → ${INTENT:-n/a}

### Context
- IPs (sample): ${IPS:-n/a}
- UA sample: \`${UA:-n/a}\`
- Source: analyze.py --candidates-json (Loki)

### Lifecycle / rollback
- staging → watch \`staging_match\` for ≥48 h (FP=0) → \`scripts/promote-fp.sh $FP --activate\`.
- Rollback: \`scripts/demote-fp.sh $FP\` or git revert (runbook catalog-rollback.md).
- Silent > ${TTL_DAYS}d → the automation will suggest a demote (active→staging→remove).
- SLA from the email to enforcement: ≤ 4 h.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF

apply_and_open "promote/fp-$SHORT-$TODAY" \
  "blocklist: promote $FP (→$STATUS)" \
  "Blocklist promote: $FP (→$STATUS)" \
  add "$FP" "$STATUS" --comment "$PASSPORT"
