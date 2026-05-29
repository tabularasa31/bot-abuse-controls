#!/usr/bin/env bash
# Shared helpers for the blocklist promotion tooling (promote-fp.sh,
# demote-fp.sh, blocklist-autopilot.sh). Source this; callers set `set -euo
# pipefail` themselves.
#
# The tooling runs host-side on the backend+obs VM: it reads the JSON artifacts
# the analytics container wrote to state/ (candidates.json / staging-observation
# .json / stale.json — computed from Loki) and the git checkout, then edits the
# catalog and opens a PR. It does NOT talk to Loki directly.

bl_die() { echo "blocklist: $*" >&2; exit 1; }
bl_warn() { echo "blocklist: $*" >&2; }

# Populate REPO / CATALOG / EDITOR / STATE_DIR / artifact paths. STATE_DIR is
# overridable (the analytics container may mount state elsewhere).
bl_resolve() {
  REPO="$(git -C "${1:-$PWD}" rev-parse --show-toplevel 2>/dev/null)" \
    || bl_die "not in a git repo (run inside the abuse-controls checkout)"
  CATALOG="$REPO/catalogs/tls_fp_blocklist.yaml"
  EDITOR_PY="$REPO/scripts/lib/blocklist_catalog.py"
  STATE_DIR="${STATE_DIR:-$REPO/state}"
  CANDIDATES="${CANDIDATES_JSON:-$STATE_DIR/candidates.json}"
  STAGING_OBS="${STAGING_OBS_JSON:-$STATE_DIR/staging-observation.json}"
  STALE_JSON="${STALE_JSON:-$STATE_DIR/stale.json}"
  [ -f "$EDITOR_PY" ] || bl_die "missing $EDITOR_PY"
}

# fp token format (infra/demo-stand/lua/ja4_compute.lua).
bl_validate_fp() {
  echo "$1" | grep -Eq '^L[0-9A-Za-z]+_[0-9a-f]+_[0-9a-f]+$' \
    || bl_die "malformed fp: $1"
}

# Echo the catalog status of an fp (active|staging) or empty if absent.
bl_catalog_status() {
  python3 "$EDITOR_PY" --file "$CATALOG" status "$1" 2>/dev/null || true
}

# Run the same loader CI uses; abort on failure so we never commit a catalog the
# backend would reject. Skippable for offline tests (BL_SKIP_VALIDATE=1) or when
# go is absent (CI still gates the PR).
bl_validate_catalog() {
  [ "${BL_SKIP_VALIDATE:-0}" = "1" ] && { bl_warn "validate skipped (BL_SKIP_VALIDATE=1)"; return 0; }
  command -v go >/dev/null 2>&1 || { bl_warn "go not found — skipping local validate (CI will gate)"; return 0; }
  ( cd "$REPO/antibot-backend" && go run ./cmd/validate-catalogs "$REPO/catalogs" ) >/dev/null \
    || bl_die "validate-catalogs failed — catalog would break the backend"
}

# Print one field of the candidate for <fp> from candidates.json, or empty.
# Usage: bl_cand_field <fp> <python-expr over `c`>
bl_cand_field() {
  local fp="$1" expr="$2"
  [ -f "$CANDIDATES" ] || { echo ""; return 0; }
  python3 - "$CANDIDATES" "$fp" "$expr" <<'PY'
import json, sys
path, fp, expr = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(path))
except Exception:
    sys.exit(0)
for c in d.get("high", []) + d.get("medium", []) + d.get("low", []):
    if c.get("fp") == fp:
        try:
            v = eval(expr, {}, {"c": c})
        except Exception:
            sys.exit(0)
        if isinstance(v, bool):
            print("true" if v else "false")
        elif isinstance(v, (list, tuple)):
            print(", ".join(str(x) for x in v))
        else:
            print(v)
        break
PY
}

# Print one field of the staging observation for <fp>, or empty.
bl_obs_field() {
  local fp="$1" expr="$2"
  [ -f "$STAGING_OBS" ] || { echo ""; return 0; }
  python3 - "$STAGING_OBS" "$fp" "$expr" <<'PY'
import json, sys
path, fp, expr = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(path))
except Exception:
    sys.exit(0)
for o in d.get("observations", []):
    if o.get("fp") == fp:
        v = eval(expr, {}, {"o": o})
        print("true" if v is True else "false" if v is False else v)
        break
PY
}

bl_today() { date -u +%Y-%m-%d; }

# Does a branch already exist (local or on origin)? Keeps the autopilot from
# opening duplicate PRs for the same fp.
bl_branch_exists() {
  local b="$1"
  git -C "$REPO" rev-parse --verify --quiet "refs/heads/$b" >/dev/null 2>&1 && return 0
  git -C "$REPO" ls-remote --exit-code --heads origin "$b" >/dev/null 2>&1 && return 0
  return 1
}

# Create branch, stage the catalog, commit. Args: branch, commit-subject, body.
bl_commit() {
  local branch="$1" subject="$2" body="$3"
  git -C "$REPO" checkout -b "$branch" >/dev/null
  git -C "$REPO" add "$CATALOG"
  git -C "$REPO" commit -q -m "$subject" -m "$body" \
    -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
}

# Push + open PR. Args: branch, base, title, body-file, draft(bool).
bl_open_pr() {
  local branch="$1" base="$2" title="$3" bodyfile="$4" draft="$5"
  git -C "$REPO" push -u origin "$branch" >/dev/null 2>&1 \
    || bl_die "git push failed (check remote/credentials on this host)"
  command -v gh >/dev/null 2>&1 || bl_die "gh CLI not found — cannot open PR"
  local args=(pr create --base "$base" --head "$branch" --title "$title" --body-file "$bodyfile")
  [ "$draft" = "true" ] && args+=(--draft)
  ( cd "$REPO" && gh "${args[@]}" )
}
