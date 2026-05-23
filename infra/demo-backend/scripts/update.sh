#!/usr/bin/env bash
# Pull latest main and redeploy the antibot-backend demo stack.
#
# Safe to run from cron every minute: no-ops once the current commit has
# been successfully deployed, single-flight via flock, refuses to merge over
# local commits, and never advances the marker on a failed build/up.
#
#   ./infra/demo-backend/scripts/update.sh
#
# Cron (every minute):
#   * * * * * /home/ubuntu/abuse-controls/infra/demo-backend/scripts/update.sh \
#       >> /home/ubuntu/abuse-controls/state/backend-update.log 2>&1
#
# Per-deploy local overrides (single-backend, custom allowlist, etc.) live in
# infra/demo-backend/docker-compose.override.yml (gitignored). Compose merges
# it automatically with the committed docker-compose.backend.yml on every
# `up -d`, so the override survives every auto-pull without touching the
# tracked tree. See infra/demo-backend/README.md "Local override".

set -euo pipefail

BRANCH="main"
COMPOSE_FILE="infra/demo-backend/docker-compose.backend.yml"

# Build-input set: any change here triggers a rebuild + recreate. Docs,
# READMEs, scripts/, .gitignore changes do NOT — those are inert at runtime
# and a no-op redeploy would be a waste.
BUILD_INPUTS=(
    "antibot-backend"                       # Go service source — image rebuild
    "infra/demo-backend/docker-compose.backend.yml"
    "infra/demo-backend/nginx"              # lb.conf (TLS / auth.conf include)
    "infra/demo-backend/auth"               # auth.conf templates + allow.list
)

# Resolve repo root from this script's location, regardless of CWD.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

mkdir -p state
MARKER="state/.backend-last-deployed-sha"

# Single-flight: lock inside the repo (predictable perms, per-checkout
# isolation — avoids /tmp permission clashes between manual and cron runs).
exec 9>"state/backend-update.lock"
flock -n 9 || { echo "$(date -Is) another backend-update in progress, skip"; exit 0; }

git fetch -q origin "$BRANCH"
# Be explicit about the branch — don't ff-merge origin/main into whatever
# happens to be checked out.
git checkout -q "$BRANCH"
git merge --ff-only "origin/${BRANCH}"

head="$(git rev-parse HEAD)"
last="$(cat "$MARKER" 2>/dev/null || true)"

# No-op only if this exact commit was already deployed successfully. Marker
# advances at end of script — a transient build/up failure leaves it stale
# so the next tick retries.
if [ "$head" = "$last" ]; then
  exit 0
fi

echo "$(date -Is) backend: head=${head:0:7} last=${last:0:7}"

# First run (no marker): always redeploy. Otherwise only redeploy when a
# build-input path actually changed; doc/README-only commits are no-ops.
redeploy=0
if [ -z "$last" ]; then
  redeploy=1
elif ! git diff --quiet "$last" "$head" -- "${BUILD_INPUTS[@]}"; then
  redeploy=1
fi

if [ "$redeploy" = "1" ]; then
  echo "$(date -Is) backend: build inputs changed, redeploying"
  # `up -d --build` rebuilds the Go service image when antibot-backend/
  # changed and recreates only the services whose image/config differs.
  # Postgres volume is named (pgdata) — survives recreates. lb config /
  # auth templates / certs are bind-mounted, so a compose `up` picks them
  # up without an explicit force-recreate.
  #
  # Override handling (gemini-review): `docker compose -f <file>` DISABLES
  # the automatic discovery of `docker-compose.override.yml` that the
  # bare `docker compose` command would do. We MUST pass the override
  # explicitly via a second `-f` for it to take effect — otherwise the
  # per-deploy customisations promised in README "Local override" would
  # silently never apply.
  compose_args=("-f" "$COMPOSE_FILE")
  override="infra/demo-backend/docker-compose.override.yml"
  if [ -f "$override" ]; then
    compose_args+=("-f" "$override")
  fi
  if ! docker compose "${compose_args[@]}" up -d --build; then
    echo "$(date -Is) backend: ERROR compose up failed, NOT advancing marker" >&2
    exit 1
  fi
else
  echo "$(date -Is) backend: only docs/scripts changed, no redeploy"
fi

# Deploy succeeded (or was a noop): record the sha so the next tick no-ops.
printf '%s\n' "$head" > "$MARKER"
echo "$(date -Is) backend: deployed ${head:0:7}"
