#!/usr/bin/env bash
# Pull latest main and hot-reload the demo edge without dropping traffic.
#
# Safe to run from cron every minute: it no-ops once the current commit has
# been successfully reloaded, validates the nginx config before reloading,
# and never leaves the live stand on a broken config.
#
#   ./infra/demo-stand/scripts/update.sh
#
# Cron (every minute):
#   * * * * * /home/ubuntu/abuse-controls/infra/demo-stand/scripts/update.sh >> /home/ubuntu/abuse-controls/state/update.log 2>&1

set -euo pipefail

BRANCH="main"
COMPOSE_FILE="infra/demo-stand/docker-compose.demo.yml"
SERVICE="nginx-demo"

# Resolve repo root from this script's location, regardless of CWD.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

mkdir -p state
REVISION_FILE="infra/demo-stand/lua/.revision"   # served by /__version (gitignored)
MARKER="state/.last-reloaded-sha"                # last sha we successfully reloaded

# Single-flight: lock inside the repo (predictable perms, per-checkout
# isolation — avoids /tmp permission clashes between manual and cron runs).
exec 9>"state/update.lock"
flock -n 9 || { echo "$(date -Is) another update in progress, skip"; exit 0; }

git fetch -q origin "$BRANCH"
# Be explicit about the branch — don't ff-merge origin/main into whatever
# happens to be checked out.
git checkout -q "$BRANCH"
git merge --ff-only "origin/${BRANCH}"

head="$(git rev-parse HEAD)"
last="$(cat "$MARKER" 2>/dev/null || true)"

# No-op only if this exact commit was already reloaded successfully. We
# compare against the last SUCCESSFUL reload, not against the remote, so a
# transient `openresty -t`/reload failure is retried on the next tick even
# when no new commit has landed.
if [ "$head" = "$last" ]; then
  exit 0
fi

echo "$(date -Is) deploying ${head:0:7}"

# Most deploys are Lua/config edits, picked up by a zero-downtime `openresty
# -s reload` inside the running container (the source is bind-mounted). But the
# image itself carries native deps (libmaxminddb) and the compose file defines
# mounts/env — those only take effect by rebuilding the image and recreating
# the container. Detect when the build inputs changed since the last successful
# deploy and recreate in that case; otherwise hot-reload as before.
#
# First run (no marker) recreates to be safe — it guarantees the running
# container matches the current Dockerfile/compose.
recreate=0
if [ -z "$last" ]; then
  recreate=1
elif ! git diff --quiet "$last" "$head" -- \
      "infra/demo-stand/Dockerfile" "$COMPOSE_FILE"; then
  recreate=1
fi

if [ "$recreate" = "1" ]; then
  echo "$(date -Is) image/compose inputs changed — rebuilding + recreating ${SERVICE}"
  # Recreating the container drops its docker-json log history, which is where
  # the BAC_LOG request stream lives (analyze.py reads it via `docker logs`).
  # Snapshot that stream to a host file first so a rebuild deploy does not lose
  # accumulated data. Best-effort: a not-yet-created container or empty log just
  # leaves no archive. (Durable persistence is the telemetry-sink task, B9.)
  ARCHIVE_DIR="state/bac-archive"
  mkdir -p "$ARCHIVE_DIR"
  archive="${ARCHIVE_DIR}/$(date +%Y%m%dT%H%M%S)-${head:0:7}.log"
  if docker compose -f "$COMPOSE_FILE" logs --no-log-prefix "$SERVICE" \
       > "$archive" 2>/dev/null && [ -s "$archive" ]; then
    echo "$(date -Is) archived pre-recreate logs -> $archive"
  else
    rm -f "$archive"
  fi
  # `up -d --build` rebuilds the image and recreates the service only when its
  # definition or image changed. init_by_lua re-runs on the fresh container; a
  # bad config makes `up` exit non-zero, so the marker is not advanced and the
  # next tick retries.
  docker compose -f "$COMPOSE_FILE" up -d --build
else
  # Validate inside the running container BEFORE reloading. A bad config must
  # not take the live stand down.
  if ! docker compose -f "$COMPOSE_FILE" exec -T "$SERVICE" openresty -t; then
    echo "$(date -Is) ERROR: openresty -t failed on ${head:0:7}, NOT reloading" >&2
    exit 1
  fi
  docker compose -f "$COMPOSE_FILE" exec -T "$SERVICE" openresty -s reload
fi

# Reload succeeded: expose the live sha to /__version and record success so
# the next tick no-ops.
printf '%s\n' "${head:0:7}" > "$REVISION_FILE"
printf '%s\n' "$head" > "$MARKER"
echo "$(date -Is) reloaded ${head:0:7}"
