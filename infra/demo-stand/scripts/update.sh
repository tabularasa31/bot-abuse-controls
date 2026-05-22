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
NGINX_CONF="infra/demo-stand/nginx.demo.conf"
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
# -s reload` inside the running container (the lua/ and config/ DIRECTORY mounts
# reflect file replacements, so reload re-reads the fresh content). Three kinds
# of change can't be hot-reloaded and need a container recreate:
#   * Dockerfile   — native deps (libmaxminddb) baked into the image.
#   * compose file — mounts / env / ports.
#   * nginx.demo.conf — it is a SINGLE-FILE bind mount, and git's inode swap on
#     pull leaves the running container pinned to the OLD file. `openresty -s
#     reload` re-reads that stale in-container inode, so a new lua_shared_dict /
#     listen / etc. silently never appears. Only recreating re-resolves the
#     mount to the new file. (Discovered in prod: PR #32's rate_limit shared
#     dict never deployed until a manual restart.)
# Detect when any of these changed since the last successful deploy and recreate
# in that case; otherwise hot-reload as before.
#
# First run (no marker) recreates to be safe — it guarantees the running
# container matches the current Dockerfile/compose/nginx.conf.
recreate=0
if [ -z "$last" ]; then
  recreate=1
elif ! git diff --quiet "$last" "$head" -- \
      "infra/demo-stand/Dockerfile" "$COMPOSE_FILE" "$NGINX_CONF"; then
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
  # Name by the OUTGOING (currently running) sha — that's the version that
  # produced these logs — not the incoming $head we're deploying.
  outgoing="${last:0:7}"; [ -n "$outgoing" ] || outgoing="unknown"
  archive="${ARCHIVE_DIR}/$(date +%Y%m%dT%H%M%S)-${outgoing}.log"
  if docker compose -f "$COMPOSE_FILE" logs --no-log-prefix "$SERVICE" \
       > "$archive" 2>/dev/null && [ -s "$archive" ]; then
    echo "$(date -Is) archived pre-recreate logs -> $archive"
  else
    rm -f "$archive"
  fi
  # --force-recreate is required, not optional: a change to the bind-mounted
  # nginx.demo.conf alters neither the image nor the compose config, so a plain
  # `up -d` would see "no changes" and skip recreation — leaving the stale-inode
  # bug in place. We only reach this branch when a build input actually changed,
  # so forcing recreation here is intended (and a no-op-cost rebuild when only
  # nginx.conf changed, thanks to layer caching). init_by_lua re-runs on the
  # fresh container; a bad config makes `up` exit non-zero, so the marker is not
  # advanced and the next tick retries.
  docker compose -f "$COMPOSE_FILE" up -d --build --force-recreate
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
