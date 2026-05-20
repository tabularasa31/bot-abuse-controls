#!/usr/bin/env bash
# Pull latest main and hot-reload the demo edge without dropping traffic.
#
# Safe to run from cron every minute: it no-ops when main hasn't moved,
# validates the nginx config before reloading, and never leaves the live
# stand on a broken config.
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

# Single-flight: don't let overlapping cron ticks race on git/reload.
exec 9>"${TMPDIR:-/tmp}/abuse-controls-update.lock"
flock -n 9 || { echo "$(date -Is) another update in progress, skip"; exit 0; }

git fetch -q origin "$BRANCH"

local_sha="$(git rev-parse HEAD)"
remote_sha="$(git rev-parse "origin/${BRANCH}")"

if [ "$local_sha" = "$remote_sha" ]; then
  exit 0   # nothing to do
fi

echo "$(date -Is) updating ${local_sha:0:7} -> ${remote_sha:0:7}"

# Fast-forward only. If history diverged (someone hand-edited on the VM),
# bail loudly rather than clobber local state.
git merge --ff-only "origin/${BRANCH}"

# Validate config inside the running container BEFORE reloading. A bad
# config must not take the live stand down.
if ! docker compose -f "$COMPOSE_FILE" exec -T "$SERVICE" openresty -t; then
  echo "$(date -Is) ERROR: openresty -t failed on ${remote_sha:0:7}, NOT reloading" >&2
  exit 1
fi

docker compose -f "$COMPOSE_FILE" exec -T "$SERVICE" openresty -s reload
echo "$(date -Is) reloaded ${remote_sha:0:7}"
