#!/usr/bin/env bash
# Long-running loop for antibot-analytics: one pass now, then every
# ANALYTICS_INTERVAL seconds (default 24h). Self-contained — no host cron. The
# host autopilot (scripts/blocklist-autopilot.sh) reads the artifacts this
# writes; run it from its own cron after this container's pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTERVAL="${ANALYTICS_INTERVAL:-86400}"
while true; do
  bash "$HERE/run.sh" || echo "[analytics] pass errored (continuing)"
  echo "[analytics] sleeping ${INTERVAL}s"
  sleep "$INTERVAL"
done
