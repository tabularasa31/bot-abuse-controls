#!/usr/bin/env bash
# antibot-analytics — ONE pass, then exit. Scheduling is external (host cron at
# 08:00, see docs/runbooks/blocklist-promotion.md), so the container does not
# loop or sleep — the standard cron-driven one-shot pattern:
#   docker compose -f docker-compose.backend.yml --profile observability run --rm analytics
# The host autopilot (scripts/blocklist-autopilot.sh) reads the artifacts this
# writes; schedule it from its own cron after this pass.
set -uo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/run.sh"
