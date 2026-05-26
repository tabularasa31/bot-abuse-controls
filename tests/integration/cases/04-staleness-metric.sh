#!/usr/bin/env bash
# B13 case 4 — staleness gauge grows on backend outage.
#
# Contract: antibot_edge_catalog_staleness_seconds{catalog="<name>"} is
# bumped to 0 on every successful pull (200 or 304); when the backend
# is unreachable, the gauge grows monotonically. Alerts on the prod-edge
# side fire on this gauge (config-distribution §"drives alerting").
#
# Test shape: scrape /metrics → record current age → stop backend →
# wait 5s → scrape again → assert the gauge for the `policy` catalog
# grew by at least 4s (one-second slack for jitter). Restore backend.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

# Invoked by EXIT trap below; shellcheck can't see that call.
# shellcheck disable=SC2329
cleanup() {
    compose_start_svc backend || true
}
trap cleanup EXIT

# extract_age — print the current age (seconds) from /metrics for the
# `policy` catalog. Empty output if the line is missing.
extract_age() {
    edge_curl --max-time 3 "${EDGE_URL}/metrics" \
        | awk -F'} ' '/antibot_edge_catalog_staleness_seconds\{catalog="policy"\}/ { print $2 }' \
        | head -n1
}

# 1. Baseline: ensure the gauge is healthy (≥0 and small) before we stop
# the backend. A small initial value confirms catalog_pull is wired and
# has been bumping. -1 means cold-start: wait a couple of pull ticks.
echo "Baseline staleness gauge..."
for _ in 1 2 3 4 5; do
    base="$(extract_age || true)"
    if [ -n "$base" ] && [ "$base" -ne -1 ]; then break; fi
    sleep 1
done
if [ -z "$base" ]; then
    echo "FAIL: gauge antibot_edge_catalog_staleness_seconds{catalog=\"policy\"} missing from /metrics"
    exit 1
fi
if [ "$base" -eq -1 ]; then
    echo "FAIL: gauge still at -1 (no successful pull yet) — harness sequencing issue"
    exit 1
fi
echo "  baseline = ${base}s"

# 2. Stop backend.
echo "Stopping backend..."
compose_stop_svc backend

# 3. Wait long enough that the gauge MUST have grown if it's
# functioning. Edge pulls every 2s (test override); 5s = at least two
# missed ticks. The gauge is `now - last_successful_pull_ts`, so it
# advances by wall time regardless of pull cadence — pull cadence only
# matters for when it RESETS.
echo "Sleeping 5s while backend is down..."
sleep 5

# 4. Re-scrape and compare.
after="$(extract_age || true)"
if [ -z "$after" ]; then
    echo "FAIL: gauge missing after backend stop"
    exit 1
fi
if [ "$after" -eq -1 ]; then
    echo "FAIL: gauge regressed to -1 — should only happen at worker start, not after stop"
    exit 1
fi

delta=$((after - base))
echo "  after stop = ${after}s (delta = ${delta}s)"

# Allow some slack: at minimum the wall-clock 5s sleep MINUS one
# second for jitter (script timing isn't monotonic-precise; backend
# stop takes a moment to take effect; the metric scrape itself is
# instantaneous but the baseline scrape was a few ms earlier).
if [ "$delta" -lt 4 ]; then
    echo "FAIL: gauge did not grow as expected (delta=${delta}s, need ≥4s after 5s outage)"
    exit 1
fi

exit 0
