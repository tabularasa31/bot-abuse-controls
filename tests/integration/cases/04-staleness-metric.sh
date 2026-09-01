#!/usr/bin/env bash
# B13 case 4 — staleness gauge grows on backend outage.
#
# Contract: catalog staleness (seconds since the last successful pull, 200 or
# 304) resets to ~0 on every successful pull and grows monotonically while the
# backend is unreachable. Alerts on the edge side fire on this signal
# (config-distribution §"drives alerting").
#
# Phase 1: the signal moved off the public /metrics Prometheus gauge to the
# private mgmt plane's /__stats JSON (`catalog_staleness_seconds.<name>`), same
# value pushed as EDGE_STATS to Loki. Test shape: read /__stats → record the
# `policy` catalog age → stop backend → wait 5s → read again → assert it grew
# by at least 3s. Restore backend.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/integration/lib.sh
. "$HERE/../lib.sh"

# Invoked by EXIT trap below; shellcheck can't see that call.
# shellcheck disable=SC2329
cleanup() {
    compose_start_svc backend || true
}
trap cleanup EXIT

# extract_age — print the current staleness (seconds) for the `policy` catalog
# from the mgmt plane's /__stats JSON: catalog_staleness_seconds.policy, an
# integer (now - last_pull_ts) or -1 if never pulled. We FIRST isolate the
# catalog_staleness_seconds object, THEN grep policy inside it — `policy` also
# appears as a key under version_mismatch{} when a mismatch has occurred, so an
# un-anchored grep over the whole document could read the wrong number. The
# staleness object is flat (int values, no nested braces), so `\{[^}]*\}` captures
# it exactly. No jq dependency (matching the other cases). Empty if missing.
extract_age() {
    mgmt_curl --max-time 3 "${EDGE_MGMT_URL}/__stats" \
        | grep -oE '"catalog_staleness_seconds":\{[^}]*\}' \
        | grep -oE '"policy":-?[0-9]+' \
        | head -n1 \
        | sed 's/.*://'
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
    echo "FAIL: catalog_staleness_seconds.policy missing from /__stats"
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

# Slack of 2s on a 5s sleep. The gauge formula `now - last_pull_ts`
# means baseline+delta could be off by up to one pull interval (2s)
# depending on where the baseline scrape lands in the pull cycle.
# Earlier `delta >= 4` left only 1s of slack and started flaking on
# warm GH runners where the baseline scrape happened just before a
# successful pull bumped the gauge to 0. `>= 3` keeps the test
# faithful (we're asserting "gauge grows on outage", not "gauge
# matches wall-clock exactly") while leaving headroom for the
# steady-state pull jitter.
if [ "$delta" -lt 3 ]; then
    echo "FAIL: gauge did not grow as expected (delta=${delta}s, need ≥3s after 5s outage)"
    exit 1
fi

exit 0
