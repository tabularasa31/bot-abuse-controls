#!/usr/bin/env bash
# B13 case 3 — fail-stale on backend outage.
#
# Contract: when antibot-backend is unreachable, the edge keeps serving
# the LAST successfully pulled policy indefinitely. Requests never block
# on the backend; staleness shows up in the staleness gauge (case 04)
# but the cascade keeps working (vision.md §«при недоступности
# бэкенда»).
#
# Test shape: PATCH mode=active → wait for the edge to see it → docker
# compose stop backend → assert /__policy STILL returns mode=active for
# ~10s, and that /__health still answers fast (no synchronous wait on
# the dead backend). Restart backend at the end so case 04 has a live
# stack to work with (it does its own stop/restart cycle).

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

# Invoked by EXIT trap below; shellcheck can't see that call.
# shellcheck disable=SC2329
cleanup() {
    echo "  cleanup: ensure backend is running"
    compose_start_svc backend || true
    # Wait a couple of seconds for healthcheck to settle so case 04
    # doesn't see a transient outage.
    sleep 3
    dash_patch '{"mode":"shadow"}' >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Plant a known policy and wait for the edge to see it (same poll
# pattern as case 01).
echo "PATCH policy/${TEST_HOST} mode=active"
dash_patch '{"mode":"active","strictness":"standard"}' \
    || { echo "  PATCH failed"; exit 1; }

# Invoked indirectly via poll_until; shellcheck can't see the call.
# shellcheck disable=SC2329
check_edge_active() {
    local body
    body="$(edge_curl "${EDGE_URL}/__policy?host=${TEST_HOST}")" || return 1
    echo "$body" | grep -q '"mode":"active"'
}
if ! poll_until 10 check_edge_active; then
    echo "FAIL: edge did not see mode=active before stopping backend"
    exit 1
fi
echo "  edge picked up active policy"

# 2. Stop the backend container.
echo "Stopping backend..."
compose_stop_svc backend

# 3. /__policy must STILL return mode=active for the affected host.
# Hit it 5 times across 5 seconds; even a single shadow / non-200
# response is a contract violation.
echo "Verifying edge keeps last-good policy without backend..."
for i in 1 2 3 4 5; do
    sleep 1
    body="$(edge_curl --max-time 3 "${EDGE_URL}/__policy?host=${TEST_HOST}")" || {
        echo "FAIL: /__policy curl error on probe $i — edge may be blocking on dead backend"
        exit 1
    }
    if ! echo "$body" | grep -q '"mode":"active"'; then
        echo "FAIL: probe $i: edge lost mode=active"
        echo "  body: $body"
        exit 1
    fi
done
echo "  all 5 probes returned mode=active (fail-stale OK)"

# 4. /__health must answer fast (no synchronous wait on backend). The
# /__health endpoint itself doesn't touch backend, but if the edge
# worker were blocked elsewhere by a synchronous backend call, even
# /__health would time out. 1s budget is generous.
if ! edge_curl --max-time 1 "${EDGE_URL}/__health" >/dev/null 2>&1; then
    echo "FAIL: /__health did not respond within 1s — edge is blocking somewhere"
    exit 1
fi
echo "  /__health responsive within 1s (no synchronous backend dependency)"

exit 0
