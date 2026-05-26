#!/usr/bin/env bash
# Shared helpers for integration test cases. Sourced, not executed.
#
# Stack endpoints (loopback only — see docker-compose.test.yml):
#   * backend (Channel C + dashboard API) on http://127.0.0.1:18080
#   * edge (cascade + /__policy + /metrics)  on https://127.0.0.1:18443
#
# Bearer token is hardcoded — only valid inside this CI harness, never
# matches production tokens.

set -u

# Cases reference BACKEND_URL / EDGE_URL after sourcing — shellcheck
# doesn't see that without `-x`, and even with `-x` SC2034 still fires
# on lib.sh because the file alone doesn't use them. Explicit disable.
# shellcheck disable=SC2034
BACKEND_URL="${BAC_TEST_BACKEND_URL:-http://127.0.0.1:18080}"
# shellcheck disable=SC2034
EDGE_URL="${BAC_TEST_EDGE_URL:-https://127.0.0.1:18443}"
DASH_TOKEN="test-token-not-secret"

# Host used by tests when querying /__policy?host=...
# Matches catalog.PoolDefault rules — backend stores the row keyed by
# the path param as-is, edge lowercases via policy.canonical_host.
TEST_HOST="test-client.example.com"

# Compose project name from docker-compose.test.yml's `name:` field. Used
# by docker compose commands when invoked from anywhere (lib.sh doesn't
# `cd` into infra/test-harness — cases run from $PWD-agnostic state).
COMPOSE_PROJECT="bac-test"
COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../infra/test-harness" && pwd)/docker-compose.test.yml"

# curl-on-edge: skip verify (self-signed cert), resolve Host inside URL
# via --resolve so the cert's SAN can be a fake hostname. Output STDOUT;
# the caller captures or pipes as needed.
edge_curl() {
    curl --silent --show-error --insecure --max-time 5 \
         --resolve "${TEST_HOST}:18443:127.0.0.1" \
         "$@"
}

# Dashboard API PATCH — Bearer-authed, mergepatch+json. Pass JSON body
# as $1, host as $2. --max-time keeps a hung backend from stalling the
# whole test (the failure path is documented: load tests run a tight
# loop and would otherwise wedge on a dead backend).
dash_patch() {
    local body="$1"
    local host="${2:-$TEST_HOST}"
    curl --silent --show-error --fail --max-time 5 \
         -X PATCH \
         -H "Authorization: Bearer ${DASH_TOKEN}" \
         -H "Content-Type: application/merge-patch+json" \
         --data "$body" \
         "${BACKEND_URL}/antibot/v1/policy/${host}"
}

# Poll until `pred` returns 0 (success) or timeout (seconds) elapses.
# Prints elapsed seconds on success. Returns 1 on timeout — case will
# fail and the runner reports it. Logs `pred`'s stderr at the end on
# failure so we get the last attempt's curl error.
poll_until() {
    local timeout="$1"
    local pred_fn="$2"
    local start
    start="$(date +%s)"
    local last_err=""
    while :; do
        if last_err="$($pred_fn 2>&1)"; then
            echo "  -> match after $(( $(date +%s) - start ))s"
            return 0
        fi
        if [ "$(( $(date +%s) - start ))" -ge "$timeout" ]; then
            echo "  -> timeout after ${timeout}s"
            echo "  last attempt error: ${last_err}"
            return 1
        fi
        sleep 1
    done
}

# Stop a compose service without removing it (so we can start it again).
# `-t 0` skips the SIGTERM grace period and sends SIGKILL immediately:
# fail-stale tests need the backend gone NOW, not in 10s. Without this
# the staleness gauge test (case 04) can fail because the backend keeps
# serving pulls during graceful shutdown, resetting the gauge while
# we're trying to measure it grow.
compose_stop_svc() {
    docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT" stop -t 0 "$1" >/dev/null
}

compose_start_svc() {
    docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT" start "$1" >/dev/null
}
