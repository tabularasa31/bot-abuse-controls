#!/usr/bin/env bash
# B13 case 1 — delivery latency.
#
# Contract: a PATCH to /antibot/v1/policy/<host> is visible on the edge
# within ≤30s of commit (config-distribution §Channel C). The harness
# compresses both intervals (CATALOG_RELOAD_INTERVAL=1s, edge
# ANTIBOT_BACKEND_PULL_INTERVAL=2s) so the same chain that runs in
# production at 30s here completes in ~5s — same code path, smaller
# time constants. The assertion budget is 10s, ~3× the configured
# pull interval to absorb jitter.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/integration/lib.sh
. "$HERE/../lib.sh"

# Symmetric with cases 03/04: revert to shadow on exit so a failure
# here doesn't leave the row at mode=active and surprise the next
# case in a clean run. The case-02 atomic-swap test doesn't care
# about initial state (it alternates) but we keep the suite's
# between-case baseline predictable for future cases.
# shellcheck disable=SC2329
cleanup() {
    dash_patch '{"mode":"shadow"}' >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. PATCH a unique mode value so we know we're seeing the new state,
# not a leftover. mode=active is benign for /__policy (read-only view)
# but provides a clear pre/post signal vs the pool default mode=shadow.
echo "PATCH policy/${TEST_HOST} mode=active"
dash_patch '{"mode":"active","strictness":"standard"}' \
    || { echo "  PATCH failed"; exit 1; }

# 2. Poll /__policy until the mode flips to "active" on the edge.
# Invoked indirectly via poll_until; shellcheck can't see the call.
# shellcheck disable=SC2329
check_edge_active() {
    local body
    body="$(edge_curl "${EDGE_URL}/__policy?host=${TEST_HOST}")" || return 1
    echo "$body" | grep -q '"mode":"active"'
}

if ! poll_until 10 check_edge_active; then
    echo "FAIL: edge did not see mode=active within 10s"
    echo "  last /__policy:"
    last_body="$(edge_curl "${EDGE_URL}/__policy?host=${TEST_HOST}")"
    echo "    ${last_body}"
    exit 1
fi

# 3. Sanity: unregistered host returns pool default (mode=shadow). Same
# request, different ?host=. Validates that the apply doesn't smear
# state across hosts.
other_body="$(edge_curl "${EDGE_URL}/__policy?host=unregistered.example")"
if ! echo "$other_body" | grep -q '"mode":"shadow"'; then
    echo "FAIL: pool default broken — unregistered host returned:"
    echo "    ${other_body}"
    exit 1
fi
echo "  pool default OK for unregistered host"

# Cleanup (revert to shadow) runs from the EXIT trap above.
exit 0
