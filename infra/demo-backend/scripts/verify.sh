#!/usr/bin/env bash
# [B1] Acceptance checks for the antibot-backend substrate:
#   1. PostgreSQL is up and accepting connections.
#   2. The edge -> backend HTTPS path answers on :443.
#   3. The LB round-robins across the >=2 backend instances (HA).
#
# Usage:
#   ./scripts/verify.sh            # checks https://localhost
#   BACKEND_HOST=antibot.internal ./scripts/verify.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
COMPOSE_FILE="${ROOT}/docker-compose.backend.yml"
HOST="${BACKEND_HOST:-localhost}"
fail=0

pass() { printf '  [ok]   %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; fail=1; }
skip() { printf '  [skip] %s\n' "$*"; }

# Strip any :port so the host part can be matched against the local names.
host_only="${HOST%%:*}"

echo "1. PostgreSQL reachable"
case "${host_only}" in
    localhost | 127.0.0.1 | ::1)
        # The Postgres check uses the local compose stack, so it only makes sense
        # on the backend host itself. When verifying the HTTPS path from a remote
        # edge VM (BACKEND_HOST set to a real host), there is no local stack to
        # exec into — run this step on the backend host instead.
        if docker compose -f "${COMPOSE_FILE}" exec -T postgres \
                pg_isready -U "${POSTGRES_USER:-antibot}" -d "${POSTGRES_DB:-antibot}" >/dev/null 2>&1; then
            pass "pg_isready"
        else
            bad "pg_isready — Postgres not accepting connections"
        fi
        ;;
    *)
        skip "remote host ${host_only} — run step 1 on the backend host"
        ;;
esac

CURL=(curl -sk --connect-timeout 3 --max-time 5)

echo "2. Edge -> backend HTTPS path (:443)"
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/health")" || code=000
if [ "${code}" = "200" ]; then
    pass "GET https://${HOST}/health -> 200"
else
    bad "GET https://${HOST}/health -> ${code}"
fi

echo "3. HA round-robin across backend instances"
seen="$(for _ in 1 2 3 4 5 6 7 8; do
    "${CURL[@]}" "https://${HOST}/health" 2>/dev/null \
        | grep -o '"instance":"[^"]*"' || true
done | sort -u | wc -l | tr -d ' ')"
if [ "${seen}" -ge 2 ]; then
    pass "saw ${seen} distinct backend instances"
else
    bad "saw ${seen} distinct backend instance(s); expected >=2 for HA"
fi

echo
if [ "${fail}" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED" >&2
    exit 1
fi
