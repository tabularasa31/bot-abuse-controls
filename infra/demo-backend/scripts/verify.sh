#!/usr/bin/env bash
# Acceptance checks for the antibot-backend demo stack.
#
# [B1] substrate:
#   1. PostgreSQL is up and accepting connections.
#   2. The edge -> backend HTTPS path answers on :443.
#   3. The LB round-robins across the >=2 backend instances (HA).
#
# [B2] real Go service surfaces (skeleton — bodies/contracts land in B3/B6/B7):
#   4. /catalog/<name> mounted (known catalog returns 501 until B3).
#   5. POST /v1/logs accepts a payload (202).
#   6. rDNS worker is alive (counter present in /metrics).
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

echo "4. /catalog/* mounted (B2 skeleton; B3 fills bodies + ETag)"
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/catalog/fp_blocklist")" || code=000
if [ "${code}" = "501" ]; then
    pass "GET /catalog/fp_blocklist -> 501 (skeleton)"
else
    bad "GET /catalog/fp_blocklist -> ${code} (expected 501 from B2 skeleton)"
fi
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/catalog/bogus")" || code=000
if [ "${code}" = "404" ]; then
    pass "GET /catalog/bogus -> 404 (unknown catalog)"
else
    bad "GET /catalog/bogus -> ${code} (expected 404)"
fi

echo "5. POST /v1/logs accepts payload (B2 skeleton; sink wiring is B6/B9)"
code="$(printf 'line1\nline2\n' \
    | "${CURL[@]}" -X POST --data-binary @- -o /dev/null -w '%{http_code}' \
        "https://${HOST}/v1/logs")" || code=000
if [ "${code}" = "202" ]; then
    pass "POST /v1/logs -> 202"
else
    bad "POST /v1/logs -> ${code} (expected 202)"
fi

echo "6. rDNS worker alive (counter present in /metrics)"
if "${CURL[@]}" "https://${HOST}/metrics" 2>/dev/null \
        | grep -q '^antibot_backend_rdns_ticks_total '; then
    pass "antibot_backend_rdns_ticks_total present"
else
    bad "antibot_backend_rdns_ticks_total missing from /metrics"
fi

echo
if [ "${fail}" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED" >&2
    exit 1
fi
