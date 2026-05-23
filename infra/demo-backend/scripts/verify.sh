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
# [B6] Channel C auth (config-distribution §Auth/transport):
#   7. AUTH_MODE=ip-allowlist (default): loopback request passes; an empty
#      allowlist rejects with 403 → restores. Verifies "unauthenticated source
#      is rejected" without disturbing the regular path.
#      AUTH_MODE=mtls: request without client cert fails; with edge-client.{crt,key} ok.
#      AUTH_MODE=off: check skipped (no auth to verify).
#
# Usage:
#   ./scripts/verify.sh            # checks https://localhost
#   BACKEND_HOST=antibot.internal ./scripts/verify.sh
#   AUTH_MODE=mtls ./scripts/verify.sh
#   AUTH_MODE override only affects which auth assertions run; the LB itself
#   reads AUTH_MODE from .env at compose-up.
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

echo "7. Channel C auth (AUTH_MODE=${AUTH_MODE:-ip-allowlist})"
auth_mode="${AUTH_MODE:-ip-allowlist}"
case "${auth_mode}" in
    ip-allowlist)
        # Loopback is in auth/allow.list.example by default — happy path.
        code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/health")" || code=000
        if [ "${code}" = "200" ]; then
            pass "loopback allowed (${code})"
        else
            bad "loopback rejected (${code}); check auth/allow.list"
        fi
        # Negative path: only attempt the "swap allow.list to empty + reload"
        # check on the local stack — on a remote BACKEND_HOST we don't have
        # docker compose to swap the file. The reload-via-exec keeps the test
        # hermetic; the file is restored regardless of outcome (trap).
        case "${host_only}" in
            localhost | 127.0.0.1 | ::1)
                allow_list="${ROOT}/auth/allow.list"
                if [ ! -f "${allow_list}" ]; then
                    skip "auth/allow.list missing — run scripts/provision.sh first"
                else
                    backup="$(mktemp)"
                    cp "${allow_list}" "${backup}"
                    # shellcheck disable=SC2064
                    trap "cp '${backup}' '${allow_list}'; rm -f '${backup}'; docker compose -f '${COMPOSE_FILE}' exec -T lb nginx -s reload >/dev/null 2>&1 || true" EXIT INT TERM
                    # Empty allow.list → ip-allowlist.conf still has `deny all;`
                    # → everything denied.
                    : > "${allow_list}"
                    docker compose -f "${COMPOSE_FILE}" exec -T lb nginx -s reload >/dev/null 2>&1 || true
                    sleep 1
                    code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/health")" || code=000
                    if [ "${code}" = "403" ]; then
                        pass "empty allowlist denies loopback (${code})"
                    else
                        bad "empty allowlist did not deny (${code}; expected 403)"
                    fi
                    cp "${backup}" "${allow_list}"
                    rm -f "${backup}"
                    docker compose -f "${COMPOSE_FILE}" exec -T lb nginx -s reload >/dev/null 2>&1 || true
                    trap - EXIT INT TERM
                fi
                ;;
            *)
                skip "negative allowlist check needs local docker compose (BACKEND_HOST=${host_only})"
                ;;
        esac
        ;;
    mtls)
        cert="${ROOT}/certs/edge-client.crt"
        key="${ROOT}/certs/edge-client.key"
        # Negative path: no client cert → nginx rejects (400 No required SSL cert,
        # or curl exits non-zero on handshake). We accept either.
        code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/health")" || code=000
        if [ "${code}" = "400" ] || [ "${code}" = "000" ] || [ "${code}" = "496" ]; then
            pass "no client cert rejected (code=${code})"
        else
            bad "no client cert accepted with code=${code} (expected 400/000/496)"
        fi
        # Happy path: present edge-client.{crt,key}.
        if [ -f "${cert}" ] && [ -f "${key}" ]; then
            code="$(curl -sk --connect-timeout 3 --max-time 5 \
                --cert "${cert}" --key "${key}" \
                -o /dev/null -w '%{http_code}' "https://${HOST}/health")" || code=000
            if [ "${code}" = "200" ]; then
                pass "edge-client cert accepted (${code})"
            else
                bad "edge-client cert rejected (${code})"
            fi
        else
            skip "edge-client.{crt,key} missing — run scripts/gen-certs.sh"
        fi
        ;;
    off)
        skip "AUTH_MODE=off — no auth check (debug only, not for any reachable deploy)"
        ;;
    *)
        bad "unknown AUTH_MODE=${auth_mode}; expected mtls|ip-allowlist|off"
        ;;
esac

echo "8. Fail-stale on edge (cross-stack, opt-in via STAND_HOST)"
if [ -n "${STAND_HOST:-}" ]; then
    # Capture the staleness gauge before and after a backend stop. We don't
    # actually stop containers here — operator does it manually so the test
    # doesn't accidentally take down a shared backend. Instead, the check
    # asserts the metric is exported and parseable; the manual scenario is
    # documented in the README ("Fail-stale verification").
    if curl -sk --connect-timeout 3 --max-time 5 "https://${STAND_HOST}/metrics" 2>/dev/null \
            | grep -q '^antibot_edge_catalog_staleness_seconds{'; then
        pass "antibot_edge_catalog_staleness_seconds exported by edge ${STAND_HOST}"
    else
        bad "edge ${STAND_HOST} does not export antibot_edge_catalog_staleness_seconds"
    fi
else
    skip "STAND_HOST not set — fail-stale check (manual scenario in README)"
fi

echo
if [ "${fail}" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED" >&2
    exit 1
fi
