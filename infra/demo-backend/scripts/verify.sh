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

# [B6] AUTH_MODE — pick up from .env if not set in the environment, so that
# AUTH_MODE in .env (which actually drives the LB at compose-up) is the
# source of truth and we don't mis-verify a stack that's already on mtls
# with the ip-allowlist default. Env > .env > hardcoded default.
#
# F7: tolerate `AUTH_MODE=mtls   # rolled 2026-05-23` and CRLF .env edits.
# Strip (in order): everything after `#`, surrounding double/single quotes,
# leading+trailing whitespace, trailing CR.
if [ -z "${AUTH_MODE:-}" ] && [ -f "${ROOT}/.env" ]; then
    AUTH_MODE="$(grep -E '^AUTH_MODE=' "${ROOT}/.env" \
        | tail -1 \
        | sed -E 's/^AUTH_MODE=//; s/[[:space:]]*#.*$//; s/^["'"'"']//; s/["'"'"']$//; s/^[[:space:]]+//; s/[[:space:]]+$//' \
        | tr -d '\r' || true)"
fi
AUTH_MODE="${AUTH_MODE:-ip-allowlist}"

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

# [B6] When the LB runs AUTH_MODE=mtls, EVERY check (#2–#6) must present a
# client cert — otherwise nginx rejects with 400 No required SSL certificate
# and the rest of verify.sh reports false failures (codex review). The "no
# cert" negative path in #7 uses a separate bare-curl invocation.
#
# F5: hard-exit rather than continue with bare CURL when certs are missing —
# the cascading false failures from #2–#6 mask the real root cause (missing
# client material) and burn operator time.
CURL=(curl -sk --connect-timeout 3 --max-time 5)
if [ "${AUTH_MODE}" = "mtls" ]; then
    cert="${ROOT}/certs/edge-client.crt"
    key="${ROOT}/certs/edge-client.key"
    if [ -f "${cert}" ] && [ -f "${key}" ]; then
        CURL+=(--cert "${cert}" --key "${key}")
    else
        echo "error: AUTH_MODE=mtls requires ${cert} and ${key} on this host." >&2
        echo "       Generate them on the backend with scripts/gen-certs.sh," >&2
        echo "       or copy them from there (see README §mTLS rotation)." >&2
        echo "       Refusing to run checks #2–#6 with a bare curl — every one" >&2
        echo "       would false-fail at the TLS handshake." >&2
        exit 2
    fi
fi

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

echo "5. POST /v1/logs accepts payload + sink ingests into PostgreSQL (B9)"
# Тело — валидный BAC_LOG-record (миним. required: request_id/timestamp/edge_id).
# Без него sink инкрементирует parse_errors_total и оставляет inserted=0,
# acceptance B9 не пройдёт.
ts="$(date -u +'%Y-%m-%dT%H:%M:%S.000Z')"
body="$(printf '{"request_id":"verify-%s","timestamp":"%s","edge_id":"verify","stage":"egress","verdict":"pass","action":"pass","mode":"shadow"}\n' \
    "$(date +%s)" "${ts}")"
code="$(printf '%s' "${body}" \
    | "${CURL[@]}" -X POST --data-binary @- -o /dev/null -w '%{http_code}' \
        "https://${HOST}/v1/logs")" || code=000
if [ "${code}" = "202" ]; then
    pass "POST /v1/logs -> 202"
else
    bad "POST /v1/logs -> ${code} (expected 202)"
fi
# inserted_total живёт в /metrics только при wired sink'е (POSTGRES_DSN +
# LOGS_SINK_SPOOL_DIR); без них считаем шаг N/A — для smoke'а CI этого
# достаточно, чтобы поймать «sink упал на init»: метрика отсутствует и
# мы тегаем 'skipped', а не 'pass'. Sink батчит до FlushInterval=2s →
# даём 5s окно.
echo "   waiting up to 5s for sink to flush the verify payload..."
sleep 5
metrics="$("${CURL[@]}" "https://${HOST}/metrics" 2>/dev/null || true)"
if printf '%s' "${metrics}" | grep -q '^antibot_backend_log_sink_inserted_total '; then
    inserted="$(printf '%s' "${metrics}" | awk '/^antibot_backend_log_sink_inserted_total / {print $2; exit}')"
    if awk -v v="${inserted}" 'BEGIN{exit !(v+0>0)}'; then
        pass "antibot_backend_log_sink_inserted_total=${inserted} (>0)"
    else
        bad "antibot_backend_log_sink_inserted_total=${inserted} (expected >0 after POST)"
    fi
else
    echo "   skip: sink metric absent (POSTGRES_DSN / LOGS_SINK_SPOOL_DIR not set?)"
fi

echo "6. rDNS worker alive (counter present in /metrics)"
if "${CURL[@]}" "https://${HOST}/metrics" 2>/dev/null \
        | grep -q '^antibot_backend_rdns_ticks_total '; then
    pass "antibot_backend_rdns_ticks_total present"
else
    bad "antibot_backend_rdns_ticks_total missing from /metrics"
fi

echo "7. Channel C auth (AUTH_MODE=${AUTH_MODE})"
case "${AUTH_MODE}" in
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
        # Negative path: use a BARE curl (no --cert/--key) — even though CURL
        # is mtls-augmented above for checks #2–#6, here we explicitly probe
        # the "no client cert" case. nginx rejects with 400 No required SSL
        # certificate; OpenSSL may also fail the handshake → curl exit non-zero.
        code="$(curl -sk --connect-timeout 3 --max-time 5 \
            -o /dev/null -w '%{http_code}' "https://${HOST}/health")" || code=000
        if [ "${code}" = "400" ] || [ "${code}" = "000" ] || [ "${code}" = "496" ]; then
            pass "no client cert rejected (code=${code})"
        else
            bad "no client cert accepted with code=${code} (expected 400/000/496)"
        fi
        # Happy path: the augmented ${CURL[@]} already carries --cert/--key
        # (set up at the top when AUTH_MODE=mtls), so reuse it.
        code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/health")" || code=000
        if [ "${code}" = "200" ]; then
            pass "edge-client cert accepted (${code})"
        else
            bad "edge-client cert rejected (${code})"
        fi
        ;;
    off)
        skip "AUTH_MODE=off — no auth check (debug only, not for any reachable deploy)"
        ;;
    *)
        bad "unknown AUTH_MODE=${AUTH_MODE}; expected mtls|ip-allowlist|off"
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
