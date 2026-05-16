#!/usr/bin/env bash
# Collect real handshake-derived fingerprints from the PoC #2 stand.
#
# Prereqs:
#   - PoC stand is up:
#       docker compose -f docker-compose.lua-poc.yml --profile lua-only up -d --build
#   - Self-signed cert exists in infra/nginx-lua-poc/certs/ (see README)
#   - python3 with `requests`
#
# What it does:
#   - Hits /__fp as curl, python-requests, and go-http-client.
#     /__fp returns the real fp (sha256 of sorted $ssl_ciphers + handshake meta;
#     see infra/nginx-lua-poc/lua/ja4_compute.lua) plus the raw components
#     ($ssl_ciphers, $ssl_curves, $ssl_protocol, $ssl_alpn_protocol,
#     $ssl_server_name) so we can paste the fp into blocklist.lua and audit
#     the inputs against Wireshark or the FoxIO Python ja4 library.
#
# What it does NOT do:
#   - Real-browser probes — open https://antibot.local:8443/__fp in Chrome /
#     Firefox / Safari and copy the `fp=` line from the response body. The
#     "manual browser probes" section at the end prints the exact instructions.

set -euo pipefail

HOST="antibot.local"
PORT="8443"
URL="https://${HOST}:${PORT}/__fp"
RESOLVE="--resolve ${HOST}:${PORT}:127.0.0.1"

container="nginx-lua-poc"
if ! docker ps --format '{{.Names}}' | grep -q "^${container}\$"; then
    echo "no ${container} running — start with --profile lua-only" >&2
    exit 1
fi
echo "using container: ${container}"
echo

# Track failures so the script exits non-zero if any probe didn't produce a
# usable fp line. A clean exit must mean "all 3 automation clients captured."
# Otherwise CI / a downstream caller can mistake a partial run for success.
FAILED_PROBES=()

probe() {
    local label="$1"; shift
    echo "--- ${label} ---"
    local out
    if ! out=$("$@" 2>&1); then
        echo "${out}"
        echo "FAIL: probe ${label} returned non-zero" >&2
        FAILED_PROBES+=("${label}")
    elif ! grep -q '^fp=' <<<"${out}"; then
        echo "${out}"
        echo "FAIL: probe ${label} exited 0 but no fp= line in output" >&2
        FAILED_PROBES+=("${label}")
    else
        echo "${out}"
    fi
    echo
    sleep 0.3
}

probe "curl" \
    curl -ksS ${RESOLVE} "${URL}"

probe "python-requests" \
    python3 -c "
import requests, urllib3
urllib3.disable_warnings()
r = requests.get('https://127.0.0.1:${PORT}/__fp', verify=False, headers={'Host': '${HOST}'})
print(r.text)
"

probe "go-http-client" \
    docker run --rm --network host golang:1.23-alpine sh -c \
    "cat > /tmp/p.go <<'EOF'
package main
import (\"crypto/tls\"; \"io\"; \"net/http\"; \"fmt\")
func main(){
  c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify:true, ServerName:\"${HOST}\"}}}
  r,e := c.Get(\"https://127.0.0.1:${PORT}/__fp\")
  if e!=nil{panic(e)}
  b,_ := io.ReadAll(r.Body); fmt.Println(string(b))
}
EOF
go run /tmp/p.go"

cat <<EOF

================================================================================
MANUAL BROWSER PROBES (Phase 2 acceptance: 6 distinct clients)
================================================================================

The acceptance gate for Phase 2 ([86exmjzug](https://app.clickup.com/t/86exmjzug)) requires the
fp catalog to cover curl / python / Go (above) plus Chrome / Firefox / Safari
— minimum 6 recognisable, comparable to Phase 1 catalog
([antibot-lab/docs/ja3-poc-results.md] §"Baseline fingerprint catalog").

For each browser:

  1. Add to /etc/hosts (one-time setup):
       127.0.0.1   antibot.local

  2. Trust the self-signed cert at infra/nginx-lua-poc/certs/cert.pem
     in your system keychain (or accept the warning).

  3. Open in the browser:
       https://antibot.local:${PORT}/__fp

  4. Copy the fp=... line from the rendered text page.

  5. Paste into docs/phase2-fp-catalog.md under the matching row.

After all 6 clients have a fingerprint, run:
    scripts/cross-validate-ja4.sh
to verify the JA4 *components* (cipher list, ALPN, TLS version, SNI presence)
match what the FoxIO Python ja4 library and Wireshark JA4 plugin extract
from the same handshake. See cross-validate-ja4.sh for the why-it-is-not-
byte-identical-to-FoxIO-JA4 caveat.
EOF

if [ ${#FAILED_PROBES[@]} -gt 0 ]; then
    echo
    echo "================================================================================" >&2
    echo "PROBE FAILURES: ${FAILED_PROBES[*]}" >&2
    echo "================================================================================" >&2
    echo "Do NOT paste these results into blocklist.lua or phase2-fp-catalog.md" >&2
    echo "until the failed probes are fixed and rerun." >&2
    exit 1
fi
