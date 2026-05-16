#!/usr/bin/env bash
# Collect synthetic fingerprints from the PoC #2 stand.
#
# Prereqs:
#   - PoC stand is up:
#       docker compose -f docker-compose.lua-poc.yml --profile lua-only up -d --build
#   - Self-signed cert exists in infra/nginx-lua-poc/certs/ (see README)
#   - python3 with `requests`
#
# What it does:
#   - Hits /__fp as curl, python-requests, and go-http-client.
#     /__fp returns the synthetic fingerprint (md5 of cipher + protocol + UA prefix)
#     plus the input components, so we can paste the fp into blocklist.lua.
#
# What it does NOT do:
#   - Real-browser probes — open https://antibot.local:8443/__fp in Chrome /
#     Firefox / Safari and copy the `fp=` line from the response body.

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

probe() {
    local label="$1"; shift
    echo "--- ${label} ---"
    "$@" || echo "(probe ${label} returned non-zero)"
    sleep 0.3
}

probe "curl" \
    curl -ksS ${RESOLVE} "${URL}"

probe "python-requests" \
    python3 -c "
import requests, urllib3
urllib3.disable_warnings()
r = requests.get('${URL}', verify=False, headers={'Host': '${HOST}'})
print(r.text)
" || true

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
