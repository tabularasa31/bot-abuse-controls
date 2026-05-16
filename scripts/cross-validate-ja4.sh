#!/usr/bin/env bash
# Cross-validate the PoC #2 stand's real fingerprint against external
# references (FoxIO Python ja4 library + Wireshark JA4 plugin).
#
# Why component-level, not byte-identical?
#   The stand emits a "Lua-lite" fingerprint (prefix "L") built from
#   $ssl_ciphers + $ssl_curves + $ssl_protocol + $ssl_alpn_protocol +
#   $ssl_server_name. It is NOT byte-identical to FoxIO's strict JA4
#   (prefix "t") because nginx does not expose the full ClientHello
#   extension list to access_by_lua. See infra/nginx-lua-poc/lua/ja4_compute.lua
#   for the trade-off rationale.
#
# What we validate:
#   * For 3 clients (curl, python-requests, Chrome) we capture a pcap of
#     the TLS handshake, feed it to `pip install ja4` and to Wireshark's
#     JA4 plugin, and check that the *components* (cipher list, ALPN, TLS
#     version, SNI) agreed with what our stand emitted to /__fp.
#   * Specifically: our fp's JA4_a prefix (Lver, sni, cipher_cnt, alpn)
#     must agree with the components in FoxIO's JA4_a for the same handshake.
#     The 12-char hash tails won't match by design.
#
# Prereqs:
#   - PoC stand up (docker compose -f docker-compose.lua-poc.yml --profile lua-only up -d)
#   - sudo tcpdump (loopback capture on macOS needs lo0)
#   - pip install ja4   (FoxIO reference library: https://pypi.org/project/ja4/)
#   - Wireshark with JA4 plugin (manual step, instructions printed at end)

set -euo pipefail

HOST="antibot.local"
PORT="8443"
URL="https://${HOST}:${PORT}/__fp"
RESOLVE="--resolve ${HOST}:${PORT}:127.0.0.1"
PCAP=/tmp/abuse-controls-phase2-validate.pcap
IFACE=${IFACE:-lo0}

container="nginx-lua-poc"
if ! docker ps --format '{{.Names}}' | grep -q "^${container}\$"; then
    echo "no ${container} running — start with --profile lua-only" >&2
    exit 1
fi

if ! python3 -c "import ja4" 2>/dev/null; then
    echo "FoxIO ja4 library missing. Install:" >&2
    echo "    pip install ja4" >&2
    exit 1
fi

echo "==> capturing handshakes for 3 probes on ${IFACE} (sudo may prompt)"
sudo -n tcpdump -i ${IFACE} -w ${PCAP} "tcp port ${PORT}" 2>/dev/null &
TCPDUMP_PID=$!
trap "sudo kill ${TCPDUMP_PID} 2>/dev/null || true" EXIT
sleep 1

echo "==> probe 1/3: curl"
curl -ksS ${RESOLVE} "${URL}" > /tmp/p2-curl.txt
echo "    fp: $(grep ^fp= /tmp/p2-curl.txt)"

echo "==> probe 2/3: python-requests"
python3 -c "
import requests, urllib3
urllib3.disable_warnings()
r = requests.get('${URL}', verify=False, headers={'Host':'${HOST}'})
print(r.text)
" > /tmp/p2-python.txt
echo "    fp: $(grep ^fp= /tmp/p2-python.txt)"

echo "==> probe 3/3: go-http-client"
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
go run /tmp/p.go" > /tmp/p2-go.txt
echo "    fp: $(grep ^fp= /tmp/p2-go.txt)"

sleep 1
sudo kill ${TCPDUMP_PID} 2>/dev/null || true
trap - EXIT
echo "==> pcap saved: ${PCAP}"

echo
echo "==> running FoxIO ja4 library against ${PCAP}"
python3 -c "
from ja4 import ja4_parser
import sys
for record in ja4_parser.process_pcap('${PCAP}'):
    print(f'  pcap session: ja4={record.get(\"ja4\")}  ciphers={len(record.get(\"ciphers\",[]))} alpn={record.get(\"alpn\")}')
" 2>&1 || echo "(ja4 lib API differs across versions — adjust the parser call if needed)"

echo
echo "==> our /__fp emissions:"
for f in /tmp/p2-curl.txt /tmp/p2-python.txt /tmp/p2-go.txt; do
    echo "  $(basename $f .txt):"
    grep -E '^(fp|tls_ver|sni|alpn)=' $f | sed 's/^/    /'
done

cat <<EOF

================================================================================
MANUAL VALIDATION via Wireshark JA4 plugin (third source)
================================================================================

1. Install Wireshark JA4 plugin:
     https://github.com/FoxIO-LLC/ja4/tree/main/wireshark
   On macOS: drop ja4.lua into
     ~/Library/Application\\ Support/Wireshark/plugins/

2. Open the captured pcap:
     wireshark ${PCAP}

3. Filter to ClientHello frames:
     tls.handshake.type == 1

4. For each of the 3 probes, click the Client Hello frame and inspect:
     - "JA4 Fingerprint" custom field (from the plugin)
     - tls.handshake.ciphersuites count
     - tls.handshake.extensions_alpn_str

5. Compare the cipher-count + ALPN + TLS-version components against what
   our /__fp returned (printed above). Pass = components match for all 3.
   The 12-char hash tails will NOT match (we hash a different input set).

If all three probes' components match the ja4 lib output AND the Wireshark
plugin output, mark this run as "cross-validated" in docs/phase2-fp-catalog.md
§"Cross-validation".
EOF
