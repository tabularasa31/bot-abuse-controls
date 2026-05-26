#!/usr/bin/env sh
# Generate the self-signed cert the edge container's nginx expects at
# /etc/nginx/certs/fullchain.pem + privkey.pem. Test-only; never use the
# resulting cert outside this harness.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
CERTS="$HERE/../test-certs"
mkdir -p "$CERTS"

if [ -f "$CERTS/fullchain.pem" ] && [ -f "$CERTS/privkey.pem" ]; then
    echo "test-certs/ already populated — reusing"
    exit 0
fi

echo "Generating self-signed cert for test edge..."
openssl req -x509 -newkey rsa:2048 -days 30 -nodes \
    -keyout "$CERTS/privkey.pem" \
    -out    "$CERTS/fullchain.pem" \
    -subj "/CN=stand-test.local" \
    -addext "subjectAltName=DNS:stand-test.local,DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
chmod 644 "$CERTS/privkey.pem" "$CERTS/fullchain.pem"
echo "Wrote $CERTS/{fullchain,privkey}.pem"
