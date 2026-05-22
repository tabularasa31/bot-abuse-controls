#!/usr/bin/env bash
# [B1] Generate a self-signed TLS cert for the antibot-backend LB.
# Demo only: a self-signed cert proves the edge -> backend HTTPS path. In a real
# deploy this is an internal-CA cert (or mTLS keypair), rotated via Channel A.
#
# Usage:
#   ./scripts/gen-certs.sh                 # CN=antibot.internal
#   BACKEND_CN=antibot.example ./scripts/gen-certs.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${HERE}/../certs"
CN="${BACKEND_CN:-antibot.internal}"

mkdir -p "${CERT_DIR}"

if [ -f "${CERT_DIR}/backend.crt" ] && [ -f "${CERT_DIR}/backend.key" ]; then
    echo "certs already present in ${CERT_DIR} — leaving as-is (rm to regenerate)"
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "${CERT_DIR}/backend.key" \
    -out "${CERT_DIR}/backend.crt" \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=DNS:${CN}"

chmod 600 "${CERT_DIR}/backend.key"
echo "wrote ${CERT_DIR}/backend.{crt,key} for CN=${CN}"
