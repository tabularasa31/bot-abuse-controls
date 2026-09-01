#!/usr/bin/env bash
# [B6] Copy the edge-client mTLS material from the backend host into this
# stand's certs/ dir. Run on the edge VM after the backend operator generated
# edge-client.{crt,key} with infra/demo-backend/scripts/gen-certs.sh.
#
# This is the Channel A distribution step for the client certificate: an
# explicit scp from the backend host, with a modulus check before installing.
#
# Usage (on edge VM):
#   BACKEND_HOST=backend-vm.internal ./scripts/install-edge-client-cert.sh
#   # or with explicit path / user:
#   BACKEND_HOST=… BACKEND_USER=ubuntu BACKEND_CERT_DIR=/opt/abuse-controls/infra/demo-backend/certs \
#       ./scripts/install-edge-client-cert.sh
#
# After install, set in infra/demo-stand/.env on this VM:
#   ANTIBOT_BACKEND_CLIENT_CERT=/etc/nginx/certs/edge-client.crt
#   ANTIBOT_BACKEND_CLIENT_KEY=/etc/nginx/certs/edge-client.key
# and `docker compose -f docker-compose.demo.yml up -d` to pick them up.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
DEST="${ROOT}/certs"

: "${BACKEND_HOST:?set BACKEND_HOST to the backend VM hostname (the host that ran demo-backend/scripts/gen-certs.sh)}"
BACKEND_USER="${BACKEND_USER:-$(whoami)}"
BACKEND_CERT_DIR="${BACKEND_CERT_DIR:-infra/demo-backend/certs}"

mkdir -p "${DEST}"

echo "==> scp ${BACKEND_USER}@${BACKEND_HOST}:${BACKEND_CERT_DIR}/edge-client.{crt,key} → ${DEST}/"
# Two separate scp calls (rather than a brace expansion that ssh might not
# expand) and a temp dir to avoid clobbering on partial transfer.
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
scp "${BACKEND_USER}@${BACKEND_HOST}:${BACKEND_CERT_DIR}/edge-client.crt" "${tmp}/edge-client.crt"
scp "${BACKEND_USER}@${BACKEND_HOST}:${BACKEND_CERT_DIR}/edge-client.key" "${tmp}/edge-client.key"

# Sanity-check: key matches cert (modulus check). Catches an in-transit swap
# / a stale half-pair from a botched rotation before we install it.
cert_mod="$(openssl x509 -noout -modulus -in "${tmp}/edge-client.crt" | openssl md5)"
key_mod="$(openssl rsa  -noout -modulus -in "${tmp}/edge-client.key" 2>/dev/null | openssl md5)"
if [ "${cert_mod}" != "${key_mod}" ]; then
    echo "error: cert/key modulus mismatch — copied files do not form a valid pair" >&2
    echo "       cert: ${cert_mod}" >&2
    echo "       key:  ${key_mod}"  >&2
    exit 1
fi

install -m 0644 "${tmp}/edge-client.crt" "${DEST}/edge-client.crt"
# 0600 on the edge: nginx master reads it in init_by_lua before privilege drop
# (catalog_pull.preload_mtls), so root-owned 0600 is fine. See catalog_pull.lua
# load_mtls_material comment.
install -m 0600 "${tmp}/edge-client.key" "${DEST}/edge-client.key"

echo "==> installed:"
ls -l "${DEST}/edge-client.crt" "${DEST}/edge-client.key"
echo
echo "Next: in ${ROOT}/.env set"
echo "  ANTIBOT_BACKEND_CLIENT_CERT=/etc/nginx/certs/edge-client.crt"
echo "  ANTIBOT_BACKEND_CLIENT_KEY=/etc/nginx/certs/edge-client.key"
echo "then \`docker compose -f docker-compose.demo.yml up -d\` and confirm the"
echo "pull channel is healthy via the EDGE_STATS dump (catalog_staleness_seconds"
echo "near 0): docker logs nginx-demo | grep EDGE_STATS | tail -1"
echo "(or ssh -L 9090:127.0.0.1:9090 <vm> then curl localhost:9090/__stats)."
