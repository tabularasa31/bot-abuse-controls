#!/usr/bin/env bash
# Generate the TLS material the antibot-backend LB needs:
#   1. [B1] server cert for the HTTPS front (fullchain.pem / privkey.pem).
#   2. [B6] edge-CA (edge-ca.crt / .key) — CA that signs edge clients for mTLS.
#   3. [B6] sample edge client cert (edge-client.crt / .key) — signed by the
#          edge-CA, CN=edge-demo; copied to the edge VM for the catalog_pull
#          mTLS opt-in path (config-distribution §Channel C "Auth/transport").
#
# Demo only: self-signed material proves the edge -> backend HTTPS+mTLS path.
# In a real deploy these come from an internal CA, rotated through Channel A
# (Puppet). See README "mTLS rotation".
#
# Idempotent: existing files are left alone; remove them to regenerate.
#
# Usage:
#   ./scripts/gen-certs.sh                          # CN=antibot.internal
#   BACKEND_CN=antibot.example ./scripts/gen-certs.sh
#   EDGE_CLIENT_CN=edge-prod ./scripts/gen-certs.sh # custom client CN
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${HERE}/../certs"
CN="${BACKEND_CN:-antibot.internal}"
EDGE_CLIENT_CN="${EDGE_CLIENT_CN:-edge-demo}"

mkdir -p "${CERT_DIR}"

# ---- 1. Server cert (B1) ----
# fullchain.pem/privkey.pem mirror the demo-stand naming so a certbot deploy-hook
# (infra/demo-stand/scripts/sync-demo-certs.sh) can refresh this LB's cert too.
if [ -f "${CERT_DIR}/fullchain.pem" ] && [ -f "${CERT_DIR}/privkey.pem" ]; then
    echo "server cert already present in ${CERT_DIR} — leaving as-is (rm to regenerate)"
else
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "${CERT_DIR}/privkey.pem" \
        -out "${CERT_DIR}/fullchain.pem" \
        -subj "/CN=${CN}" \
        -addext "subjectAltName=DNS:${CN}"
    chmod 600 "${CERT_DIR}/privkey.pem"
    echo "wrote ${CERT_DIR}/{fullchain,privkey}.pem for CN=${CN}"
fi

# ---- 2. Edge-CA (B6) ----
# The CA that signs every edge client cert. Its public part (edge-ca.crt) is
# what nginx loads in ssl_client_certificate when AUTH_MODE=mtls. The private
# key stays on the backend host; rotation just re-issues client certs against
# the same CA.
if [ -f "${CERT_DIR}/edge-ca.crt" ] && [ -f "${CERT_DIR}/edge-ca.key" ]; then
    echo "edge-CA already present — leaving as-is"
else
    openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
        -keyout "${CERT_DIR}/edge-ca.key" \
        -out "${CERT_DIR}/edge-ca.crt" \
        -subj "/CN=antibot-edge-CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    chmod 600 "${CERT_DIR}/edge-ca.key"
    echo "wrote ${CERT_DIR}/edge-ca.{crt,key} (CA for edge client certs)"
fi

# ---- 3. Sample edge client cert (B6) ----
# Signed by the edge-CA above. Copy edge-client.crt + edge-client.key to the
# edge VM (gitignored on this side, distributed via Channel A in prod).
#
# Half-pair guard (code-review F2): if exactly one of crt/key exists, bail out.
# Otherwise the openssl req -newkey below would overwrite the surviving key
# (or leave a stale cert paired with a fresh key), silently producing a
# cert/key mismatch that breaks mTLS on every edge still holding the other
# half. Force the operator to delete both or restore both.
crt_present=0; key_present=0
[ -f "${CERT_DIR}/edge-client.crt" ] && crt_present=1
[ -f "${CERT_DIR}/edge-client.key" ] && key_present=1
if [ "$((crt_present + key_present))" = "1" ]; then
    echo "error: edge-client cert/key pair is half-present in ${CERT_DIR}" >&2
    echo "       (crt=${crt_present}, key=${key_present}). Refusing to regenerate," >&2
    echo "       which would overwrite the surviving half and produce a silent" >&2
    echo "       cert/key mismatch on edges holding the other half." >&2
    echo "       Either restore the missing file, or delete BOTH and re-run." >&2
    exit 1
fi
if [ "${crt_present}" = "1" ] && [ "${key_present}" = "1" ]; then
    echo "edge client cert already present — leaving as-is"
else
    # CSR + sign with edge-CA. Two steps so we can pin CN and extensions.
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "${CERT_DIR}/edge-client.key" \
        -out "${CERT_DIR}/edge-client.csr" \
        -subj "/CN=${EDGE_CLIENT_CN}"

    # extfile pins clientAuth EKU — nginx ssl_verify_client accepts any signed
    # leaf by default, but pinning the EKU prevents a stolen server cert from
    # the same CA from being usable as a client cert.
    extfile="$(mktemp)"
    cat >"${extfile}" <<EOF
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
    openssl x509 -req -in "${CERT_DIR}/edge-client.csr" \
        -CA "${CERT_DIR}/edge-ca.crt" \
        -CAkey "${CERT_DIR}/edge-ca.key" \
        -CAcreateserial \
        -out "${CERT_DIR}/edge-client.crt" \
        -days 825 \
        -extfile "${extfile}"
    rm -f "${extfile}" "${CERT_DIR}/edge-client.csr"

    chmod 600 "${CERT_DIR}/edge-client.key"
    echo "wrote ${CERT_DIR}/edge-client.{crt,key} (CN=${EDGE_CLIENT_CN}, signed by edge-CA)"
fi
