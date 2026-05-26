#!/bin/sh
# [C1] Generate the Phase 4 HMAC secret for clearance cookies on the demo
# stand. Writes a 32-byte base64-encoded random string to ./certs/
# challenge_secret.key (gitignored via infra/demo-stand/certs/*.key).
#
# The file is bind-mounted into the nginx-demo container at
# /etc/nginx/certs/challenge_secret.key; init_by_lua loads it via
# challenge_secret.lua. Channel A on the demo = file mount + nginx reload.
#
# Usage (run from repo root):
#   ./infra/demo-stand/scripts/generate-challenge-secret.sh
#
# Rotation:
#   rm  infra/demo-stand/certs/challenge_secret.key
#   ./infra/demo-stand/scripts/generate-challenge-secret.sh
#   docker compose -f infra/demo-stand/docker-compose.demo.yml \
#       exec nginx-demo openresty -s reload
# Reload invalidates every clearance cookie signed under the old secret
# (by design — vision §«Ротация»).

set -eu

dest="${1:-infra/demo-stand/certs/challenge_secret.key}"

if [ -e "$dest" ]; then
    echo "refuse: $dest already exists." >&2
    echo "        To rotate, remove it first (rm \"$dest\") and re-run." >&2
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl not found on PATH — required to generate the secret." >&2
    exit 1
fi

mkdir -p "$(dirname "$dest")"
umask 077
# No trailing newline: challenge_secret.lua trims whitespace before hashing,
# so a `>` redirect (which appends `\n`) would print a fingerprint that
# disagrees with /__version. printf '%s' guarantees byte-for-byte match.
printf '%s' "$(openssl rand -base64 32)" > "$dest"
chmod 600 "$dest"

# 8-hex fingerprint = first 4 bytes of sha256(secret), same shape as
# challenge_secret.lua reports via /__version and /__admin so the operator
# can cross-check what the stand loaded after reload. `openssl dgst -r`
# prints "<hex>  <name>" (coreutils-style), works on both OpenSSL 1.1+ and
# LibreSSL — verified on the alpine base image the stand runs on.
fp=$(openssl dgst -sha256 -r < "$dest" | cut -c1-8)

echo "wrote $dest (fp=$fp)"
echo "next: docker compose -f infra/demo-stand/docker-compose.demo.yml exec nginx-demo openresty -s reload"
