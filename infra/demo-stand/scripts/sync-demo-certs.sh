#!/bin/sh
# certbot deploy-hook: refresh the demo stand's ./certs after a renewal
# and reload the edge. The repo compose mounts ./certs (not /etc/letsencrypt),
# so renewed certs must be copied in or the stand serves a stale cert until
# the next manual restart.
#
# Install on the VM (run as root):
#   install -m755 infra/demo-stand/scripts/sync-demo-certs.sh \
#       /etc/letsencrypt/renewal-hooks/deploy/sync-demo-certs.sh
#
# certbot runs every deploy-hook after a successful renewal. Adjust DOMAIN
# and REPO if yours differ.

set -eu

DOMAIN="${DOMAIN:-bac.example.com}"
REPO="${REPO:-/home/ubuntu/abuse-controls}"

LIVE="/etc/letsencrypt/live/${DOMAIN}"
CERTS="${REPO}/infra/demo-stand/certs"
COMPOSE="${REPO}/infra/demo-stand/docker-compose.demo.yml"

install -m644 "${LIVE}/fullchain.pem" "${CERTS}/fullchain.pem"
install -m600 "${LIVE}/privkey.pem"   "${CERTS}/privkey.pem"

# Reload if the container is up; ignore if it isn't (e.g. during initial setup).
docker compose -f "${COMPOSE}" exec -T nginx-demo openresty -s reload || true
