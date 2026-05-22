#!/usr/bin/env bash
# [B1] Provision the antibot-backend demo substrate on a fresh Debian/Ubuntu VM:
# docker + compose plugin, firewall for the edge -> backend HTTPS path, TLS cert,
# .env, and the Postgres + HA backend pair stack. Idempotent: safe to re-run.
#
# Run on the demo VM (needs sudo for host setup):
#   ./scripts/provision.sh
#
# What it does NOT do: allocate the VM itself, or deploy the real Go backend
# ([B2]/[B15]). It prepares the substrate the acceptance criteria check.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
COMPOSE_FILE="${ROOT}/docker-compose.backend.yml"

log() { printf '==> %s\n' "$*"; }

# ---- host packages: docker + compose plugin ----
if ! command -v docker >/dev/null 2>&1; then
    log "installing docker engine + compose plugin"
    curl -fsSL https://get.docker.com | sudo sh
else
    log "docker already installed: $(docker --version)"
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "error: 'docker compose' plugin not available after install" >&2
    exit 1
fi

# ---- firewall: open the edge -> backend HTTPS port ----
if command -v ufw >/dev/null 2>&1; then
    log "allowing 443/tcp (edge -> backend HTTPS, Channel C pull)"
    sudo ufw allow 443/tcp || true
else
    log "ufw not present — ensure 443/tcp is reachable from the edge egress range by other means"
fi

# ---- .env ----
if [ ! -f "${ROOT}/.env" ]; then
    log "generating ${ROOT}/.env with a random POSTGRES_PASSWORD"
    pw="$(openssl rand -hex 24)"
    {
        echo "POSTGRES_DB=antibot"
        echo "POSTGRES_USER=antibot"
        echo "POSTGRES_PASSWORD=${pw}"
    } > "${ROOT}/.env"
    chmod 600 "${ROOT}/.env"
else
    log ".env already present — leaving as-is"
fi

# ---- TLS cert for the LB ----
"${HERE}/gen-certs.sh"

# ---- bring up the stack ----
log "starting Postgres + HA backend pair + TLS LB"
docker compose -f "${COMPOSE_FILE}" up -d

# `up -d` returns once containers start, not once nginx serves. Wait for the LB
# to actually answer so a verify.sh run straight after doesn't race startup.
log "waiting for the LB to serve HTTPS"
for _ in $(seq 1 15); do
    if curl -sk --connect-timeout 2 --max-time 3 -o /dev/null \
            "https://localhost/health"; then
        break
    fi
    sleep 1
done

log "done. Verify with: ${HERE}/verify.sh"
