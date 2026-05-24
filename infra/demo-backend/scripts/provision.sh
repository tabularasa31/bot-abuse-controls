#!/usr/bin/env bash
# Provision the antibot-backend demo stack on a fresh Debian/Ubuntu VM:
# docker + compose plugin, firewall for the edge -> backend HTTPS path, TLS cert,
# .env, and the Postgres + HA backend pair (real Go service from B2) behind the
# TLS LB. Idempotent: safe to re-run.
#
# Run on the demo VM (needs sudo for host setup):
#   ./scripts/provision.sh
#
# What it does NOT do: allocate the VM itself, or run DB migrations ([B15]).
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
        # [B6] Default Channel C auth mode (config-distribution §Auth/transport).
        # ip-allowlist is the safe demo default — flip to mtls once edge clients
        # have edge-client.{crt,key} (see scripts/gen-certs.sh + README).
        echo "AUTH_MODE=ip-allowlist"
    } > "${ROOT}/.env"
    chmod 600 "${ROOT}/.env"
else
    log ".env already present — leaving as-is"
    if ! grep -q '^AUTH_MODE=' "${ROOT}/.env"; then
        log "adding AUTH_MODE=ip-allowlist to existing .env (B6 default)"
        # Ensure a trailing newline before appending — a hand-written .env like
        # `printf 'POSTGRES_PASSWORD=secret' > .env` lacks one, and `>>` would
        # concatenate onto the previous line (corrupting POSTGRES_PASSWORD with
        # the AUTH_MODE suffix). Code-review F3.
        if [ -n "$(tail -c1 "${ROOT}/.env" 2>/dev/null)" ]; then
            echo >> "${ROOT}/.env"
        fi
        echo "AUTH_MODE=ip-allowlist" >> "${ROOT}/.env"
    fi
fi

# ---- DASHBOARD_API_TOKEN seed (B10) ----
# Без значения backend warn'ит «policy API disabled» и /antibot/v1/* возвращает
# 404. Дашборду нужен этот же секрет в его конфиге. Генерим раз, оператор
# синхронизирует на стороне дашборда.
if [ ! -f "${ROOT}/.env" ] || ! grep -q '^DASHBOARD_API_TOKEN=' "${ROOT}/.env"; then
    DASH_TOKEN="$(openssl rand -hex 32)"
    if [ -n "$(tail -c1 "${ROOT}/.env" 2>/dev/null)" ]; then
        echo >> "${ROOT}/.env"
    fi
    echo "DASHBOARD_API_TOKEN=${DASH_TOKEN}" >> "${ROOT}/.env"
    log "generated DASHBOARD_API_TOKEN — sync it to dashboard-backend's env"
fi

# ---- TLS cert for the LB (+ edge-CA + sample client cert from B6) ----
"${HERE}/gen-certs.sh"

# auth/allow.list AND auth/dashboard-cidr.conf both ship committed (см.
# auth/allow.list, auth/dashboard-cidr.conf) с safe loopback baseline'ом —
# no seed step needed. Оператор правит CIDR'ы in-place на VM перед prod.

# ---- bring up the stack ----
log "starting Postgres + HA backend pair + TLS LB"
docker compose -f "${COMPOSE_FILE}" up -d --build

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
