# infra/demo-backend — antibot-backend demo stack

Reproducible deploy of the **antibot-backend** demo VM: PostgreSQL plus a
≥2-instance backend pair behind a TLS-terminating LB, with the edge → backend
HTTPS path opened. Topology from
[ADR-005](../../docs/architecture-decisions/005-centralized-antibot-backend.md)
and [config-distribution §HA](../../docs/architecture/config-distribution.md).

The substrate (compose, LB, certs, firewall, provision scripts) is [B1]. The
`backend-*` containers run the real Go service from
[`../../antibot-backend/`](../../antibot-backend/) — task [B2], skeleton of the
three backend functions: catalog server, log receiver, rDNS worker. Full
contracts for those functions land in B3 (catalog HTTP/ETag), B6/B9 (log sink),
B7 (rDNS state machine). App-level production deploy with DB migrations is
[B15].

> This is our own demo infra, **not** the prod-edge prod edge pool — see
> [PROGRESS.md](../../PROGRESS.md) "НЕ НАШЕ".

## Topology

```
edge (demo-stand)  ──HTTPS:443──►  lb (nginx, TLS term)  ──RR──►  backend-1 ─┐
                                                                  backend-2 ─┴─► postgres:5432
```

- **lb** — small LB per config-distribution §HA ("DNS round-robin or a small
  LB"); terminates TLS on `:443` (`antibot.internal`), round-robins
  the pair, fails over on instance death.
- **backend-1 / backend-2** — the ≥2 instances ADR-005 requires for HA.
- **postgres** — single instance with a named volume; bound to loopback, reached
  by the backend over the compose network.

## Quickstart (on the demo VM)

```bash
cd infra/demo-backend
./scripts/provision.sh        # docker + compose, ufw 443, .env, cert, stack up
./scripts/verify.sh           # acceptance checks
```

`provision.sh` is idempotent. To run the steps by hand instead:

```bash
cp .env.example .env          # then set POSTGRES_PASSWORD
./scripts/gen-certs.sh        # self-signed cert for the LB
docker compose -f docker-compose.backend.yml up -d
./scripts/verify.sh
```

Tear down: `docker compose -f docker-compose.backend.yml down`
(add `-v` to drop the Postgres volume).

## Acceptance

`scripts/verify.sh` checks each criterion:

| Criterion | Check | Task |
|---|---|---|
| VM(s) up, PostgreSQL accessible | `pg_isready` inside the `postgres` container | B1 |
| Edge → backend reachable over HTTPS | `GET https://<host>/health` → `200` on `:443` | B1 |
| Deploy reproducible | compose file + scripts; `provision.sh` re-runnable | B1 |
| HA (≥2 instances) | `/health` round-robins ≥2 distinct `instance` tags | B1 |
| Backend serves the three function surfaces | `/catalog/<name>` (501 until B3), `POST /v1/logs` (202), `antibot_backend_rdns_ticks_total` in `/metrics` | B2 |
| Backend not on hot path | edge fail-stale if backend down — see [demo-stand](../demo-stand/) Channel C client | B5/B6 |
| Channel C auth rejects unauthenticated | loopback passes; empty `allow.list` → 403 (ip-allowlist) / no client cert → 400 (mtls) | B6 |
| Edge fail-stale on backend outage | `antibot_edge_catalog_staleness_seconds` exported, grows when backend down, edge keeps serving | B6 |

From the edge VM, verify reach with the real hostname:

```bash
BACKEND_HOST=antibot.internal ./scripts/verify.sh
```

## Auth / firewall (B6)

Channel C edge → backend auth is selected via `AUTH_MODE` in `.env`. The LB
includes `auth/${AUTH_MODE}.conf` as `/etc/nginx/conf.d/auth.conf`, picked up
from [`nginx/lb.conf`](nginx/lb.conf):

| `AUTH_MODE` | What it does | When to use |
|---|---|---|
| `ip-allowlist` (default) | `auth/ip-allowlist.conf` → `include allow.list; deny all;`. `auth/allow.list` ships with safe loopback + RFC1918 defaults (committed baseline); edit per deploy and `docker compose exec lb nginx -s reload` to apply. | Demo default. config-distribution §Channel C "Auth/transport" names it as the fallback to mTLS. |
| `mtls` | `auth/mtls.conf` → `ssl_client_certificate /etc/nginx/certs/edge-ca.crt; ssl_verify_client on;`. Edges must present a cert signed by edge-CA (`scripts/gen-certs.sh` rolls a sample pair). | Production-path per the doc. Switch once edges have `edge-client.{crt,key}`. |
| `off` | Empty `auth.conf` — no application-layer auth. **Not for any reachable deploy.** | Local debugging only. |

Flip the mode:

```bash
sed -i 's/^AUTH_MODE=.*/AUTH_MODE=mtls/' .env
docker compose -f docker-compose.backend.yml up -d   # re-binds auth.conf
AUTH_MODE=mtls ./scripts/verify.sh                   # asserts the new mode
```

`provision.sh` opens `443/tcp` via `ufw`. **Restrict it to CDN operator's edge
egress range** in a real deploy — `ufw allow 443/tcp` is just the
out-of-the-box convenience; the production rule must be more specific.

### mTLS rotation

Per config-distribution §Channel C, client certs are distributed to edges
through Channel A (Puppet). Rotation without an outage:

1. **Issue new client cert** against the existing edge-CA:
   `EDGE_CLIENT_CN=edge-prod-v2 ./scripts/gen-certs.sh`. To replace in place
   delete BOTH `edge-client.crt` and `edge-client.key` first — the script
   refuses to run on a half-pair (it would overwrite the surviving half and
   silently produce a cert/key mismatch). For a rolling cutover keep both
   sides intact and stage the new files under different names.
2. **Distribute**:
   - **Prod**: via Channel A — e.g. edge-puppet
     `modules/nginx/files/antibot/edge-client.{crt,key}` → Puppet agent run on
     the edge nodes → `nginx -s reload` per edge.
   - **Demo**: there's no Puppet, so the edge VM operator runs
     [`infra/demo-stand/scripts/install-edge-client-cert.sh`](../demo-stand/scripts/install-edge-client-cert.sh)
     which scp's the pair from this host and checks the modulus matches
     before installing. Then `.env` gets the two `ANTIBOT_BACKEND_CLIENT_*`
     paths and the demo-stand container is recreated.
3. **CA rotation** (rarer): generate a new CA, sign the new client cert
   against it, drop a bundle `edge-ca.crt` containing both old + new into
   `certs/`, reload LB. After all edges have flipped to the new client cert,
   drop the old CA from the bundle and reload.
4. **Sanity-check** with `AUTH_MODE=mtls ./scripts/verify.sh` after each step
   — assertion #7 confirms "no client cert" still rejects and "valid cert"
   still passes. The script hard-exits at the top if the local
   `certs/edge-client.{crt,key}` are missing, so a stale `verify.sh` won't
   bury the real cause in cascaded false failures.

### Channel C staleness SLA

The edge exposes `antibot_edge_catalog_staleness_seconds{catalog="..."}` on
`/metrics` (B5 — `infra/demo-stand/lua/metrics.lua`). Contract per
config-distribution §Channel C and the B6 task:

- **≤ 30 s** for fast catalogs (the 30-s pull cadence; one missed tick is
  normal, two consecutive misses warrant a page).
- **≤ 15 min** for PR-merged catalogs (`fp_blocklist`, `ua_blacklist`, IP
  lists) — Channel A → Puppet bandwidth, well above one pull cycle, but a
  prolonged outage of the backend or LB is the alarm condition.

Whoever scrapes `/metrics` (Prometheus / external observability) writes the
alertmanager rule against these thresholds; this repo only guarantees the
metric is exported.

### Fail-stale verification

Manual scenario (two terminals — one on each VM):

```bash
# Backend VM: stop both Go instances; LB still listens but every catalog
# pull from the edge fails handshake/transport.
docker compose -f docker-compose.backend.yml stop backend-1 backend-2

# Edge VM (or anywhere with reach): watch the gauge climb in real time.
watch -n 5 'curl -sk https://<stand-host>/metrics | grep antibot_edge_catalog_staleness_seconds'

# Edge keeps serving:
curl -sk -o /dev/null -w '%{http_code}\n' https://<stand-host>/
# → 200 (fail-stale; verdict pipeline reads the previous gen from shared_dict)

# Restore:
docker compose -f docker-compose.backend.yml start backend-1 backend-2
# Within ~30s the gauge drops back near 0 — staleness reset on first successful pull.
```

## Secrets

`.env` and `certs/` are gitignored. `provision.sh` generates a random
`POSTGRES_PASSWORD` and a self-signed cert (`certs/{fullchain,privkey}.pem`, same
naming as demo-stand so a certbot deploy-hook can refresh it) on first run; never
commit either.
