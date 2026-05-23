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

From the edge VM, verify reach with the real hostname:

```bash
BACKEND_HOST=antibot.internal ./scripts/verify.sh
```

## Auth / firewall

`provision.sh` opens `443/tcp` via `ufw`. Restrict it to CDN operator's edge egress
range in a real deploy. **mTLS is the preferred edge → backend auth** (config-
distribution §Auth) — the directives are present but commented in
[`nginx/lb.conf`](nginx/lb.conf); enable them once the edge client CA is issued.

## Secrets

`.env` and `certs/` are gitignored. `provision.sh` generates a random
`POSTGRES_PASSWORD` and a self-signed cert (`certs/{fullchain,privkey}.pem`, same
naming as demo-stand so a certbot deploy-hook can refresh it) on first run; never
commit either.
