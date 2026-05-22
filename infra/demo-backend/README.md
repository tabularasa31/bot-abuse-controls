# infra/demo-backend — [B1] antibot-backend substrate (provisioning)

Reproducible provisioning for the **antibot-backend** demo VM: PostgreSQL plus a
≥2-instance backend pair behind a TLS-terminating LB, with the edge → backend
HTTPS path opened. This is the *substrate* task ([B1]) — it stands up and proves
the topology from [ADR-005](../../docs/architecture-decisions/005-centralized-antibot-backend.md)
and [config-distribution §HA](../../docs/architecture/config-distribution.md),
nothing more.

> **Reality level: backlog / provisioning only.** The `backend-*` containers are
> placeholders (nginx returning a health JSON), **not** the real Go service. The
> antibot-backend app is [B2] (catalog/log/rDNS) and its app-level deploy +
> migrations are [B15]. They drop into this exact topology: swap the placeholder
> image, point it at `postgres`, keep the LB + certs + firewall.
>
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

## Acceptance ([B1])

`scripts/verify.sh` checks each criterion:

| Criterion | Check |
|---|---|
| VM(s) up, PostgreSQL accessible | `pg_isready` inside the `postgres` container |
| Edge → backend reachable over HTTPS | `GET https://<host>/health` → `200` on `:443` |
| Deploy reproducible | compose file + scripts; `provision.sh` re-runnable |
| HA (≥2 instances) | `/health` round-robins ≥2 distinct `instance` tags |

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
