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
# Repo must be a real git checkout (so scripts/update.sh can `git pull`).
# Generate a deploy key on this VM, add the public half to the repo's
# Deploy Keys (read-only is enough), then:
ssh-keygen -t ed25519 -N "" -f ~/.ssh/abuse-controls-deploy
# → paste ~/.ssh/abuse-controls-deploy.pub into GitHub Settings → Deploy keys
cat >> ~/.ssh/config <<EOF
Host github-abuse
  HostName github.com
  User git
  IdentityFile ~/.ssh/abuse-controls-deploy
  IdentitiesOnly yes
EOF
git clone git@github-abuse:tabularasa31/abuse-controls.git ~/abuse-controls
cd ~/abuse-controls/infra/demo-backend

./scripts/provision.sh        # docker + compose, ufw 443, .env, cert, stack up
./scripts/verify.sh           # acceptance checks

# Optional: enable cron auto-pull (see "Auto-pull from main every minute" below).
( crontab -l 2>/dev/null; echo "* * * * * /home/$(whoami)/abuse-controls/infra/demo-backend/scripts/update.sh >> /home/$(whoami)/abuse-controls/state/backend-update.log 2>&1" ) | crontab -
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

## Auto-pull from `main` every minute

The backend VM, like the edge, can keep itself synchronised with `main`
through a cron job. [`scripts/update.sh`](scripts/update.sh) does it
safely:

- Single-flight (`flock`); skips when a previous run is still in progress.
- Refuses to merge over local commits — `git merge --ff-only`.
- Only rebuilds when a **build input** path actually changed
  (`antibot-backend/`, the compose file, `nginx/`, `auth/`). Doc-only
  commits no-op without disturbing the running stack.
- On rebuild: `docker compose up -d --build`, with `docker-compose.override.yml`
  (see below) merged automatically so per-deploy overrides survive.
- Marker file `state/.backend-last-deployed-sha` advances only after a
  successful `up`; a transient build failure is retried on the next tick.

Cron line (one minute cadence — matches edge; replace `<USER>` with the
account that owns the checkout, e.g. `ubuntu` on the demo VMs):

```cron
* * * * * /home/<USER>/abuse-controls/infra/demo-backend/scripts/update.sh \
    >> /home/<USER>/abuse-controls/state/backend-update.log 2>&1
```

The checkout this script lives in must be a real `git` working copy with
read access to the repo (deploy key on GitHub, or PAT-baked HTTPS remote).
A pre-baked tarball will fail at `git fetch`. The script is symmetric to
[`../demo-stand/scripts/update.sh`](../demo-stand/scripts/update.sh) — same
flock / marker / ff-only / fail-on-up-error invariants.

## Local override

Per-deploy customisations (single-backend setup, custom allowlist file,
substitute LB config) live in `infra/demo-backend/docker-compose.override.yml`
on the host. Docker Compose auto-merges this file with the committed
`docker-compose.backend.yml` on every `up`, so the override survives every
auto-pull without touching the tracked tree. `.gitignore` lists the override
plus a `nginx/lb.local.conf` slot used by the most common case below.

**Example: single-backend demo VM** (the production setup wants HA, but a
single-instance demo on its own VM is enough to validate the pipeline). Two
files on the host:

```yaml
# infra/demo-backend/docker-compose.override.yml — disables backend-2
# and remaps the LB's bind-mount to a single-backend lb.conf.
services:
  backend-2:
    # Compose has no "delete service" knob, but we can stop the service
    # from running by overriding its restart policy + a no-op command.
    # The cleaner alternative is profiles — see comment below.
    restart: "no"
    command: ["true"]
    healthcheck:
      disable: true
    depends_on: []
  lb:
    volumes:
      - ./nginx/lb.local.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - ./auth/${AUTH_MODE:-ip-allowlist}.conf:/etc/nginx/conf.d/auth.conf:ro
      - ./auth/allow.list:/etc/nginx/conf.d/allow.list:ro
    depends_on:
      - backend-1
```

```nginx
# infra/demo-backend/nginx/lb.local.conf — copy of nginx/lb.conf with
# backend-2 stripped from the upstream so nginx doesn't fail on DNS
# resolution at startup.
upstream antibot_backend {
    server backend-1:8080 max_fails=3 fail_timeout=10s;
}
# ... rest identical to nginx/lb.conf
```

Both files are gitignored, so update.sh runs cleanly forever. To go back
to HA, delete both files and `docker compose up -d` — the committed
two-backend topology comes back.

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
`/metrics` (B5 — `infra/demo-stand/lua/metrics.lua`).

**Semantics**: the gauge is "seconds since the last successful **contact**
with antibot-backend" — both `200` (new data landed) and `304` (ETag
matched, no new data, channel still healthy) reset it. Transport errors,
non-200/304 statuses, and decode failures leave the gauge growing. **This
is a liveness signal, not a data-freshness one** — the alert fires when
backend stops answering, not when a PR-merged catalog has been the same
payload for a week (which is the steady state for `fp_blocklist`,
`ua_blacklist`, IP lists). Pinned by `tests/catalog_pull_test.lua` case 2.

Contract per config-distribution §Channel C and the B6 task:

- **≤ 30 s** — backend reachable on the 30-s pull cadence. One missed tick
  is normal jitter, two consecutive misses warrant a page.
- **≤ 15 min** — hard outage budget; beyond this the catalog payload on
  edge starts being meaningfully out of date for live changes (dashboard
  attack-mode toggle, urgent blocklist additions delivered via the
  dashboard, not via PR).

Whoever scrapes `/metrics` (Prometheus / external observability) writes the
alertmanager rule against these thresholds; this repo only guarantees the
metric is exported with the contract above.

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

## Policy API for the dashboard (B10)

`antibot-backend` exposes `/antibot/v1/policy/{site}/*` for per-host mutations
from the the platform dashboard-backend. Server-to-server only: the dashboard
authenticates its end users on its side, then forwards the change to
antibot-backend with a shared bearer token in `Authorization: Bearer …`.

**Setup.** `provision.sh` generates a random `DASHBOARD_API_TOKEN` on first
run (32 random bytes → 64 hex chars) and writes it into `.env`. Sync it to
dashboard-backend's own env; never commit.

If `DASHBOARD_API_TOKEN` is unset, `/antibot/v1/*` is NOT registered on
backend startup (fail-closed; dashboard would get 404). A warn line lands in
the backend log on every restart in that state.

**Defence-in-depth at the LB** (`nginx/lb.conf`):
1. `/antibot/v1/` has a **dedicated `location`** block, separate from
   `/catalog/` and `/health`. The block `include`s
   `auth/dashboard-cidr.conf` — a CIDR-allowlist of the dashboard-backend
   egress IPs. The file **ships committed** with loopback-only defaults so
   CI / fresh checkout bring up the stack out of the box; operators MUST
   edit it in-place on the VM (don't commit prod CIDRs back) with the real
   dashboard-backend egress before exposing the policy API to prod.
2. Per-IP rate limit `limit_req zone=antibot_api burst=10 nodelay` at
   `rate=20r/s`. Bounds blast radius if `DASHBOARD_API_TOKEN` leaks: a
   scripted PATCH flood from one source can't saturate the backend pgxpool
   and starve `/catalog/*` reads (edge would otherwise fall into fail-stale
   for all clients).

These layers are independent of `AUTH_MODE`. Even with `AUTH_MODE=off`
(debug, never for prod) the CIDR-allowlist + rate-limit still gate
`/antibot/v1/*`.

**Rotation.** Pick a new token; update env on both services simultaneously;
`docker compose restart backend-1 backend-2` (rolling restart, no downtime
thanks to the HA pair). The old token stops working the moment its instance
restarts; there is no overlap window — coordinate the dashboard env update
with the restart.

**Endpoints (short).** All under `/antibot/v1/policy/{site}/`:
- `GET .` — full Policy (404 if site never touched).
- `PATCH .` — merge-patch of `mode` / `strictness` / `attack_mode`. Strict
  decode (unknown keys → 400). Idempotent: `{"changed":false}` and
  `updated_at` is preserved on no-op.
- `GET/POST/DELETE ./{ua_blacklist|ip_blocklist|ip_whitelist|geo_whitelist|asn_block}`
  — list operations on per-host arrays. POST is dedup'd; DELETE returns 404
  if the item wasn't there.

Dashboard mutation → backend reload tick (5s, [B4]) → edge `/catalog/*` pull
(30s, [B5]) → swap on edge. End-to-end ≤30s under the contract from
[`config-distribution.md`](../../docs/architecture/config-distribution.md).
