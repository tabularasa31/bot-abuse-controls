# Integration test harness (D8 / B13)

Boots a minimal antibot stack (postgres + antibot-backend + edge) under
docker compose and exercises the [Channel C contract](../../docs/architecture/config-distribution.md)
from `vision.md §«Обновление каталогов»`:

| Contract claim | Case |
|---|---|
| ≤30s end-to-end latency, backend PATCH → edge applied | [`01-latency.sh`](../../tests/integration/cases/01-latency.sh) |
| Atomic shared_dict swap under load (no half-written reads) | [`02-atomic-swap.sh`](../../tests/integration/cases/02-atomic-swap.sh) |
| Fail-stale on backend outage (edge keeps last-good policy) | [`03-fail-stale.sh`](../../tests/integration/cases/03-fail-stale.sh) |
| `antibot_edge_catalog_staleness_seconds` grows when backend dead | [`04-staleness-metric.sh`](../../tests/integration/cases/04-staleness-metric.sh) |

## Run

```sh
make test-integration
```

This builds the images (first time), brings the stack up, waits for
healthchecks, runs `tests/integration/run.sh`, and tears everything
down — pass or fail. Total wall time on M-class laptop: ~60-90s.

Manual lifecycle (when iterating on a single case):

```sh
infra/test-harness/scripts/setup.sh            # one-time: gen test certs
docker compose -f infra/test-harness/docker-compose.test.yml up -d --wait
tests/integration/cases/03-fail-stale.sh       # run just one case
docker compose -f infra/test-harness/docker-compose.test.yml down -v
```

## What's different vs production

The harness reuses the same image builds as `infra/demo-{backend,stand}`
(no separate dockerfiles, no risk of drift). Two intervals are
compressed to keep CI wall-time bounded:

| Env var | Production | Harness | Why |
|---|---|---|---|
| `CATALOG_RELOAD_INTERVAL` (backend) | 5s | 1s | Backend's policy reloader tick |
| `ANTIBOT_BACKEND_PULL_INTERVAL` (edge) | 30s | 2s | Channel C pull cadence |

Both intervals exercise the **same code path** at every scale. The 30s
production SLA is asserted by construction: `1s reload + 2s pull = 3s`
on the harness; that's a 10× compression of the `5s reload + 30s pull
= 35s` production worst case. If the contract fails at 3s it fails at
35s; passing at 3s scales to ≥35s.

Other simplifications:
- Single backend instance (no HA / no nginx LB). The LB is a transport
  layer; the contract being tested is backend ↔ edge.
- Plain HTTP backend ↔ edge (no TLS / no mTLS / no IP allowlist). Auth
  is enforced at the LB in production; here the LB is omitted.
- Postgres on tmpfs (no persistent volume).

## Ports (loopback only)

- `https://127.0.0.1:18443` — edge public surface (`/__health`).
  Self-signed cert; use `curl -k`.
- `http://127.0.0.1:19090` — edge private mgmt plane (`/__policy`,
  `/__stats`); the harness publishes the loopback `:9090` here.
- `http://127.0.0.1:18080` — backend (`/antibot/v1/policy/...`,
  `/health`).

Both bound to `127.0.0.1` so a CI runner with parallel jobs can co-host
multiple harnesses without port collision.

## Adding a new case

1. Drop `tests/integration/cases/NN-shortname.sh` (numeric prefix
   determines run order; later cases assume earlier ones left a clean
   stack — case 03/04 stop the backend, so they MUST be the last two).
2. Source `tests/integration/lib.sh` for helpers (`edge_curl`,
   `dash_patch`, `poll_until`, `compose_stop_svc`).
3. Exit 0 on pass, non-zero on fail. Use stderr for diagnostics; the
   runner prints them on failure.
4. `chmod +x` it. `run.sh` discovers `cases/*.sh` by glob.

Cascade-behaviour scenarios (bot vs browser, attack_mode flow, per-host
list matches) go into `cases/adversarial/` under
[D9](https://app.clickup.com/t/86exmr6yf), not here — D8/B13 are
strictly about the catalog-delivery contract.

## Troubleshooting

- **`make test-integration` hangs at `--wait`**: a healthcheck isn't
  going green. `docker compose -f docker-compose.test.yml ps` shows
  which one. Common causes: postgres data dir won't initialize because
  tmpfs filled (rare) or backend can't migrate (check
  `docker compose logs backend`).
- **Case 01 fails with timeout**: pull interval override didn't reach
  the edge. Check `docker compose logs edge | grep catalog_pull` —
  startup line should say `interval=2`.
- **Case 02 fails with `malformed reads`**: regression in
  `catalog_pull.lua`'s gen-flip ordering — investigate any recent
  change to `handle_response`'s apply/flip/sweep sequence.
- **Test certs absent**: `infra/test-harness/scripts/setup.sh` requires
  `openssl` in PATH. CI image has it; older Alpine on a dev laptop
  might need `brew install openssl` / `apk add openssl`.
