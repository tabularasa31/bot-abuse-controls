# Demo stand — abuse-controls antibot

A long-running demo of the production verdict pipeline, designed to be hosted on a VM with a public URL so reviewers (CDN operator admins, security, product) can probe it from their own machine without setting anything up.

The stand runs in **shadow mode** — the cascade computes and logs a verdict for every request, but the blocklist is empty so nothing is actually blocked (`200` for everyone). Blocking default curl/python would also block our own devs, and real bots masquerade as browsers anyway; we accumulate data first and decide what to block later. This is the same `infra/nginx-lua-poc/lua/verdict.lua` that ships in production, fronted by the multi-scenario endpoints below. To switch to active blocking, paste fp tokens into [`lua/blocklist.lua`](lua/blocklist.lua) and reload.

## Scenarios a reviewer can probe

| Endpoint | Try with | Expected | What it demonstrates |
|---|---|---|---|
| `/` | a real browser | 200, demo landing page | Browsers are allowed by default. |
| `/` | `curl -k https://<host>/` | 200 | Shadow mode: the cascade computes curl's fp and logs `would_verdict`, but the empty blocklist means no block. Confirm the computed fp via `/__fp`. |
| `/` | `python3 -c "import requests; requests.get('https://<host>/', verify=False)"` | 200 | Same — fp computed and logged, not blocked. |
| `/` | `wget -O - --no-check-certificate https://<host>/` | 200 | Same. wget's fp varies by build; visible in `/__fp` and the logs. |
| `/__fp` | anything | text dump | Educational — shows the fp the pipeline computed for *your* client + the raw `$ssl_*` components. |
| `/__health` | anything | `ok` | Liveness probe; bypasses verdict pipeline. |
| `/__version` | anything | git sha + uptime | What code is actually deployed. |
| `/__admin` | a real browser | HTML status page | Live counters: total requests, blocks, allows, cache hit ratio, blocklist size, uptime. No mutation surface. |
| `/metrics` | `curl -k https://<host>/metrics` | Prometheus text | Scrape-friendly metrics: `antibot_requests_total`, `antibot_verdict_total{verdict="allow"\|"block"}`, `antibot_cache_total{outcome="hit"\|"miss"}`, `antibot_cache_hit_ratio`, `antibot_blocklist_entries`, `antibot_uptime_seconds`. No latency histogram in this stand — cascade task [86exmk0ar](https://app.clickup.com/t/86exmk0ar) adds full `lua-resty-prometheus` with duration buckets. |
| `/baseline/` | anything | same site, **no** antibot | Bypasses `access_by_lua` entirely. Direct comparison: hit `/` and `/baseline/` with `wrk`, see the latency delta. |

The blocklist (in [`lua/blocklist.lua`](lua/blocklist.lua)) ships **empty** — shadow mode. Candidate automation fps to seed it from (curl/python/Go, captured 2026-05-16 on macOS arm64) are documented in [`docs/phase2-fp-catalog.md`](../../docs/phase2-fp-catalog.md); promoting them into the blocklist is a deliberate, data-driven step (see analyze.py HIGH-confidence candidates), not the default.

## Quickstart on a fresh VM

```sh
git clone <repo> abuse-controls && cd abuse-controls

# Pin your domain into nginx.demo.conf (one line).
$EDITOR infra/demo-stand/nginx.demo.conf
#   server_name <yourdomain>;

# Drop a real TLS cert in (or symlink your letsencrypt tree).
mkdir -p infra/demo-stand/certs
cp /your/fullchain.pem infra/demo-stand/certs/fullchain.pem
cp /your/privkey.pem   infra/demo-stand/certs/privkey.pem

# Bring up. The REVISION env var feeds /__version so reviewers can see
# what code is actually deployed. Without it the endpoint reports
# `commit: dev` (the compose default in docker-compose.demo.yml).
REVISION=$(git rev-parse --short HEAD) \
  docker compose -f infra/demo-stand/docker-compose.demo.yml up -d

# Smoke from the VM itself.
curl -k https://localhost/__health           # ok
curl -k https://localhost/                   # 200 (shadow mode: nothing blocked)
curl -k https://localhost/__fp               # see your fp
curl -k https://localhost/metrics            # prometheus text
```

## Updating a running stand

The Lua and nginx config are bind-mounted, so an update is just "pull the
files + reload" — no image rebuild. [`scripts/update.sh`](scripts/update.sh)
does it safely: fast-forwards `main`, runs `openresty -t` to validate the
config, and only then `openresty -s reload` (no dropped connections). It
no-ops when `main` hasn't moved and is safe to run from cron.

**Manual:**

```sh
./infra/demo-stand/scripts/update.sh
```

**Auto-pull from `main` every minute (cron on the VM):**

```sh
* * * * * /home/ubuntu/abuse-controls/infra/demo-stand/scripts/update.sh \
    >> /home/ubuntu/abuse-controls/state/update.log 2>&1
```

With this, your loop is just `git push` to `main` → edge picks it up within
a minute. Verify what's live with `curl -k https://<host>/__version`, and
watch the run log at `state/update.log`.

## What this does NOT show

- **Hot-reload of the blocklist** (cascade task [В1](https://app.clickup.com/t/86exmk08u)). The demo uses a static blocklist loaded at init.
- **Grey-verdict / sidecar scoring** (cascade task [В2](https://app.clickup.com/t/86exmk09b)). The demo is edge-only.
- **JS challenge issuance** (cascade task [A8](https://app.clickup.com/t/86exmk02c)). The demo blocks or allows; no challenge flow.
- **Rate limiting** (cascade task [A3](https://app.clickup.com/t/86exmjzxm)). Each request is independent.
- **UA↔JA consistency** (cascade task [A5](https://app.clickup.com/t/86exmk00m)). The demo's blocklist doesn't include this signal.

The demo is intentionally the **A1 fp blocklist** slice of the cascade only — the part that's production-ready post-PR #3/#4. Other cascade tasks are sequenced after a successful demo + integration with CDN operator edge.

## Files

```
infra/demo-stand/
├── README.md                       (this file)
├── nginx.demo.conf                 nginx config with all the scenario endpoints
├── docker-compose.demo.yml         stock openresty/openresty:alpine + bind mounts
├── certs/                          TLS material (gitignored)
├── lua/
│   ├── verdict.lua                 verdict pipeline (production variant; symlink-equivalent of infra/nginx-lua-poc/lua/verdict.lua)
│   ├── ja4_compute.lua             same compute as production
│   ├── blocklist.lua               seed automation fps
│   ├── init.lua                    load blocklist, init metrics counters
│   ├── metrics.lua                 /metrics handler (Prometheus text format)
│   ├── admin.lua                   /__admin HTML status page
│   ├── probe.lua                   /__fp educational endpoint
│   └── log_event.lua               per-request counter increment + log line
└── sites/default-site/
    └── index.html                  demo landing page (served via content_by_lua)
```

## Talking points for a sceptical reviewer

| Concern | Where to look |
|---|---|
| "Is this AI-generated slop?" | `make ci` passes 61 unit tests + 0 lint warnings. ADRs in [`docs/architecture-decisions/`](../../docs/architecture-decisions/) document every non-obvious decision with alternatives explicitly considered. Engineering narrative in [`docs/engineering-narrative.md`](../../docs/engineering-narrative.md) traces the work commit-by-commit. |
| "What if it crashes my edge?" | [`docs/security-review.md`](../../docs/security-review.md) §"Fail-open philosophy" — the pipeline never `ngx.exit(5xx)`s itself. If our Lua throws, the request is served. Worst case: we don't block. We never break. |
| "How much overhead per request?" | Hit `/baseline/` vs `/` with `wrk`. Measured ~32 K RPS allow path vs ~40 K baseline on a 4-core MacBook — see [`docs/lua-poc-results.md`](../../docs/lua-poc-results.md). |
| "How do I roll it back?" | Single config-line change (per [ADR-002](../../docs/architecture-decisions/002-spike-2-lua-ssl-vars.md) consequences). Demo shadow-mode-style fallback at [`infra/nginx-shadow/`](../nginx-shadow/) if you want enforcement off but observability on. |
| "Why not just use cloudflare/qrator/foxio/etc?" | RFC [`docs/architecture/edge-lua-vs-sidecar.md`](../../docs/architecture/edge-lua-vs-sidecar.md) §А explains: lua-nginx-module is already on the edge; this is additive, not a stack replacement. |
| "What do I monitor?" | `/metrics` for Prometheus scrape. [`docs/runbook.md`](../../docs/runbook.md) (when written) covers on-call patterns. |
