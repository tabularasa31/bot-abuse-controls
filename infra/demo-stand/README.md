# Demo stand — abuse-controls antibot

A long-running demo of the production verdict pipeline, designed to be hosted on a VM with a public URL so reviewers (CDN operator admins, security, product) can probe it from their own machine without setting anything up.

The stand demonstrates **active blocking** (not shadow mode) — curl and python-requests get 403, browsers get 200. This is the same `infra/nginx-lua-poc/lua/verdict.lua` that ships in production, fronted by the multi-scenario endpoints below.

## Scenarios a reviewer can probe

| Endpoint | Try with | Expected | What it demonstrates |
|---|---|---|---|
| `/` | a real browser | 200, demo landing page | Browsers are allowed by default. |
| `/` | `curl -k https://<host>/` | 403 | Default curl (LibreSSL on macOS / OpenSSL elsewhere) matches the seed blocklist — the fp `L13d49h2_...` is one of the pre-loaded automation entries. |
| `/` | `python3 -c "import requests; requests.get('https://<host>/', verify=False)"` | 403 | Same: python-requests fp is in the seed blocklist. |
| `/` | `wget -O - --no-check-certificate https://<host>/` | depends on wget's TLS stack | wget's fp differs by build; may not be in seed blocklist (will pass through with `would_verdict=allow`). |
| `/__fp` | anything | text dump | Educational — shows the fp the pipeline computed for *your* client + the raw `$ssl_*` components. Same response whether or not your fp is blocked. |
| `/__health` | anything | `ok` | Liveness probe; bypasses verdict pipeline. |
| `/__version` | anything | git sha + uptime | What code is actually deployed. |
| `/__admin` | a real browser | HTML status page | Live counters: total requests, blocks, allows, cache hit ratio, blocklist size, uptime. No mutation surface. |
| `/metrics` | `curl -k https://<host>/metrics` | Prometheus text | Scrape-friendly metrics: `antibot_verdict_total{verdict=...}`, `antibot_cache_hit_total`, `antibot_request_duration_seconds_bucket{...}`, `antibot_blocklist_entries`. |
| `/baseline/` | anything | same site, **no** antibot | Bypasses `access_by_lua` entirely. Direct comparison: hit `/` and `/baseline/` with `wrk`, see the latency delta. |

The seed blocklist (in [`lua/blocklist.lua`](lua/blocklist.lua)) is the same 3 automation fps documented in [`docs/phase2-fp-catalog.md`](../../docs/phase2-fp-catalog.md), captured 2026-05-16 on macOS arm64. Real production traffic would have a wider seed set; this is enough to demonstrate visible blocking from day 1.

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

# Bring up.
docker compose -f infra/demo-stand/docker-compose.demo.yml up -d

# Smoke from the VM itself.
curl -k https://localhost/__health           # ok
curl -k https://localhost/                   # 403 (curl is in seed blocklist)
curl -k https://localhost/__fp               # see your fp
curl -k https://localhost/metrics            # prometheus text
```

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
│   ├── verdict.lua                 active blocking (production variant; symlink-equivalent of infra/nginx-lua-poc/lua/verdict.lua)
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
