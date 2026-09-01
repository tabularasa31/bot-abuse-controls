# bot-abuse-controls

[![CI](https://github.com/tabularasa31/bot-abuse-controls/actions/workflows/ci.yml/badge.svg)](https://github.com/tabularasa31/bot-abuse-controls/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Bot and abuse controls for a CDN edge: a request-scoped verdict cascade running in
OpenResty/Lua at the edge, driven by a centralized Go control plane.

Every request is classified through five layers and gets exactly one verdict —
`allow`, `block`, `challenge` or `permissive` — together with the rule that decided
it. The verdict is always computed and always logged; whether it is physically
enforced is a per-host setting, so a customer can be run in observation mode and
switched to enforcement without a code change.

## The cascade

| Layer | Stage | What it decides | Cost |
|---|---|---|---|
| L1 | `hygiene.lua` | Method whitelist, User-Agent blacklist, header anomalies | microseconds, no I/O |
| L2 | `reputation.lua` | Clearance cookie (HMAC verify), verified bots (rDNS), IP allow/block lists, ASN and geo | one shared_dict lookup |
| L3 | `tls_fp.lua` | JA4-style TLS fingerprint: known automation signatures, browser-profile mismatches | fingerprint computed once per connection |
| L4 | `rate_limit.lua` | GCRA rate limits keyed on IP, IP+UA, API path, scanned URLs, TLS fingerprint | shared_dict counters |
| L5 | `verification.lua` | JS challenge, clearance cookie issuance, under-attack behaviour | only for grey traffic |

`verdict.lua` is the entry point and the only place that exits a request. Layers
L1–L4 accumulate signals; L5 is the single decision point for issuing a challenge.

The TLS fingerprint is computed in pure Lua from the `$ssl_*` variables nginx
already exposes — no external service and no C module, with GREASE values stripped
per RFC 8701.

## Architecture

The edge stays stateless and cheap. Everything that changes — blocklists,
per-host policy, verified-bot IPs — is data delivered to it, never code.

```
  Puppet ──────────────► edge (nginx + OpenResty/Lua)
  (framework: Lua, nginx snippets)      │
                                        │ HTTPS pull, 30s, ETag/If-None-Match
                                        ▼
                              antibot-backend (Go)
                                 ├─ catalog server
                                 ├─ log receiver
                                 └─ rDNS worker
                                        │
                            PostgreSQL  +  catalogs/ (git)
```

Two delivery paths, split by how fast the data has to move:

- Framework — the Lua sources and nginx configuration, shipped by Puppet at human cadence.
- Runtime data — catalogs and policy, pulled by the edge every 30 seconds with
  conditional GETs. A failed pull is fail-stale: the last good snapshot keeps
  serving, and the cascade never blocks on a missing catalog.

Catalog updates land in a `lua_shared_dict` through a generation-counter swap, so a
request never sees a half-applied list.

## Policy and modes

Policy is keyed by `Host`, so one edge serves many tenants independently.

- Mode — `shadow` computes and logs the verdict while traffic reaches the origin; `active` enforces it.
- Strictness — `Standard` challenges on soft signals, `Permissive` records them and passes.
- Attack mode — per host, forces a challenge for anything not explicitly trusted and shortens the clearance cookie TTL.
- Staged rollout — a catalog entry lands as `staging` first: it matches and is logged, but does not block. Promotion to `active` is a second, separate change.

## Repository layout

- `infra/demo-stand/` — the edge: the Lua cascade, nginx configuration, challenge page asset
- `antibot-backend/` — the Go control plane: catalog server, log receiver, rDNS worker
- `infra/demo-backend/` — the backend's HA stack: two replicas behind a load balancer, PostgreSQL, Loki, Grafana
- `catalogs/` — the slow catalogs as YAML, reviewed through pull requests
- `docs/product/` — the behavioural specification the cascade implements
- `docs/runbooks/` — operational procedures: secret rotation, mode toggle, catalog rollback
- `tests/`, `infra/test-harness/` — unit tests, and an integration harness for the catalog contract

What is built and what is planned: [ROADMAP.md](ROADMAP.md).

## Running it

The edge and the backend each run standalone under Docker Compose:

```bash
docker compose -f infra/demo-stand/docker-compose.demo.yml up
```

See [`infra/demo-stand/README.md`](infra/demo-stand/README.md) and
[`antibot-backend/README.md`](antibot-backend/README.md) for configuration.

## Tests

```bash
make test-docker
```

Runs the Lua suite inside the OpenResty container. CI additionally runs
golangci-lint, luacheck, shellcheck, the Go and Python suites, catalog validation,
compose smoke tests, and an integration job that exercises catalog delivery
latency, atomicity and fail-stale behaviour.

## License

[AGPL-3.0](LICENSE). Network use counts as distribution: if you run a modified
version as a service, you have to publish the source of your modifications.

Two vendored Lua files stay under Apache-2.0 — see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
