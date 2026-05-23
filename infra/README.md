# infra/ — what each directory is

Two directories, two distinct roles.

## `demo-stand/` — the live demo

The hosted demo (`bac.example.com`): a real OpenResty reverse proxy that
runs the full verdict cascade and proxies to an origin (`ORIGIN_URL`). Runs
in **shadow** (empty blocklist — computes and logs verdicts, blocks nothing).
This is the one thing we actually deploy and keep alive. Has its own
observability (`/__admin`, `/metrics`), structured `BAC_LOG`, analytics
(`scripts/analyze.py`), and a cron auto-update loop. См.
[`demo-stand/README.md`](demo-stand/README.md).

Источник правды fp-кода ([`lua/ja4_compute.lua`](demo-stand/lua/ja4_compute.lua),
[`lua/ja4_helpers.lua`](demo-stand/lua/ja4_helpers.lua)) лежит здесь же —
рядом с остальным каскадом.

## `demo-backend/` — antibot-backend HA-стек

Docker compose substrate (Postgres + HA-пара antibot-backend за TLS-LB) для
централизованного Go-сервиса из [`antibot-backend/`](../antibot-backend/) по
ADR-005 / config-distribution. См. [`demo-backend/README.md`](demo-backend/README.md).

## Not here anymore

- **`nginx-lua-poc/`** — спайк PoC #2 (`access_by_lua` verdict path benchmark).
  Бенчмарк-стенд больше не нужен; `ja4_compute.lua` / `ja4_helpers.lua`
  переехали в `demo-stand/lua/`. Сопутствующее — `docker-compose.lua-poc.yml`,
  `scripts/lua-poc-probe.sh`, `docs/lua-poc-results.md`,
  `docs/phase2-fp-catalog.md` — тоже удалено.
- **`nginx-shadow/`** — removed. It was a separate "shadow proxy in front of
  a real backend" package; that role is now exactly `demo-stand`.

## Related (other repo)

The **vanilla** stack (FoxIO `ja4-nginx-module` + Go sidecar,
`bac-vanilla.example.com`) lives in the separate
[`antibot-lab`](https://github.com/tabularasa31/antibot-lab) repo — a parallel
comparison track, not part of this repo.
