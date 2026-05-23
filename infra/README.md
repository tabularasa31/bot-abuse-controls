# infra/ — what each directory is

Three directories, three distinct roles. They are **not** competing "stands".

## `demo-stand/` — the live demo

The hosted demo (`bac.example.com`): a real OpenResty reverse proxy that
runs the full verdict cascade and proxies to an origin (`ORIGIN_URL`). Runs
in **shadow** (empty blocklist — computes and logs verdicts, blocks nothing).
This is the one thing we actually deploy and keep alive. Has its own
observability (`/__admin`, `/metrics`), structured `BAC_LOG`, analytics
(`scripts/analyze.py`), and a cron auto-update loop. See
[`demo-stand/README.md`](demo-stand/README.md).

Источник правды fp-кода ([`lua/ja4_compute.lua`](demo-stand/lua/ja4_compute.lua),
[`lua/ja4_helpers.lua`](demo-stand/lua/ja4_helpers.lua)) теперь лежит здесь
же — рядом с остальным каскадом.

## `demo-backend/` — antibot-backend HA-стек

Docker compose substrate (Postgres + HA-пара antibot-backend за TLS-LB) для
централизованного Go-сервиса из [`antibot-backend/`](../antibot-backend/) по
ADR-005 / config-distribution. См. [`demo-backend/README.md`](demo-backend/README.md).

## `nginx-lua-poc/` — removed

Был отдельный спайк PoC #2 (`access_by_lua` verdict path benchmark). После
переезда `ja4_compute.lua` / `ja4_helpers.lua` в `demo-stand/lua/` папка
полностью удалена; компоуз `docker-compose.lua-poc.yml`, пробник
`scripts/lua-poc-probe.sh` и результаты `docs/lua-poc-results.md` /
`docs/phase2-fp-catalog.md` — тоже.

## Not here anymore

- **`nginx-shadow/`** — removed. It was a separate "shadow proxy in front of
  a real backend" package; that role is now exactly `demo-stand` (shadow +
  proxy to `ORIGIN_URL`), and keeping it meant a third drifting copy of the
  pipeline.

## Related (other repo)

The **vanilla** stack (FoxIO `ja4-nginx-module` + Go sidecar,
`bac-vanilla.example.com`) lives in the separate
[`antibot-lab`](https://github.com/tabularasa31/antibot-lab) repo — a parallel
comparison track, not part of this repo.
