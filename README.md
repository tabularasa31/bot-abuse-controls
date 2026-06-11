# abuse-controls

Bot & Abuse Controls v1 для the platform (продукт на инфраструктуре CDN operator).

Реализует архитектурное решение из [RFC edge Lua vs Go sidecar](docs/architecture/edge-lua-vs-sidecar.md) + [config-distribution.md](docs/architecture/config-distribution.md): фильтрация — на edge через OpenResty/Lua, control plane (каталоги, dashboard, rDNS, log sink) — централизованный Go-сервис [`antibot-backend/`](antibot-backend/). Per-edge sidecar отменён (см. config-distribution §"What was rejected").

## Структура

- `infra/demo-stand/` — long-running демо-эдж (cascade, B-серия)
- `infra/demo-backend/` — HA-стек для antibot-backend (Postgres + LB)
- `antibot-backend/` — централизованный Go-сервис (catalog server + log receiver + rDNS)
- `docs/architecture/config-distribution.md` — двухканальная модель (Channel A Puppet + Channel C HTTP pull)
- `docs/architecture/edge-lua-vs-sidecar.md` — исторический RFC (superseded ADR-005)

## Запуск

См. [`infra/demo-stand/README.md`](infra/demo-stand/README.md) для demo-эджа и
[`antibot-backend/README.md`](antibot-backend/README.md) для backend'a.
