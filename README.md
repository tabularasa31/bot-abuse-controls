# bot-abuse-controls

Bot & Abuse Controls v1 — антибот-каскад для CDN-эджа (OpenResty/Lua) с централизованным control plane.

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

## Лицензия

[AGPL-3.0](LICENSE). Сетевое использование считается распространением: если ты
запускаешь модифицированную версию как сервис, исходники модификаций нужно
опубликовать.

Два вендоренных Lua-файла остаются под Apache-2.0 — см.
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
