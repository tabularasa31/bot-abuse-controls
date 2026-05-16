# abuse-controls

Bot & Abuse Controls v1 для the platform (продукт на инфраструктуре CDN operator).

Реализует архитектурное решение из [RFC edge Lua vs Go sidecar](docs/architecture/edge-lua-vs-sidecar.md): большая часть фильтрации — на edge через OpenResty/Lua, Go sidecar остаётся для control plane (catalog hot-reload, ML logging, dashboard analytics, heavy scoring).

## Связь с antibot-lab

Phase 1 PoC (модули JA3/JA4 для nginx, выбор FoxIO ja4-nginx-module) выполнен в [../antibot-lab](../antibot-lab) — этот репо остаётся как Phase 1 артефакт. Сюда перенесён только Go sidecar `antibot/` для будущего `with-sidecar` профиля.

## Структура

- `infra/nginx-lua-poc/` — стенд PoC #2 (OpenResty + lua-resty-ja3, Lua-only verdict path)
- `antibot/` — Go sidecar (copied from antibot-lab, не используется в текущем `lua-only` профиле)
- `scripts/lua-poc-probe.sh` — JA3 probe (curl/python/go)
- `docs/lua-poc-results.md` — wrk-числа PoC #2
- `docs/architecture/edge-lua-vs-sidecar.md` — расширенный RFC

## Запуск PoC #2

См. [infra/nginx-lua-poc/README.md](infra/nginx-lua-poc/README.md).

## Ветки

Активная: `feature/poc2-lua-and-rfc`. Remote не настроен.
