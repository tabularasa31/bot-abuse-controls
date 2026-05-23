# antibot-backend — централизованный Go-сервис (B2)

Реализация antibot-backend по
[ADR-005](../docs/architecture-decisions/005-centralized-antibot-backend.md) и
[config-distribution.md](../docs/architecture/config-distribution.md): три
функции, ничего сверх:

1. **catalog server** — отдаёт каталоги на edge по Channel C
   (`GET /catalog/<name>`). HTTP-контракт (ETag/If-None-Match, тела) — задача
   [B3] поверх схемы [B4]. Сейчас известные каталоги отвечают `501`, неизвестные
   — `404`.
2. **log receiver** — `POST /v1/logs`, принимает поток BAC_LOG с эджей, отвечает
   `202`. Метрика `antibot_backend_log_lines_received_total` считает строки.
   Валидация схемы, батч в sink, disk-queue — задачи [B6]/[B9].
3. **rDNS worker** — фоновый таймер (`RDNS_INTERVAL`, по умолчанию `30m`).
   Метрика `antibot_backend_rdns_ticks_total` доказывает, что воркер живёт.
   Реальный PTR+forward DNS и 3-state machine (verified/rejected/provisional)
   — задача [B7].

Сервис **stateless** поверх своей PostgreSQL. На hot-path edge не висит —
fail-stale (см. config-distribution §"Channel C / Failure mode").

## Запуск

Локально:

```bash
go run ./cmd/antibot-backend
# затем:
curl http://localhost:8080/health
curl -i http://localhost:8080/catalog/fp_blocklist        # 501
curl -i -X POST --data 'line1\nline2\n' http://localhost:8080/v1/logs  # 202
curl http://localhost:8080/metrics | grep antibot_backend_
```

В составе демо-стека (HA-пара за TLS-LB + Postgres) — см.
[`../infra/demo-backend/`](../infra/demo-backend/).

## Конфиг (env)

| Переменная | Дефолт | Назначение |
|---|---|---|
| `HTTP_ADDR` | `:8080` | listen для HTTP. LB B1-substrate'а ходит сюда. |
| `INSTANCE_NAME` | hostname | метка в `/health` и логах (для round-robin checks). |
| `POSTGRES_DSN` | пусто | DSN для pgxpool. Пусто = skeleton-режим без DB. |
| `RDNS_INTERVAL` | `30m` | тик rDNS-воркера. |
| `SHUTDOWN_TIMEOUT` | `10s` | graceful-shutdown HTTP-сервера. |
