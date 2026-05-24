# antibot-backend — централизованный Go-сервис (B2)

Реализация antibot-backend по
[ADR-005](../docs/architecture-decisions/005-centralized-antibot-backend.md) и
[config-distribution.md](../docs/architecture/config-distribution.md): три
функции, ничего сверх:

1. **catalog server** — отдаёт каталоги на edge по Channel C
   (`GET /catalog/<name>`, ETag/If-None-Match, `?site=<host>`). HTTP-контракт
   реализован в [B3]; схема PostgreSQL + per-host policy и периодический
   reload — в [B4]. Источник данных выбирается по `POSTGRES_DSN` (БД,
   приоритетно) или `CATALOG_YAML` (fallback). Без обоих Store пуст и
   `/catalog/*` отвечает `503`.
2. **log receiver** — `POST /v1/logs`, принимает поток BAC_LOG с эджей, отвечает
   `202`. Метрика `antibot_backend_log_lines_received_total` считает строки.
   Валидация схемы, батч в sink, disk-queue — задачи [B6]/[B9].
3. **rDNS worker** ([B7]) — reactive фоновая горутина. Receiver, парсящий
   BAC_LOG, дёргает `Worker.Enqueue` для каждой строки с поисковым UA
   (Googlebot/bingbot/YandexBot/DuckDuckBot) и непустым IP. Воркер делает
   `PTR → forward DNS` (оба этапа должны сойтись на официальный домен
   поисковика — `.googlebot.com`, `.search.msn.com` и т.д.) и пишет
   verdict в каталог `verified_bot_ips` с TTL 1ч симметрично для обоих
   исходов (`verified` / `rejected`). Edge на L2.2 различает их по
   значению (`"verified:<family>"` / `"rejected:<family>"`); отсутствие
   ключа = provisional fastpath. Метрики: `..._rdns_enqueued_total`,
   `..._rdns_verified_total`, `..._rdns_rejected_total`,
   `..._rdns_queue_length`.

Сервис **stateless** поверх своей PostgreSQL. На hot-path edge не висит —
fail-stale (см. config-distribution §"Channel C / Failure mode").

## Запуск

Локально:

```bash
go run ./cmd/antibot-backend
# затем:
curl http://localhost:8080/health
curl -i http://localhost:8080/catalog/fp_blocklist        # 503 catalog_not_loaded без CATALOG_YAML / POSTGRES_DSN; 200 если источник задан
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
| `POSTGRES_DSN` | пусто | DSN для pgxpool. Пусто = skeleton-режим без DB. Если задан — становится источником каталогов (B4), CATALOG_YAML игнорируется. |
| `CATALOG_YAML` | пусто | путь до YAML с каталогами (dev-fallback B3). Игнорируется, если задан `POSTGRES_DSN`. |
| `CATALOG_RELOAD_INTERVAL` | `5s` | как часто backend перечитывает каталоги из БД (B4). Короче 30 с edge-poll'a, чтобы изменения доезжали ≤30 c. |
| `MIGRATE_ON_STARTUP` | `true` | прогон встроенных миграций до старта HTTP при `POSTGRES_DSN`. `false` для прод-сценариев с внешним мигратором (B15). |
| `RDNS_INTERVAL` | `30m` | устаревший knob от B2-скелета. В B7 воркер reactive (триггер — поток логов), периодического тика нет; параметр игнорируется. |
| `RDNS_QUEUE_SIZE` | `1024` | буфер reactive-очереди rDNS-воркера. Переполнение = receiver дропает задачу в метрику `..._rdns_dropped_total`, edge продолжит выдавать provisional. |
| `RDNS_WORKERS` | `4` | параллельных DNS-резолверов на воркера. |
| `RDNS_DNS_TIMEOUT` | `5s` | потолок на одну итерацию PTR+forward для IP. |
| `RDNS_GC_INTERVAL` | `1h` | как часто `DELETE` протухшие строки `verified_bot_ips`. |
| `SHUTDOWN_TIMEOUT` | `10s` | graceful-shutdown HTTP-сервера. |

## Схема PostgreSQL (B4)

Восемь таблиц для восьми каталогов Channel C + singleton `catalog_version`.
SQL-файл — [`internal/dbloader/migrations/0001_init.sql`](internal/dbloader/migrations/0001_init.sql),
встраивается через `//go:embed` и применяется на старте при
`MIGRATE_ON_STARTUP=true`. Все `CREATE TABLE IF NOT EXISTS` — повторный
запуск безопасен; полноценный мигратор (golang-migrate с tracking-table)
принесёт [B15].

Per-host `policy` — единственная таблица с JSONB-полями: `ua_blacklist`,
`ip_whitelist`, `ip_blocklist`, `asn_block`, `geo_whitelist`, `rate_rules`.
Lookup ключ — `host`. Незарегистрированный host → дефолт пула
(`mode=shadow`, `strictness=standard`, всё пусто, `attack_mode=false`).

Тесты dbloader интеграционные, гейтятся `POSTGRES_TEST_DSN`:

```bash
docker run -d --rm --name pg-test -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16-alpine
POSTGRES_TEST_DSN="postgres://postgres:test@localhost:55432/postgres?sslmode=disable" \
  go test ./internal/dbloader/ -count=1 -v
docker stop pg-test
```
