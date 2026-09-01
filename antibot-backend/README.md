# antibot-backend — the centralized Go service (B2)

The implementation of antibot-backend per
the design decision and
[config-distribution.md](../docs/architecture/config-distribution.md): three
functions, nothing more:

1. **The catalog server** — serves the catalogs to the edge over Channel C
   (`GET /catalog/<name>`, ETag/If-None-Match, `?site=<host>`). After
   the design decision
   there are two sources:
   - **the slow catalogs** (`tls_fp_blocklist`, `ua_blacklist`, `ip_blocklist`,
     `ip_whitelist`, `asn_datacenters` plus `version`) live in the
     `../catalogs/` git repo and are read by `internal/filesource` with an mtime cache;
   - **the runtime state** (`verified_bot_ips`, `policy`) lives in PostgreSQL and is
     read by `dbloader.LoadRuntime`.
   On every tick the reloader merges both layers through `catalog.Merge` and
   publishes them atomically into Store.Replace. Without a database the service goes into skeleton
   mode and `/catalog/*` answers `503`.
2. **The log receiver** — `POST /v1/logs` accepts the BAC_LOG stream from the edges and answers
   `202`. The `antibot_backend_log_lines_received_total` metric counts the lines.
   Schema validation, batching into the sink and the disk queue are tasks / .
3. **The rDNS worker**  — a reactive background goroutine. The receiver parsing
   BAC_LOG calls `Worker.Enqueue` for every line with a search engine UA
   (Googlebot/bingbot/YandexBot/DuckDuckBot) and a non-empty IP. The worker performs
   `PTR → forward DNS` (both steps must resolve to the search engine's official
   domain — `.googlebot.com`, `.search.msn.com` and so on) and writes the
   verdict into the `verified_bot_ips` catalog with a 1 h TTL, symmetric for both
   outcomes (`verified` / `rejected`). At L2.2 the edge tells them apart by the
   value (`"verified:<family>"` / `"rejected:<family>"`); a missing
   key means the provisional fastpath. Metrics: `..._rdns_enqueued_total`,
   `..._rdns_verified_total`, `..._rdns_rejected_total`,
   `..._rdns_queue_length`.

The service is **stateless** on top of its own PostgreSQL. It does not sit on the edge hot path —
fail-stale (see config-distribution §"Channel C / Failure mode").

## Running it

Locally:

```bash
go run ./cmd/antibot-backend
# then:
curl http://localhost:8080/health
curl -i http://localhost:8080/catalog/tls_fp_blocklist        # 503 catalog_not_loaded without POSTGRES_DSN; 200 when the database and ./catalogs/ are set
curl -i -X POST --data 'line1\nline2\n' http://localhost:8080/v1/logs  # 202
curl http://localhost:8080/metrics | grep antibot_backend_
```

As part of the demo stack (an HA pair behind a TLS LB plus Postgres) — see
[`../infra/demo-backend/`](../infra/demo-backend/).

## Config (env)

| Variable | Default | Purpose |
|---|---|---|
| `HTTP_ADDR` | `:8080` | the HTTP listen address. The B1 substrate's LB comes here. |
| `INSTANCE_NAME` | hostname | the label in `/health` and the logs (for round-robin checks). |
| `POSTGRES_DSN` | empty | the DSN for pgxpool. Empty means skeleton mode with no DB (Channel C answers 503). |
| `CATALOGS_DIR` | `./catalogs` | the directory of slow catalogs from product. Without files there, Bootstrap fails. |
| `CATALOG_RELOAD_INTERVAL` | `5s` | how often the backend rereads the catalogs (files plus DB → Merge → Store). Shorter than the 30 s edge poll, so that changes arrive within ≤30 s. |
| `MIGRATE_ON_STARTUP` | `true` | run the embedded migrations before the HTTP start when `POSTGRES_DSN` is set. `false` for production scenarios with an external migrator (B15). |
| `RDNS_INTERVAL` | `30m` | a deprecated knob from the B2 skeleton. In B7 the worker is reactive (triggered by the log stream) with no periodic tick; the parameter is ignored. |
| `RDNS_QUEUE_SIZE` | `1024` | the rDNS worker's reactive queue buffer. An overflow means the receiver drops the task into the `..._rdns_dropped_total` metric and the edge keeps issuing provisional passes. |
| `RDNS_WORKERS` | `4` | parallel DNS resolvers per worker. |
| `RDNS_DNS_TIMEOUT` | `5s` | the ceiling on one PTR+forward iteration for an IP. |
| `RDNS_GC_INTERVAL` | `1h` | how often we `DELETE` expired `verified_bot_ips` rows. |
| `SHUTDOWN_TIMEOUT` | `10s` | the HTTP server's graceful shutdown. |

## The PostgreSQL schema

Only the runtime tables live in the database:
- `policy` — per-host settings, written through antibotapi from the dashboard;
- `verified_bot_ips` — written by the rDNS worker (B7);
- `logs` — the BAC_LOG receiver (B9).

The slow catalogs (`tls_fp_blocklist`, `ua_blacklist`, `ip_blocklist`,
`ip_whitelist`, `asn_datacenters`) and the singleton `catalog_version` were dropped
by migration [`0004_drop_slow_catalogs.sql`](internal/dbloader/migrations/0004_drop_slow_catalogs.sql).
Their data now lives in `../catalogs/`; migrating the stand's contents is done
with the [`../scripts/seed-catalogs-from-db.sh`](../scripts/seed-catalogs-from-db.sh) script
before applying 0004.

The SQL files live in [`internal/dbloader/migrations/`](internal/dbloader/migrations/),
are embedded through `//go:embed` and are applied at startup when
`MIGRATE_ON_STARTUP=true`. `CREATE TABLE IF NOT EXISTS` / `DROP TABLE IF EXISTS`
— rerunning them is safe. A full migrator (golang-migrate with a tracking
table) would be a later change.

The per-host `policy` is the only table with JSONB fields: `ua_blacklist`,
`ip_whitelist`, `ip_blocklist`, `asn_block`, `geo_whitelist`, `rate_rules`.
The lookup key is `host`. An unregistered host → the pool default
(`mode=shadow`, `strictness=standard`, everything empty, `attack_mode=false`).

The dbloader tests are integration tests gated on `POSTGRES_TEST_DSN`:

```bash
docker run -d --rm --name pg-test -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16-alpine
POSTGRES_TEST_DSN="postgres://postgres:test@localhost:55432/postgres?sslmode=disable" \
  go test ./internal/dbloader/ -count=1 -v
docker stop pg-test
```
