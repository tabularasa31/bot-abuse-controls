# Runbooks — demo-stand (Phase 4 readiness)

Операционные процедуры для **демо-стенда** (`infra/demo-stand/`, long-running
reverse proxy на VM). Это не прод prod-edge: Channel A на стенде = file/mount +
`openresty -s reload`, а не Puppet. Каждая процедура ниже проверена на живом
стенде — см. раздел «Verified on stand» в конце каждого файла.

Все четыре механизма уже реализованы в каскаде (C1–C7). Эти runbook'и —
аварийные рычаги и регламент перед включением реальной верификации
(`mode=active`) на пилотном клиенте.

## Phase 4 readiness — чеклист перед `mode=active` на пилоте

- [ ] **HMAC secret** сгенерирован, fingerprint виден в EDGE_STATS
  (`challenge_secret_fp`), ротация проверена → [secret-rotation.md](secret-rotation.md)
- [ ] **Challenge-страница** version-pinned к каскаду; рассинхрон валит старт →
  [challenge-version-pinning.md](challenge-version-pinning.md)
- [ ] **Mode toggle** ресурса shadow↔active доезжает на эдж ≤30с →
  [mode-toggle.md](mode-toggle.md)
- [ ] **Rollback каталога** обратим в обе стороны ≤15м →
  [catalog-rollback.md](catalog-rollback.md)

## Операционные workflow

- **Blocklist promotion (D1)** — провести fp из утреннего отчета в enforcement
  (staging → наблюдение → active) и снять устаревший, через PR с аудит-следом →
  [blocklist-promotion.md](blocklist-promotion.md). Логика решений —
  [`docs/blocklist-scoring.md`](../blocklist-scoring.md).

## Контракт (источник правды)

[`docs/product/vision.md`](../product/vision.md): §«Аварийные рычаги»,
§«Rollback каталога», §«HMAC secret»/«Ротация», §«Channel C» (продуктовый
контракт доставки), §Roadmap Phase 4/5.

## Топология стенда (одно место, чтобы не повторять в каждом файле)

| Узел | SSH | Что крутится |
|---|---|---|
| edge | `ubuntu@<EDGE_VM_IP>` | контейнер `nginx-demo` (весь каскад), `promtail` |
| backend+obs | `ubuntu@<BACKEND_VM_IP>` | `antibot-backend-1/2` + `antibot-lb` + postgres + loki + grafana + `antibot-analytics` (daily report + blocklist-candidate producer, читает Loki) |

IP-адреса — **текущие VM стенда** (если VM пересоздаются/меняют IP — обнови эту
таблицу; это единственное место с адресами). Ключ — `~/.ssh/gpu-key`. Контейнер
`nginx-demo` слушает на LAN-IP
(`192.168.10.208:443`), поэтому curl к публичным эндпоинтам идет через контейнер:

```sh
docker exec nginx-demo curl -ks https://127.0.0.1/__health -H 'Host: bac.example.com'
```

Счетчики и deploy-метаданные эджа (commit, cascade_version, challenge_secret_fp,
blocklist_entries, catalog_staleness_seconds.*) больше не на публичном :443 —
они идут строкой `EDGE_STATS {json}` в stdout → promtail → Loki
(`{kind="edge_stats"}`), на VM: `docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1`.
Снимок по требованию — приватный read-only mgmt-план на :9090 (loopback):
`ssh -L 9090:127.0.0.1:9090 ubuntu@<EDGE_VM_IP>`, затем
`curl -s http://localhost:9090/__stats` или `/__policy?host=<host>`.

Backend читает медленные каталоги из git-чекаута `~/abuse-controls/catalogs`
(монтируется `:/catalogs:ro`); Policy API живет за `antibot-lb:443`
(Host `antibot.internal`), bearer `DASHBOARD_API_TOKEN` из
`infra/demo-backend/.env`.

> Прод-материал prod-edge (Puppet/hiera/canary) заморожен в
> [`docs/archive/CDN operator-rollout/`](../archive/CDN operator-rollout/) — это не
> стендовые инструкции.
