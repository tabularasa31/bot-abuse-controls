# Runbooks — demo-stand (Phase 4 readiness)

Операционные процедуры для **демо-стенда** (`infra/demo-stand/`, long-running
reverse proxy на VM). Это не прод prod-edge: Channel A на стенде = file/mount +
`openresty -s reload`, а не Puppet. Каждая процедура ниже проверена на живом
стенде — см. раздел «Verified on stand» в конце каждого файла.

Все четыре механизма уже реализованы в каскаде (C1–C7). Эти runbook'и —
аварийные рычаги и регламент перед включением реальной верификации
(`mode=active`) на пилотном клиенте.

## Phase 4 readiness — чеклист перед `mode=active` на пилоте

- [ ] **HMAC secret** сгенерирован, fingerprint виден в `/__version`, ротация
  проверена → [secret-rotation.md](secret-rotation.md)
- [ ] **Challenge-страница** version-pinned к каскаду; рассинхрон валит старт →
  [challenge-version-pinning.md](challenge-version-pinning.md)
- [ ] **Mode toggle** ресурса shadow↔active доезжает на эдж ≤30с →
  [mode-toggle.md](mode-toggle.md)
- [ ] **Rollback каталога** обратим в обе стороны ≤15м →
  [catalog-rollback.md](catalog-rollback.md)

## Контракт (источник правды)

[`docs/product/vision.md`](../product/vision.md): §«Аварийные рычаги»,
§«Rollback каталога», §«HMAC secret»/«Ротация», §«Channel C» (продуктовый
контракт доставки), §Roadmap Phase 4/5.

## Топология стенда (одно место, чтобы не повторять в каждом файле)

| Узел | SSH | Что крутится |
|---|---|---|
| edge | `ubuntu@<EDGE_VM_IP>` | контейнер `nginx-demo` (весь каскад), `promtail` |
| backend+obs | `ubuntu@<BACKEND_VM_IP>` | `antibot-backend-1/2` + `antibot-lb` + postgres + loki + grafana |

Ключ — `~/.ssh/gpu-key`. Контейнер `nginx-demo` слушает на LAN-IP
(`192.168.10.208:443`), поэтому curl к эндпоинтам идет через контейнер:

```sh
docker exec nginx-demo curl -ks https://127.0.0.1/__version -H 'Host: bac.example.com'
```

Backend читает медленные каталоги из git-чекаута `~/abuse-controls/catalogs`
(монтируется `:/catalogs:ro`); Policy API живет за `antibot-lb:443`
(Host `antibot.internal`), bearer `DASHBOARD_API_TOKEN` из
`infra/demo-backend/.env`.

> Прод-материал prod-edge (Puppet/hiera/canary) заморожен в
> [`docs/archive/CDN operator-rollout/`](../archive/CDN operator-rollout/) — это не
> стендовые инструкции.
