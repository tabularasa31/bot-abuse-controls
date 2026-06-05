# Runbook — challenge-page version pinning

**Цель.** Гарантировать, что HTML+JS challenge-страница и Lua-каскад согласованы
по версии: страница не может «уехать» от каскада незаметно. Версия страницы
(`<meta name="cascade-version">`) обязана совпадать с файлом
[`CASCADE_VERSION`](../../infra/demo-stand/CASCADE_VERSION).

**Механизм.** [`challenge.lua`](../../infra/demo-stand/lua/challenge.lua) `preload()`
вызывается из `init_by_lua`. Он читает `CASCADE_VERSION` и meta-тег шаблона; при
несовпадении (или отсутствии meta-тега) делает `error()`, что **валит
`init_by_lua` и не дает nginx стартовать/перезагрузиться**. Это и есть pin: версии
можно развести только осознанно — bump в обоих местах одновременно.

## Нормальный bump версии шаблона

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand

# 1. Поправить шаблон и обе версии (page.html meta + CASCADE_VERSION).
$EDITOR challenge/page.html        # текст/JS challenge + <meta name="cascade-version" content="X.Y.Z">
$EDITOR CASCADE_VERSION            # тот же X.Y.Z
#    (есть и человекочитаемый комментарий <!-- cascade-version: … --> в начале
#     page.html — обновить для глаза; машинно проверяется только meta-тег.)

# 2. Reload — preload сверит версии.
docker compose -f docker-compose.demo.yml exec nginx-demo openresty -s reload

# 3. Проверить. cascade_version — поле в EDGE_STATS-строке логов (reload роняет
#    свежую).
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"cascade_version":"[^"]*"'
```

## Что наблюдает pin (negative-тест)

Если развести версии (bump только `CASCADE_VERSION`, забыв meta-тег), reload
**падает** на `init_by_lua` со строкой вида:

```
challenge: cascade/template version mismatch — /etc/nginx/CASCADE_VERSION=0.2.0 vs template meta=0.1.0 (bump both sides together; …)
```

Важно: при провале reload **старые worker'ы продолжают обслуживать трафик** —
nginx не применяет битую конфигурацию (reload отвергается на стадии загрузки).
`/__health` остается `ok`, `cascade_version` в EDGE_STATS остается прежним. То
есть pin ловит рассинхрон, не уронив стенд.

> `openresty -t` на этой сборке **не** исполняет `init_by_lua_file`, поэтому
> config-test mismatch не ловит — проверка идет именно через `openresty -s reload`
> (failed reload безопасен: отвергается, старые worker'ы живут).

## Откат

Восстановить согласованность (вернуть meta-тег или `CASCADE_VERSION` к прежнему
значению) и сделать `openresty -t` → чистый reload. Поскольку битый reload не
применяется, отдельного «отката» рабочей конфигурации не требуется.

## Verified on stand

2026-05-28, commit e3a72f7. Развел версии (host `CASCADE_VERSION` 0.1.0 → 0.2.0),
`openresty -s reload`:

```
[error] 1#1: init_by_lua_file error: /etc/nginx/lua/challenge.lua:114:
challenge: cascade/template version mismatch — /etc/nginx/CASCADE_VERSION=0.2.0
vs template meta=0.1.0 (bump both sides together; see …/challenge/README.md)
```

`/__health` = `ok`, `cascade_version` в EDGE_STATS остался `0.1.0` (старые
worker'ы обслуживали) — стенд не упал. Восстановил `0.1.0` → чистый reload,
`cascade_version: 0.1.0`, `git status` чист.
