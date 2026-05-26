# challenge/ — HTML+JS challenge page asset (C2)

Статический ассет, который edge сервит при `verdict=challenge` (Phase 4, Step 5.2
«Ветка A» в [vision.md](../../../docs/product/vision.md)). На демо доставляется
file-mount'ом (Channel A на демо = bind-mount, см.
[docker-compose.demo.yml](../docker-compose.demo.yml)); в проде это будет
Puppet (`modules/nginx/files/lua/nginx2/`), но контракт «один файл, читается
один раз на init, обновление = `openresty -s reload`» одинаковый.

## Файлы

- `page.html` — единственный шаблон. Edge подставляет в плейсхолдеры на render:
  - `{{NONCE}}` — base64url payload + HMAC, выдается `challenge.issue_nonce(host)`
    (см. [../lua/challenge.lua](../lua/challenge.lua)). Подписан тем же HMAC
    secret'ом, что и clearance cookie ([C1](../lua/challenge_secret.lua));
    содержит `host` + `expiry` (TTL 60с). Любой proxy пула валидирует без
    shared state.
  - `{{EXPIRY}}` — unix-timestamp истечения nonce (для дебага в DevTools).

  Версия каскада в шаблоне — **литералы** (не плейсхолдеры): в
  `<meta name="cascade-version">`, в HTML-комментарии и в
  `data-cascade-version` зашита та версия, с которой шаблон совместим.
  `init_by_lua` сверяет meta с [../CASCADE_VERSION](../CASCADE_VERSION) и
  фейлит nginx старт при расхождении.

## Контракт с C5 (verify endpoint)

JS POST-ит на `/__challenge/verify` тело:

```json
{
  "nonce": "<base64url-payload>.<base64url-hmac>",
  "token": "<hex sha256(nonce + JS_SECRET)>",
  "cascade_version": "0.1.0",
  "not_a_robot": false,
  "fp": {
    "ua": "...",
    "languages": ["ru-RU", "en"],
    "screen": {"width": 1920, "height": 1080, "depth": 24},
    "timezone": "Europe/Moscow",
    "hwc": 8,
    "platform": "MacIntel"
  }
}
```

Сервер (C5) должен:
1. Декодировать nonce, проверить HMAC через `challenge_secret.get()`.
2. Проверить `expiry > now` (одноразовость через TTL — replay-защита по vision §5.2).
3. Пересчитать `sha256(nonce + JS_SECRET)` и сравнить с `token`. `JS_SECRET`
   — константа в [`page.html`](page.html), смена требует bump'a `CASCADE_VERSION`.
4. Сравнить `cascade_version` с серверной — отвергнуть несовпадающие
   (защита от stale-кеша браузера со старой страницей).
5. Записать `fp` в BAC_LOG (challenge-pass событие, аналитика) и выписать
   clearance cookie с тем же HMAC secret'ом.

## Bump `CASCADE_VERSION`

Bump обязателен в любом PR, который меняет:
- формат nonce-payload (поля, кодирование),
- `JS_SECRET`,
- ожидаемые поля POST'а на verify,
- набор fingerprint-полей,
- путь verify endpoint'a.

Bump = одна строка в [../CASCADE_VERSION](../CASCADE_VERSION) + замена всех
литералов версии в [`page.html`](page.html) (HTML-комментарий + `<meta>` +
`data-cascade-version`). `init_by_lua` валит старт, если meta и
`CASCADE_VERSION` разъехались — это и есть страховка от забытого bump'a.
