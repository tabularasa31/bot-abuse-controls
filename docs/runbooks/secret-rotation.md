# Runbook — HMAC secret rotation

**Цель.** Ротировать общий HMAC secret, которым каскад подписывает clearance
cookie (L5 issue, L2.1 verify) и self-signed nonce challenge-страницы. Ротация
**инвалидирует все ранее выданные cookie** — это by design (vision §«Ротация»):
клиент проходит challenge заново.

**Когда.** Плановая ротация (раз в квартал) или экстренная (компрометация
секрета).

**Механизм.** [`challenge_secret.lua`](../../infra/demo-stand/lua/challenge_secret.lua)
грузит секрет из файла в `lua_shared_dict challenge_secret` в `init_by_lua`.
`openresty -s reload` перезапускает `init_by_lua` → перечитывает файл →
переписывает запись в dict. Cookie, подписанные старым секретом, перестают
проходить constant-time HMAC verify на L2.1. На стенде Channel A = bind-mount
файла `infra/demo-stand/certs/challenge_secret.key` (не Puppet).

## Процедура (на edge VM)

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand

# 1. Запомнить текущий fingerprint (8-hex от sha256 секрета; сам секрет наружу
#    не выводится никогда).
docker exec nginx-demo curl -ks https://127.0.0.1/__version -H 'Host: bac.example.com' | grep challenge_secret_fp

# 2. Сгенерировать новый секрет. Скрипт отказывается перезаписывать
#    существующий файл — сначала удалить (это и есть «ротация»).
#    ВАЖНО: dest по умолчанию у скрипта — относительно repo root. Из каталога
#    infra/demo-stand передаем dest явно, иначе ключ уедет в неверный путь.
rm certs/challenge_secret.key
./scripts/generate-challenge-secret.sh certs/challenge_secret.key
# → печатает: wrote certs/challenge_secret.key (fp=<новый-fp>)

# 3. Reload — init_by_lua перечитывает файл.
docker compose -f docker-compose.demo.yml exec nginx-demo openresty -s reload

# 4. Проверить, что эдж подхватил именно новый файл.
docker exec nginx-demo curl -ks https://127.0.0.1/__version -H 'Host: bac.example.com' | grep challenge_secret_fp
#    fp должен совпасть с напечатанным на шаге 2 и отличаться от шага 1.
```

`/__admin` показывает тот же fingerprint в шапке — второй способ cross-check.

## Что наблюдать

- `/__version` `challenge_secret_fp` сменился на напечатанный скриптом.
- В `docker logs nginx-demo` строка `challenge_secret: loaded from … (fp=<новый>)`,
  без ERR/WARN.
- **Инвалидация cookie**: запрос с `tf_clearance`, подписанным старым секретом,
  после ротации дает `verdict≠cookie_valid` (метрика
  `antibot_clearance_verify_total{result="invalid"}` инкрементится), и клиент
  идет на challenge.

Проверка инвалидации без браузера — крафт cookie старым секретом. Формат
([`clearance.lua`](../../infra/demo-stand/lua/clearance.lua)):
`cookie = body . "." . b64url(sig)`, где `body = b64url(host):iat:exp`,
`sig = HMAC-SHA256(secret, body)` (подпись — **b64url**, не hex):

```sh
SECRET=$(cat certs/challenge_secret.key)        # ДО ротации
HOST=bac.example.com                          # shadow-хост, без реальных юзеров
NOW=$(date +%s); EXP=$((NOW+86400))
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
BODY="$(printf '%s' "$HOST" | b64url):$NOW:$EXP"
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
COOKIE="$BODY.$SIG"
# До ротации → result=valid; после ротации тот же COOKIE → result=invalid.
docker exec nginx-demo curl -ks https://127.0.0.1/ -H "Host: $HOST" \
    -H "Cookie: tf_clearance=$COOKIE" -o /dev/null
docker exec nginx-demo curl -ks https://127.0.0.1/metrics -H 'Host: bac.example.com' \
    | grep clearance_verify_total
```

## Fail-closed (важно)

Если файл удалили и сделали reload без регенерации (или файл пустой / короче
32 байт / больше 1024 байт) — `challenge_secret.lua` логирует WARN/ERR и **явно
вычищает** dict (нет «зомби-секрета»). Тогда `/__version` `challenge_secret_fp`
пуст, а L2.1/L5 пропускают cookie verify/issue (фастпас по cookie отключен,
challenge продолжает работать). Лечение — выполнить шаг 2–3.

## Откат

Отдельного отката нет: новый секрет валиден сразу. Если регенерация прошла, но
fp не сменился — проверить, что bind-mount указывает на тот же файл
(`docker exec nginx-demo ls -l /etc/nginx/certs/challenge_secret.key` vs
host-файл) и что reload не упал.

## Verified on stand

2026-05-28, commit e3a72f7 (с backup+restore исходного секрета → net-zero для
реального active-клиента):

- Исходный `/__version` `challenge_secret_fp: 77b4e803`. Crafted cookie старым
  секретом (host `bac.example.com`) → `clearance_verify_total{result="valid"}` +1.
- Ротация (`rm` + `generate-challenge-secret.sh certs/challenge_secret.key` + reload):
  скрипт напечатал `fp=d520c80e`, `/__version` показал `challenge_secret_fp: d520c80e`.
- Тот же old-secret cookie после ротации → `clearance_verify_total{result="invalid"}` +1
  (инвалидация подтверждена).
- Restore исходного ключа из backup + reload → `fp` назад `77b4e803`, тот же cookie
  снова `valid` (real client не затронут). `git status` чист.

Замечен и поправлен баг процедуры: `generate-challenge-secret.sh` без явного dest
пишет относительно repo root; из `infra/demo-stand` без аргумента — fail-closed
`fp=null` (секрет не загрузился). Передавать dest явно (см. шаг 2).
