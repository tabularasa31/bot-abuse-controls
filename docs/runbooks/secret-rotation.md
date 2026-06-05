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
#    не выводится никогда). Берем из EDGE_STATS-строки в логах эджа.
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"challenge_secret_fp":"[^"]*"'

# 2. Сгенерировать новый секрет. Скрипт отказывается перезаписывать
#    существующий файл — сначала удалить (это и есть «ротация»).
#    ВАЖНО: dest по умолчанию у скрипта — относительно repo root. Из каталога
#    infra/demo-stand передаем dest явно, иначе ключ уедет в неверный путь.
rm certs/challenge_secret.key
./scripts/generate-challenge-secret.sh certs/challenge_secret.key
# → печатает: wrote certs/challenge_secret.key (fp=<новый-fp>)

# 3. Reload — init_by_lua перечитывает файл.
docker compose -f docker-compose.demo.yml exec nginx-demo openresty -s reload

# 4. Проверить, что эдж подхватил именно новый файл. Reload роняет новую
#    EDGE_STATS-строку — берем самую свежую.
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"challenge_secret_fp":"[^"]*"'
#    fp должен совпасть с напечатанным на шаге 2 и отличаться от шага 1.
```

Второй способ cross-check — приватный mgmt-план на :9090 (loopback, через
ssh-туннель): `ssh -L 9090:127.0.0.1:9090 ubuntu@<EDGE_VM_IP>`, затем
`curl -s http://localhost:9090/__stats | grep challenge_secret_fp`.

## Что наблюдать

- `challenge_secret_fp` в EDGE_STATS (или `:9090/__stats`) сменился на
  напечатанный скриптом.
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
b64url() { openssl base64 -A | tr -d '\n\r' | tr '+/' '-_' | tr -d '='; }
BODY="$(printf '%s' "$HOST" | b64url):$NOW:$EXP"
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
COOKIE="$BODY.$SIG"
# До ротации → result=valid; после ротации тот же COOKIE → result=invalid.
docker exec nginx-demo curl -ks https://127.0.0.1/ -H "Host: $HOST" \
    -H "Cookie: tf_clearance=$COOKIE" -o /dev/null
# Счетчики clearance_verify_* — в EDGE_STATS (или :9090/__stats через туннель).
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"clearance_verify[^,}]*'
```

## Fail-closed (важно)

Если файл удалили и сделали reload без регенерации (или файл пустой / короче
32 байт / больше 1024 байт) — `challenge_secret.lua` логирует WARN/ERR и **явно
вычищает** dict (нет «зомби-секрета»). Тогда `challenge_secret_fp` в EDGE_STATS
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

- Исходный EDGE_STATS `challenge_secret_fp: 77b4e803`. Crafted cookie старым
  секретом (host `bac.example.com`) → `clearance_verify` `result=valid` +1.
- Ротация (`rm` + `generate-challenge-secret.sh certs/challenge_secret.key` + reload):
  скрипт напечатал `fp=d520c80e`, EDGE_STATS показал `challenge_secret_fp: d520c80e`.
- Тот же old-secret cookie после ротации → `clearance_verify` `result=invalid` +1
  (инвалидация подтверждена).
- Restore исходного ключа из backup + reload → `fp` назад `77b4e803`, тот же cookie
  снова `valid` (real client не затронут). `git status` чист.

Замечен и поправлен баг процедуры: `generate-challenge-secret.sh` без явного dest
пишет относительно repo root; из `infra/demo-stand` без аргумента — fail-closed
`challenge_secret_fp` пуст в EDGE_STATS (секрет не загрузился). Передавать dest
явно (см. шаг 2).
