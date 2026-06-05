# Runbook — per-resource mode toggle (shadow ↔ active)

**Цель.** Переключить отдельный ресурс (домен) между `shadow` (каскад считает и
логирует would-be вердикт, физически ничего не блокирует) и `active` (вердикты
исполняются: 403/429/challenge). Per-host, не глобально на пул — включение
enforce у одного клиента не задевает остальных (vision §«Режимы работы»,
§Roadmap: «боевой режим включается синхронно с per-resource mode»).

**Механизм.** Mode живет в каталоге `policy` (БД backend, не git). На эдже
[`policy.lua`](../../infra/demo-stand/lua/policy.lua) `enforce(status)` — единая
mode-gate: `bac_log.set_verdict` пишет would-be вердикт в любом режиме, но
физический `ngx.exit` происходит только при `mode=active`. Toggle = запись в
policy через Policy API (B10/B11); Channel C доставляет на эдж ≤30с (vision
§Channel C контракт). На стенде «имитация B11» = реальный Policy API — тот же
путь, что пойдет из клиентского дашборда.

## Процедура (Policy API на backend VM)

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls
TOKEN=$(grep -E '^DASHBOARD_API_TOKEN=' infra/demo-backend/.env | cut -d= -f2- | tr -d '"'\''')  # strip optional quotes
API='https://127.0.0.1:443'; H='Host: antibot.internal'
HOSTQ=c8-test.example.com     # throwaway-ресурс, не трогаем реальных клиентов

# 1. Текущий mode.
curl -ks "$API/antibot/v1/policy/$HOSTQ" -H "$H" -H "Authorization: Bearer $TOKEN"

# 2. shadow → active.
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"mode":"active"}'

# 3. Подождать ≤30с (backend reloader ≤5с + edge catalog_pull ≤30с), проверить
#    на эдже.
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "docker exec nginx-demo curl -ks 'https://127.0.0.1/__policy?host=$HOSTQ' -H 'Host: $HOSTQ'"
#    → "mode":"active"

# 4. Вернуть active → shadow.
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"mode":"shadow"}'
```

`/__policy?host=<host>` на эдже read-only показывает effective policy. PATCH
идемпотентен: повтор того же значения → `changed:false`.

## Что наблюдать (контраст shadow vs active)

Для запроса, который каскад помечает как блокирующий (например, fp в
`tls_fp_blocklist`):

- `mode=shadow` → would-be `verdict=block` в BAC_LOG, но физически **200** от
  origin (запрос проксируется).
- `mode=active` → тот же `verdict=block`, физически **403**.

Это видно в Loki `{kind="bac_log"}` (BAC_LOG, отфильтровать по `host` / `mode`:
один и тот же blocklist-fp дает status 200 на shadow-хосте и 403 на active-хосте)
и в статусах ответов.

## Откат

Вернуть `mode=shadow` (шаг 4). Это безопасное состояние по умолчанию для любого
ресурса без записи в policy (pool default = shadow).

## Verified on stand

2026-05-28, commit e3a72f7, throwaway host `c8-test.example.com`:

- `PATCH {"mode":"active"}` → `{"changed":true,"diff":["mode"]}` (хост создан
  первой мутацией); `/__policy` на эдже показал `"mode":"active"` через ≤32с
  (backend reloader + edge pull, в пределах SLA ≤30с).
- `PATCH {"mode":"shadow"}` → эдж вернулся к `"mode":"shadow"` через ≤32с.
- Идемпотентность: повтор `{"mode":"shadow"}` → `{"changed":false,"diff":[]}`.
- Контраст enforcement (живой трафик, Loki `{kind="bac_log"}`): один и тот же
  blocklist-fp `L13d1900_f3fd9e8f6e2b_fac63a6ff214` дал **403** на active
  `dashboard.example.com` и **200** на shadow `bac.example.com`.

Хост `c8-test.example.com` остался в policy с дефолтом (`mode=shadow`,
пустые поля) — поведенчески эквивалентно отсутствию записи (pool default).
