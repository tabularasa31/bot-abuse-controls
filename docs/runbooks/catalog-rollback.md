# Runbook — catalog rollback

**Цель.** Откатить плохой PR в медленный каталог (например, в
`tls_fp_blocklist` попал fp, общий для всех Chrome → массовый false-positive).
Откат обратим в обе стороны без ручных операций на эдже или в БД — атомарная
замена `shared_dict` работает в любую сторону (vision §«Rollback каталога»).

**SLA.** Применение изменения на пуле эджей ≤15 мин от merge'а PR (vision
§Channel C). На стенде фактически ~1 мин: backend reloader (5с) + edge
`catalog_pull` (≤30с).

**Механизм.** Медленные каталоги — git-репо
[`catalogs/`](../../catalogs/) (ADR-006, единственный источник истины). Backend
читает файлы из чекаута (`~/abuse-controls/catalogs` → монтируется `/catalogs:ro`,
`CATALOGS_DIR=/catalogs`) через `internal/filesource` с mtime-кешем и отдает на
эдж по `/catalog/<name>` с ETag. Эдж
[`catalog_pull.lua`](../../infra/demo-stand/lua/catalog_pull.lua) опрашивает
backend (`ngx.timer.every(30s)` + If-None-Match), на изменении делает atomic swap
в `antibot_*` shared_dict, fail-stale при недоступности backend.

## Боевой путь (как в проде)

1. Продакт делает `git revert` плохого PR в репозитории каталогов.
2. Merge → backend (source of truth) пересобирает каталог из файлов.
3. Эджи подтягивают откаченную версию ≤15 мин и атомарно подменяют shared_dict.
4. Новые запросы матчатся против старой (рабочей) версии — инцидент закончился.

Откат всегда делать через `status: staging` для новых паттернов (A11 staged
rollout, см. [`catalogs/README.md`](../../catalogs/README.md)).

## Какие каталоги реально тянутся на эдж (важно для выбора объекта демо)

На стенде эдж по Channel C тянет **5** каталогов (`/metrics`
`antibot_edge_catalog_staleness_seconds{catalog=…}`): `tls_fp_blocklist`,
`tls_fp_catalog`, `tls_fp_browser_profiles`, `verified_bot_ips`, `policy`.
`ua_blacklist`/`ip_*`/`asn_datacenters` грузятся из локального конфига эджа, по
Channel C **не** доставляются. Отдельная тонкость `tls_fp_blocklist`: по Channel C
тянется только **active**-набор (в `tls_fp_blocklist` shared_dict); **staging**-набор
строится из локального файла ([`tls_fp.lua`](../../infra/demo-stand/lua/tls_fp.lua)
≈312), поэтому staging-запись через backend на эдж не доедет.

Вывод: демо rollback'а гоняем на **active**-записи `tls_fp_blocklist` — это и есть
PR-каталог из vision-примера.

## Демонстрация на стенде

Backend читает **файлы** (mtime), не git-историю, поэтому на стенде ту же
атомарную замену показывает прямая правка файла + восстановление (эквивалент
merge → revert на слое доставки каталога). В качестве записи берем реальный
HIGH-кандидат из дневного анализа (D1, email label `the platform/abuse-controls`) —
подтвержденный бот, не легитимный клиент:

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls

# 0. Блоклист до правки (на эдже): N записей.
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "docker exec nginx-demo curl -ks https://127.0.0.1/__admin -H 'Host: bac.example.com' | grep -oE 'Blocklist \([0-9]+ entries\)'"

# 1. Добавить HIGH-fp как active (формат <fp>: <status>).
#    FP=… — подставить РЕАЛЬНЫЙ fp из дневного анализа (валидный L-префикс
#    JA4-токен); литерал <HIGH-fp> backend отвергнет на валидации.
FP='L13d3000_bcf826a2cd28_430ec2476535'    # пример из отчёта 2026-05-28
printf '\n"%s": active\n' "$FP" >> catalogs/tls_fp_blocklist.yaml

# 2. Backend подхватит ≤5с; эдж — ≤30с. Проверить, что fp доехал.
sleep 38
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "docker exec nginx-demo curl -ks https://127.0.0.1/__admin -H 'Host: bac.example.com' | grep -oE \"Blocklist \([0-9]+ entries\)|$FP\""
#    → N+1 entries, fp в списке. Запрос с этим fp → verdict=block,rule=tls_fp_blocklist
#      (403 на active-хосте, would-be block + 200 на shadow).

# 3. Откат — git checkout (эквивалент revert PR на слое доставки).
git checkout -- catalogs/tls_fp_blocklist.yaml

# 4. ≤30с спустя fp исчезает на эдже (atomic swap обратно) → снова N entries.
sleep 38
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "docker exec nginx-demo curl -ks https://127.0.0.1/__admin -H 'Host: bac.example.com' | grep -oE 'Blocklist \([0-9]+ entries\)'"
```

## Что наблюдать

- После шага 2: `/__admin` блоклист N→N+1, fp в списке; `verdict=block,rule=tls_fp_blocklist`
  для запросов с этим fp; `antibot_edge_catalog_staleness_seconds{catalog="tls_fp_blocklist"}`
  остается низкой (контакт с backend жив).
- После шага 4: блоклист N+1→N, fp ушел — эдж атомарно вернулся к прежней версии.
- Битый каталог от backend (не проходит валидацию) → эдж **не применяет**,
  работает на последней валидной копии (fail-stale) и тикает счетчик отвергнутых
  обновлений.

## Откат демонстрации

`git checkout -- catalogs/tls_fp_blocklist.yaml` (шаг 3) уже возвращает стенд в
исходное состояние. Убедиться `git status` чист.

## Verified on stand

2026-05-28, commit e3a72f7. Два HIGH-кандидата из дневного отчета
(`L13d3000_bcf826a2cd28_430ec2476535`, `L13d1300_69e852b66fc7_10d89aa70559`)
добавлены как `active` в `catalogs/tls_fp_blocklist.yaml` на backend:

- Доставка: `/__admin` блоклист **7 → 9**, оба fp в списке на эдже через ~38с
  (PR-каталог, SLA ≤15м — на стенде ~1мин; `staleness=21с`, контакт жив).
- Откат: `git checkout -- catalogs/tls_fp_blocklist.yaml` → блоклист **9 → 7**,
  оба fp исчезли через ~38с (atomic swap обратно). `git status` чист.

Подтверждает обратимость в обе стороны без ручных операций на эдже/в БД.
