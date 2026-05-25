# catalogs/ — медленные каталоги Channel C

Этот каталог — **единственный источник истины** для медленных каталогов,
которые ведёт продакт. Backend читает его на каждом тике reloader'а
(default 5с), отдаёт эджу через `/catalog/<name>`. SLA от мержа PR до
применения на пуле эджей — **≤ 15 минут** (см. [vision.md](../docs/product/vision.md)
§"Обновление каталогов на proxy").

См. также [ADR-006](../docs/architecture-decisions/006-slow-catalogs-as-files.md)
о том, почему медленные каталоги лежат в git, а не в БД.

## Файлы

| Файл                              | Что внутри                                              |
|-----------------------------------|---------------------------------------------------------|
| `version`                         | semver схемы payload, идёт в `X-Catalog-Version`.       |
| `fp_blocklist.yaml`               | TLS fingerprints → status. `verdict=block` для active.  |
| `ua_blacklist.yaml`               | RE2-regex по User-Agent → status. Складывается в combined regex. |
| `ip_blocklist.yaml`               | CIDR → status. `verdict=block` для active.              |
| `ip_whitelist.yaml`               | CIDR (без status). Системный allow-list.                |
| `asn_datacenters.yaml`            | uint32 ASN. Справочник для тега `reputation:asn_dc`.    |
| `tls_fp_catalog.yaml`             | hash_b → { family, status }. Правило tls_fp_impersonator. |
| `tls_fp_browser_profiles.yaml`    | family → { expected_cipher_cnt, status }. Правило tls_fp_suspicious_ciphers. |

Что **не** здесь:
- `policy/<host>` — клиентские настройки, живут в БД, правятся через дашборд.
- `verified_bot_ips` — runtime state от rDNS-воркера, живёт в БД.

## Как вносить изменения

1. **Создайте feature-branch** (никогда не правьте `main` напрямую).
2. **Откройте PR** с правкой соответствующего файла. CODEOWNERS требует
   ревью продакта.
3. **CI валидирует**: regex компилируется (`regexp.Compile`), CIDR парсится,
   ASN в диапазоне uint32, status ∈ `{active, staging}`. Одна битая запись
   — fail-stale, backend не подхватывает (Store не обновляется,
   `antibot_backend_catalog_reload_failures_total` тикает).
4. **После мержа** — backend подхватывает в течение `CATALOG_RELOAD_INTERVAL`
   (5с), эдж — в течение `+30с` (Channel C poll). Суммарно ≤ ~1 минуты на
   стенде; продуктовый SLA `≤ 15 мин` оставляет запас.

## Staged rollout

Для каталогов со status (`fp_blocklist`, `ua_blacklist`, `ip_blocklist`)
работает A11 staged rollout:

1. **PR-1**: добавить запись со `status: staging`. Эдж матчит, пишет
   `staging_match: ["<catalog>:<pattern>"]` в bac_log, **не блокирует**.
2. **Наблюдение** (24–48ч): проверьте, что запись срабатывает только
   на ожидаемом трафике (нет ложных матчей по легитимным клиентам).
3. **PR-2**: смените `status: staging` → `status: active`. Эдж начинает
   эмитить `verdict=block`.

Откат — `git revert` PR в течение того же SLA.

## Формат YAML

Файлы парсятся через `gopkg.in/yaml.v3` в strict-режиме (`KnownFields(true)`).
Опечатка в имени поля валит загрузку, не молча игнорируется.

Пустой файл / только комментарии = пустой каталог.
