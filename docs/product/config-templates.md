# Bot & Abuse Controls — шаблоны конфигов

Иллюстративные шаблоны для всех конфигурационных файлов, упомянутых в [vision.md](vision.md) и Phase 1/2 specs.

**Формат:** показан как YAML с комментариями для удобства чтения. Главное — структура данных и семантика полей, не конкретный синтаксис.

> **Реальная реализация slow-каталогов (Phase 1+, фактически в репо):**
> файлы лежат в [`../../catalogs/`](../../catalogs/) (`tls_fp_blocklist.yaml`,
> `ua_blacklist.yaml`, `ip_blocklist.yaml`, `ip_whitelist.yaml`,
> `asn_datacenters.yaml`, `version`). Формат отличается от иллюстративного
> `.conf` ниже: используется компактный YAML map `<entry>: <status>`
> вместо секций. Контракт staged rollout (`active`/`staging`),
> валидация (regex/CIDR/uint32), Channel C — те же. См.
> [ADR-006](../architecture-decisions/006-slow-catalogs-as-files.md).

## Иерархия конфигов

```
defaults.conf            ← главный конфиг каскада (рулрегистрация, пороги, категории)
whitelist_ip.conf        ← системный IP-whitelist (мониторинг, чек-сервисы)
blocklist_ip.conf        ← кураторский IP-blocklist (PR-наполняемый)
ua_blacklist.conf        ← UA-паттерны (PR-наполняемый, с staging)
asn_datacenters.conf     ← ASN-номера ДЦ для тега reputation:asn_dc
tls_fp_blocklist.conf    ← TLS-fingerprints botov (Phase 2+, PR-наполняемый, с staging)
tls_fp_catalog.conf      ← signatures automation для impersonator-детекции (Phase 2+, с staging)
tls_fp_browser_profiles.conf ← cipher_cnt для браузеров (Phase 2+, заполнен базовым)
challenge_secret         ← HMAC secret для clearance cookie (Phase 4+, доставка через Puppet env/file)
policy/<host>.yaml       ← per-resource policy (Phase 3+, приходит из backend через Channel C, не хранится локально как файл)
```

---

## 1. `defaults.conf` — базовый конфиг каскада

Главный конфиг, без которого каскад не запускается. Структура секций задает категорию каждого правила.

```yaml
# defaults.conf — базовый конфиг каскада (Phase 1+)

# L1 Hygiene
hygiene:
  method_whitelist:
    - GET
    - HEAD
    - POST
    - OPTIONS
  api_path_patterns:
    # Что считать «API-эндпоинтом» для правила rate_api
    - /api/*
    - /graphql

# Категория blocking — правила, эмитящие verdict=block
rules:
  blocking:
    method_not_allowed:
      stage: hygiene
      source: built-in              # хардкод в коде proxy

    ua_blacklist:
      stage: hygiene
      source: ua_blacklist.conf
      enabled: true                 # Phase 1: каталог пуст, правило заложено

    ip_blocklist:
      stage: reputation
      source: blocklist_ip.conf
      enabled: true

    asn_customer:
      stage: reputation
      source: policy[host].asn_block
      enabled: true                 # активно только если в policy есть записи

    geo_blocklist:
      stage: reputation
      source: policy[host].geo_whitelist  # инвертированная логика
      enabled: true

    tls_fp_blocklist:                 # Phase 2+
      stage: tls_fp
      source: tls_fp_blocklist.conf
      enabled: true

    rate_ip:
      stage: rate_limits
      key: ip
      window_10s: 100
      window_60s: 600

    rate_ip_ua:
      stage: rate_limits
      key: ip+ua
      window_10s: 100
      window_60s: 600

    rate_api:
      stage: rate_limits
      key: ip
      paths: ${hygiene.api_path_patterns}
      window_10s: 50
      window_60s: 300

    rate_tls_fp:                      # Phase 2+
      stage: rate_limits
      key: tls_fp
      window_10s: 50
      window_60s: 300
      fallback: skip                  # если fp не вычислился — правило не срабатывает

    rate_scan_urls:
      stage: rate_limits
      key: ip
      metric: unique_urls
      window_10s: 50
      window_60s: 200

    non_browser_blocked:              # Phase 4+, L5 logic
      stage: verification
      source: built-in

  # Категория allow — правила, эмитящие verdict=allow (fastpath)
  allow:
    cookie_valid:                     # Phase 4+, не lookup, а HMAC verify
      stage: reputation
      source: built-in                # Lua-логика
      # ВАЖНО: cookie_valid — ЧАСТИЧНЫЙ фастпас. Пропускает L3 (tls_fp) и L5 (verification),
      # но НЕ L4: rate-limits применяются к держателю cookie. verdict=allow,rule=cookie_valid
      # выставляется, только если L4 чист; иначе выигрывает сработавшее правило L4.
      # Полный фастпас (skip L3/L4/L5) — только у bot_verified и ip_whitelist.
      cookie_name: tf_clearance
      secret_source: challenge_secret # см. отдельный файл
      # Привязка к клиенту: cookie выписывается под TLS-fp + подсеть IP (/24 для IPv4, /64 для IPv6) того клиента,
      # который прошел challenge, и на L2.1 фастпасит только при их совпадении —
      # украденный или переданный на другой клиент cookie не действует.
      ttl_seconds_normal: 86400       # 24 часа — обычный режим
      ttl_seconds_under_attack: 3600  # 1 час — при attack_mode=on
      # Значения TTL — системные константы, общие для всего пула; клиент в дашборде их не настраивает.
      # Выбор per-request на L5: proxy смотрит attack_mode ИМЕННО для того host'a, на который пришел запрос.
      #   attack_mode[host]=on  → выписывает cookie с ttl_under_attack
      #   attack_mode[host]=off → выписывает cookie с ttl_normal
      # Включение attack_mode у одного клиента не затрагивает TTL cookie других клиентов:
      # cookie скоупится Domain=<host>, в запросах на чужие хосты не передается.
      # Ранее выписанные 24-часовые cookie не инвалидируются при включении attack_mode — они доживают свой TTL.

    bot_verified:                     # Phase 3+, lookup в каталоге
      stage: reputation
      source: catalog.bot_verification_status
      ua_pattern: "Googlebot|bingbot|YandexBot|DuckDuckBot"
      provisional_pending: true       # выдавать bot_verified_pending при отсутствии записи

    ip_whitelist:
      stage: reputation
      source:
        - whitelist_ip.conf           # системный
        - policy[host].ip_whitelist   # per-resource (Phase 3+)

  # Категория soft — правила, накапливающие challenge-flag
  soft:
    tls_fp_impersonator:              # Phase 2+
      stage: tls_fp
      source: tls_fp_catalog.conf

    tls_fp_suspicious_ciphers:        # Phase 2+
      stage: tls_fp
      source: tls_fp_browser_profiles.conf

    tls_fp_dc_browser:                # Phase 2+
      stage: tls_fp
      source: built-in                 # cross-layer: L3 fp + asn_datacenters.conf

# Информационные теги (не правила, не эмитят verdict)
tags:
  - id: hygiene:header_anomaly
    stage: hygiene
    source: built-in                 # Lua-проверка заголовков (напр. HTTP/2 без Accept)

  - id: reputation:asn_dc
    stage: reputation
    source: asn_datacenters.conf

  - id: tls_fp:automation_ua         # Phase 2+
    stage: tls_fp
    source: built-in                 # Lua-проверка UA-паттернов автоматизации

  - id: tls_fp:no_sni                # Phase 2+
    stage: tls_fp
    source: built-in                 # из TLS handshake данных

# Kill-switch — выключатели на случай инцидентов
kill_switch:
  global:                            # выключает каскад целиком
    enabled: false                   # по умолчанию выключатель НЕ активирован
  per_stage:                         # выключает отдельный слой
    hygiene: false
    reputation: false
    tls_fp: false                    # Phase 2+
    rate_limits: false
    verification: false              # Phase 4+

# attack_mode — только per-host, живет внутри policy[host].attack_mode.
# Глобального тоггла на весь пул нет. Для инфра-уровня инцидентов — kill-switch.
```

---

## 2. `whitelist_ip.conf` — системный IP-whitelist

Список IP и CIDR-подсетей нашего мониторинга, чек-сервисов, доверенных системных клиентов. Используется правилом `ip_whitelist` (категория `allow`).

```
# whitelist_ip.conf — системный IP-whitelist (Phase 1+)
# Заполнен на старте. PR для изменений.

# Внутренние сервисы мониторинга
10.0.1.0/24   # мониторинговая подсеть
10.0.2.5      # health-checker

# Внешние uptime-мониторинги (с письменным согласованием)
# UptimeRobot:
69.162.124.0/24
63.143.42.0/24

# Healthchecks.io:
# (добавить актуальный CIDR при подключении)
```

---

## 3. `blocklist_ip.conf` — кураторский IP-blocklist

Пустой на старте. Наполняется через PR по результатам анализа логов или жалоб. Используется правилом `ip_blocklist` (категория `blocking`).

```
# blocklist_ip.conf — IP-blocklist (Phase 1+)
# Пустой на старте. PR для добавления, обязательно через staged rollout (см. ниже).

# Формат:
# <ip-or-cidr>  status=staging|active  reason=<short>

# Примеры (после первых PR):
# 203.0.113.42  status=active  reason=brute-force /login
# 198.51.100.0/24  status=staging  reason=scanner-pattern
```

**Staged rollout:** новые IP сначала добавляются с `status=staging` — матчатся, пишутся в `staging_match` лога, но не блокируют. После 24-48ч анализа FP-rate (отсутствие срабатываний на легитимном трафике) — отдельный PR с переводом в `status=active`.

---

## 4. `ua_blacklist.conf` — UA-паттерны

Пустой на старте. Наполняется через PR по результатам анализа топа UA в логах. Поддерживает staged rollout.

```
# ua_blacklist.conf — UA-паттерны (Phase 1+)
# Пустой на старте. PR для добавления, обязательно через staged rollout.

# Формат:
# <regex-pattern>  status=staging|active  reason=<short>

# Примеры (после первых PR):
# (?i)\bsqlmap/[\d\.]+   status=active  reason=SQL-scanner
# (?i)\bAhrefsBot\b      status=staging  reason=SEO-crawler-competitor
```

**Подсказка по составлению:** на стороне backend паттерны склеиваются в один combined regex для O(1)-матчинга на proxy. Формат на стороне backend.

---

## 5. `asn_datacenters.conf` — ASN-номера датацентров

Заполнен на старте базовым стабильным списком. Используется для тега `reputation:asn_dc` (информационный, не правило).

```
# asn_datacenters.conf — ASN ДЦ (Phase 1+)
# Заполнен базовым. Меняется редко (новые провайдеры или передача номеров).
# Источник: публичные данные.

# Cloud providers
14618    # Amazon AWS
16509    # Amazon AWS
8075     # Microsoft Azure
8068     # Microsoft Azure
15169    # Google Cloud / GCP
396982   # Google Cloud
14061    # DigitalOcean
24940    # Hetzner Online
16276    # OVH SAS
20473    # Choopa / Vultr
63949    # Linode
14955    # Linode

# Альтернативные облака и VPS
51167    # Contabo
197540   # netcup
210558   # 1984 Hosting

# Список меняется через PR.
```

---

## 6. `tls_fp_blocklist.conf` — TLS-fingerprint blocklist (Phase 2+)

Пустой на старте. Наполняется через PR. Поддерживает staged rollout.

```
# tls_fp_blocklist.conf — TLS-fingerprints известных ботов (Phase 2+)
# Пустой на старте. PR для добавления, через staged rollout.

# Формат:
# <fp-string>  status=staging|active  reason=<short>

# Примеры (после первых PR):
# L12d11h1_abc123def456_xyz789  status=active  reason=scrapy-3.x
# L13d15h2_qweasdzxc987_lmnopq  status=staging  reason=newly-seen-pattern
```

---

## 7. `tls_fp_catalog.conf` — сигнатуры автоматизации для impersonator-детекции (Phase 2+)

Пустой на старте. Map `hash_b → семейство автоматизации`. Используется правилом `tls_fp_impersonator`.

```yaml
# tls_fp_catalog.conf — Phase 2+
# Пустой на старте. PR для добавления, через staged rollout.

# Каждая запись:
# hash_b: <12-hex-chars>
# family: <name>
# status: staging | active

entries:
  # - hash_b: 1ed0482b9b4c
  #   family: python-requests
  #   status: active

  # - hash_b: a1b2c3d4e5f6
  #   family: curl
  #   status: staging
```

---

## 8. `tls_fp_browser_profiles.conf` — ожидаемые cipher_cnt для браузеров (Phase 2+)

Заполнен базовым на старте. Используется правилом `tls_fp_suspicious_ciphers`.

```yaml
# tls_fp_browser_profiles.conf — Phase 2+
# Заполнен базовым набором. Корректируется по мере появления новых версий браузеров.

profiles:
  chrome:
    expected_cipher_cnt: 15
    status: active

  firefox:
    expected_cipher_cnt: 16
    status: active

  safari:
    expected_cipher_cnt: 20
    status: active

  proxy:
    expected_cipher_cnt: 15           # обычно совпадает с Chrome
    status: active
```

Если у браузера обновилась версия и cipher_cnt сдвинулся — продакт сначала добавляет новое значение с `status: staging` (для тестирования рядом со старым), потом промоутит после калибровки.

---

## 9. `challenge_secret` — HMAC secret для clearance cookie (Phase 4+)

Не файл со списком — это одна строка секрета. Доставляется через Puppet (Channel A) как env-переменная или защищенный файл. Один общий для всего edge-пула.

```bash
# Пример доставки через env (на proxy при старте nginx):
# CHALLENGE_HMAC_SECRET=<32-bytes-base64-encoded-random-string>

# Или через файл (Puppet хранит content шифрованно):
# /etc/antibot/challenge_secret.key
# (chmod 600, читается только nginx user)
```

**Ротация:** Краткая схема:

- *Плановая* — раз в квартал, через PR в Puppet + reload nginx по пулу.
- *Экстренная* (компрометация) — через эскалацию к prod-edge-админам по incident-процедуре.
Любая ротация инвалидирует все ранее выданные clearance cookie (by design).

---

## 10. `policy/<host>.yaml` — per-resource policy (Phase 3+)

**Не хранится на proxy как файл** — приходит из backend через Channel C как часть каталога `policy`. Каталог = map `host → policy_json`. Здесь — структура одной записи в map'е для информации.

**Покрытие домена (parent-domain fallback, 86exrefdz).** Запись для домена покрывает и его поддомены: эдж при чтении policy для хоста сначала ищет точную запись, а если её нет — поднимается вверх по доменным меткам до первой существующей (`www.example.com` → `example.com`). То есть регистрация `example.com` автоматически защищает `www.example.com`, `app.example.com` и т.д. с тем же `mode`/`strictness`/`origin_ip`. Более специфичная запись (`api.example.com`) переопределяет родительскую. На public-suffix (`com`, `рф`) walk-up не «протекает» — матчатся только реально заведённые записи.

```yaml
# Пример per-resource policy для одного домена
# Формат внутри каталога backend; на proxy приходит как часть policy каталога

example.com:
  mode: active                       # shadow | active
  strictness: standard               # standard | permissive
  attack_mode: false                 # тоггл "Under Attack mode"

  # origin_ip — bare IPv4/IPv6 бэкенда клиента. Маркер проксируемого тенанта
  # (multi-tenant routing, 86exrefdz): эдж матчит входящий Host с записью
  # policy и проксирует на этот IP (хостнейм в upstream подменяется на IP,
  # loop-safe; Host/SNI наверх остаются example.com). Пусто = хост не
  # тенант и не проксируется (эдж tenant-only: не-тенант отбрасывается
  # через 444). Без CIDR — это destination одного
  # бэкенда. Схема апстрима — https/443 (per-host scheme/port — отдельный тикет).
  origin_ip: 203.0.113.9

  # IP-whitelist легитимных серверных интеграций клиента
  ip_whitelist:
    - 203.0.113.10/32                # бэкенд клиента
    - 198.51.100.0/24                # пул его микросервисов

  # ASN-блок клиента
  asn_block:
    - 12345                          # ASN, который клиент решил блокировать
    - 67890

  # Whitelist стран (если задан — все остальные блокируются geo_blocklist)
  geo_whitelist:
    - RU
    - BY
    - KZ
    # пусто = разрешены все страны

  # Custom UA-паттерны клиента (применяются поверх глобального ua_blacklist)
  custom_ua_blacklist:
    - "(?i)\\bcompetitor-scraper\\b"

  # Клиентские rate-rules (per-path)
  rate_rules:
    - path: /login*
      methods: [POST]
      rps: 5
      burst: 10
      action: challenge              # block | challenge | log_only

    - path: /api/*
      rps: 20
      burst: 40
      action: block

    - path: /search
      rps: 10
      burst: 20
      action: challenge

  # Кастомное имя API-key header — если клиенту нужна интеграция с собственным auth
  # (в v1 OOS, но место в schema зарезервировано)
  # api_key_header: X-Client-Token
```

---

## Соглашения по staged rollout

Для всех каталогов с `status` field (ua_blacklist, ip_blocklist, tls_fp_blocklist, tls_fp_catalog, tls_fp_browser_profiles):

1. **Новые паттерны/записи всегда добавляются с `status: staging`.**
2. Период наблюдения — минимум 24 часа после доставки на proxy (что-то более коротковременное не даст репрезентативной выборки).
3. После наблюдения — отдельный PR с переводом `status: staging` → `status: active`.
4. Если в `staging`-периоде паттерн дал false-positive — revert исходного PR (не оставляем в staging, чтобы не накапливать «забытые» записи).

Промоут паттерна — это отдельный, осознанный этап, не автоматический.

---
