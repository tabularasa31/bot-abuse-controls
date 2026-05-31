# API Contract & Governance — шаблоны конфигов (серия Q)

Иллюстративные шаблоны конфигурации оси контрактной защиты API: структура policy-полей, формат
schema-каталога, пороги resource-limits, конфиг JWT/JWKS и mTLS, transport/header config,
паттерны устаревших версий.

Источник правды по поведению — [api-contract-governance-spec.md](api-contract-governance-spec.md).
Правила «если условие → вердикт» — [api-contract-rules-reference.md](api-contract-rules-reference.md);
словарь сущностей — [api-contract-entities-reference.md](api-contract-entities-reference.md).

**Статус:** проектный контракт (целевое поведение) — показывает целевую структуру конфигов оси Q; что уже в стенде, сверяй с PROGRESS.md и кодом.

**Формат:** показан как YAML с комментариями для удобства чтения. Главное — структура данных и
семантика полей, не конкретный синтаксис. Точное размещение и формат фиксируются при реализации.

> **Где живут эти конфиги.** Per-endpoint contract, resource-limits, JWT/mTLS-config,
> transport/header config и deprecated-version patterns — поля `policy` (per-host/per-endpoint),
> редактируются через B10 Policy API. Schema-каталог — slow-каталог через Channel C
> (ADR-006, PR-only, staged rollout `active`/`staging`, CI-валидация B13). JWKS/секрет —
> доставка как секрет/каталог (паттерн C1). Все блокирующие правила mode-gated через
> `policy.enforce` (`mode: shadow` по умолчанию).

## Иерархия конфигов оси Q

```
policy[host].endpoints[]        ← Q1 per-endpoint contract (method/CT/required-params) + ссылка на схему
schema_catalog/<ref>.yaml       ← Q2 JSON-схемы тел (Channel C, ADR-006, slow-каталог)
policy[host].resource_limits    ← Q3 размер тела / глубина JSON / GraphQL
policy[host].jwt                 ← Q4 JWKS/секрет + iss/aud/scope
policy[host].mtls                ← Q5 ssl_verify_client + CA-bundle (опц., per-tenant)
policy[host].transport           ← Q6 HSTS/CORS/header config + маскировка ошибок
policy[host].deprecated_versions ← Q7 паттерны устаревших версий → 410
```

---

## 1. Q1 — Per-endpoint contract

Позитивная модель по эндпоинту поверх глобального method-whitelist гигиены (`hygiene.lua`
`method_set`/`method_lookup`: GET/HEAD/POST/OPTIONS на весь хост). Пути матчатся glob'ом
(`is_api_path`). На путях без записи — skip.

```yaml
# policy[host].endpoints — per-endpoint contract (mode-gated)
example.com:
  mode: active                        # shadow | active — общий mode-gate (policy.enforce)
  endpoints:
    - path: /api/v1/login             # матчинг glob (is_api_path)
      methods: [POST]                 # allowed_methods; всё прочее → reject 403, тег api:contract_violation
      content_types: [application/json] # allowed_content_types; иначе → reject (415/403)
      required_params: [username]     # отсутствие → reject 422
      schema_ref: login_v1            # ссылка на запись schema-каталога (Q2), опц.

    - path: /api/v1/items/*
      methods: [GET, HEAD]
      # content_types/required_params не заданы → не проверяются
      schema_ref: null                # тело не валидируется по схеме

    - path: /upload/*
      methods: [POST]
      schema_bypass: true             # Q2 skip — upload/бинарное тело не парсится cjson
```

**Конвенции.**
- Путь без записи в `endpoints[]` → Q1 skip (запрос идёт дальше). Detection таких путей — Q7 (`api:shadow_endpoint`).
- `methods` всегда подмножество глобального method-whitelist гигиены — Q1 сужает, не расширяет.
- В `shadow` нарушение тегируется (`api:contract_violation`), но reject не исполняется.

---

## 2. Q2 — Schema-каталог (JSON-схема тела)

Компилированное подмножество OpenAPI (типы, `required`, `additionalProperties`). НЕ полный
OpenAPI-движок в hot-path. Валидация требует чтения тела (`lua_need_request_body` + парс
`cjson`) в пределах resource-limit (Q3). Доставка — slow-каталог через Channel C (ADR-006,
PR-only). Тот же контракт staged rollout (`active`/`staging`) и CI-валидация (B13), что и у
slow-каталогов серии P.

```yaml
# schema_catalog/login_v1.yaml — запись schema-каталога (Channel C, ADR-006)
ref: login_v1
status: active                        # active | staging (staged rollout)
schema:
  type: object
  additionalProperties: false         # лишние поля → reject 422 (mass-assignment-вектор НА ВХОДЕ)
  required: [username, password]      # отсутствие → reject 422
  properties:
    username:
      type: string                    # неверный тип → reject 422
    password:
      type: string
    remember:
      type: boolean
```

**Конвенции.**
- `additionalProperties: false` режет неизвестные поля на входе. Семантика mass-assignment (какое поле кому можно менять) — ⛔ бэкенд, не сюда.
- Новые/изменённые схемы добавляются с `status: staging`, промоутятся в `active` отдельным PR после калибровки (как у PR-каталогов серии P).
- Непарсимое тело там, где объявлена схема → `api:schema_violation`, reject 422.

---

## 3. Q3 — Resource limits

Защита от «тяжёлого» одного запроса. Размер тела — nginx до Lua (`client_max_body_size`);
структурная сложность — Lua после безопасного парса. Дополняет `limit_conn` (там соединения,
тут стоимость одного запроса).

```yaml
# policy[host].resource_limits (mode-gated)
example.com:
  resource_limits:
    max_body_size: 256k               # nginx client_max_body_size; превышение → reject 413
    max_json_depth: 16                # глубина вложенности JSON («billion laughs»-защита) → 422
    max_array_length: 1000            # макс. длина массивов в теле → 422

    # опц. GraphQL (если хост обслуживает GraphQL)
    graphql:
      max_depth: 10                   # глубина запроса → 422
      max_cost: 500                   # стоимость запроса
      max_aliases: 30                 # число алиасов
```

**Конвенции.**
- `max_body_size` может задаваться per-host и переопределяться per-endpoint.
- Size-лимит проверяется на уровне nginx (отдаёт 413) до входа в Lua; структурные пороги — после `cjson`-парса в пределах того же size-лимита.
- В стенде `client_max_body_size` сейчас стоит только на solver-локации; per-API политики ещё нет — это целевое поведение.

---

## 4. Q4 — Edge JWT / JWKS config

Stateless-проверка токена через `lua-resty-jwt`: подпись (JWKS или симметричный секрет),
`exp`/`nbf`, `iss`/`aud`, опц. required-scope (coarse authz). Ключи доставляются как
секрет/каталог (паттерн C1). Сырой токен в лог не пишется.

```yaml
# policy[host].jwt (mode-gated, на api-путях is_api_path)
example.com:
  jwt:
    enabled: true
    key_source: jwks                  # jwks | secret
    jwks_uri_ref: example_jwks        # доставляется как каталог/секрет (паттерн C1), НЕ fetch в hot-path
    # для симметричного секрета вместо jwks:
    # key_source: secret
    # secret_ref: example_hs256       # секрет через C1

    expected_iss: https://auth.example.com   # iss mismatch → reject 401
    expected_aud: example-api                 # aud mismatch → reject 401
    clock_skew_seconds: 60            # допуск на exp/nbf

    # опц. required-scope per-endpoint (coarse authz, НЕ полный BFLA)
    required_scopes:
      "/api/v1/admin/*": [admin]      # нет scope → reject 401/403
```

**Конвенции.**
- ⚠️ Q4 — аутентификация токена, не авторизация объекта. BOLA и полный BFLA — ⛔ бэкенд. Ревокация/интроспекция со state — тоже бэкенд.
- Невалидная подпись / протухший / неверный iss/aud → `api:token_invalid`, reject 401 (403 для scope).
- JWKS/секрет в hot-path не fetch'атся: ключи приходят заранее как каталог/секрет (C1).

---

## 5. Q5 — mTLS / client-cert (опц., per-tenant)

Транспортный уровень, до каскада. nginx `ssl_verify_client` + проверка `$ssl_client_verify` в
Lua на mTLS-хостах. По умолчанию выключено.

```yaml
# policy[host].mtls (опц., per-tenant, mode-gated)
api.example.com:
  mtls:
    enabled: true                     # по умолчанию false
    ssl_verify_client: on             # nginx ssl_verify_client (on | optional)
    ca_bundle_ref: example_client_ca  # CA для проверки клиентских сертификатов
    # Lua проверяет $ssl_client_verify == "SUCCESS"; иначе → reject, тег api:mtls_fail
```

**Конвенции.**
- Проверка `$ssl_client_verify` ≠ `SUCCESS` (нет cert / не та CA / истёк) → `api:mtls_fail`, reject.
- ⚠️ Совместимость с on-demand TLS (`lua-resty-acme`) проверяется отдельно (серия E про TLS-стек).

---

## 6. Q6 — Transport-гигиена (header / CORS config)

Response/header-фаза, per-host через policy. Не режет запрос — нормализует ответ.

```yaml
# policy[host].transport (response-side)
example.com:
  transport:
    server_tokens: off                # срезка версии сервера
    strip_banner_headers: true        # убрать banner-заголовки (X-Powered-By и т.п.)

    security_headers:
      hsts: "max-age=31536000; includeSubDomains"
      x_content_type_options: nosniff

    cors:
      allow_origins:                  # явный allowlist — НЕ "*" вслепую
        - https://app.example.com
      allow_methods: [GET, POST]
      allow_headers: [Authorization, Content-Type]
      allow_credentials: true

    mask_5xx_errors: true             # маскировать многословные 5xx origin (стектрейсы/детали)
```

**Конвенции.**
- CORS задаётся явным allowlist origin'ов; `*` вслепую не используется (особенно при `allow_credentials: true`).
- HSTS / X-Content-Type-Options / banner-срезка / `server_tokens off` — дёшево, высокий ROI; включаются на ранней фазе внедрения.

---

## 7. Q7 — Deprecated-version patterns + inventory

Enforcement устаревших версий API — поле policy. Inventory (shadow/zombie) — аналитика поверх
`bac_log` (diff вызываемых vs объявленных путей), отдельной конфигурации не требует; опц.
draft-PR кандидатов в декларацию (паттерн `find_asn_watch_candidates` из G2).

```yaml
# policy[host].deprecated_versions (mode-gated)
example.com:
  deprecated_versions:
    - pattern: /api/v1/*              # путь устаревшей версии → reject 410 Gone
      reason: "v1 sunset 2026-01-01"
    - pattern: /legacy/*
      reason: "legacy API retired"

  # inventory не конфигурируется здесь — diff vs endpoints[] (Q1) поверх bac_log:
  #   вызван путь не из endpoints[] → тег api:shadow_endpoint (undeclared / shadow)
  #   объявленный путь без вызовов  → zombie (declared-but-unused), аналитический сигнал
```

**Конвенции.**
- Запрос на deprecated-pattern → reject 410 Gone (mode-gated).
- Shadow-endpoint detection бесплатна: эдж уже логирует весь трафик (`bac_log`) и знает объявленные пути (`is_api_path` / `endpoints[]`).

---

## Соглашения по mode-gate и staged rollout

1. **Все блокирующие Q-правила mode-gated** через `policy.enforce`. По умолчанию `mode: shadow` — нарушения тегируются (`api:*`) и логируются в `bac_log`, но reject не исполняется. Включение enforcement — переключение в `mode: active` после калибровки по логам.
2. **Schema-каталог** следует контракту slow-каталогов серии P: Channel C / ADR-006, PR-only, статусы `active`/`staging`, CI-валидация (B13). Новые/изменённые схемы — сначала `staging`, промоут в `active` отдельным PR.
3. **Per-endpoint contract, resource-limits, JWT/mTLS/transport config, deprecated-versions** живут в `policy` и редактируются через B10 Policy API — без правки локальных файлов на эдже.
4. **JWKS/секреты** доставляются заранее (паттерн C1) и не fetch'атся в hot-path.

Включение контракта на хосте — осознанный этап: сперва объявить эндпоинты и схемы в `shadow`,
снять статистику нарушений по `bac_log`, затем перевести в `active`.
