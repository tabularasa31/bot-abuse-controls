# API и Account Protection — шаблоны конфигов

Иллюстративные шаблоны policy-полей, профилей и каталогов слоя (обе оси). Контракт
поведения — [api-spec.md](api-spec.md); правила — [api-rules-reference.md](api-rules-reference.md);
словарь — [api-entities-reference.md](api-entities-reference.md).

Формат — YAML с комментариями для читаемости. Главное — структура и семантика полей,
не точный синтаксис. Слой встраивается в существующую per-host политику и в
rate-limit-движок; декларация путей расширяет матчинг API-путей; схемы и
disposable-email доставляются как slow-каталоги (PR-only).

> PII-инвариант. Username и токен/ключ используются как ключ и пишутся в лог только
> хешированными (HMAC). Пароль не логируется, не хранится, не инспектируется — в
> конфигах его нет и быть не может.

---

## Что добавляется к политике хоста

Слой расширяет запись `policy[host]` группами полей: декларация эндпоинтов и
per-endpoint contract, профили по идентичности, failed-auth feedback, resource limits,
JWT/mTLS-конфиг, transport-флаги, disposable-email. Все mode-gated: при `enforce: false`
все считается и логируется, но физически не исполняется.

---

## 1. Декларация эндпоинтов + per-endpoint contract

```yaml
example.com:
  # ... базовые поля policy (mode/strictness/origin_ip/...) ...

  # Декларация путей (фундамент). Glob, как rate_rules.
  endpoints:
    login:    [ /login, /api/v1/auth/login, /signin* ]
    register: [ /register, /signup* ]
    api:      [ /api/*, /graphql ]

  # Per-endpoint contract (позитивная модель): что разрешено на пути.
  contract:
    - path: /api/v1/orders
      allowed_methods: [ GET, POST ]
      allowed_content_types: [ application/json ]
      required_params: [ ]
    - path: /api/v1/auth/login
      allowed_methods: [ POST ]
      allowed_content_types: [ application/json, application/x-www-form-urlencoded ]

  enforce: false   # false = наблюдение (shadow), true = активное исполнение
```

| Поле | Тип | Что задает |
| --- | --- | --- |
| `endpoints.login/register/api` | array of glob | классы путей; стадии идентичности и контракта работают только здесь |
| `contract[].allowed_methods` | array | разрешенные методы эндпоинта; прочее → reject (403) |
| `contract[].allowed_content_types` | array | разрешенные content-type тела; прочее → reject (415/422) |
| `contract[].required_params` | array | обязательные параметры; отсутствие → reject (422) |
| `enforce` | boolean | mode-gate слоя: наблюдение vs исполнение (дефолт `false`) |

Чтение тела включается только для классов `login`/`register` (где нужен username) и
для эндпоинтов со схемой; для upload/бинарных — bypass. API-ключ/токен берутся из
заголовков/query — тело для `api`-класса не требуется.

## 2. Профили по идентичности

GCRA-профили поверх rate-limit-движка; ключ — идентичность, не сетевой параметр.

```yaml
example.com:
  identity_rate_profiles:
    login_per_account:                 # ключ = hashed username
      key: hashed_username
      windows:
        - { seconds: 60,  limit: 5 }
        - { seconds: 600, limit: 20 }
      action: challenge                # challenge | block — финал по strictness/enforce
    per_api_key:                       # ключ = hashed api key
      key: hashed_api_key
      windows:
        - { seconds: 60,   limit: 600 }
        - { seconds: 3600, limit: 10000 }
      action: block                    # для API на JS-challenge не опираемся

  # опц. переопределение окон на конкретном пути
  per_endpoint_quotas:
    - { path: /api/v1/auth/login, profile: login_per_account, windows: [ { seconds: 60, limit: 3 } ] }
    - { path: /api/bulk-export,   profile: per_api_key,       windows: [ { seconds: 60, limit: 50 } ] }
```

| Поле | Тип | Что задает |
| --- | --- | --- |
| `key` | enum (`hashed_username` / `hashed_api_key`) | источник ключа; всегда хешированный |
| `windows` | list of `{seconds, limit}` | окна GCRA; срабатывает любое превышенное |
| `action` | enum (`challenge` / `block`) | желаемое действие; исполнение mode-gated по `enforce` и strictness |

Для login с браузерным клиентом `challenge` уместен; для API — `block` (429), на
JS-challenge не опираемся.

## 3. Failed-auth feedback

```yaml
example.com:
  failed_auth_feedback:
    enabled: true
    fail_statuses: [ 401, 403 ]
    keys: [ hashed_account, ip_24 ]
    spike: { min_attempts: 10, fail_ratio: 0.8, window_seconds: 300 }
    on_spike: { reputation_score: increase, escalate: challenge_strictness }
```

Это статистика ответов, не проверка пароля. Допущение: origin отдает различимые
статусы на успех/неуспех — фиксируется при внедрении на домене.

## 4. Schema-каталог (slow-каталог, PR-only)

Доставляется как медленный каталог, отдельно от per-host политики. Компилированное
подмножество JSON-схем по эндпоинтам.

```yaml
# catalog: api_schemas
example.com:
  /api/v1/orders:
    POST:
      type: object
      additionalProperties: false        # поля вне схемы → reject (mass-assignment-вектор)
      required: [ item_id, qty ]
      properties:
        item_id: { type: string }
        qty:     { type: integer }
  upload_bypass:                          # эндпоинты, где тело не парсится как JSON
    - /api/v1/files/upload
```

## 5. Resource limits

```yaml
example.com:
  resource_limits:
    max_body_bytes: 262144               # размер тела; превышение → 413 (часть на nginx)
    json:
      max_depth: 32                      # защита от «billion laughs»
      max_array_len: 10000
    graphql:                             # опционально
      max_depth: 12
      max_aliases: 50
```

## 6. Edge JWT и mTLS

```yaml
example.com:
  jwt:
    enabled: true
    applies_to: [ api ]                  # классы путей, где валидируем токен
    jwks_source: jwks_example_com        # JWKS/секрет (доставляется как секрет/каталог)
    expected_iss: [ https://auth.example.com ]
    expected_aud: [ api.example.com ]
    required_scope:                      # опц. coarse authz per-endpoint
      - { path: /api/v1/admin/*, scope: admin }

  mtls:                                  # опц., per-tenant, по умолчанию выкл.
    enabled: false
    verify: optional                     # off | optional | on (на уровне nginx всегда optional, при on проверка идет в Lua)
```

JWT — stateless-проверка (подпись/exp/nbf/iss/aud); ревокация/интроспекция со
state — backend. Сырой токен не логируется. mTLS — транспортный уровень;
совместимость с on-demand TLS проверяется отдельно.

## 7. Transport-гигиена и deprecated-версии

```yaml
example.com:
  transport:
    hsts: true
    x_content_type_options: nosniff
    cors:
      allow_origins: [ https://app.example.com ]   # не "*" вслепую
    strip_server_banner: true
    mask_5xx_details: true

  deprecated_versions:                   # путь устаревшей версии → 410 (mode-gated)
    - /api/v0/*
```

## 8. Disposable-email (опционально)

```yaml
example.com:
  disposable_email:
    enabled: true
    catalog: disposable_email_domains    # slow-каталог (PR-only)
    applies_to: [ register, login ]
    action: soft_signal                  # +score/флаг, не самостоятельный блок
```

---

## Соглашения

- Glob-паттерны путей — как в базовых rate-правилах; на их основе строится класс
  эндпоинта.
- Хеширование ключей — всегда HMAC в контексте и логе; сырье username/токена в конфиг
  не попадает.
- mode-gate — поведение слоя определяется `enforce` (per-host); при `false` все
  считается и логируется, но не исполняется.
- slow-каталоги (схемы, disposable-email, JWKS) доставляются PR-only, отдельно от
  быстрой per-host политики.
- parent-domain fallback — запись хоста покрывает поддомены; более специфичная
  переопределяет родительскую.
