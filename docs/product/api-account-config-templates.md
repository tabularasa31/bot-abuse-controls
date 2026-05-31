# API & Account Protection — шаблоны конфигов

Иллюстративные шаблоны policy-полей и профилей оси защиты от абьюза аккаунтов и API. Источник правды по поведению — [api-account-protection-spec.md](api-account-protection-spec.md); каталог правил «если → то» — [api-account-rules-reference.md](api-account-rules-reference.md); словарь сущностей — [api-account-entities-reference.md](api-account-entities-reference.md).

**Статус:** проектный контракт (целевое поведение), предшествует реализации. Что уже в стенде — сверяй с [PROGRESS.md](../../PROGRESS.md) и кодом.

**Формат:** показан как YAML с комментариями для удобства чтения. Главное — структура данных и семантика полей, не конкретный синтаксис.

> Ось встраивается в существующую модель `policy` (per-host, см. базовый шаблон `policy/<host>.yaml`) и движок `rate_limit.lua`. Декларация auth-путей расширяет существующую модель `is_api_path(uri, patterns)`. Каталог `disposable_email_domains` доставляется через Channel C, как `ua_blacklist` (ADR-006).

> **PII/security (сквозной инвариант).** Username и token/API-key используются как ключ и пишутся в лог только хешированными (HMAC/sha256). Пароль никогда не логируется, не хранится и не инспектируется — в конфигах его нет и быть не может.

---

## Что добавляется к policy домена

Ось расширяет запись `policy[host]` тремя группами полей:

1. **Auth-endpoint config (P4)** — декларация login/register/API-путей + опц. per-endpoint квоты.
2. **Профили по идентичности (P2)** — параметры `rate_login_per_account` и `rate_api_key`.
3. **Failed-auth feedback (P3)** — пороги всплеска неуспешных логинов.
4. **Breached-cred (P5, опц.)** — подключение каталога disposable-email.

Управляются через B10 Policy API (PATCH массивов auth-путей). Доставка policy на эдж — как у базового каскада (≤ 30 секунд).

---

## 1. Auth-endpoint config (фундамент)

Декларация per-host, какие пути считать login/register/API. Glob-паттерны — как `rate_rules` в базовой policy. На основе этого эдж строит `endpoint_class(uri)`, гейтит стадию identity-extraction и включает чтение тела только там, где нужно.

```yaml
example.com:
  # ... базовые поля policy (mode/strictness/origin_ip/...) ...

  # Auth-endpoint config (P4) — декларация путей. Glob, как rate_rules.
  # Расширяет модель is_api_path(uri, patterns).
  auth_login_paths:
    - /login
    - /api/v1/auth/login
    - /signin*

  auth_register_paths:
    - /register
    - /signup*

  api_paths:
    - /api/*
    - /graphql

  # Включает ли ось enforcement физически. mode-gated через policy.enforce.
  # Наблюдательный режим: профили считаются и логируются, но не блокируют.
  enforce: false                     # false = наблюдение, true = активное исполнение
```

**Семантика полей.**

| Поле                  | Тип               | Что задаёт                                                                                       | Конвенция                                  |
| --------------------- | ----------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------ |
| `auth_login_paths`    | array of glob     | Пути, на которых идёт извлечение username и работает `rate_login_per_account` + failed-auth feedback | пусто = login-защита по идентичности выключена |
| `auth_register_paths` | array of glob     | Пути регистрации; на них извлекается username/email и применяется disposable-email сигнал (P5)    | пусто = register-сигналы выключены         |
| `api_paths`           | array of glob     | API-пути; на них извлекается API-key/bearer и работает `rate_api_key`                             | расширяет/дополняет `is_api_path` patterns |
| `enforce`             | boolean           | `policy.enforce` для оси: наблюдение vs активное исполнение                                       | дефолт `false` (как mode=shadow по духу)   |

**Чтение тела.** `lua_need_request_body` включается только для путей класса `login`/`register` (где нужен username из тела). Лимит размера тела обязателен; для крупных/upload-эндпоинтов — bypass (тело не читается). API-key/bearer берутся из заголовков/query — тело для `api`-класса не требуется.

---

## 2. Профили по идентичности (P2)

GCRA-профили поверх `rate_limit.lua` (`gcra` / `windows` / shared_dict-ячейки). Ключ — идентичность из identity-extraction, а не сетевой параметр. Структура окон — как у существующих rate-профилей (несколько окон, срабатывает любое превышенное).

```yaml
example.com:
  # Профили по идентичности (P2). Те же gcra/windows, что у rate_ip/rate_tls_fp,
  # но ключ = hashed username / hashed api key из identity-extraction.
  identity_rate_profiles:

    rate_login_per_account:          # ключ = hashed username
      key: hashed_username
      windows:
        - { seconds: 60,  limit: 5 }   # не более 5 попыток логина в аккаунт за 60с
        - { seconds: 600, limit: 20 }  # и не более 20 за 10 минут
      action: challenge              # challenge | block — финал по strictness/enforce
      # graceful skip: нет hashed username из P1 → профиль не срабатывает

    rate_api_key:                    # ключ = hashed api key
      key: hashed_api_key
      windows:
        - { seconds: 60,  limit: 600 }
        - { seconds: 3600, limit: 10000 }
      action: block                  # для API на JS-challenge не опираемся
      # graceful skip: нет hashed api key из P1 → профиль не срабатывает
```

**Семантика полей.**

| Поле        | Тип                       | Что задаёт                                                                                       |
| ----------- | ------------------------- | ------------------------------------------------------------------------------------------------ |
| `key`       | enum (`hashed_username` / `hashed_api_key`) | Источник ключа из identity-extraction. Всегда хешированный, никогда сырьём                        |
| `windows`   | list of `{seconds, limit}`| Окна GCRA; срабатывает любое превышенное (как у сетевых профилей)                                  |
| `action`    | enum (`challenge` / `block`)| Желаемое действие; финальное исполнение mode-gated через `enforce` и определяется strictness       |

**Конвенция по `action`.** Для login-путей с браузерным клиентом `challenge` (step-up верификация) уместен. Для API-путей нельзя полагаться на JS-challenge (он браузерный) — опора на `block` (429) / key-auth / reputation. При `enforce: false` любое `action` даёт только лог.

**Per-endpoint квоты (опц.).** Окна можно переопределить на конкретном пути из auth-endpoint config — для эндпоинтов с заведомо иным легитимным профилем нагрузки:

```yaml
  per_endpoint_quotas:
    - path: /api/v1/auth/login
      profile: rate_login_per_account
      windows:
        - { seconds: 60, limit: 3 }    # строже общего на чувствительном эндпоинте
    - path: /api/bulk-export
      profile: rate_api_key
      windows:
        - { seconds: 60, limit: 50 }   # дороже обычного → ниже лимит
```

---

## 3. Failed-auth feedback (P3)

Пороги всплеска доли неуспешных логинов. Эдж читает upstream `$status` в log/response-фазе, классифицирует 401/403 как fail и копит failed-ratio по hashed-account и по IP-/24. Превышение → `+score` в reputation и эскалация challenge/strictness на следующих запросах. Прецедент — паттерн G1.

```yaml
example.com:
  failed_auth_feedback:
    enabled: true
    fail_statuses: [401, 403]        # какие $status считать неуспешным логином
    keys:
      - hashed_account               # по аккаунту
      - ip_24                        # и по подсети /24 источника
    spike:
      min_attempts: 10               # минимум попыток, ниже которого ratio не считаем
      fail_ratio: 0.8                # доля неуспешных, выше которой — всплеск
      window_seconds: 300
    on_spike:
      reputation_score_delta: +score # эскалация в reputation
      escalate: challenge_strictness # step-up на последующих запросах источника
```

> ⚠️ Это статистика ответов, не проверка валидности пароля. Допущение: origin отдаёт различимые статусы на success/fail — фиксируется при внедрении на конкретном домене. Пароль не читается.

**Семантика полей.**

| Поле                  | Тип            | Что задаёт                                                                  |
| --------------------- | -------------- | --------------------------------------------------------------------------- |
| `fail_statuses`       | list of int    | Какие upstream `$status` считаются неуспешным логином (401/403)             |
| `keys`                | enum list      | По чему агрегировать failed-ratio: `hashed_account` и/или `ip_24`           |
| `spike.fail_ratio`    | float          | Порог доли неуспешных, при котором фиксируется всплеск                       |
| `on_spike.escalate`   | enum           | Что делать на следующих запросах источника (эскалация challenge/strictness)  |

---

## 4. Breached-cred / disposable-email (P5, опционально)

Подключение каталога disposable-email доменов. Реалистичный edge-скоуп — только домены одноразовой почты. Полноценная breached-password проверка — бэкенд (ADR-005), не Lua hot-path; в конфиге эджа её нет.

```yaml
example.com:
  breached_cred:
    disposable_email:
      enabled: true
      catalog: disposable_email_domains   # доставляется через Channel C (как ua_blacklist)
      applies_to: [register, login]       # классы эндпоинтов из auth-endpoint config
      action: soft_signal                 # +score/флаг в reputation, не самостоятельный блок
```

**Конвенция.** `action: soft_signal` — комбинируется на верификации, сам блок не выносит (см. правило P5.1). Каталог `disposable_email_domains` ведётся и доставляется как медленный каталог (ADR-006), формат — как у `ua_blacklist`. Никаких паролей/брешь-листов в edge-конфиге.

---

## Соглашения

- **Glob-паттерны путей** — как в `rate_rules` базовой policy; матчатся через расширение `is_api_path(uri, patterns)` → `endpoint_class(uri)`.
- **Хеширование ключей** — всегда HMAC/sha256 в `ctx` и логе; сырьё username/токена в конфиг не попадает и не сохраняется.
- **Mode-gate** — поведение оси определяется `enforce` (per-host); при `false` всё считается и логируется, но физически не исполняется.
- **Управление** — массивы auth-путей правятся через B10 Policy API (PATCH); доставка на эдж — как у остальной policy.
- **Parent-domain fallback** — запись для домена покрывает поддомены так же, как базовая policy (более специфичная запись переопределяет родительскую).
