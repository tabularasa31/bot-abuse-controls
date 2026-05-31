# API & Account Protection — спецификация (серия P)

**Версия:** v0.1 · **Статус:** проектный контракт (целевое поведение) · **Дата:** 2026-05-31

Документ описывает целевое поведение оси защиты от абьюза аккаунтов и API —
в том же смысле, в каком [vision.md](vision.md) описывает каскад. Что уже в стенде, а
что нет — сверяй с [PROGRESS.md](../../PROGRESS.md) и кодом.

**Сопутствующие материалы (как у vision):**
[api-account-rules-reference.md](api-account-rules-reference.md) — правила/флаги/теги в
формате «если условие → вердикт»; [api-account-entities-reference.md](api-account-entities-reference.md)
— словарь (стадии, ключи, профили, теги, поля лога, перечисления);
[api-account-config-templates.md](api-account-config-templates.md) — структура policy-полей
и профилей.

---

## 1. Что это

Контроль абьюза двух близких поверхностей:
- **Account abuse** — credential stuffing, brute force, массовая фейковая регистрация.
- **API abuse** — scraping, перебор/утечка ключей, enumeration.

Это abuse-control-срез защиты API (домены auth-credential-abuse + rate/quota). Более
широкая API-защита (контракт/схема/инвентарь/JWT/транспорт) — отдельная ось,
см. [api-contract-governance-spec.md](api-contract-governance-spec.md) (серия Q).

## 2. Зачем (чего не хватает сегодня)

Каскад уже имеет rate-limit (`rate_limit.lua`: `rate_ip`/`rate_ip_ua`/`rate_api`/
`rate_scan_urls`), reputation и challenge. Но все ключи rate-лимита — сетевые
(IP, IP+UA, fp, URI-bucket). Этого мало против:

- стаффинга, размазанного по тысяче IP, но бьющего в один аккаунт;
- abuse одного API-ключа с многих IP;
- targeted brute force одного аккаунта.

Per-IP лимит обходится ботнетом/прокси-ротацией. Нужен контроль по идентичности
(аккаунт / ключ), которого у эджа сейчас нет.

## 3. Ключевое ограничение: эдж identity-blind

`verdict.lua` видит IP/fp/UA/Host/path/заголовки, но НЕ «какой аккаунт» и не «какой
ключ». Поэтому фундамент оси — стадия извлечения идентичности (P1), которая кладёт
нормализованный ключ в `ctx`, ровно как `rate_tls_fp` кеит на fp. Без неё ось не строится.

Второй сквозной принцип: сильнейший сигнал auth-абьюза — доля неуспешных логинов, а её
эдж видит только из ответа origin (`$status` 401/403 в response/log-фазе). Это тот же
паттерн обратной связи, что G1 (challenge solve-rate).

## 4. Где в каскаде

```
hygiene → reputation → tls_fp → [P1 identity-extract] → rate_limits(+P2) → verification
                                          ↑                                       
                              только на auth/API-путях (P4)                       
log-фаза: [P3 failed-auth feedback]  →  reputation/score, challenge-эскалация      
```

P1 — лёгкая стадия перед rate_limits, активна только на путях, объявленных в P4.
P2 добавляет профили в существующий rate_limits. P3 живёт в log/response-фазе.

## 5. Как — по компонентам

### 5.1 Identity-extraction (P1) — фундамент
Извлекает на auth/API-путях (P4): API-key/bearer из `Authorization`/`X-API-Key`/query;
username из login-формы (form-urlencoded/JSON). Нормализует в ключ для rate (P2) и reputation.

⚠️ **PII/security (жёстко):**
- username/token хешируются (HMAC/sha256) перед использованием как ключ и в логах —
  никогда не сырьём.
- **Пароль никогда не логируется, не хранится, не инспектируется** — его значение нам не нужно.
- Чтение тела (`lua_need_request_body`) только на login-путях, с лимитом размера (см. Q3),
  bypass для крупных/upload-эндпоинтов.

### 5.2 Per-credential / per-key профили (P2)
Новые GCRA-профили поверх движка `rate_limit.lua` (те же `gcra`/`windows`/shared_dict-ячейки),
ключ = идентичность из P1:
- `rate_login_per_account` — окна по hashed-username (стаффинг по многим аккаунтам + brute одного);
- `rate_api_key` — окна по hashed-ключу (scraping/abuse, leaked-key).

Graceful skip при отсутствии ключа (как `fp_usable`-guard). Enforcement mode-gated через
`policy.enforce` (challenge/429 по strictness, как rate_limit 429).

### 5.3 Failed-auth feedback (P3)
`log_by_lua`/`header_filter` на login-путях: читает upstream `$status`, классифицирует
success/fail. Всплеск failed-ratio по hashed-account / IP-/24 → +score в reputation и
эскалация challenge/strictness на следующих запросах источника. Прецедент — G1.

⚠️ Это статистика ответов, не проверка валидности пароля. Зависит от того, что origin
отдаёт различимые статусы на success/fail (задокументировать допущение).

### 5.4 Auth-endpoint policy-config (P4) — фундамент-компаньон
Декларация per-host: `auth_login_paths`/`auth_register_paths`/`api_paths` (glob, как
`rate_rules`) + опц. per-endpoint квоты. Edge даёт классификатор `endpoint_class(uri)`.
Расширяет существующую модель `is_api_path(uri, patterns)`. B10 Policy API (PATCH массивов).

### 5.5 Breached-cred / disposable-email (P5) — опционально
Сигнал для стаффинга/фейк-регистрации. ⚠️ Эдж пароль не валидирует — реалистичный
edge-скоуп это disposable-email домены (каталог через Channel C, как `ua_blacklist`).
Полноценная breached-password проверка — бэкенд-функция (ADR-005), не Lua hot-path. В тикете
сначала решается граница edge↔backend.

## 6. Что переиспользуем
`rate_limit.lua` (GCRA-движок + keying), `is_api_path`/glob, `policy` + B10 Policy API,
`reputation` (per-key/per-account рядом с per-IP), `challenge`/`attack_mode` (step-up на auth),
`bac_log` + теги (`account:cred_stuffing`, `api:key_abuse`, `account:auth_fail_spike`),
паттерн G1, Channel C/ADR-006 (для P5).

## 7. Честные границы (⛔ это бэкенд, не эдж)
- **ATO** (аномальный успешный вход) — эдж не знает истории аккаунта; решение на бэкенде,
  эдж даёт лишь fp/geo-контекст.
- **Business-logic abuse** (скальпинг, купоны) — нужен app-контекст.
- **Credential stuffing detection** на эдже = объём + failed-ratio + bot-score, не проверка
  пароля по брешь-листу.
- **Нюанс enforcement:** для API нельзя полагаться на JS-challenge (C-серия браузерная) —
  опора на rate / key-auth / reputation / mTLS.

## 8. Состав и порядок внедрения
| Компонент | Суть | Зависит от |
|---|---|---|
| Identity-extraction | username/token/key → ключ (фундамент) | — |
| Auth-endpoint config | декларация login/register/API-путей (фундамент) | — |
| Per-key/per-account профили | `rate_login_per_account`, `rate_api_key` | оба фундамента |
| Failed-auth feedback | origin 401/403 → счётчик → reputation/challenge | identity + config |
| Breached-cred/disposable-email | каталог-сигнал (опц.) | identity |

Порядок: два фундамента (identity-extraction + auth-endpoint config) параллельно → профили
и feedback → опц. breached-cred. Разбор правил — в
[api-account-rules-reference.md](api-account-rules-reference.md).
