# API Contract & Governance — справочник сущностей (серия Q)

Термины и определения оси контрактной защиты API + таблицы сущностей: новые стадии каскада,
каталоги, поля policy, теги, поля лога, перечисления и status-коды.

Источник правды по поведению — [api-contract-governance-spec.md](api-contract-governance-spec.md).
Правила в формате «если условие → вердикт» — [api-contract-rules-reference.md](api-contract-rules-reference.md);
структура конфигов и policy-полей — [api-contract-config-templates.md](api-contract-config-templates.md).

**Статус:** проектный контракт (целевое поведение) — описывает, как ось Q должна выглядеть на эдже; что уже в стенде, сверяй с PROGRESS.md и кодом.

---

## Термины

| Термин                       | Определение                                                                                                                                                                                                                                                  |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Позитивная модель (Q)**    | Подход «белый список разрешённого»: контракт описывает, что РАЗРЕШЕНО (методы, типы, параметры, схема тела, токены), и режет всё прочее. Ось Q — это позитивная модель.                                                                                          |
| **Негативная модель (WAF)**  | Подход «сигнатуры конкретных атак» (серия W, [waf-spec.md](waf-spec.md)): ищет известные паттерны вредоносного. Комплементарна Q; граница фиксируется в ADR-007.                                                                                                  |
| **Per-endpoint contract**    | Позитивный контракт по конкретному эндпоинту: `allowed_methods` + `allowed_content_types` + опц. `required_params`. Поверх глобального method-whitelist гигиены (`hygiene.lua` `method_set`/`method_lookup`). На путях без правил — skip.                          |
| **Schema-валидация**         | Проверка тела запроса против JSON-схемы (компилированное подмножество OpenAPI, не полный движок в hot-path). Требует чтения тела (`lua_need_request_body` + `cjson`).                                                                                              |
| **Resource limit**           | Лимит на стоимость одного запроса: размер тела, структурная сложность JSON, опц. сложность GraphQL. Дополняет `limit_conn` (там — соединения, тут — один запрос).                                                                                                 |
| **Edge JWT-валидация**       | Stateless-проверка токена на эдже: подпись (JWKS/секрет), `exp`/`nbf`, `iss`/`aud`, опц. scope. Через `lua-resty-jwt`. Аутентификация токена, НЕ авторизация объекта.                                                                                              |
| **mTLS / client-cert**       | Взаимная TLS-аутентификация: nginx `ssl_verify_client` + проверка `$ssl_client_verify`. Транспортный уровень, до каскада. Опц., per-tenant.                                                                                                                       |
| **Transport-гигиена**        | Response-side нормализация: security-заголовки (HSTS, X-Content-Type-Options, CORS), `server_tokens off`, срезка banner-заголовков, маскировка многословных 5xx.                                                                                                  |
| **API inventory**            | Инвентаризация эндпоинтов поверх `bac_log`: diff вызываемых vs объявленных → shadow / zombie. Сюда же enforcement устаревших версий.                                                                                                                              |
| **Shadow endpoint**          | Вызываемый путь, которого нет среди объявленных эндпоинтов (undeclared). Отмечается тегом `api:shadow_endpoint`, кандидат в декларацию.                                                                                                                            |
| **Zombie endpoint**          | Объявленный эндпоинт, который фактически не вызывается (declared-but-unused). Кандидат на вывод из контракта.                                                                                                                                                     |
| **mode-gate**                | Механизм исполнения вердикта по режиму (`policy.enforce`): при `mode=active` reject исполняется, при `mode=shadow` (дефолт) — только считается и логируется. Все блокирующие Q-правила mode-gated.                                                                  |
| **Вердикт (reject)**         | Блокирующий исход Q-правила — отказ на эдже до проксирования на origin (для API нет JS-challenge). HTTP-статус зависит от правила (403/422/413/410/401).                                                                                                            |
| **Тег (tag)**                | Информационная пометка `api:<short_name>` в поле `tags` лога `bac_log`. Не эмитит вердикт; пишется в т.ч. в shadow-режиме для калибровки.                                                                                                                          |

---

## Новые стадии каскада (ось Q)

Размещение стадий фиксируется при реализации; принцип — контракт/схема рано (дёшево отсекают
мусор до дорогих слоёв), token-валидация перед проксированием на origin. Ориентир из спеки:

```
hygiene → [Q1 contract] → [Q2 schema] → reputation → tls_fp → rate_limits → [Q4 JWT] → verification
   ↑ Q3 resource-limits (часть nginx до Lua, часть Lua после парса)
   ↑ Q5 mTLS — transport, до каскада
   ↓ Q6 transport-гигиена — response/header-фаза
   ↓ Q7 inventory — аналитика поверх bac_log
```

| Стадия / компонент    | Где в потоке                            | Что делает                                                                       | OWASP | Зависит от                |
| --------------------- | --------------------------------------- | -------------------------------------------------------------------------------- | ----- | ------------------------- |
| Q1 contract           | после `hygiene`, рано                   | per-endpoint allowlist метода / content-type / параметров                        | API5  | auth-endpoint config (P)  |
| Q2 schema             | после Q1                                | тело против JSON-схемы (`cjson`, `lua_need_request_body`)                         | API3-вход | contract + resource-limits |
| Q3 resource-limits    | часть nginx до Lua, часть Lua после парса | размер тела (`client_max_body_size`) + глубина JSON/GraphQL                       | API4  | —                         |
| Q4 JWT                | перед проксированием на origin           | подпись + exp/nbf/aud/iss через `lua-resty-jwt`                                  | API2  | identity-extraction (P)   |
| Q5 mTLS               | transport, до каскада                   | `ssl_verify_client` + `$ssl_client_verify`                                       | API2  | —                         |
| Q6 transport-гигиена  | response/header-фаза                    | HSTS/CORS/X-Content-Type-Options + `server_tokens off` + маскировка 5xx          | API8  | —                         |
| Q7 inventory          | аналитика поверх `bac_log`              | shadow/zombie diff + deprecated-version enforcement                              | API9  | auth-endpoint config (P)  |

---

## Каталоги и источники данных (ось Q)

| Имя / источник                | Что внутри                                                                                              | Кто наполняет / откуда       | Доставка                        | Используется в |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------- | ------------------------------- | -------------- |
| **schema-каталог**            | Map `endpoint → компилированная JSON-схема` (подмножество OpenAPI: типы, required, `additionalProperties`) | Продакт/клиент через PR        | slow-каталог, **Channel C** (ADR-006, PR-only, staged rollout, B13 CI-контракт) | Q2             |
| **per-endpoint contract**     | Per-endpoint `allowed_methods` / `allowed_content_types` / `required_params`. Пути — из объявленных api-путей (glob `is_api_path`) | Клиент через B10 Policy API   | в составе `policy` (Channel C)  | Q1             |
| **JWKS / JWT-секрет**         | Публичные ключи (JWKS) или симметричный секрет для проверки подписи + ожидаемые `iss`/`aud`/scope        | Клиент / интеграция           | секрет/каталог, паттерн C1      | Q4             |
| **mTLS trust config**         | CA-bundle для `ssl_verify_client`, перечень mTLS-хостов                                                  | Клиент через policy           | nginx + policy (per-tenant)     | Q5             |
| **transport/header config**   | Per-host флаги security-заголовков, CORS-allowlist, маскировка ошибок                                    | Клиент через B10 Policy API   | в составе `policy`              | Q6             |
| **deprecated-version pattern**| Per-host паттерны путей устаревших версий API → 410                                                      | Клиент через B10 Policy API   | в составе `policy`              | Q7             |
| `bac_log`                     | Лог всего трафика эджа (уже существует) + объявленные пути                                              | эдж                          | —                               | Q7 (источник инвентаря), теги всех Q |

Schema-каталог следует тому же контракту slow-каталогов, что и серия P: Channel C / ADR-006,
PR-only, staged rollout (`active`/`staging`), CI-валидация (B13). Per-endpoint contract,
transport/header config и deprecated-version patterns живут в `policy` и редактируются через
B10 Policy API.

---

## Поля policy (ось Q) — keyed by host / endpoint

| Поле                          | Уровень       | Тип             | Описание                                                                                              | Используется в |
| ----------------------------- | ------------- | --------------- | ----------------------------------------------------------------------------------------------------- | -------------- |
| `allowed_methods`             | per-endpoint  | list of string  | Разрешённые HTTP-методы на эндпоинте; всё прочее → reject                                              | Q1             |
| `allowed_content_types`       | per-endpoint  | list of string  | Разрешённые `Content-Type` тела на эндпоинте                                                           | Q1             |
| `required_params`             | per-endpoint  | list of string  | Обязательные параметры запроса; отсутствие → reject (422)                                              | Q1             |
| `schema_ref`                  | per-endpoint  | string          | Ссылка на запись в schema-каталоге для валидации тела                                                  | Q2             |
| `schema_bypass`               | per-endpoint  | bool            | Пропуск schema-валидации (upload / бинарные тела)                                                      | Q2             |
| `max_body_size`               | per-host/endpoint | size        | Лимит размера тела (через `client_max_body_size`); превышение → 413                                    | Q3             |
| `max_json_depth`              | per-host/endpoint | int         | Макс. глубина вложенности JSON («billion laughs»-защита)                                               | Q3             |
| `max_array_length`            | per-host/endpoint | int         | Макс. длина массивов в теле                                                                            | Q3             |
| `graphql_limits`              | per-host/endpoint | object      | (опц.) глубина / стоимость / число алиасов GraphQL                                                     | Q3             |
| `jwt`                         | per-host/endpoint | object      | Конфиг проверки токена: источник ключей (JWKS/секрет), ожидаемые `iss`/`aud`, опц. required-scope       | Q4             |
| `mtls`                        | per-host      | object          | Конфиг mTLS: вкл/выкл, режим `ssl_verify_client`, CA-bundle                                            | Q5             |
| `transport`                   | per-host      | object          | security-заголовки (HSTS, X-Content-Type-Options), CORS-allowlist, маскировка 5xx, banner-срезка        | Q6             |
| `deprecated_versions`         | per-host      | list of pattern | Паттерны путей устаревших версий → 410                                                                 | Q7             |

Поля выше mode-gated через `policy.enforce` и подчиняются `mode`/`shadow`/`active` так же, как
остальная policy. Заданные поля = есть контракт; незаданные = на этом пути/хосте правило skip.

---

## Теги оси Q (информационные) — копятся в `tags` лога `bac_log`

Формат тега — `api:<short_name>` (namespace `api:`, как `hygiene:` / `reputation:` / `tls_fp:`
в основном каскаде). Теги пишутся и в `shadow`, и в `active` — это позволяет калибровать
контракт до включения enforcement.

| Тег                       | Где появляется | Что означает                                                                                            | Источник                          |
| ------------------------- | -------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `api:contract_violation`  | Q1             | Запрос нарушил per-endpoint contract: метод / content-type / required-param не по allowlist               | `policy[host]` per-endpoint contract |
| `api:schema_violation`    | Q2             | Тело не прошло JSON-схему: непарсимо, неверный тип, нет required-поля, лишнее поле при `additionalProperties=false` | schema-каталог (`cjson`)          |
| `api:token_invalid`       | Q4             | JWT не прошёл валидацию: подпись / `exp`/`nbf` / `iss`/`aud` / scope                                      | `lua-resty-jwt` + JWKS/секрет     |
| `api:mtls_fail`           | Q5             | Клиентский сертификат отсутствует или `$ssl_client_verify` ≠ `SUCCESS`                                    | nginx `ssl_verify_client`         |
| `api:shadow_endpoint`     | Q7             | Вызван путь, которого нет среди объявленных (undeclared / shadow)                                        | `bac_log` diff vs объявленные пути |

---

## Перечисления (enums)

### HTTP status-коды reject (что отдаёт эдж в `mode=active`)

| Status            | Когда                                                                                  | Правило (rules-reference) |
| ----------------- | -------------------------------------------------------------------------------------- | ------------------------- |
| `401 Unauthorized`| JWT невалиден: подпись / exp / nbf / iss / aud (и обычно scope)                         | Q4.1–Q4.4                 |
| `403 Forbidden`   | per-endpoint contract: метод не в allowlist (и опц. scope)                              | Q1.1 (Q4.4)               |
| `410 Gone`        | путь устаревшей/deprecated версии                                                       | Q7.3                      |
| `413 Payload Too Large` | размер тела превышает лимит (`client_max_body_size`)                              | Q3.1                      |
| `415 / 403`       | `Content-Type` не в `allowed_content_types` (точный статус фиксируется при реализации)  | Q1.2                      |
| `422 Unprocessable Entity` | отсутствие required-param, schema-violation, структурная сложность JSON/GraphQL | Q1.3, Q2.1–Q2.3, Q3.2–Q3.3 |

### Категория Q-правила

| Значение   | Что делает                                                                                  |
| ---------- | ------------------------------------------------------------------------------------------- |
| `blocking` | Выносит reject с HTTP-статусом (mode-gated через `policy.enforce`)                           |
| `soft`     | Response-side нормализация (transport-гигиена) — не режет запрос                             |
| `tag`      | Только информационная пометка `api:*` в `bac_log`, вердикт не эмитит                         |

### Режим исполнения (наследуется из основного каскада)

| Значение | Поведение Q-правил                                                                        |
| -------- | ----------------------------------------------------------------------------------------- |
| `shadow` *(дефолт)* | Q-правила считаются и тегируются в `bac_log`, но reject физически не исполняется |
| `active` | Блокирующие Q-правила исполняют reject (403/422/413/410/401) до проксирования на origin    |

---

## Честные границы (⛔ бэкенд, не эдж)

Эти сущности **не** входят в ось Q — у эджа нет identity + ownership + бизнес-правил:

- **Авторизация объектов** (BOLA) — доступ к чужому объекту по ID. Эдж даёт сигнал (перебор ID, бот-скор), не решение.
- **Полный BFLA** — авторизация функций по роли (Q4 даёт лишь coarse required-scope).
- **Mass-assignment в семантике** — какое поле какому пользователю можно менять (Q2 режет лишь лишние поля на входе через `additionalProperties=false`).
- **Бизнес-логика** и **PII-в-ответах** — требуют знания домена и владения данными.
- **Ревокация/интроспекция токена со state** — Q4 только stateless-проверка.
