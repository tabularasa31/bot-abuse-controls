# API Contract & Governance — каталог всех правил (серия Q)

Полный перечень правил контрактной оси защиты API в формате «Если условие → то вердикт». Источник правды по поведению — [api-contract-governance-spec.md](api-contract-governance-spec.md); этот документ — плоский справочник «что на что срабатывает». Словарь сущностей — [api-contract-entities-reference.md](api-contract-entities-reference.md); структура policy-полей и конфигов — [api-contract-config-templates.md](api-contract-config-templates.md).

**Статус:** проектный контракт (целевое поведение) — описывает, как ось Q должна вести себя на эдже; что уже в стенде, сверяй с PROGRESS.md и кодом.

**Позитивная модель (Q) vs негативная (WAF).** Правила ниже — это позитивная модель: они описывают, что РАЗРЕШЕНО (методы, типы, схема, токены), и режут всё прочее. Это не сигнатурный поиск конкретных атак (то — негативная модель WAF, серия W). Две модели комплементарны; граница фиксируется в ADR-007.

**Как читать.** Каждое правило либо выносит блокирующий вердикт (reject), либо помечает запрос информационным тегом для аналитики. Большинство правил mode-gated: при `mode=shadow` (по умолчанию) срабатывание считается и логируется, но физически запрос не режется; при `mode=active` исполняется. Решение об исполнении — через `policy.enforce` (mode-gate).

Обозначения:

- **Категория** — `blocking` (выносит reject с HTTP-статусом), `soft` (накапливает сигнал/влияет косвенно), `tag` (только информационная пометка, вердикт не эмитит).
- **Источник** — откуда берутся данные для проверки.
- **Компонент** — к какому компоненту оси Q относится правило (per-endpoint contract, schema-валидация, resource limits, edge JWT, mTLS, transport-гигиена, API inventory).

> **Граница ⛔ бэкенд.** Эдж не делает авторизацию объектов/функций (BOLA / полный BFLA), mass-assignment в семантике, бизнес-логику и контроль PII-в-ответах — для этого нужны identity + ownership + бизнес-правила, которых у эджа нет. Эдж даёт сигнал, не решение. Правила ниже остаются в пределах того, что эдж видит на транспорте и в контракте запроса.

---

## Q1 — Per-endpoint contract (компонент: per-endpoint contract)

Позитивная модель по эндпоинту поверх глобального method-whitelist гигиены (`hygiene.lua` `method_set`: GET/HEAD/POST/OPTIONS на весь хост). Пути берутся из объявленных auth-эндпоинтов (серия P). На путях без правил — skip. Размещение в каскаде — рано (контракт дёшево отсекает мусор до дорогих слоёв).

| #  | Если…                                                                                                                          | То…                                                                                  | Категория | Источник                                  | Компонент             |
| -- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ | --------- | ----------------------------------------- | --------------------- |
| Q1.1 | Путь запроса совпал с объявленным эндпоинтом (`is_api_path` / glob), а HTTP-метод не входит в `allowed_methods` этого эндпоинта | `verdict=reject` (403), тег `api:contract_violation`. mode-gated                     | blocking  | `policy[host]` per-endpoint contract       | per-endpoint contract |
| Q1.2 | Путь совпал с объявленным эндпоинтом, а `Content-Type` тела не входит в `allowed_content_types` эндпоинта                       | `verdict=reject` (415/422 — на уровне контракта; точный статус фиксируется при реализации), тег `api:contract_violation`. mode-gated | blocking  | `policy[host]` per-endpoint contract       | per-endpoint contract |
| Q1.3 | Путь совпал с объявленным эндпоинтом, для которого заданы `required_params`, и запрос их не содержит                            | `verdict=reject` (422), тег `api:contract_violation`. mode-gated                     | blocking  | `policy[host]` per-endpoint contract       | per-endpoint contract |
| Q1.4 | Путь запроса НЕ совпал ни с одним объявленным эндпоинтом                                                                        | skip (Q1 не применяется; запрос идёт дальше по каскаду). Detection shadow-эндпоинтов — в Q7 | —         | `policy[host]` per-endpoint contract       | per-endpoint contract |

---

## Q2 — Schema-валидация (компонент: schema-валидация)

Поверх Q1: валидация тела запроса против JSON-схемы (компилированное подмножество OpenAPI, не полный движок в hot-path). Требует чтения тела (`lua_need_request_body` + парс через `cjson`) с лимитом из Q3 и bypass для upload-эндпоинтов. `additionalProperties=false` отсекает mass-assignment-вектор на входе (но не семантику mass-assignment — это ⛔ бэкенд). Схемы доставляются как slow-каталог через Channel C (ADR-006, PR-only).

| #  | Если…                                                                                                                  | То…                                                            | Категория | Источник                              | Компонент        |
| -- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | --------- | ------------------------------------- | ---------------- |
| Q2.1 | Тело запроса непарсимо как JSON (`cjson`-парс упал) на эндпоинте, где объявлена JSON-схема                              | `verdict=reject` (422), тег `api:schema_violation`. mode-gated | blocking  | schema-каталог (Channel C, ADR-006)   | schema-валидация |
| Q2.2 | Тело распарсилось, но не проходит схему: отсутствует `required`-поле, неверный тип поля                                 | `verdict=reject` (422), тег `api:schema_violation`. mode-gated | blocking  | schema-каталог (Channel C, ADR-006)   | schema-валидация |
| Q2.3 | Тело содержит поля, не объявленные в схеме, при `additionalProperties=false` (mass-assignment-вектор на входе)          | `verdict=reject` (422), тег `api:schema_violation`. mode-gated | blocking  | schema-каталог (Channel C, ADR-006)   | schema-валидация |
| Q2.4 | Эндпоинт помечен как upload / бинарный (bypass-список схемы)                                                            | skip schema-валидации (тело не парсится как JSON)             | —         | schema-каталог (Channel C, ADR-006)   | schema-валидация |

---

## Q3 — Resource limits (компонент: resource limits)

Защита от «тяжёлого» одного запроса, который не ловит rate-лимит по числу запросов (дополняет `limit_conn` из серии D — там соединения, тут стоимость одного запроса). Часть проверок — nginx до Lua (размер тела через `client_max_body_size`), часть — Lua после безопасного парса (структурная сложность). Превышение size-лимита на уровне nginx отдаёт 413.

| #  | Если…                                                                                                            | То…                                                          | Категория | Источник                          | Компонент       |
| -- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | --------- | --------------------------------- | --------------- |
| Q3.1 | Размер тела запроса превышает per-host/per-endpoint лимит (`client_max_body_size`)                               | `verdict=reject` (413 Request Entity Too Large). mode-gated | blocking  | nginx-лимит (policy)              | resource limits |
| Q3.2 | Структурная сложность JSON превышает порог: глубина вложенности или длина массивов («billion laughs»-защита)     | `verdict=reject` (422). mode-gated                          | blocking  | resource-limit пороги (policy)    | resource limits |
| Q3.3 | (опц.) GraphQL-запрос превышает порог по глубине / стоимости / числу алиасов                                     | `verdict=reject` (422). mode-gated                          | blocking  | resource-limit пороги (policy)    | resource limits |

---

## Q4 — Edge JWT/token-валидация (компонент: edge JWT)

Серия P извлекает токен как ключ; Q4 проверяет его валидность на api-путях (`is_api_path`) через `lua-resty-jwt`: подпись (JWKS или секрет), `exp`/`nbf`, `iss`/`aud`. Форжед/протухший токен режется до проксирования на origin (разгрузка бэкенда + ранний блок). Размещение — перед проксированием на origin. Опц. required-scope per-endpoint = coarse authz.

> ⚠️ Это аутентификация токена, не авторизация объекта. BOLA (владение объектом по ID) и полный BFLA — ⛔ бэкенд. Q4 — только stateless-проверка; ревокация/интроспекция со state — тоже бэкенд. Сырой токен не логируется.

| #  | Если…                                                                                                       | То…                                                       | Категория | Источник                          | Компонент |
| -- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | --------- | --------------------------------- | --------- |
| Q4.1 | На api-пути предъявлен токен с невалидной подписью (не сходится с JWKS/секретом)                             | `verdict=reject` (401), тег `api:token_invalid`. mode-gated | blocking  | JWKS/секрет (паттерн C1)          | edge JWT  |
| Q4.2 | Токен протух или ещё не активен (`exp` в прошлом / `nbf` в будущем)                                          | `verdict=reject` (401), тег `api:token_invalid`. mode-gated | blocking  | `lua-resty-jwt`                   | edge JWT  |
| Q4.3 | `iss`/`aud` токена не совпадают с ожидаемыми для этого хоста/эндпоинта                                       | `verdict=reject` (401), тег `api:token_invalid`. mode-gated | blocking  | `policy[host]` JWT-config         | edge JWT  |
| Q4.4 | (опц.) Для эндпоинта задан required-scope, а в валидном токене этого scope нет (coarse authz, НЕ полный BFLA) | `verdict=reject` (401/403). mode-gated                    | blocking  | `policy[host]` JWT-config         | edge JWT  |

---

## Q5 — mTLS / client-cert (компонент: mTLS)

Опц., per-tenant. Для API с сильной клиентской аутентификацией: nginx `ssl_verify_client` + проверка `$ssl_client_verify` в Lua на mTLS-хостах. Транспортный уровень, до каскада. По умолчанию выключено.

> ⚠️ Совместимость с on-demand TLS (`lua-resty-acme`) проверяется отдельно (серия E про TLS-стек).

| #  | Если…                                                                                                  | То…                                                         | Категория | Источник                       | Компонент |
| -- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- | --------- | ------------------------------ | --------- |
| Q5.1 | На mTLS-хосте клиент не предъявил клиентский сертификат, а `ssl_verify_client` требует его             | `verdict=reject` (отказ на транспорте), тег `api:mtls_fail`. mode-gated | blocking  | nginx `ssl_verify_client`      | mTLS      |
| Q5.2 | Клиентский сертификат предъявлен, но `$ssl_client_verify` ≠ `SUCCESS` (невалиден / не той CA / истёк)  | `verdict=reject`, тег `api:mtls_fail`. mode-gated          | blocking  | `$ssl_client_verify` (Lua)     | mTLS      |

---

## Q6 — Transport-гигиена (компонент: transport-гигиена)

Response-side, дёшево / высокий ROI. Per-host через policy. Это правила на фазе ответа: они не режут запрос, а исправляют/добавляют заголовки и маскируют утечки на ответе.

| #  | Если…                                                                                          | То…                                                                             | Категория | Источник              | Компонент           |
| -- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------- | --------------------- | ------------------- |
| Q6.1 | Хост отдаёт ответ, для него в policy включены security-заголовки                               | Добавить/нормализовать HSTS, X-Content-Type-Options и корректный CORS по policy (не `*` вслепую) | soft      | `policy[host]`        | transport-гигиена   |
| Q6.2 | Ответ содержит banner-заголовки сервера / `server_tokens` раскрывает версию                     | Срезать banner-заголовки, `server_tokens off`                                   | soft      | nginx / `policy[host]` | transport-гигиена   |
| Q6.3 | Origin вернул многословную 5xx-ошибку (стектрейс / внутренние детали)                           | Замаскировать тело/детали ошибки в ответе клиенту                               | soft      | `policy[host]`        | transport-гигиена   |

---

## Q7 — API inventory / governance (компонент: API inventory)

Аналитика поверх `bac_log`: эдж уже логирует весь трафик и знает объявленные пути (серия P). Diff вызываемых vs объявленных эндпоинтов даёт инвентаризацию почти бесплатно. Сюда же — enforcement устаревших версий.

| #  | Если…                                                                                                                 | То…                                                                                | Категория | Источник                          | Компонент     |
| -- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | --------- | --------------------------------- | ------------- |
| Q7.1 | Вызывается путь, которого нет среди объявленных эндпоинтов (undeclared / shadow)                                       | тег `api:shadow_endpoint` (аналитика). Опц. draft-PR кандидата в декларацию        | tag       | `bac_log` diff vs `policy[host]`  | API inventory |
| Q7.2 | Объявленный эндпоинт ни разу не вызывается за окно наблюдения (declared-but-unused / zombie)                           | сигнал для аналитики (кандидат на вывод из контракта)                              | tag       | `bac_log` diff vs `policy[host]`  | API inventory |
| Q7.3 | Запрос пришёл на путь, помеченный в policy как устаревшая версия (deprecated-version pattern)                          | `verdict=reject` (410 Gone). mode-gated                                            | blocking  | `policy[host]` deprecated-version | API inventory |

---

## Сводка: правила, теги и HTTP-статусы

| Правило / тег              | Компонент             | Категория | HTTP-статус при reject |
| -------------------------- | --------------------- | --------- | ---------------------- |
| Q1.1–Q1.3 contract         | per-endpoint contract | blocking  | 403 / 422 (415 для CT) |
| Q2.1–Q2.3 schema           | schema-валидация      | blocking  | 422                    |
| Q3.1 body size             | resource limits       | blocking  | 413                    |
| Q3.2–Q3.3 структура/GraphQL | resource limits       | blocking  | 422                    |
| Q4.1–Q4.4 JWT              | edge JWT              | blocking  | 401 (403 для scope)    |
| Q5.1–Q5.2 mTLS             | mTLS                  | blocking  | отказ на транспорте    |
| Q6.1–Q6.3 transport        | transport-гигиена     | soft      | — (response-side)      |
| Q7.1–Q7.2 inventory        | API inventory         | tag       | —                      |
| Q7.3 deprecated-version    | API inventory         | blocking  | 410                    |

**Теги оси Q** (копятся в поле `tags` лога `bac_log`, формат `api:<short_name>`): `api:contract_violation`, `api:schema_violation`, `api:token_invalid`, `api:mtls_fail`, `api:shadow_endpoint`. Подробнее — [api-contract-entities-reference.md](api-contract-entities-reference.md).
