# API и Account Protection — справочник правил

Правила слоя в формате «если условие → вердикт/действие», по обеим осям. Контракт
поведения — [api-spec.md](api-spec.md); словарь сущностей —
[api-entities-reference.md](api-entities-reference.md); структура конфигов —
[api-config-templates.md](api-config-templates.md).

Категории: `blocking` (выносит reject с HTTP-статусом), `soft` (накапливает
сигнал/влияет косвенно), `tag` (информационная пометка, вердикт не эмитит), `—`
(фундамент: ставит ключ/контекст, вердикт не эмитит). Большинство blocking-правил
mode-gated: при shadow срабатывание считается и логируется, но запрос не режется; при
active исполняется.

> PII-инвариант (сквозной для всех правил оси A). Username и токен/ключ используются
> как ключ и пишутся в лог только в хешированном виде (HMAC), никогда сырьем. Пароль
> не логируется, не хранится, не инспектируется. Чтение тела — только для классов login/register и эндпоинтов со схемой,
> с лимитом размера и bypass для upload.

---

## Ось A — abuse аккаунтов и API

### ID — извлечение идентичности (фундамент, только на объявленных путях)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| ID-1 | на auth/API-пути из заголовка авторизации / `X-API-Key` / query извлечен ключ или bearer-токен | в контекст кладется hashed-ключ; вердикт не эмитится | — |
| ID-2 | на login/register-пути из тела (form-urlencoded/JSON) извлечен username | в контекст кладется hashed-username; вердикт не эмитится | — |
| ID-3 | идентичность извлечь не удалось (нет поля / тело не читается / путь не объявлен) | graceful skip — зависящие профили пропускаются, запрос продолжает каскад | — |

### RK — per-credential / per-key rate-профили (стадия rate_limits)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| RK-1 | по hashed-username превышены окна профиля логина (стаффинг по многим аккаунтам / brute force одного) | challenge или 429 по mode/строгости; тег `account:cred_stuffing` | blocking / soft |
| RK-2 | по hashed-ключу превышены окна профиля ключа (abuse ключа с многих IP / scraping / enumeration / утечка) | 429 или challenge по mode/строгости; тег `api:key_abuse` | blocking / soft |
| RK-3 | идентичность из ID отсутствует | per-key профили пропускаются; сетевые профили каскада продолжают работать | — |

### FA — failed-auth feedback (log/response-фаза)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| FA-1 | ответ origin на login-пути имеет статус 401/403 | классифицируется как неуспех; инкремент счетчика по hashed-аккаунту и по /24. Вердикт текущего запроса не меняется | — |
| FA-2 | доля неуспешных логинов по hashed-аккаунту или /24 превышает порог | +score в репутацию + эскалация challenge/строгости на последующих запросах; тег `account:auth_fail_spike` | soft |

### DE — disposable-email / breached-cred (опционально)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| DE-1 | домен email из формы регистрации/логина есть в каталоге disposable-email доменов | soft-сигнал фейк-регистрации: +score/флаг в репутацию; сам блок не выносит | soft |

---

## Ось B — контракт и governance

### CT — per-endpoint contract (позитивная модель)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| CT-1 | путь совпал с объявленным эндпоинтом, метод не входит в разрешенные для него | reject (403), тег `api:contract_violation`. mode-gated | blocking |
| CT-2 | путь совпал, content-type тела не входит в разрешенные | reject (415/422), тег `api:contract_violation`. mode-gated | blocking |
| CT-3 | путь совпал, заданы обязательные параметры, запрос их не содержит | reject (422), тег `api:contract_violation`. mode-gated | blocking |
| CT-4 | путь не совпал ни с одним объявленным эндпоинтом | skip (контракт не применяется); detection shadow-путей — в IV | — |

### SC — schema-валидация

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| SC-1 | тело непарсимо как JSON на эндпоинте с объявленной схемой | reject (422), тег `api:schema_violation`. mode-gated | blocking |
| SC-2 | тело распарсилось, но не проходит схему (нет required-поля / неверный тип) | reject (422), тег `api:schema_violation`. mode-gated | blocking |
| SC-3 | тело содержит поля вне схемы при `additionalProperties=false` (mass-assignment-вектор на входе) | reject (422), тег `api:schema_violation`. mode-gated | blocking |
| SC-4 | эндпоинт в bypass-списке (upload / бинарный) | skip schema-валидации | — |

### RL — resource limits

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| RL-1 | размер тела превышает per-host/per-endpoint лимит | reject (413). mode-gated | blocking |
| RL-2 | структурная сложность JSON превышает порог (глубина / длина массивов) | reject (422). mode-gated | blocking |
| RL-3 | (опц.) GraphQL-запрос превышает порог по глубине / стоимости / алиасам | reject (422). mode-gated | blocking |

### JW — edge JWT/token-валидация (API-пути)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| JW-1 | подпись токена не сходится с JWKS/секретом | reject (401), тег `api:token_invalid`. mode-gated | blocking |
| JW-2 | токен протух или еще не активен (`exp`/`nbf`) | reject (401), тег `api:token_invalid`. mode-gated | blocking |
| JW-3 | `iss`/`aud` не совпадают с ожидаемыми для хоста/эндпоинта | reject (401), тег `api:token_invalid`. mode-gated | blocking |
| JW-4 | (опц.) для эндпоинта задан required-scope, в валидном токене его нет (coarse authz) | reject (401/403). mode-gated | blocking |

### MT — mTLS / client-cert (опционально, per-tenant)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| MT-1 | на mTLS-хосте клиент не предъявил сертификат, а проверка его требует | reject на транспорте, тег `api:mtls_fail`. mode-gated | blocking |
| MT-2 | сертификат предъявлен, но невалиден (не та CA / истек / не верифицирован) | reject, тег `api:mtls_fail`. mode-gated | blocking |

### TH — transport-гигиена (response-side)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| TH-1 | для хоста в политике включены security-заголовки | добавить/нормализовать HSTS, X-Content-Type-Options, корректный CORS (не `*` вслепую) | soft |
| TH-2 | ответ раскрывает banner-заголовки / версию сервера | срезать banner-заголовки, отключить раскрытие версии | soft |
| TH-3 | origin вернул многословную 5xx (стектрейс / внутренние детали) | замаскировать детали ошибки в ответе клиенту | soft |

### IV — API inventory / governance (аналитика поверх лога)

| # | Если | → действие | Категория |
| --- | --- | --- | --- |
| IV-1 | вызван путь, которого нет среди объявленных (undeclared / shadow) | тег `api:shadow_endpoint`; опц. draft-PR кандидата в декларацию | tag |
| IV-2 | объявленный эндпоинт не вызывается за окно наблюдения (zombie) | сигнал для аналитики (кандидат на вывод из контракта) | tag |
| IV-3 | запрос на путь, помеченный как устаревшая версия | reject (410 Gone). mode-gated | blocking |

---

## Сводка: теги и HTTP-статусы

| Группа | Категория | HTTP при reject |
| --- | --- | --- |
| ID | — (фундамент) | — |
| RK | blocking / soft | 429 (или challenge) |
| FA | soft | — (log-фаза) |
| DE | soft | — |
| CT | blocking | 403 / 415 / 422 |
| SC | blocking | 422 |
| RL | blocking | 413 / 422 |
| JW | blocking | 401 (403 для scope) |
| MT | blocking | отказ на транспорте |
| TH | soft | — (response-side) |
| IV | tag / blocking | — / 410 (deprecated) |

Теги слоя (копятся в поле `tags` лога, формат `account:*` / `api:*`):
`account:cred_stuffing`, `account:auth_fail_spike`, `api:key_abuse`,
`api:contract_violation`, `api:schema_violation`, `api:token_invalid`,
`api:mtls_fail`, `api:shadow_endpoint`.

## Граница (что НЕ делают эти правила)

Авторизация объектов/функций (BOLA / полный BFLA), бизнес-логика, mass-assignment в
семантике, контроль PII-в-ответах, ATO, проверка пароля по брешь-листу, ревокация
токенов — это backend. Эдж дает сигнал, не решение. Словарь сущностей и границ —
[api-entities-reference.md](api-entities-reference.md).
