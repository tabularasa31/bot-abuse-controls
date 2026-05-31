# API Contract & Governance — спецификация (серия Q)

**Версия:** v0.1 · **Статус:** проектный контракт (целевое поведение) · **Дата:** 2026-05-31

Документ описывает **целевое поведение** оси контрактной защиты API — в том же смысле,
в каком [vision.md](vision.md) описывает каскад. Что уже в стенде, а что нет — сверяй с
[PROGRESS.md](../../PROGRESS.md) и кодом.

**Сопутствующие материалы (как у vision):**
[api-contract-rules-reference.md](api-contract-rules-reference.md) — правила в формате
«если условие → вердикт»; [api-contract-entities-reference.md](api-contract-entities-reference.md)
— словарь (стадии, каталоги, теги, поля лога, перечисления);
[api-contract-config-templates.md](api-contract-config-templates.md) — структура policy-полей,
формат каталога схем и waf-родственных конфигов.

---

## 1. Что это

Вторая волна защиты API: то, что edge-доступно, но не вошло в abuse-control-срез серии P.
Покрывает **позитивную модель** (белый список разрешённого), валидацию контракта,
ресурсные лимиты, edge-аутентификацию токенов, транспортную гигиену и инвентаризацию API.

**Позитивная модель Q ↔ негативная модель WAF (W).** Q описывает, что РАЗРЕШЕНО (схема,
методы, типы) и режет всё остальное; WAF ([waf-spec.md](waf-spec.md)) ищет сигнатуры
конкретных атак. Они комплементарны; границу фиксируем в ADR-007 (W1).

## 2. Зачем

Серия P закрывает auth-абьюз и квоты, но «защита API» шире. Сегодня на эдже нет: валидации
контракта/схемы, лимитов размера/сложности тела, edge-валидации JWT, security-заголовков,
инвентаризации эндпоинтов. Всё это — edge-доступные пробелы (см. матрицу покрытия в роадмапе).

## 3. Где в каскаде

```
hygiene → [Q1 contract] → [Q2 schema] → reputation → tls_fp → rate_limits → [Q4 JWT] → verification
   ↑ Q3 resource-limits (часть nginx до Lua, часть Lua после парса)
   ↑ Q5 mTLS — transport, до каскада
   ↓ Q6 transport-гигиена — response/header-фаза
   ↓ Q7 inventory — аналитика поверх bac_log
```

Точное размещение стадий фиксируется при реализации; принцип — контракт/схема рано (дёшево
отсекают мусор до дорогих слоёв), token-валидация перед проксированием на origin.

## 4. Как — по компонентам

### 4.1 Позитивный per-endpoint contract (Q1) — API5/BFLA-срез
Сейчас hygiene даёт только **глобальный** method-whitelist (`hygiene.lua` `method_set`:
GET/HEAD/POST/OPTIONS на весь хост). Q1 вводит позитивную модель **по эндпоинту** (пути из P4):
allowed_methods + allowed_content_types + опц. required_params; всё прочее → reject. На путях
без правил — skip. mode-gated (403/422), shadow по умолчанию, тег `api:contract_violation`.

### 4.2 Schema-валидация (Q2)
Поверх Q1 — валидация тела против JSON-схемы (подмножество OpenAPI): типы, required,
`additionalProperties=false` (отсекает mass-assignment-вектор **на входе**). Схемы — slow-каталог
через Channel C (ADR-006, PR-only). Не тащить полный OpenAPI-движок в hot-path: компилированное
подмножество. Требует чтения тела (`lua_need_request_body` + `cjson`) с лимитом (Q3) и bypass
для upload. Тег `api:schema_violation`.

### 4.3 Resource limits (Q3) — API4
Защита от «тяжёлого» одного запроса, который не ловит rate-лимит по числу:
- размер тела (сейчас `client_max_body_size` только на solver-локации `nginx.demo.conf:459`;
  для API политики нет) — per-host/per-endpoint;
- структурная сложность JSON: max глубина/длина массивов («billion laughs»-защита);
- GraphQL (опц.): глубина/стоимость/алиасы.
Часть — nginx (размер), часть — Lua (структура после безопасного парса). Дополняет `limit_conn`
из D21 (там соединения, тут стоимость одного запроса).

### 4.4 Edge JWT/token-валидация (Q4) — API2
P1 извлекает токен как ключ; Q4 **проверяет его валидность**: подпись (JWKS/секрет), exp/nbf,
iss/aud — на api-путях (P4), через `lua-resty-jwt`. Форжед/протухший токен режется до origin
(разгрузка бэкенда + ранний блок). Ключи/JWKS — доставка как секрет/каталог (паттерн C1).
Опц. required-scope per-endpoint = coarse authz (НЕ полноценный BFLA). Тег `api:token_invalid`.
⚠️ Это аутентификация токена, не авторизация объекта (BOLA — ⛔ бэкенд). Сырой токен не логируем.

### 4.5 mTLS / client-cert (Q5) — опц., per-tenant
Для API с сильной клиентской аутентификацией: nginx `ssl_verify_client` + проверка
`$ssl_client_verify` в Lua на mTLS-хостах. Транспортный уровень, до каскада. ⚠️ Проверить
совместимость с on-demand TLS (`lua-resty-acme`) — см. E2/E3 про TLS-стек. По умолчанию выкл.

### 4.6 Transport-гигиена (Q6) — API8
Response-side, дёшево/высокий ROI: security-заголовки (HSTS, X-Content-Type-Options,
корректный CORS по policy — не `*` вслепую); `server_tokens off` + срезка banner-заголовков;
маскировка многословных 5xx-ошибок origin. Per-host через policy.

### 4.7 API inventory / governance (Q7) — API9
Эдж уже логирует весь трафик (`bac_log`) и знает объявленные пути (P4) → почти бесплатная
инвентаризация: diff вызываемых vs объявленных → undeclared (shadow) / declared-but-unused
(zombie), тег `api:shadow_endpoint`; enforcement устаревших версий (deprecated path → 410,
mode-gated); опц. draft-PR кандидатов в декларацию (паттерн `find_asn_watch_candidates` из D14).

## 5. Что переиспользуем
hygiene method-модель (`method_lookup`), `policy` + B10 Policy API, glob (`is_api_path`),
Channel C/ADR-006 (схемы, staged rollout, B13 CI-контракт), `cjson`, `policy.enforce` (mode-gate),
`bac_log`/метрики, секрет-доставка C1 (JWKS), `bac_log` как источник инвентаря (Q7).

## 6. Честные границы (⛔ бэкенд, не эдж)
- **Авторизация объектов/функций** (BOLA / полный BFLA), **mass-assignment в семантике**,
  **бизнес-логика**, **PII-в-ответах** — требуют identity+ownership+бизнес-правил, которых у
  эджа нет. Эдж даёт сигнал (перебор ID, бот-скор), не решение.
- Q4 — только stateless-проверка токена; ревокация/интроспекция со state — бэкенд.
- Для API нет JS-challenge — enforcement через rate/key-auth/reputation/mTLS.

## 7. Состав и порядок внедрения
| Компонент | Суть | OWASP | Зависит от |
|---|---|---|---|
| Per-endpoint contract | allowlist метода/CT/параметров | API5 | auth-endpoint config (P) |
| Schema-валидация | тело против JSON-схемы | API3-вход | contract + resource-limits |
| Resource limits | размер тела + глубина JSON/GraphQL | API4 | — |
| Edge JWT-валидация | подпись + exp/aud/iss | API2 | identity-extraction (P) |
| mTLS | client-cert (опц.) | API2 | — |
| Transport-гигиена | HSTS/CORS + баннеры + ошибки | API8 | — |
| API inventory | shadow-эндпоинты + deprecated-версии | API9 | auth-endpoint config (P) |

Ранние/дешёвые: resource limits, transport-гигиена (и спайк-уровня mTLS). Разбор правил —
в [api-contract-rules-reference.md](api-contract-rules-reference.md).
