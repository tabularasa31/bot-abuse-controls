# WAF — шаблоны конфигов (серия W)

Иллюстративные шаблоны форматов WAF-оси: сигнатурный каталог `waf_rules`,
per-host WAF-профиль в policy, соглашения по staged rollout и шаблон
virtual-patch правила. Источник правды по поведению — [waf-spec.md](waf-spec.md).
Перечень правил — [waf-rules-reference.md](waf-rules-reference.md), словарь
сущностей — [waf-entities-reference.md](waf-entities-reference.md).

**Статус:** проектный контракт (целевое поведение); движок (build-vs-buy) не
выбран — открыт в ADR-007. **Точный синтаксис сигнатур фиксируется вместе с
движком** (своя Lua / Coraza+CRS seclang / гибрид). Шаблоны ниже сознательно
описывают структуру и семантику на уровне контракта — поля записи, статусы,
скоуп инспекции, mode-gate — так, чтобы они держались независимо от выбора
движка. Внутренности сигнатур (regex/seclang) показаны как абстрактные
placeholder'ы.

**Формат:** показан как YAML с комментариями для удобства чтения. Главное —
структура данных и семантика полей, не конкретный синтаксис.

> **Прецедент.** `waf_rules` доставляется через Channel C ровно как
> `tls_fp_blocklist`: git — единственный источник истины (ADR-006), PR-only +
> CODEOWNERS, staged rollout (`staging`/`active`), `git revert`, CI-валидация
> (синтаксис/компиляция) перед мержем. Контракт каталога-блоклиста тот же,
> отличается лишь содержимое записи (сигнатура вместо fp-строки).

## Иерархия конфигов WAF

```
waf_rules/                  ← сигнатурный каталог (PR-наполняемый, через Channel C, с staging)
  sqli.yaml                 ← сигнатуры SQL-инъекций
  xss.yaml                  ← сигнатуры XSS
  path_traversal.yaml       ← сигнатуры path-traversal
  command_injection.yaml    ← сигнатуры command-injection
  ssrf_lfi.yaml             ← сигнатуры SSRF/LFI
  virtual_patch.yaml        ← точечные правила-щиты под CVE/эндпоинты клиентов
policy/<host>.yaml          ← per-host WAF-профиль (часть policy, через B10 Policy API)
```

Разбивка по файлам — иллюстративная; фактическая раскладка (один файл или
несколько) уточняется при реализации. Контракт — формат записи, не файла.

---

## 1. `waf_rules` — сигнатурный каталог

Каждая запись — одна сигнатура под класс атаки. Поля записи контрактны
(`id`, `class`, `category`, `targets`, `status`); тело сигнатуры (`signature`)
— абстрактный placeholder, его синтаксис задаёт ADR-007.

```yaml
# waf_rules — сигнатурный каталог (через Channel C, PR-only, с staged rollout)
# Тело сигнатуры (signature) — placeholder; реальный синтаксис фиксирует ADR-007.

rules:
  - id: sqli_union_select_001          # стабильный id, пишется в rule / staging_match
    class: sqli                        # sqli | xss | path_traversal | command_injection | ssrf_lfi | virtual_patch
    category: blocking_critical        # blocking_critical | soft_flag
    flag: "waf:sqli"                   # какой challenge-flag ставит soft-правило (для soft_flag)
    targets: [query, body]             # цели инспекции: query | body | headers | path
    paranoia: low                      # с какого уровня waf_paranoia правило включается
    status: active                     # staging | active (см. staged rollout ниже)
    signature: <ABSTRACT>              # тело сигнатуры — синтаксис по ADR-007
    reason: "UNION SELECT exfil pattern"

  - id: sqli_boolean_blind_014
    class: sqli
    category: soft_flag                # шумная эвристика → флаг, решение на L5
    flag: "waf:sqli"
    targets: [query, body]
    paranoia: medium
    status: staging                    # новая сигнатура — сначала наблюдение
    signature: <ABSTRACT>
    reason: "boolean-based blind heuristic"

  - id: xss_script_tag_002
    class: xss
    category: blocking_critical
    flag: "waf:xss"
    targets: [query, body, headers]
    paranoia: low
    status: active
    signature: <ABSTRACT>
    reason: "inline <script> injection"

  - id: path_traversal_dotdot_003
    class: path_traversal
    category: blocking_critical
    flag: "waf:path_traversal"
    targets: [path, query, body]
    paranoia: low
    status: active
    signature: <ABSTRACT>              # обход директорий / нулевые байты / протокольные аномалии пути
    reason: "../ directory traversal + NUL byte"
```

**Семантика полей записи:**

- `id` — стабильный идентификатор сигнатуры. Пишется в `rule` лога (при
  критичном матче) и в `staging_match` (формат `waf_rules:<id>`). Используется
  в `waf_disabled_rules` для точечного подавления.
- `class` — класс атаки (OWASP Top-10 ядро + `virtual_patch`). Определяет, какой
  флаг класса ставится.
- `category` — `blocking_critical` (прямой hard-block через `policy.enforce`) или
  `soft_flag` (накапливает challenge-flag, решение на L5). Один класс атаки
  покрывается набором правил разной критичности; разбиение — часть содержимого
  каталога, калибруется через staged rollout.
- `targets` — что инспектируется: `query`, `body`, `headers`, `path`. Инспекция
  тела требует буферизации (`lua_need_request_body` / `request_body`) — действует
  лимит размера тела и bypass для media/upload (см. открытые вопросы в спеке).
- `paranoia` — с какого уровня `waf_paranoia` per-host профиля правило включается
  (`low`/`medium`/`high`). Соответствие уровней правилам — содержимое каталога.
- `status` — `staging` или `active` (staged rollout).
- `signature` — тело сигнатуры. Применяется ПОСЛЕ общей нормализации
  (URL-decode, unicode, comment-strip) — иначе тривиален evasion. Синтаксис —
  ADR-007.

---

## 2. Per-host WAF-профиль (внутри `policy/<host>.yaml`)

Расширение policy домена. Редактируется через B10 Policy API (PATCH), приходит
на proxy через Channel C как часть каталога `policy`. Независим от
`mode`/`strictness`: `mode` управляет shadow/active исполнением (mode-gate
`policy.enforce`), WAF-профиль — охватом инспекции.

```yaml
example.com:
  # ... остальная policy домена (mode, strictness, rate_rules и т.д.) ...

  # --- per-host WAF-профиль ---
  waf_enabled: true                    # boolean, дефолт false — стадия waf пропускается целиком
  waf_paranoia: low                    # low | medium | high (дефолт low)
  waf_disabled_rules:                  # id правил из waf_rules, выключенных для ЭТОГО домена
    - sqli_boolean_blind_014           # точечное подавление ложняка конкретного клиента
    - xss_attribute_ctx_021
```

**Семантика:**

- `waf_enabled=false` (дефолт) — стадия `waf` для домена пропускается целиком,
  инспекция не выполняется.
- `waf_paranoia` — сколько/насколько агрессивно правил включено. `low` —
  стартовый уровень нового домена (только ядро однозначных сигнатур, минимум
  ложняков); `high` — максимально агрессивный набор, требует тюнинга
  `waf_disabled_rules`. CRS paranoia 3+ — вне MVP.
- `waf_disabled_rules` — точечное подавление сигнатур по `id` для конкретного
  домена, не трогая глобальный каталог. Для ложняков, специфичных одному клиенту.

**Взаимодействие с mode-gate.** При `mode=shadow` матч любого WAF-правила
пишется в `bac_log` (и инкрементит `antibot_rule_total{stage="waf"}`), но
физически не исполняется. При `mode=active` критичные правила реально блокируют
через `policy.enforce(403)`; soft-флаги уходят на консолидацию L5.

---

## 3. Соглашения по staged rollout (как у `tls_fp_blocklist`)

Те же правила, что и для прочих PR-каталогов каскада (ADR-006), применяются к
`waf_rules`:

1. **Новые сигнатуры всегда добавляются с `status: staging`.** В этом статусе
   правило матчится и факт пишется в `staging_match` лога (формат
   `waf_rules:<rule_id>`), но не приводит к hard-block даже в `mode=active`.
2. Период наблюдения — минимум 24 часа после доставки на proxy (репрезентативная
   выборка по логам).
3. После наблюдения, при отсутствии false-positive, — отдельный PR с переводом
   `status: staging` → `status: active`.
4. Если в `staging`-периоде сигнатура дала false-positive — **revert исходного
   PR** (не оставляем в staging, чтобы не копить «забытые» записи).

Промоут сигнатуры — отдельный осознанный этап, не автоматический. CI-валидация
(синтаксис/компиляция правила) — обязательный гейт перед мержем любого PR в
`waf_rules`.

---

## 4. Шаблон virtual-patch правила

Точечный щит под конкретную CVE/уязвимый эндпоинт клиента — технически обычная
запись в `waf_rules` класса `virtual_patch`, но с быстрым PR-воркфлоу (по
образцу HIGH-кандидата blocklist → PR в `tls_fp_blocklist`). Закрывает дыру на
эдже за минуты, пока origin патчат.

```yaml
rules:
  - id: vpatch_cve_2026_XXXX_login     # привязка к CVE/инциденту в id
    class: virtual_patch
    category: blocking_critical        # острый CVE-щит — обычно сразу hard-block
    flag: "waf:virtual_patch"
    targets: [path, query, body, headers]
    paranoia: low                      # щит работает на всех уровнях
    status: staging                    # короткое наблюдение, затем быстрый промоут в active
    scope_host: example.com            # опционально: щит только под конкретный домен/эндпоинт
    scope_path: /vulnerable-endpoint   # опционально: сузить до уязвимого пути
    signature: <ABSTRACT>              # сигнатура эксплойта конкретной CVE
    reason: "virtual patch for CVE-2026-XXXX until origin is patched"
```

**Runbook быстрого выката:**

1. PR с virtual-patch записью (`status: staging`) → доставка через Channel C.
2. Короткое наблюдение по `staging_match` (что не задевает легит-трафик).
3. PR-промоут в `status: active` — щит начинает блокировать на эдже.
4. После патча origin — быстрый `git revert` записи.

Критичность (`soft_flag` vs `blocking_critical`) задаётся прямо в правиле; для
острого CVE-щита обычно `blocking_critical` сразу после короткого staging.

---

## 5. Чего в формате НЕТ (границы)

- **Синтаксис тела сигнатуры** — не зафиксирован до ADR-007 (`signature:
  <ABSTRACT>`). Зависит от выбора движка (своя Lua / seclang CRS / гибрид).
- **Позитивная модель (контракт API)** — отдельная ось и отдельный формат; WAF
  (негативная модель) её не заменяет, см. [waf-spec.md](waf-spec.md) §1 и
  спеку контракта API.
- **Multipart-инспекция тела, ML-аномалии, полная анти-evasion всех кодировок**
  — вне MVP; в формат записи не закладываются сверх `targets`/нормализации.
