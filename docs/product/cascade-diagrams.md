# Каскад Bot & Abuse Controls — схемы

Четыре комплементарные диаграммы, описывающие работу каскада. Каждая фокусируется на своем аспекте — все вместе дают полную картину. Источник правды по семантике — [vision.md](vision.md), эти схемы — визуальный комментарий к нему.

Диаграммы в формате Mermaid. Рендерятся в GitHub, GitLab, IDE с расширениями. Для Google Docs / PDF — экспортировать в PNG через mermaid.live или CLI.

---

## 1. Главный flow — путь запроса от приема до ответа

Высокоуровневый обзор. Показывает все слои каскада, терминальные состояния (block / allow / challenge), и куда уходит пропущенный трафик.

```mermaid
flowchart TD
    Start([HTTP-запрос на защищенный домен])
    TLS[TLS handshake<br/>nginx получает handshake-данные]
    L1{L1 Hygiene<br/>method whitelist, ua_blacklist}
    L2{L2 Reputation<br/>cookie / bot_verified / ip /<br/>asn / geo + теги}
    L3{L3 TLS-fingerprint<br/>fp_blocklist, impersonator,<br/>suspicious_ciphers + теги}
    L4{L4 Rate-limits<br/>системные + клиентские правила}
    L5{L5 Active verification<br/>консолидирует challenge-flags}
    Cache[Отдача контента:<br/>из кэша, если есть<br/>иначе с origin клиента]
    Response[Доставка ответа клиенту]
    Log[Log JSON → backend async]

    Block([verdict=block → 403/429])
    Allow([verdict=allow → fastpath, skip L3-L5])
    Challenge([JS challenge page])
    ChOutcome{Клиент<br/>прошел JS-задачу?}
    GetCookie[Получает clearance cookie<br/>браузер делает retry с cookie]
    Stuck[Застрял на странице:<br/>бот / не выполняет JS]

    Start --> TLS
    TLS --> L1
    L1 -->|method не в whitelist /<br/>UA в blacklist| Block
    L1 -->|чисто| L2
    L2 -->|cookie_valid / bot_verified /<br/>bot_verified_pending /<br/>ip_whitelist| Allow
    L2 -->|ip_blocklist / asn_customer /<br/>geo_blocklist| Block
    L2 -->|идем дальше<br/>+ теги в лог| L3
    L3 -->|fp в tls_fp_blocklist| Block
    L3 -->|impersonator / suspicious_ciphers<br/>+ challenge-flag| L4
    L3 -->|идем дальше<br/>+ tls_fp:* теги в лог| L4
    L4 -->|rate-limit exceeded,<br/>action=block| Block
    L4 -->|rate-rule с action=challenge<br/>+ challenge-flag| L5
    L4 -->|чисто| L5
    L5 -->|есть challenge-flags<br/>+ Standard, browser| Challenge
    L5 -->|Permissive / нет флагов| Cache
    L5 -->|non-browser + есть флаги| Block

    Challenge --> ChOutcome
    ChOutcome -->|да, JS вычислил токен| GetCookie
    ChOutcome -->|нет, JS не выполняется| Stuck
    GetCookie -.->|новый запрос с cookie<br/>→ L2.1 фастпасит| TLS

    Allow --> Cache
    Cache --> Response
    Response --> Log
    Block --> Log
    Challenge --> Log
    %% Stuck отдельно НЕ логируется: исходный запрос уже залогирован как verdict=challenge.
    %% Второго запроса нет, никакого "stuck event" каскад не эмитит.

    classDef terminalBlock fill:#fee,stroke:#c00,color:#900
    classDef terminalAllow fill:#efe,stroke:#0a0,color:#060
    classDef terminalChallenge fill:#ffe,stroke:#cc0,color:#660
    class Block terminalBlock
    class Stuck terminalBlock
    class Allow terminalAllow
    class GetCookie terminalAllow
    class Challenge terminalChallenge
```

---

## 2. L5 decision tree — что именно решает финальный слой

Зум на самый сложный слой. Как L5 принимает решение о challenge vs pass vs block на основе накопленных сигналов.

```mermaid
flowchart TD
    Start([Запрос дошел до L5])
    AM{attack_mode<br/>включен?}
    Flags{Накоплены<br/>challenge-flags?}
    NoFlagsPass[verdict=pass<br/>→ cache/origin]
    Strict{Strictness?}
    Permissive[verdict=permissive<br/>rule=имя последнего soft-флага<br/>физически → cache/origin]
    Browser{Клиент похож<br/>на браузер?<br/>UA + headers}
    BranchA[Ветка A:<br/>выдать JS challenge<br/>verdict=challenge]
    BranchB[Ветка B:<br/>verdict=block<br/>rule=non_browser_blocked]
    Recovery[Клиент видит блок в дашборде<br/>может добавить IP в whitelist]

    ChOutcome{Прошел<br/>JS-задачу?}
    GetCookie[Получает clearance cookie на 24ч<br/>браузер делает retry на оригинальный URL]
    Stuck[Застрял на challenge-page<br/>JS не выполняется, контент недоступен]
    Retry[Новый запрос с cookie:<br/>L2.1 cookie_valid → fastpath<br/>до конца TTL cookie не видит challenge]

    Start --> AM
    AM -->|yes — любой запрос,<br/>дошедший до L5| Browser
    AM -->|no| Flags
    Flags -->|нет flags| NoFlagsPass
    Flags -->|есть flags| Strict
    Strict -->|Permissive| Permissive
    Strict -->|Standard| Browser
    Browser -->|UA Mozilla/Chrome/etc.| BranchA
    Browser -->|UA curl/python/SDK| BranchB
    BranchB --> Recovery

    BranchA --> ChOutcome
    ChOutcome -->|да| GetCookie
    ChOutcome -->|нет| Stuck
    GetCookie --> Retry

    classDef terminalBlock fill:#fee,stroke:#c00,color:#900
    classDef terminalAllow fill:#efe,stroke:#0a0,color:#060
    classDef terminalChallenge fill:#ffe,stroke:#cc0,color:#660
    class BranchB terminalBlock
    class Stuck terminalBlock
    class NoFlagsPass terminalAllow
    class Permissive terminalAllow
    class Retry terminalAllow
    class BranchA terminalChallenge
    class GetCookie terminalChallenge
```

---

## 3. Матрица «Что физически происходит» — mode × Strictness × verdict

Один и тот же verdict из каскада ведет к разным реальным действиям в зависимости от настроек ресурса.

| Verdict из каскада | `mode=shadow` *(бесплатный)* | `mode=active` + `Strictness=Permissive` | `mode=active` + `Strictness=Standard` |
|---|---|---|---|
| **`block`** (blocking-правило сработало) | Только лог | **403** (или 429 для rate-rule с Retry-After) | **403/429** |
| **`allow`** (allow-правило сработало) | Лог, каскад идет дальше | **Fastpath** — skip L3-L5 | **Fastpath** |
| **challenge-flag** (soft, накоплен) | Только лог (verdict=challenge при Standard / verdict=permissive при Permissive — dry-run) | `verdict=permissive`, → cache/origin | **JS challenge** (если браузер) / **403 `non_browser_blocked`** (если не браузер) |
| **`pass`** (ни одного срабатывания) | → cache/origin | → cache/origin | → cache/origin |

**Отдельно — `attack_mode` (тоггл поверх mode=active):**
- При `attack_mode=on` все запросы, дошедшие до L5 (т.е. не отбитые ранее и не пропущенные L2-allow), идут на challenge независимо от Strictness и флагов
- Verified search bots и держатели clearance cookie уходят в `allow` еще на L2 → до L5 не доходят → SEO под атакой не страдает

---

## 4. Data flow в лог — что и где накапливается

Каждый шаг каскада добавляет свои поля в одну итоговую JSON-запись лога. Финально она уезжает в backend асинхронно.

```mermaid
flowchart LR
    L0[TLS handshake] -->|ssl_protocol, ciphers,<br/>curves, alpn, sni| Rec
    L1[L1 Hygiene] -->|rule если matched<br/>request_id, host, ip, ua,<br/>method, path| Rec
    L2[L2 Reputation] -->|rule если matched<br/>asn, geo_country<br/>+ теги reputation:*| Rec
    L3[L3 TLS-fp] -->|tls_fp, tls_cipher_count,<br/>tls_alpn, tls_sni_present<br/>+ теги tls_fp:*<br/>+ challenge-flags| Rec
    L4[L4 Rate-limits] -->|rule если matched<br/>+ challenge-flags| Rec
    L5[L5 Verify] -->|финальный verdict,<br/>финальный rule| Rec
    Cache[Отдача контента<br/>из кэша или с origin] -->|status, latency_ms| Rec

    Rec[Лог-запись запроса JSON<br/>request_id, edge_id, timestamp,<br/>host, path, method, status,<br/>ip, asn, geo_country, ua,<br/>tls_*, stage, verdict, rule,<br/>action, mode, tags, staging_match]

    Rec -->|async| Backend[Antibot-backend<br/>приемник логов]
    Backend -->|batch| Telemetry[Приемник телеметрии<br/>ClickHouse]
```

**Важные свойства:**
- Каждый запрос — ровно одна итоговая запись лога (не несколько)
- `verdict` и `rule` отражают последнее сработавшее правило, не все
- `tags` накапливаются — попадают все, что сработали по пути
- `challenge-flags` не уезжают в лог отдельным полем — они влияют на финальный `verdict` через L5
- Доставка лог-записи не блокирует hot-path запроса

---

## Что эти диаграммы НЕ показывают

Для полной картины смотри [vision.md](vision.md). Не вошло в диаграммы:

- **Фоновые процессы:** обновление каталогов от backend на edge, rDNS-воркер для bot_verified_ips, доставка логов с edge до приемника телеметрии, kill-switch механизм. Это все происходит параллельно основному flow и не показано на per-request диаграммах.
- **Staged rollout для PR-каталогов:** новые паттерны добавляются в `staging`-статус, матчатся и логируются (поле `staging_match`), но не влияют на verdict. После калибровки промоутятся в `active`.
- **Recovery loop для Branch B:** заблокированные non-browser запросы попадают в дашборд клиента, клиент может одним кликом добавить IP в whitelist.
- **Per-request input → output** для конкретных кейсов (Googlebot, curl, импersonator, реальный пользователь) — это уже сценарии тестирования, не схемы.
