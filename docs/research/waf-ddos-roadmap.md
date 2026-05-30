# WAF и DDoS — направления развития (research / roadmap)

> **Статус: ПЛАНИРУЕТСЯ / research.** Это снимок брейншторма «куда растить продукт
> после закрытия C-серии (challenge) и D1 (скоринг)» в сторону WAF и анти-DDoS.
> Ничего из описанного ниже **НЕ реализовано** в стенде, пока явно не уехало в
> [PROGRESS.md](../../PROGRESS.md) → «ЕСТЬ СЕЙЧАС». Не выдавать за сделанное.
> WAF-движок намеренно оставлен как **research/ADR-кандидат** (build-vs-buy не
> решён) — см. §3. Волюметрика L3/L4 включена в roadmap по запросу, но честно
> помечена как **выходящая за рамки OpenResty-стенда** (reality-level 3 по
> [CLAUDE.md](../../CLAUDE.md)) — см. §4.3.
>
> **Что с момента первой версии уже уехало в бэклог:** connection/protocol-level
> DDoS (slow-attacks D21–D23, HTTP/2-DoS E3–E4) заведён как тикеты (§4.2). Ось
> **API/account** разложена в §5 (серия `P` — кандидаты, тикетов пока нет).
>
> **Где это на шкале продукта:** WAF/DDoS — это **post-post-MVP** (новые оси рядом
> с детектором), а не продолжение D-серии. Широкая рамка «на что замахиваемся» —
> [../product/product-scope.md](../product/product-scope.md).

## 1. Точка отсчёта — что у нас уже есть (и чего нет)

Каскад `infra/demo-stand/lua/` сегодня — это **bot abuse control (BAC)**, а не WAF
и не anti-DDoS. Стадии (см. [PROGRESS.md](../../PROGRESS.md) «ЕСТЬ СЕЙЧАС»):

| Слой | Что делает | Отношение к WAF/DDoS |
|---|---|---|
| **L1 hygiene** (`hygiene.lua`) | method-whitelist, `ua_blacklist`, header-anomaly | гигиена протокола — соседствует с WAF, но не инспекция контента |
| **L2 reputation** (`reputation.lua`, `verified_bots.lua`, `clearance.lua`) | IP allow/block, geo/ASN, verified-bots, clearance-cookie | репутационный слой — общий фундамент для обоих направлений |
| **L3 tls_fp** (`tls_fp.lua`) | JA4-фингерпринт (blocklist + soft) | анти-бот, ортогонален WAF |
| **L4 rate_limits** (`rate_limit.lua`) | GCRA: `rate_ip`/`rate_ip_ua`/`rate_api`/`rate_tls_fp`/`rate_scan_urls`, окна 10с/60с | **ядро анти-DDoS L7** уже здесь |
| **L5 verification** (`verification.lua`, `challenge*.lua`) | JS-challenge, Strictness, `attack_mode` (C7) | **анти-DDoS L7**: challenge как фильтр под нагрузкой |

Три вывода, задающие вектор:

1. **Анти-DDoS L7 уже частично есть.** L4 rate-limits + `attack_mode` + challenge — это
   рабочая защита от application-layer флуда. Развитие здесь = **углубление
   существующего**, не новая дисциплина.
2. **WAF не реализован нигде.** Нет инспекции тела запроса, query/POST-параметров,
   заголовков на сигнатуры (SQLi/XSS/path-traversal/RCE/SSRF), нет virtual patching.
   В [vision.md](../product/vision.md) DDoS — явная цель (§«отсекать DDoS-ботов»), WAF
   упомянут лишь косвенно (XSS — как причина `HttpOnly` на cookie). Это **зелёное поле**.
3. **Инфраструктура доставки и наблюдения переиспользуема.** Channel C
   (`catalog_pull.lua`, ADR-006 git-каталоги), shadow/active mode (`policy.enforce`),
   staged rollout (staging→active), структурный лог (`bac_log.lua`), метрики,
   kill-switch (A12) — всё это переиспользуется и для WAF-сигнатур, и для DDoS-правил
   без переизобретения.

## 2. Принцип: WAF и DDoS — это две новые **оси**, а не новые стадии «вместо»

Каскад остаётся одной точкой принятия решения (L5 `verification` сводит флаги в вердикт).
WAF и DDoS добавляют **источники флагов**, а не параллельные пайплайны:

- **WAF** → новая стадия инспекции контента, которая копит флаги (`waf:sqli`,
  `waf:xss`, …) и в active-режиме может сама блокировать на критичных правилах —
  по аналогии с тем, как `tls_fp_blocklist` hit делает прямой `policy.enforce(403)`.
- **DDoS L7 (rate-based)** → не новая стадия и **не новая ось**: это адаптивность
  существующих L4/L5 (пороги rate-limit + авто-`attack_mode`), уже заскоупленная в
  D-серии (D12–D17, §4.1).
- **DDoS connection/protocol-level (slow-attacks, HTTP/2-DoS)** → это **реально новый
  скоуп**, и он **не ложится в каскад** вовсе: slowloris/slow-POST/slow-read и Rapid
  Reset живут НИЖЕ `access_by_lua` (соединение/фрейм, до HTTP-семантики). Лечатся
  nginx-директивами и версией билда, а Lua здесь только наблюдает и кормит репутацию.
  Заскоуплено как D21–D23 / E3–E4 (§4.2).

Это сохраняет инвариант rules-reference: «единственная точка решения — L5», флаги не
выдают вердикт сами (кроме явных hard-block exit-точек под `policy.enforce`).

## 3. WAF — контентная инспекция L7 (build-vs-buy НЕ решён → ADR-кандидат)

### 3.1 Что входит в скоуп MVP
Минимальный полезный WAF на эдже:
- инспекция **query-string и POST-тела** (form-urlencoded + JSON; multipart — фаза 2);
- инспекция **заголовков и пути** (path-traversal, нулевые байты, протокольные аномалии);
- набор сигнатур под **OWASP Top-10 ядро**: SQLi, XSS, path-traversal, command-injection,
  очевидный SSRF/LFI;
- **virtual patching** — точечное правило под конкретную CVE/эндпоинт клиента
  (быстрый PR-каталог, как `tls_fp_blocklist`);
- shadow-режим по умолчанию (как весь каскад) + per-host on/off через Policy.

Вне MVP: ML-аномалии тела, полный CRS paranoia-level 3+, анти-evasion нормализация
всех мыслимых кодировок (это длинный хвост, добивается итеративно).

### 3.2 Развилка движка — нужен спайк + ADR (решение отложено)

**Вариант A — интегрировать [Coraza](https://github.com/corazawaf/coraza) + OWASP CRS.**
Coraza — Go-реализация ModSecurity seclang, есть
[coraza-proxy / openresty-связки](https://github.com/corazawaf). OWASP Core Rule Set —
проверенный годами набор.
- **+** Мгновенный охват Top-10, поддерживаемые правила, знакомый seclang операторам.
- **−** Чужая модель правил вне нашего Channel C / shadow-mode / `bac_log`; либо тянем
  как Go-сервис (ещё один `auth_request`-хоп — мы это уже отвергали в ADR-001 в пользу
  edge-Lua), либо ищем Lua-биндинг (зрелость под вопросом). Латентность инспекции тела
  на каждом запросе — нужен замер. CRS славится ложняками — потребует тюнинга, который
  не ляжет в наш staging→active workflow «из коробки».

**Вариант B — свой ruleset в стиле каскада.**
Lua-стадия `waf.lua` со своими сигнатурами; каталоги (`waf_rules.yaml`) через Channel C
ровно как `tls_fp_blocklist`; shadow/active через `policy.enforce`; флаги в `bac_log`;
staged rollout и `git revert` бесплатно (ADR-006).
- **+** Единая архитектура: тот же лог, метрики, kill-switch, mode-gate, PR-воркфлоу,
  CI-валидация правил. Управляемая латентность (инспектируем ровно то, что решили).
- **−** Мы сами отвечаем за полноту и анти-evasion. Медленный набор охвата. Риск
  «изобрести свой CRS хуже CRS».

**Вариант C (компромисс) — свой движок исполнения + импорт подмножества CRS-сигнатур**
как данных в наш каталожный формат. Берём проверенные паттерны, но прогоняем через нашу
машину/воркфлоу.

**Рекомендация: спайк перед коммитом.** Сделать research-спайк (по образцу
`infra/nginx-lua-poc/spikes/` из ADR-002): (1) замерить per-request латентность инспекции
тела при Coraza-интеграции vs нативной Lua-инспекции на репрезентативном теле; (2)
оценить, ложится ли CRS-тюнинг в shadow→staging→active; (3) прикинуть объём своего
сигнатурного ядра для Top-10. По результатам — **ADR-007 «WAF-движок: build vs buy»**.
До ADR в код не коммитимся.

### 3.3 Открытые вопросы для WAF
- Инспекция тела требует его **буферизации** (`lua_need_request_body` / чтение
  `request_body`) — конфликтует с проксированием больших аплоадов; нужен лимит размера
  и bypass для media/upload-эндпоинтов.
- Где нормализация (URL-decode, unicode, comment-strip) — общий пре-процессор перед
  сигнатурами, иначе тривиальный evasion.
- Per-host WAF-профиль (paranoia level / выключенные правила) — расширение `policy`
  (B10 Policy API уже умеет PATCH скаляров и JSONB-массивов).

## 4. DDoS — три слоя с разной зрелостью

> **Поправка после сверки с бэклогом ClickUp (список «Resty BAC»).** DDoS у нас
> распадается на три слоя, не на один:
> - **§4.1 L7 rate-based** — уже заскоуплено в D-серии (D12–D17), не дублируем.
> - **§4.2 connection/protocol-level (slow-attacks, HTTP/2-DoS)** — реально новый
>   скоуп, заведён как D21–D23 / E3–E4; живёт в nginx-директивах + версии билда,
>   НЕ в каскаде.
> - **§4.3 волюметрика L3/L4** — вне OpenResty-стенда (reality-level 3), только
>   контракт edge-ACL feed.

### 4.1 L7 application-layer — уже заскоуплено в D-серии (не дублируем)
Всё, что я изначально набросал как «DDoS-Фаза 1/2», при сверке с бэклогом оказалось
уже оформленными D-тикетами:

| Идея | Где уже живёт (ClickUp / research) |
|---|---|
| Авто-взвод `attack_mode` по «плохому» трафику (не голому объёму), гистерезис, precedence ручного над авто, per-host флаг `auto_attack_mode` | **[D16]** `86ext6yuq` (backlog, дизайн готов) — детект по bot-rate/solve_rate/origin-latency относительно базлайна хоста |
| Subnet/ASN-репутация DC-пулов (soft, аналитика) | **[D14]** `86ext6yn6` (backlog) + [subnet-unit-design.md](subnet-unit-design.md) |
| Transient subnet challenge→drop под атакой | **[D15]** `86ext6ytk` (backlog) |
| Быстрый hot-list атакующих (пред-взвод эджей при пивоте ботнета) | **[D17]** `86ext718e` (backlog) + [cross-tenant-threat-intel-design.md](cross-tenant-threat-intel-design.md) |
| solve-rate как сигнал бота под флудом | **[D12]** `86ext5daf` (to do) + [challenge-solve-rate-design.md](challenge-solve-rate-design.md) |

**Вывод:** механизмы L4 (`rate_limit`) + L5 (`attack_mode`/challenge) уже есть, а их
адаптивное углубление — это D-серия, которую и так делаем. По **rate-based** L7-DDoS
нового скоупа нет — он закрывается завершением D14–D17. Не плодим дубль-тикеты.
Новое по DDoS — **не rate-based**, а connection/protocol-level: §4.2.

### 4.2 Connection/protocol-level — slow-attacks и HTTP/2-DoS (реально новое, НЕ в каскаде)
Это то, что rate-based L7 (§4.1) принципиально не ловит: атаки на уровне соединения и
HTTP/2-фреймов. Все они живут **ниже `access_by_lua`** — каскад их не видит, поэтому
лечение в nginx-директивах + версии билда, а Lua только наблюдает и кормит репутацию
(паттерн: nginx митигирует → Lua логирует → reputation/edge-ACL эскалирует).

| Угроза | Почему мимо §4.1 | Где лечится | Тикеты |
|---|---|---|---|
| **slowloris / slow POST / slow read** | GCRA считает запросы; здесь мало запросов, много idle-соединений; challenge незавершающему запрос клиенту не доходит | `client_*_timeout`, `limit_conn`, `keepalive_*` в nginx + `log_by_lua`-шим → `bac_log` → репутация | **[D21]** baseline, **[D22]** observability, **[D23]** policy-ручка (опц.) |
| **HTTP/2 Rapid Reset (CVE-2023-44487) и родня** | frame-уровень, ниже HTTP-семантики; стрим сброшен до того, как Lua увидит запрос | пропатченный билд (nginx ≥1.25.3) + `http2_max_concurrent_streams` | **[E3]** mitigation-аудит; **[E4]** h2-abuse как сигнал репутации (зависит от E2) |

Принципиально: **ни D21–D23, ни E3–E4 не добавляют стадию в `verdict.lua`** — slow-клиент
и сброшенный стрим туда не доходят. Наш BAC-вклад здесь = observability + подмешивание в
репутацию (D14) и эскалация в edge-ACL feed (§4.3), а не новая точка решения.

> ⚠️ **E3 ≠ E2.** E2 — это HTTP/2 **fingerprint** (детект/идентификация клиента,
> анти-JA4-ротация). E3 — HTTP/2 **DoS-mitigation** (Rapid Reset). Разные слои задачи;
> в тикетах граница проговорена явно.

### 4.3 Волюметрика L3/L4 — сетевой слой (⚠️ ВНЕ OpenResty-стенда)
**Честная граница:** SYN-флуд, UDP/амплификация, пакетный флуд **не лечатся в
OpenResty/Lua** — к моменту, когда трафик дошёл до nginx, TCP-handshake уже состоялся.
Это сетевой уровень: edge-ACL, conntrack/iptables-rate, eBPF/XDP-дроп, BGP-blackhole,
anycast-размазывание. По [CLAUDE.md](../../CLAUDE.md) это **reality-level 3** — зона
prod-edge/инфра-админов CDN operator, прод-доступа к которой у нас нет.

Что **можем** сделать в нашем скоупе, не залезая в чужую инфру:
- **спроектировать контракт** между нашим L7-детектором и сетевым уровнем: когда L7
  видит, что источник безнадёжен (грубый флуд, ноль solve-rate, бюджет эджа исчерпан) —
  эмитить сигнал «дропни на L3/L4» (формат, транспорт), который сетевой слой исполнит.
  Это **edge-ACL feed**, аналог `ip_blocklist`, но для firewall, а не для Lua;
- **исследовательский ADR/дизайн** по eBPF/XDP-дропу как будущей фазе — без реализации
  на проде.
- НЕ выдумывать интеграцию с salt/Puppet-прод prod-edge (CLAUDE.md §«Чего НЕ делать»). Если
  понадобится прод-сетевой слой — это отдельная фаза с прод-доступом, **СПРОСИТЬ**.

## 5. API security / account protection — соседняя ось (в бэклоге 0 задач)

Третья новая ось рядом с WAF (§3) и DDoS (§4). **Ближе к существующему ядру, чем WAF** —
почти весь фундамент (rate/reputation/challenge/fp) уже в коде, поэтому дешевле.

### 5.1 Ключевое ограничение — эдж identity-blind
`verdict.lua` видит IP, fp, UA, Host, path, заголовки, но **НЕ «какой аккаунт» и не
«какой API-ключ»**. `rate_limit.lua` кеит по IP / IP+UA / fp / URI-bucket. Чтобы делать
per-account / per-key контроль, нужна **новая стадия извлечения идентичности** (username
из login-формы, токен из `Authorization`, API-key из заголовка/query) → ключ для
rate-limit/reputation, ровно как `rate_tls_fp` кеит на fp. Без неё ось не строится.

Второй сквозной момент: сильнейший сигнал auth-абьюза — **доля неуспешных логинов**, а её
эдж видит только из ответа origin (`$status` 401/403 в log/header-фазе). Это тот же
паттерн обратной связи, что **D12 (challenge solve-rate)**.

### 5.2 Скоуп — два кластера

**Account protection:**
| Угроза | Что на эдже | Fit |
|---|---|---|
| Credential stuffing | объём + per-username/per-IP rate-limit + challenge + bot-score + failed-ratio feedback | ★★★ |
| Brute force (1 аккаунт) | per-account rate-limit + эскалация challenge | ★★★ |
| Fake registration | rate-limit на /signup + challenge + fp/reputation | ★★★ |
| Account takeover (ATO) | только контекст-сигналы (fp/geo/ASN); решение на **бэкенде** (эдж не знает истории) | ★ частичный |

**API security:**
| Угроза | Что на эдже | Fit |
|---|---|---|
| API scraping / abuse | уже частично `rate_api` (A7) + `rate_scan_urls`; ново — per-API-key квоты | ★★★ |
| API-key brute / leaked-key | rate-limit + reputation per key | ★★★ |
| Enumeration / BOLA-probing | пересекается с `rate_scan_urls` (recon-URI) | ★★ |
| Schema/contract enforcement | частично hygiene, частично **WAF** (§3) — граница в ADR | ★★ |
| Business-logic abuse (купоны, скальпинг) | нужен app-контекст → **бэкенд**, не эдж | ★ вне скоупа |

### 5.3 Что переиспользуем
`rate_limit.lua` (GCRA-движок + keying — добавляем ключи account/api_key/endpoint-class),
`is_api_path()`/glob-matching, `policy` + B10 Policy API (per-host auth-пути и квоты),
`reputation` (per-key/per-account), `challenge`/`attack_mode` (step-up на auth), `bac_log`
+ теги, паттерн D12 (response-phase feedback для failed-login-ratio).

### 5.4 Что реально новое (кандидаты в серию `P`)
1. **Identity-extraction стадия** — username/token/API-key → ключи. ⚠️ **PII/security**:
   хешировать username, **никогда не логировать/хранить пароли**, тело пароля не инспектировать.
2. **Per-credential / per-key GCRA-профили** (`rate_login_per_account`, `rate_api_key`).
3. **Failed-auth feedback loop** — origin 401/403 → счётчик → reputation/challenge (по образцу D12).
4. **Auth-endpoint policy config** — декларация login/register/API-путей + квот per-host.
5. *(опц., возможно бэкенд)* **breached-cred / disposable-email сигнал** — каталог типа
   `ip_blocklist`; эдж пароль не валидирует.

### 5.5 Честные границы
- **ATO** (аномальный успешный вход) — эдж не знает истории аккаунта; решение на бэкенде.
- **Business-logic abuse** — нужен app-контекст, вне эджа.
- **Credential stuffing** на эдже = объём + failed-ratio + bot-score, **НЕ** проверка
  валидности пароля по брешь-листу (эдж пароли не трогает).
- **Schema enforcement** частично перетекает в WAF (§3) — границу зафиксировать в ADR,
  чтобы не дублить с W-серией.

## 6. Предлагаемая очерёдность (по «эффект/стоимость»)

Опорная точка: post-MVP (D-серия) ещё в работе и **сам по себе закрывает L7-DDoS**
(D12–D17). post-post-MVP добавляет **новые оси**, которых в бэклоге нет вообще:

1. **Slow-attacks baseline** (§4.2, [D21]) — самый дешёвый и срочный: стенд сейчас
   уязвим к slowloris из коробки (нет `limit_conn`/таймаутов). Чистый nginx-конфиг.
2. **WAF спайк + ADR-007** (§3.2) — research, не блокирует D-серию, можно начинать рано.
3. **API security / account protection** (§5) — дешевле WAF, т.к. ближе к ядру
   (rate/reputation/challenge/fp). Фундамент — identity-extraction (§5.4).
4. **WAF MVP** (§3.1) — после ADR, по выбранному пути.
5. **HTTP/2 DoS аудит** (§4.2, [E3]) — точечно, зависит от версии билда.
6. **DDoS L3/L4-контракт** (§4.3) — спроектировать edge-ACL feed; реализация сетевого
   дропа — будущая фаза с прод-доступом.
7. **DDoS L7 rate-based** — отдельным пунктом НЕ ведём: это D14–D17 в D-серии.

## 7. Связь с существующим бэклогом и research
- **DDoS L7 rate-based — уже в бэклоге:** [D12] `86ext5daf`, [D14] `86ext6yn6`,
  [D15] `86ext6ytk`, [D16] `86ext6yuq` (авто-attack-mode), [D17] `86ext718e`. Опирается на
  `attack_mode` (C7) + `rate_limit` (A7/A10), которые уже в коде.
- **DDoS connection/protocol-level — заведено (§4.2):** [D21] `86ext8r0p` (slow-attacks
  baseline), [D22] `86ext8r0x` (observability), [D23] `86ext8r15` (policy-ручка, опц.);
  [E3] `86ext8r2q` (HTTP/2 DoS mitigation-аудит), [E4] `86ext8r31` (h2-abuse как сигнал,
  зависит от E2 `86ext6dez`). Переиспользует `bac_log`, метрики, D14-репутацию, edge-ACL.
- **WAF — новой оси в бэклоге НЕТ** (сверено: 0 задач по WAF/SQLi/XSS). Предложить серию
  `W`: W1 спайк/ADR-007, W2 движок, W3 сигнатурный каталог через Channel C, W4 per-host
  WAF-профиль в policy, W5 virtual patching. Переиспользует ADR-006 (git-каталоги), B10
  (Policy API), `policy.enforce` (mode-gate), `bac_log`/метрики.
- **API security / account protection — в бэклоге НЕТ** (сверено: 0 задач). Кандидаты на
  новую серию `P` (§5.4): P1 identity-extraction, P2 per-key/per-account профили, P3
  failed-auth feedback, P4 auth-endpoint policy-config, P5 (опц.) breached-cred сигнал.
  Ближе к существующему ядру, чем WAF.
- **Волюметрика L3/L4** — вне репо-скоупа стенда; присутствует как контракт + research,
  не как реализация (reality-level 3).

## 8. Что НЕ делаем на этом шаге
- Не коммитим WAF-код до ADR-007 (build-vs-buy решается спайком).
- Не плодим **rate-based** DDoS-L7-тикеты — это D-серия (D12–D17), уже в бэклоге.
- Не добавляем slow-attacks / HTTP/2-DoS как стадию каскада — они ниже `access_by_lua`
  (nginx-директивы + билд + log-шим; D21–D23 / E3–E4).
- Не лезем в прод-сеть prod-edge (salt/Puppet/eBPF на боевых эджах) — нет доступа, не наша фаза.
