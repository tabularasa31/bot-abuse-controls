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
- **DDoS L7** → не новая стадия, а **адаптивность** существующих L4/L5: пороги
  rate-limit и решение «challenge vs block» становятся функцией текущей нагрузки,
  а `attack_mode` взводится автоматически, а не только руками через Policy API.

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

## 4. DDoS — поэтапно, от L7 (наша зона) к L3/L4 (за рамками стенда)

### 4.1 Фаза 1 — углубить L7 application-layer (наша прямая зона, дёшево)
Надстройки над уже существующими L4/L5:
- **Адаптивные пороги rate-limit.** Сейчас пороги статичны (`defaults.conf
  [blocking.rate_*]`). Ввести зависимость от текущей нагрузки на host/эдж: при росте
  RPS/латентности origin — автоматически ужесточать `rate_*` и понижать порог challenge.
- **Авто-`attack_mode`.** `attack_mode` (C7) сейчас взводится только руками через Policy
  API. Добавить **детектор атаки** (всплеск RPS / доля грей-вердиктов / рост 5xx от
  origin) → авто-взвод `attack_mode` для host с гистерезисом и авто-сбросом. Перекликается
  с research §6 кросс-тенант threat-intel ([cross-tenant-threat-intel-design.md](cross-tenant-threat-intel-design.md)).
- **Бюджет CPU/полосы эджа** как сигнал — частично уже продуман в
  [subnet-unit-design.md](subnet-unit-design.md) (критерий (а) volumetric). Когда challenge-rate
  упирается в бюджет эджа — эскалация на более дешёвый дроп.

### 4.2 Фаза 2 — агрегаты выше отдельного IP/fp (пересекается с D14/D15/#3)
L7-флуд с ротацией IP/fp бьётся только на агрегатах:
- **subnet/ASN-уровень rate-limit и репутация** — единица «/24 датацентра» вместо
  отдельного IP (см. [subnet-unit-design.md](subnet-unit-design.md), тикеты D14/D15/D16).
  `reputation.lua` уже знает ASN/geo — рейт-лимит этим пока не пользуется.
- **быстрый hot-list атакующих** (short-TTL, авто-публикация во время атаки, пред-взвод
  всех эджей) — см. [cross-tenant-threat-intel-design.md](cross-tenant-threat-intel-design.md).
- challenge-solve-rate как сигнал бота под флудом
  ([challenge-solve-rate-design.md](challenge-solve-rate-design.md), D12).

### 4.3 Фаза 3 — волюметрика L3/L4 (⚠️ ВНЕ OpenResty-стенда)
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

## 5. Предлагаемая очерёдность (по «эффект/стоимость»)

1. **DDoS Фаза 1** (§4.1) — авто-`attack_mode` + адаптивные пороги. **Дёшево, данные и
   механизмы (`attack_mode`, rate_limit, метрики) уже есть.** Наибольший эффект на вложенное.
2. **WAF спайк + ADR-007** (§3.2) — параллельно, это research, не блокирует №1.
3. **WAF MVP** (§3.1) — после ADR, по выбранному в нём пути.
4. **DDoS Фаза 2** (§4.2) — subnet-агрегаты; синхронизировать с D14/D15 и threat-intel.
5. **DDoS Фаза 3 контракт** (§4.3) — спроектировать edge-ACL feed; реализация сетевого
   дропа — будущая фаза с прод-доступом.

## 6. Связь с существующим бэклогом и research
- **DDoS Фаза 1/2** прямо опирается на: `attack_mode` (C7, есть), `rate_limit` (A7/A10, есть),
  [subnet-unit-design.md](subnet-unit-design.md) (D14/D15/D16),
  [cross-tenant-threat-intel-design.md](cross-tenant-threat-intel-design.md) (D17),
  [challenge-solve-rate-design.md](challenge-solve-rate-design.md) (D12).
- **WAF** — новая ветка (предложить серию `W` в бэклоге: W1 спайк/ADR, W2 движок,
  W3 сигнатурный каталог через Channel C, W4 per-host WAF-профиль в policy,
  W5 virtual patching workflow). Переиспользует ADR-006 (git-каталоги), B10 (Policy API),
  `policy.enforce` (mode-gate), `bac_log`/метрики.
- **Волюметрика L3/L4** — вне репо-скоупа стенда; в roadmap присутствует как контракт +
  research, не как реализация (reality-level 3).

## 7. Что НЕ делаем на этом шаге
- Не коммитим WAF-код до ADR-007 (build-vs-buy решается спайком).
- Не выдаём DDoS Фазу 1/2 за сделанное — пока это research-документ.
- Не лезем в прод-сеть prod-edge (salt/Puppet/eBPF на боевых эджах) — нет доступа, не наша фаза.
