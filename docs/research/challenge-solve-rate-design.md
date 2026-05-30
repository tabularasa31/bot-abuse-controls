# Дизайн #1 — challenge solve-rate как сигнал скоринга

> **Статус: ПЛАНИРУЕТСЯ / design draft.** НЕ реализовано. Развивает идею #1 из
> [bot-detector-roadmap.md](bot-detector-roadmap.md). Базируется на D1
> ([blocklist-scoring.md](../blocklist-scoring.md)) и C5 (challenge verify).

## Идея в одну строку

Fp, которому массово выдавали JS-challenge и который его почти не решает
(`solve_rate ≈ 0` при N выданных), — это near-ground-truth метка бота, сильнее любой
статической эвристики из таблицы score. Сигнал **уже эмитится**, но в скоринг не течёт.

## Главное открытие: данные уже в Loki, per-fp

Оба плеча уже пишутся в `BAC_LOG` с `tls_fp` и доезжают в Loki (тот же канал
`log_shipper`), откуда `analyze.py` уже читает:

| Плечо | Как выглядит событие | Откуда |
|---|---|---|
| **issued** | `verdict=challenge`, есть `tls_fp` | основной поток, verdict.lua Branch A (emit до `ngx.exit(200)`) |
| **solved** | `verdict=allow`, `rule=challenge_pass`, `tls_fp` выставлен | [challenge_verify.lua](../../infra/demo-stand/lua/challenge_verify.lua):382/404/405 |

Значит `solve_rate(fp)` считается **полностью в `analyze.py`**, без новых стадий каскада
и (в минимальном варианте) без правок Lua. Это надстройка над D1, не новая подсистема.

> Замечание про single-use: одно решение challenge → `clearance` cookie, дальше запросы
> фастпасят на L2.1 (`rule=cookie_valid`, тоже `verdict=allow`). Их **нельзя** считать
> новыми «solved» — иначе один solve раздувает числитель. Считаем `solved` строго по
> `rule=challenge_pass`, не по любому `verdict=allow`.

## Что не так с текущим поведением (два дефекта)

`_fp_has_identity_allow` ([analyze.py:589](../../infra/demo-stand/scripts/analyze.py))
возвращает True на **любой** `verdict=allow`, и `challenge_pass` попадает в ту же корзину,
что `ip_whitelist` / `cookie_valid`. Следствия:

1. **Один solve шилдит fp навсегда.** Современный headless (Playwright/UDC) решает
   `SHA-256(nonce+secret)` тривиально. Один решённый challenge → allowlist-gate проваливается
   → fp нельзя авто-промоутить, а на staging он даёт `fp_caught`. Бот покупает иммунитет одним
   решением.
2. **Сильнейший сигнал не используется.** «issued=500, solved=0» сегодня не даёт ни очков в
   score, ни ускорения на staging. Чистая потеря информации.

Корень — **бинарность**: identity-allow трактует challenge_pass так же жёстко, как настоящую
идентичность. Решение — перевести именно challenge_pass из бинарного вето в **ставку**.

## Предложение

### A. Определение сигнала

Для fp за окно аналитики:
```
issued(fp)  = |events: verdict==challenge|
solved(fp)  = |events: verdict==allow AND rule=="challenge_pass"|
solve_rate  = solved / issued          # только при issued >= MIN_CHALLENGE_ISSUED
```
Сглаживание малых N: считаем сигнал только при `issued >= MIN_CHALLENGE_ISSUED` (старт: **10**),
иначе сигнал «нет данных» (нейтрален, ничего не добавляет и ничего не ветирует). Это защищает от
вывода по 1-2 challenge.

### B. Два независимых применения

**(1) Доп-сигнал score (ранжирование):**
```
issued >= MIN_CHALLENGE_ISSUED AND solve_rate <= LOW_SOLVE_RATE(0.05)  → +2, reason "challenge не решается (issued=N, solved=M)"
```
Вес +2: между impersonator(+3) и слабыми эвристиками(+1) — сигнал сильный (поведенческий,
трудно подделать), но не словарный-точный как impersonator. Только ранжирует, сам не блокирует
(инвариант D1: score ≠ допуск).

**(2) Уточнение gate (допуск) — главное:**
Расщепить `_fp_has_identity_allow` на два класса вместо одного `verdict==allow`:
- **hard identity** (`ip_whitelist`, `cookie_valid`, и пр. — НЕ challenge_pass): остаётся
  жёстким вето, как сейчас.
- **challenge_pass**: больше НЕ бинарное вето. Превращается в `solve_rate`-гейт:
  - `solve_rate <= LOW_SOLVE_RATE` → НЕ вето (это бот, который не решает) — промоут разрешён;
  - `solve_rate >= HUMAN_SOLVE_RATE(0.5)` → вето (реально решают → есть люди/легит-браузеры);
  - между порогами → консервативно вето (серая зона, не рискуем).

То же расщепление применить в `find_staging_observation`
([analyze.py:964](../../infra/demo-stand/scripts/analyze.py)): сейчас любой identity-allow среди
матчей → `fp_caught`. После: challenge_pass с низким solve_rate **не** даёт `fp_caught`;
high solve_rate — по-прежнему `fp_caught`.

> **Важно — purity не дублирует это.** purity (`human_share`) смотрит на «выглядит как браузер»
> по UA+cipher+hash. solve_rate смотрит на **способность пройти активную проверку**. Headless с
> идеальным браузерным fp пройдёт purity (human_share высок), но если он не решает challenge —
> solve_rate его ловит. Сигналы ортогональны; оба — вето-классы с разных сторон.

### C. Изменения в коде (объём)

Минимальный вариант — **только `analyze.py`**:
1. В `_event_from_bac_line` уже есть `verdict` и `rule` — ничего добавлять не нужно.
2. Новая функция `challenge_stats(events_for_fp) -> {issued, solved, solve_rate|None}`.
3. `score_fp_candidate`: добавить ветку сигнала (B1).
4. Расщепить `_fp_has_identity_allow` → `_fp_hard_identity_allow` (без challenge_pass) +
   отдельная проверка challenge_pass через solve_rate; обновить вызовы в
   `find_blocklist_candidates` (gate `allowlist`) и `find_staging_observation`.
5. Новые константы + флаги/env (паттерн D1): `MIN_CHALLENGE_ISSUED`, `LOW_SOLVE_RATE`,
   `HUMAN_SOLVE_RATE` (+ `BAC_*` env).
6. Тесты: unit на `challenge_stats` + матрица solve_rate × gate (0/0.03/0.5/0.9/None).

Опциональный edge-follow-up (НЕ в этом дизайне): явный `rule=challenge_issued` маркер вместо
вывода из `verdict=challenge`, если захотим различать Branch A render от прочих challenge-путей.
Сейчас не нужно — `verdict=challenge` достаточно.

### D. Anti-gaming / безопасность

- **Бот решает, чтобы поднять solve_rate и защитить fp.** Чтобы перевалить `HUMAN_SOLVE_RATE=0.5`,
  ему надо решать ≥половину выданных challenge — это уже дорого и, главное, означает, что
  enforcement РАБОТАЕТ (он платит CPU за каждый визит). Низкий порог промоута (`<=0.05`)
  оставляет широкую серую зону под вето — мы осознанно НЕ блокируем, когда неуверены.
- **Загрязнение чужого fp.** solve_rate per-fp; подмешать «нерешения» в чужой fp = слать трафик с
  тем же ClientHello — та же модель угроз, что у purity-poisoning (#5), отдельный трек.
- **Single-use не раздувает solved** — считаем строго `rule=challenge_pass` (см. выше).

## Пороги (стартовые, переопределяемы)

| Параметр | Старт | Флаг / env |
|---|---|---|
| min issued для сигнала | 10 | `--min-challenge-issued` / `BAC_MIN_CHALLENGE_ISSUED` |
| low solve-rate (бот) | 0.05 | `--low-solve-rate` / `BAC_LOW_SOLVE_RATE` |
| human solve-rate (вето) | 0.50 | `--human-solve-rate` / `BAC_HUMAN_SOLVE_RATE` |
| вес сигнала в score | +2 | константа |

## Не входит (non-goals)

- Новые стадии каскада, изменение challenge-механики C5, привязка nonce к fp.
- HTTP/2 fp, поведенческие сигналы (#2-#4) — отдельные треки.
- Per-fp метрики на эдже (на стенде нет per-host метрик-инфры; считаем в аналитике из Loki).

## Открытые вопросы

1. Окно для issued/solved — то же 7д Loki, или отдельное (challenge редок → может нужно длиннее)?
2. Branch B/C (`non_browser_blocked`/`unchallengeable`) — учитывать как «не-solved» сигнал или
   игнорировать (они и так блок)? Скорее игнор: они не получают решаемый challenge.
3. Порог `HUMAN_SOLVE_RATE=0.5` — калибровать по реальным staging-данным стенда.
