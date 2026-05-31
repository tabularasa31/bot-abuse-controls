# Дизайн #1 — challenge solve-rate как сигнал скоринга

> **Статус: РЕАЛИЗОВАНО (D12).** Сигнал в `analyze.py` + 1 строка на эдже
> (`attack_mode` в `bac_log`); тесты в `tests/test_analyze.py`. Пороги
> (`LOW_SOLVE_RATE`/`HUMAN_SOLVE_RATE`) остаются на калибровку по реальным
> active-staging-данным (env-overridable). Развивает идею #1 из
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

**Только `mode=active` И `attack_mode=off` события.** Сигнал валиден лишь когда challenge выдан
**как вердикт о самом fp**, а не как блановая поза хоста:
- *shadow*: страница физически не серверится (C5) → `solved` всегда 0 → ложный «бот» у всех. Поле
  `mode` в логе есть (B11).
- *attack_mode=on*: L5 форсит challenge почти всем не-`allow` запросам (C4), включая нормальные
  браузеры. Часть живых людей уходит с неожиданного interstitial, не решив → легитимный fp копит
  «нерешённые» challenge → ложно низкий solve_rate → риск ложного промоута. Под атакой challenge —
  не суждение о fp, поэтому в сигнал не идёт. **Требует залогировать `attack_mode`** (см. §C).

Следствие для продукта: сигнал «включается» только для хостов в active-энфорсменте **вне атаки** —
зависимость от раската enforcement, не баг. Атака даёт много challenge, но это самый зашумлённый
период (форс-проверки + отвал людей), поэтому осознанно его не учитываем.

**Окно — накопительное (lifetime), НЕ 24ч.** challenge редок, и low-and-slow бот не наберёт
`MIN_CHALLENGE_ISSUED` за сутки (review). Поэтому `issued`/`solved` копим per-fp в `seen-fps.json`
рядом с `count`/`days_seen`: на каждом прогоне инкрементим дельтой из свежего Loki-окна (watermark
для дедупа уже есть у `count`), **учитывая только active-вне-атаки события**. Это же убирает
зависимость от того, в каком суточном окне оказалось событие.

> Счётчик — **all-time (lifetime)**, не скользящее окно: устойчив, но медленно реагирует на смену
> поведения fp (для ботов норма). Отдельного «забывания» нет — fp выходит из рассмотрения через
> auto-demote по молчанию > TTL (14д).

```
issued(fp)  = накопл. |events: mode==active AND attack_mode==off AND verdict==challenge|
solved(fp)  = накопл. |events: mode==active AND attack_mode==off AND verdict==allow AND rule=="challenge_pass"|
solve_rate  = min(solved / issued, 1.0)   # cap 1.0 (см. ниже), при issued > 0
```
**Cap на 1.0 (review):** даже при накопительном счёте на самой первой загрузке fp solved-событие
может попасть в окно, а парный issued — остаться за нижней границей ретенции → `solved > issued`.
`min(…, 1.0)` это поглощает; накопление со временем выправляет числа.

Порог объёма для сигнала **асимметричен** (это ключ к корректности на малых N):
- **score-сигнал** (B1) начисляем только при `issued >= MIN_CHALLENGE_ISSUED` (старт **10**) — не
  выводим «бот не решает» по 1-2 challenge.
- **gate-вето** (B2) — солвы человека НЕ игнорируем даже на малых N: при `issued < MIN` любой
  `solved > 0` всё равно ветирует (review). Подробности — в B2.

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
- **challenge_pass**: больше НЕ бинарное вето. Лестница по объёму (порядок важен):
  - `issued < MIN_CHALLENGE_ISSUED` — **данных мало, судить по rate нельзя**:
    - `solved > 0` → **вето** (человек/клиент решил challenge при малом объёме — не рискуем
      промоутить; review). Снять вето на малых N нельзя — `solved/issued` тут шумит.
    - `solved == 0` → нейтрально (этот сигнал не ветирует). На практике такой fp почти всегда
      отсекает volume-гейт `n_lifetime >= MIN_EVENTS(20)` — снятие вето здесь почти ни на что не влияет.
  - `issued >= MIN_CHALLENGE_ISSUED` — **данных достаточно, судим по rate** (три зоны, не две):
    - `solve_rate <= LOW_SOLVE_RATE(0.05)` → **НЕ вето** (бот, который не решает) — промоут разрешён,
      **даже если было несколько случайных solved** (это и есть headless, «решил пару раз из сотен»;
      ровно тот дефект «один solve шилдит навсегда», который дизайн чинит);
    - `solve_rate >= HUMAN_SOLVE_RATE(0.5)` → **вето** (реально решают → есть люди/легит-браузеры);
    - `LOW < solve_rate < HUMAN` — **серая зона → не авто-промоут, но и не хард-вето**: сигнал
      неубедителен, отдаём решение staging-наблюдению (см. ниже). На practике: fp **не** становится
      `auto_eligible`, но как кандидат на staging допустим (через ручной promote или просто
      остаётся в отчёте). Staging безвреден — только логирует, не блокирует, — поэтому «припарковать
      сомнительный fp в наблюдении» безопаснее, чем поспешно блокировать или поспешно простить.

  > Асимметрия осознанная: **добавить/сохранить** вето можно по одному solved (защита человека),
  > **снять** вето — только при достаточном `issued`; в промежутке — не блок и не прощение, а
  > наблюдение.

То же расщепление — в `find_staging_observation`
([analyze.py:964](../../infra/demo-stand/scripts/analyze.py)), и **здесь у `HUMAN_SOLVE_RATE`
появляется реальный смысл** (B-решение). Сейчас любой identity-allow среди staging-матчей →
`fp_caught`. После — по solve_rate среди матчей (только active):
  - `>= HUMAN_SOLVE_RATE` → `fp_caught` (поймали живых → demote/remove);
  - `<= LOW_SOLVE_RATE` (и прочие staging-гейты ок) → `activate`;
  - серая зона → `observe` (остаёмся в staging, добираем данные по решаемости — ровно «наблюдать
    дольше»). Парковка в `observe` безопасна: staging не блокирует.

> **Важно — purity не дублирует это.** purity (`human_share`) смотрит на «выглядит как браузер»
> по UA+cipher+hash. solve_rate смотрит на **способность пройти активную проверку**. Headless с
> идеальным браузерным fp пройдёт purity (human_share высок), но если он не решает challenge —
> solve_rate его ловит. Сигналы ортогональны; оба — вето-классы с разных сторон.

### C. Изменения в коде (объём)

**Edge (одна строка):** добавить `attack_mode = p.attack_mode` в схему `bac_log`
([bac_log.lua](../../infra/demo-stand/lua/bac_log.lua):320-321, рядом с `mode`/`strictness`; `p`
уже читается из `policy.get`). Без этого поля аналитика не отличит атак-challenge от обычного.
Поле `mode` уже логируется (B11) — отдельно добавлять не нужно. Приём на backend нестрогий (лишнее
поле уходит в `raw` jsonb).

**`analyze.py` (основной объём):**
1. В `_event_from_bac_line` есть `verdict`/`rule`/`mode`(если уже); добавить чтение `mode` и
   `attack_mode` — нужно для фильтра §A (`mode==active AND attack_mode==off`).
2. **Накопление в `seen-fps.json`:** к существующим per-fp полям (`count`/`days_seen`) добавить
   `challenge_issued`/`challenge_solved`, инкремент дельтой на каждом прогоне **только по
   active-вне-атаки событиям** (`load_seen`/`save_seen` уже есть, watermark-дедуп общий с `count`).
   Это lifetime-окно сигнала (см. §A).
3. Чистая функция `solve_signal(seen_entry) -> {issued, solved, solve_rate(cap 1.0), enough:bool}`
   (`enough = issued >= MIN_CHALLENGE_ISSUED`).
4. `score_fp_candidate`: добавить ветку сигнала (B1).
5. Расщепить `_fp_has_identity_allow` → `_fp_hard_identity_allow` (без challenge_pass) +
   отдельная проверка challenge_pass через лестницу §B2 с тремя исходами (veto / no-veto /
   gray→no-auto). Обновить вызовы в `find_blocklist_candidates` (gate `allowlist` + снятие
   `auto_eligible` в серой зоне) и `find_staging_observation` (исходы `fp_caught`/`activate`/
   `observe` по solve_rate среди active-матчей).
6. Новые константы + флаги/env (паттерн D1): `MIN_CHALLENGE_ISSUED`, `LOW_SOLVE_RATE`,
   `HUMAN_SOLVE_RATE` (+ `BAC_*` env).
7. Тесты: unit на `solve_signal` (cap >1.0; фильтр игнорит shadow- И attack-события) + матрица
   лестницы §B2 (issued<MIN×{solved 0,1} ; issued≥MIN×solve_rate{0,0.03,0.3(серая),0.9}) +
   staging-исходы fp_caught/activate/observe.

Опциональный edge-follow-up (НЕ в этом дизайне): явный `rule=challenge_issued` маркер вместо
вывода из `verdict=challenge`, если захотим различать Branch A render от прочих challenge-путей.
Сейчас не нужно — `verdict=challenge` достаточно.

### D. Anti-gaming / безопасность

- **Бот решает, чтобы поднять solve_rate и защитить fp.** Чтобы перевалить `HUMAN_SOLVE_RATE=0.5`,
  ему надо решать ≥половину выданных challenge — это уже дорого и, главное, означает, что
  enforcement РАБОТАЕТ (он платит CPU за каждый визит). А чтобы хотя бы выйти из зоны промоута
  (`>0.05`), он попадает лишь в серую зону → staging-наблюдение, а не мгновенное прощение: добиться
  блокировки сложно, но и иммунитет одним-двумя solve не купить.
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

## Решённые вопросы (обсуждение 2026-05-30)

1. **Окно для issued/solved** → накопительно в `seen-fps.json` (lifetime), не 24ч — иначе
   low-and-slow бот не наберёт `MIN_CHALLENGE_ISSUED`. См. §A/§C.
2. **Shadow vs active** → считаем строго по `mode==active`; под shadow страница не серверится,
   `solved` всегда 0 → сигнал не валиден. Следствие: сигнал работает только на active-хостах. §A.
6. **Режим атаки** → **исключаем attack-mode события** (`attack_mode==off`). Под атакой L5 форсит
   challenge всем (C4), живые люди отваливаются с interstitial → ложно низкий solve_rate. Challenge
   под атакой — поза хоста, не суждение о fp. Цена: **+1 строка на эдже** (`attack_mode` в
   `bac_log`), «только analyze.py» больше неверно. §A/§C.
3. **Branch B/C** (`non_browser_blocked`/`unchallengeable`) → **игнорируем**: каскад логирует их как
   `verdict=block`, в знаменатель `issued` (только `verdict=challenge`) они не попадают
   автоматически; и они уже блокируются. Паттерн «браузер, но всегда Branch C» — сигнал для трека
   #4 (поведение), не сюда.
4. **Структура порогов** → три зоны (не две): серая зона `LOW<rate<HUMAN` = **не авто-промоут и не
   хард-вето**, а staging-наблюдение. Так у `HUMAN_SOLVE_RATE` появляется реальный смысл (на решении
   staging→active). §B2.
5. **Рост `seen-fps.json`** от двух новых полей — в пределах существующего D7 (state rotation),
   отдельного решения не требует.

## Остаётся на калибровку (не блокирует код)

- Конкретные значения `LOW_SOLVE_RATE` (старт 0.05) и `HUMAN_SOLVE_RATE` (старт 0.5) — подстроить по
  реальным active-staging-данным стенда, когда они накопятся. Вынесены в флаги/env, меняются без кода.
