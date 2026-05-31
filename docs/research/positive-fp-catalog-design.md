# Дизайн #2 / Phase 1 — позитивный каталог браузерных fp (D2) + хеш-mismatch

> **Статус: ПЛАНИРУЕТСЯ / design draft.** НЕ реализовано. Развивает идею #2 из
> [bot-detector-roadmap.md](bot-detector-roadmap.md). Связано с бэклогом D2/D3/D4.

## Идея в одну строку

Перевернуть модель детекта: вместо **чёрного списка** известных инструментов
(`tls_fp_catalog`, бесконечно перечислять curl/python/go) — **белый список** реальных
браузеров. Вопрос меняется с «знаем ли мы этот плохой fp?» на «похож ли fp на known-good
браузер?». Белый список конечен и ловит **новые/самопальные/headless** стеки, которых нет
ни в одном словаре инструментов.

## Что есть сегодня (и потолок)

- **`tls_fp_impersonator`** ([tls_fp.lua](../../infra/demo-stand/lua/tls_fp.lua),
  каталог `catalogs/tls_fp_catalog.yaml`): `hash_b → известный инструмент`. Чёрный список,
  ручное перечисление, вечно догоняет.
- **`tls_fp_suspicious_ciphers`** (каталог `catalogs/tls_fp_browser_profiles.yaml`):
  `family → expected_cipher_cnt` (15/16/20). Позитив есть, но **грубый** — только число
  шифров на семейство, без хешей и версий. Headless с `cipher_cnt=15` и не-хромовыми хешами
  проходит.
- **`classify_ua`** возвращает только семейство (chrome/firefox/safari/edge/other), **НЕ
  версию** → «Chrome 120 с рукопожатием Chrome 99» сейчас не ловится (это Phase 2).

## Phase 1 — desktop, family-level, без версий

Самый дешёвый кусок с быстрой отдачей: точное хеш-сравнение вместо грубого `cipher_cnt`,
плюс заострение purity-гейта из #1 (D12).

### Механика харвестера — без нового кода на эдже

На эдже уже есть **`/__fp`** ([probe.lua](../../infra/demo-stand/lua/probe.lua)): возвращает
`fp` + сырые компоненты, **обходит verdict, всегда 200**. Ферма просто гонит браузер на
`https://<stand>/__fp` и читает наш `fp` (тот, что считает `ja4_compute`). Реплицировать
ja4-логику в ферме не нужно.

### Компоненты

1. **Харвестер (ферма), cron-one-shot.** Playwright + реальные stable Chrome / Firefox /
   Edge (desktop), auto-update до текущего stable. Каждый браузер → `/__fp` → берём **полный
   `fp`** (`L<ver><sni><cnt><alpn>_<hash_b>_<hash_c>`, как отдаёт `probe.lua`). Выход —
   `{full_fp → {family, status}}`. Переиспользует cron + draft-PR паттерн `antibot-analytics`.
   Частота калибруется по реальному дрейфу (TLS у Chrome задаётся BoringSSL, меняется редко —
   вероятно «раз в несколько мажоров», не ежемесячно).
2. **Позитивный каталог** — **новый файл** `catalogs/tls_fp_browser_known.yaml`:
   **`full_fp → {family, status}`** (зеркало `tls_fp_catalog`, только known-good). PR-only,
   `status: active|staging` как у всех slow-каталогов (ADR-006). *Решение 1: новый файл, а не
   расширение `tls_fp_browser_profiles.yaml` — другой ключ (полный fp, не `family`) и обратная
   семантика.*
3. **Эдж — усилить `tls_fp_suspicious_ciphers`** ([tls_fp.lua](../../infra/demo-stand/lua/tls_fp.lua)):
   UA=браузер И **полный fp** запроса **не** в known-good set → soft-флаг. **Проверка —
   membership по ПОЛНОМУ fp** (не по `hash_b`, БЕЗ сверки семейства): спрашиваем «это вообще
   рукопожатие реального браузера?». **Почему полный fp, а не `hash_b` (catch Codex):** `hash_b`
   считается ТОЛЬКО из отсортированных шифров (`ja4_compute.lua`), а curves/ALPN/TLS-версия — в
   `hash_c`+префиксе. Membership по одному `hash_b` = та же cipher-list-проверка, только тоньше:
   headless, скопировавший шифры Chrome, но с другими расширениями, прошёл бы как known-good.
   Полный fp это закрывает. **Почему БЕЗ сверки семейства (catch Gemini):** `classify_ua` делит
   `edge`/`chrome` — сверка `family==family` дала бы ложный mismatch у Edge на chrome-fp; полный fp
   family-agnostic, поэтому проблемы нет. Сверка family/version — Phase 2 (D3). **soft-only**
   (challenge/флаг, никогда не hard-block) — лаг каталога стоит максимум одной капчи раннему
   апдейтеру. **mobile-UA → исключение** через подстроку `mobi` в lower-case UA (стандартный
   лёгкий способ, MDN; без regex) — новый хелпер `is_mobile_ua`, т.к. в `classify_ua` мобильного
   флага нет; фермы мобильных fp нет → иначе ложняки по живым телефонам. *Решение 3: точные хеши
   делают `cipher_cnt`-проверку избыточной — старую ветку сворачиваем в known-good-чек (cipher_cnt
   остаётся как поле каталога для наблюдения/отчёта, но решение принимает хеш).*
4. **Аналитика — заострить `is_genuine_browser`** ([analyze.py](../../infra/demo-stand/scripts/analyze.py)):
   сейчас genuine = `cipher_cnt ∈ {15,16,20}` + «нет в tool-словаре»; Phase 1 → genuine =
   `full_fp ∈ known-good`. Прямо усиливает purity-гейт из #1 (меньше и ложняков, и пропусков).

### Приятное свойство покрытия

Chromium-форки (Brave, Vivaldi, Opera, Edge) на одном Chromium-build дают **идентичный полный
fp** (ciphers + curves/ALPN/version — всё из BoringSSL) → **один entry покрывает их
транзитивно**, и проверка family-agnostic, так что `ua_family=edge` на chrome-fp не флагуется.
Если форк тронул расширения — у него другой полный fp → своя запись (это правильно: мы хотим это
видеть). Реально фармить надо мало: Chrome (= весь Chromium), Firefox, Edge-если-отличается.
Отдельная забота — Firefox-форки (LibreWolf) и Tor (намеренно унифицированный fp) — кандидаты в
ручные staging-записи.

### Где крутить ферму

*Решение 2: CI-раннер* (job с Playwright — desktop-браузеры из коробки, draft-PR логично
эмитить из CI). Альтернатива — маленькая VM; на Phase 1 не нужна.

## Не входит в Phase 1 (→ Phase 2)

- **Версии + полный D3:** `classify_ua → (family, major)`, mismatch по версии — нужен новый
  UA-парсинг (UA-строки врут и разнообразны).
- **Self-healing триггер:** всплеск mismatch на UA-версии, которой нет в каталоге, но с
  высоким human_share → авто-пере-сбор. Детектор сам сигналит, что каталог протух (замыкает
  петлю с #1).
- **Mobile / Safari:** iOS Safari / Android Chrome имеют другие fp; нужен macOS-раннер и
  мобильные стеки, которых headless-ферма не даёт. По mobile-UA mismatch не применяем.

## Риски

- **Лаг каталога — ДВА окна, не путать** (catch из review):
  - *Окно 1: релиз браузера → ферма сняла → draft-PR смержен как `staging`.* Здесь нового fp
    ещё нет в каталоге вообще → mismatch срабатывает. Гасится только **soft-only** (одна капча),
    cadence фермы и Phase 2 self-healing. Staging тут НЕ помогает.
  - *Окно 2: `staging` → `active` (калибровка).* **Семантика staging для белого списка
    ИНВЕРТИРОВАНА** относительно чёрного: для blocklist `staging` = «матчим, но не блокируем»; для
    allowlist `staging` = «уже доверяем, флаг подавляем». Поэтому membership-проверка считает
    `full_fp ∈ (active ∪ staging)` → **staging-запись сразу подавляет mismatch** у юзеров новой
    версии. Промоут в `active` — это «благословение» человеком (проверка, что в выхлоп фермы не
    просочился бот-hash), а не гейт, за которым ждут живые пользователи.
- **Неизвестный легитимный desktop-браузер** не в каталоге → mismatch. Покрытие Chromium
  транзитивно снижает риск; soft-режим оставляет цену = одна капча.
- **Отравление** (если когда-нибудь авто-наполнять каталог из трафика) — в Phase 1 НЕ
  делаем: каталог только из фермы + ручных PR. Авто-наполнение — отдельный трек (#5).

## Объём работ (Phase 1)

- Ферма: Playwright-скрипт + CI job + эмиттер draft-PR в `catalogs/tls_fp_browser_known.yaml`.
- Backend Channel C: новый каталог `tls_fp_browser_known` (как `tls_fp_catalog`).
- Эдж: загрузка known-set в shared_dict (по образцу `tls_fp_catalog`), правка
  `tls_fp_suspicious_ciphers` + mobile-UA исключение.
- Аналитика: `is_genuine_browser` через known-set.
- Тесты: Lua (known-good hit/miss, mobile-skip, soft-not-block) + Python (`is_genuine_browser`).
