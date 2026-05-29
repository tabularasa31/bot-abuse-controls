# Blocklist scoring и promotion — логика решений

Этот документ описывает, **как система решает**, какой TLS-fingerprint (fp) вносить
в `catalogs/tls_fp_blocklist.yaml`, когда переводить из `staging` в `active` и когда
снимать. Операционный регламент (команды, SLA, кто что делает) — в
[blocklist-promotion.md](blocklist-promotion.md); процедура на VM — в
[runbooks/blocklist-promotion.md](runbooks/blocklist-promotion.md).

Реализация: `infra/demo-stand/scripts/analyze.py` (скоринг + JSON-вьюхи),
`scripts/promote-fp.sh` / `demote-fp.sh` / `blocklist-autopilot.sh` (промоут/снятие),
`scripts/lib/blocklist_catalog.py` (правка каталога).

## Что такое отпечаток (fp) и cipher_count

Любой клиент при HTTPS-рукопожатии шлет TLS ClientHello: список шифров, расширения,
версии — в определенном порядке. Это «почерк», который мы сворачиваем в строку-отпечаток
`L<ver><sni><cipher_cnt><alpn>_<hash_b>_<hash_c>` (`infra/demo-stand/lua/ja4_compute.lua`).

Важно: **внутри одного fp `cipher_count` и хеши фиксированы** — это часть токена. Реальные
браузеры (Chrome/Firefox/Safari) предлагают число шифров из набора `{15, 16, 20}`;
инструменты-автоматизаторы (curl/python/go) — другое. Эмпирика со стенда.

## Два слоя решения: score (ранжирование) ≠ gates (допуск)

**Score — насколько это похоже на бота.** Аддитивная сумма сигналов, нужна только чтобы
отсортировать кандидатов в утреннем письме. Сама по себе **ничего не блокирует**.

| Сигнал | Очки |
|---|---|
| impersonator — браузерный UA + fp известного инструмента | +3 |
| suspicious cipher — `cipher_count ∉ {15,16,20}` при браузерном UA | +1 |
| automation UA — UA сам по себе бот (curl/python/go/okhttp/bot/scanner) | +1 |
| DC ASN — хотя бы один IP в hosting-ASN | +1 |
| multi-IP — ≥2 разных IP под fp | +1 |
| persistent — fp виден ≥2 разных дней | +1 |
| recon URI — `/admin`, `/.env`, `/wp-login`, … | +1 |

Тиры: **HIGH ≥5 · MEDIUM 3–4 · LOW 1–2**.

> suspicious весит +1 (а не больше) намеренно: это слабая эвристика, ложащаяся на
> нетипичных, но легитимных браузерах. impersonator (+3) опирается на словарь известных
> инструментов — высокая точность.

**Gates — безопасно ли блокировать этот fp.** Не складываются, это пороги-вето. Score
может быть сколь угодно высоким — если gate не пройден, промоута нет.

## Два разных риска ложноположительного блока

Это ключ ко всему дизайну. Заблокировать fp по ошибке можно двумя разными способами, и
закрываются они разными механизмами.

### Риск 1: «неизвестный легитимный браузер приняли за бота» → purity-вето

Считаем долю событий fp, которые выглядят как **настоящий браузер**. Событие = *genuine
browser*, если одновременно:

1. UA говорит браузер (Chrome/Firefox/Safari);
2. число шифров браузерное (`∈ {15,16,20}`);
3. хеши fp **не** из словаря инструментов.

`human_share = genuine_browser / total`. Гейт **purity**: `human_share ≤ 0.05`
(флаг `--max-human-share`). Если порог превышен — блокировать нельзя, какой бы ни был score:
под этим fp ходят живые люди.

Почему три условия вместе: UA подделать легко (бот пишет «я Chrome»), «почерк» рукопожатия —
труднее. Верим, что это человек, только когда UA браузерный И почерк браузерный И это не
опознанный инструмент. Если UA = Chrome, а почерк = curl (пункты 1 и 2 расходятся) — это
**маскировка**, и она НЕ считается человеком.

### Риск 2: «заблокировали общий отпечаток инструмента» → intent-правило

Отпечаток самого `curl` (или python-requests) **общий для всех его пользователей** в мире:
мониторинги, CI/CD, healthcheck'и, легитимные API-клиенты. recon-URI от одного актора **не
делает общий fp безопасным** — purity тут не спасает (браузерных событий под curl нет,
`human_share = 0`). Заблокировать fp curl = отрезать всю легитимную автоматизацию.

Поэтому авто-блок fp оправдан только при **намерении, специфичном для самого fp**:

- **impersonator** — браузерный UA на инструментальном fp. Сочетание само по себе аномально:
  настоящий пользователь так не делает. Отпечаток такого «притворщика» специфичен — блокировать
  безопасно.
- **recon на не-generic fp** — recon-URI под отпечатком, который **не** является известным
  honest-инструментом (`generic_honest_tool = известный_tool И не impersonator`). Неизвестный
  сканерный fp с recon — специфичная сигнатура, блок безопасен.

`intent = impersonator OR (recon AND NOT generic_honest_tool)`. Честный curl с recon →
`intent = false` → авто его не трогает, кейс для `ua_blacklist`/`ip_blocklist`, решает человек.

### Остальные gates

- **volume** — `n_events_lifetime ≥ 20` (`--min-events`) и `n_ips ≥ 1`. Отсекает шум на
  единичных запросах. Ручной promote может перебить `--force-low-volume`.
- **allowlist/verified (жесткое вето)** — ни один IP fp не в `ip_whitelist`, и ни одно событие
  fp не было identity-allow (verified-bot / ip_whitelist / cookie_valid в логе).
- **dedup** — fp еще нет в каталоге.

## Auto-promote (триггер автомата)

`auto_eligible = tier==HIGH И days_seen≥3 (--min-days-promote) И все gates И intent`.
Автомат открывает **draft-PR** на `staging`, никогда не active напрямую и никогда не auto-merge.

«evidence неизменна 3 дня» аппроксимируется как «HIGH сейчас + наблюдается ≥3 дня + проходит
gates»; точный daily-snapshot diff цепочки — future-follow-up (см. PROGRESS).

## staging → active — подтверждение наблюдением

promote ставит `staging`: эдж матчит и пишет `staging_match: ["tls_fp_blocklist:<fp>"]` в
bac_log (`infra/demo-stand/lua/bac_log.lua`), но **не блокирует**. Это дает наземную правду о
ложняках до enforcement'а. Активируем по факту, а не по исходному прогнозу.

По событиям с `staging_match ⊇ tls_fp_blocklist:<fp>` за окно наблюдения:

| Гейт | Условие | Зачем |
|---|---|---|
| окно | в staging ≥ `--min-staging-hours` (48ч) | разный суточный трафик |
| объем | ≥ `--min-staging-matches` (10) | иначе судить не о чем |
| ноль ложняков (ВЕТО) | `human_share` среди матчей = 0 | задел живой браузер → НЕ активировать |
| allowlist re-check | среди матчей нет whitelist/verified | перепроверка на реальном трафике |

Вердикты: `activate` (все ок → flip в active), `fp_caught` (поймал легит → кандидат на
demote/remove, активацию НЕ предлагаем), `observe` (мало/коротко → наблюдаем дальше).

## Auto-demote — снятие по неактивности

Человек не отследит, какой fp перестал быть угрозой, поэтому это делает автомат. «Последний
раз виден» = `max(days_seen)` из аккумулятора `seen-fps.json` (живет дольше 7д Loki-ретенции).
Если `days_silent > TTL_DAYS` (14, флаг `--ttl-days`) — кандидат на снятие. Двухступенчато:
`active → staging` (молчит) → `staging → remove` (снова молчит). Тоже draft-PR.

> TTL здесь — **не** enforced-протухание на эдже (его в каталоге нет), а порог неактивности
> для авто-детектора снятия.

## Полный жизненный цикл

```
кандидат в письме
   │ promote (прогноз: HIGH + gates + intent)
   ▼
 staging ──набл. ≥48ч, FP=0, ≥10 матчей──► activate (подтверждено) ──► active
   │ задел живой браузер → флаг demote/remove                          │ молчит >14д
   └────────────────────────────────────────────◄──────────────────────┘
                                       auto-demote: active → staging → remove
```

Вход — через подтверждение, выход — через неактивность, в обе стороны draft-PR + аппрув
человека.

## Константы (дефолты, переопределяются флагами/env)

| Параметр | Дефолт | Флаг / env |
|---|---|---|
| purity-порог | 0.05 | `--max-human-share` / `BAC_MAX_HUMAN_SHARE` |
| min events (lifetime) | 20 | `--min-events` / `BAC_MIN_EVENTS` |
| min дней для auto-promote | 3 | `--min-days-promote` / `BAC_MIN_DAYS_PROMOTE` |
| TTL неактивности (дни) | 14 | `--ttl-days` / `BAC_TTL_DAYS` |
| окно staging-наблюдения (ч) | 48 | `--min-staging-hours` / `BAC_MIN_STAGING_HOURS` |
| min staging-матчей | 10 | `--min-staging-matches` / `BAC_MIN_STAGING_MATCHES` |

## Где это считается

Аналитика живет на **backend+obs VM** (`antibot-analytics`-контейнер), источник — **Loki**
(7д истории всех эджей, in-network). См. [config-distribution](architecture/config-distribution.md)
и [ADR-006](architecture-decisions/006-slow-catalogs-as-files.md). Контейнер пишет JSON-артефакты
в `state/`; host-side `blocklist-autopilot.sh` превращает их в draft-PR.
