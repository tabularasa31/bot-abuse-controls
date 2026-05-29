# Blocklist promotion — регламент оператора

Как провести TLS-fingerprint из утреннего письма в enforcement и как снять. Логика решений
(score, gates, purity, intent, жизненный цикл) — в [blocklist-scoring.md](blocklist-scoring.md).
Процедура на VM с командами — в [runbooks/blocklist-promotion.md](runbooks/blocklist-promotion.md).

## Зачем это

Раньше единственный способ внести fp в `catalogs/tls_fp_blocklist.yaml` — править файл руками, а
снять устаревшую запись не делал никто. Тулинг закрывает оба конца: промоут одной командой с
аудит-следом (evidence-«паспорт» в PR и в комментарии записи) и автоматическое снятие по
неактивности. Все авто-действия — **draft-PR, человек аппрувит** (никакого auto-merge).

## SLA

**От утреннего письма до прод-блокировки — ≤ 4 часа.** Это бюджет на: увидеть HIGH-кандидата →
запустить `promote-fp.sh` → ревью staging-PR → мерж → наблюдение → activate-PR → мерж. После мержа
каталог доезжает на эдж за ≤15 мин (Channel C, см. [catalogs/README](../catalogs/README.md)).

## Когда промоутить

- **impersonator** (UA = браузер, fp = инструмент) — самый надежный сигнал, промоутить.
- **recon на неизвестном/специфичном fp** (не общий curl/python) — промоутить.
- **HIGH без intent** (честный curl из ДЦ, даже с recon) — **НЕ** в `tls_fp_blocklist`: его
  отпечаток общий для всех пользователей инструмента. Это кейс для `ua_blacklist` / `ip_blocklist`.
- **purity-вето** (`human_share > 0.05`) — не промоутить: под fp есть живые браузеры.

Автомат сам открывает draft-PR для кандидатов, прошедших все gates + intent — оператору остается
ревью. Письмо помечает, почему HIGH-кандидат НЕ был авто-промоутирован.

## Что писать в `--reason`

Одна строка, по делу: что это и почему блокируем. Хорошо: `"impersonator-кампания, маскировка
под Chrome + recon /.env"`, `"go-сканер Atlassian-эндпоинтов, 8 IP из ДЦ"`. Плохо: `"бот"`,
`"плохой fp"`. Reason попадает в PR и в комментарий-паспорт записи — это и есть ответ на будущий
вопрос «почему этот fp в блоклисте».

## Жизненный цикл и команды

```sh
# 1. Промоут в staging (матчит, пишет staging_match, НЕ блокирует) — открывает PR
scripts/promote-fp.sh <fp> --reason "одна строка"

# 2. Наблюдение ≥48ч. Проверить, что паттерн ловит только ботов (см. runbook).

# 3. Активация (staging → active) — сверяется с наблюдением, открывает PR-2
scripts/promote-fp.sh <fp> --activate

# Снятие (обратимо):
scripts/demote-fp.sh <fp> --reason "почему сняли"            # active → staging
scripts/demote-fp.sh <fp> --reason "campaign over" --remove  # удалить совсем

# Посмотреть, что предложит автомат, ничего не делая:
scripts/blocklist-autopilot.sh --dry-run
```

Полезные флаги promote: `--status active` (пропустить staging — против A11, только осознанно),
`--ttl-days N` (advisory review-by в паспорте), `--force-low-volume` (перебить volume-гейт),
`--dry-run` (показать diff + тело PR, ничего не делать), `--auto` (draft-PR — режим автомата).

## Обратимость

- **`demote-fp.sh`** — штатный обратный путь, адресуется по ключу fp (хирургически, без конфликтов
  с другими записями). По умолчанию мягко `active → staging`, `--remove` — снять.
- **`git revert`** — аварийный откат всего PR целиком, в рамках того же SLA. Применять, когда нужно
  быстро отменить именно последний PR (см. [runbooks/catalog-rollback.md](runbooks/catalog-rollback.md)).
- **auto-demote** — автомат сам открывает draft-PR на снятие fp, который молчит > 14 дней. Человек
  не обязан отслеживать неактивные записи вручную.

## Где это работает

Аналитика и артефакты (`candidates.json` / `staging-observation.json` / `stale.json`) — на
**backend+obs VM** (`antibot-analytics`, источник Loki). Скрипты promote/demote/autopilot
запускаются **там же host-side** (нужен git-чекаут + gh). Прод prod-edge / Puppet — не наш контур
(заморожено в `docs/archive/CDN operator-rollout/`); наш путь доставки — git → backend → эдж.
