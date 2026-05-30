# Runbook — blocklist promotion (D1)

**Цель.** Провести TLS-fingerprint из утреннего отчета в enforcement и снять
устаревший — через PR, с аудит-следом, обратимо. Логика решений (score, gates,
purity, intent) — в [blocklist-scoring.md](../blocklist-scoring.md); регламент и
SLA — в [blocklist-promotion.md](../blocklist-promotion.md).

**SLA.** Письмо → прод-блокировка ≤ 4ч (включая staging-наблюдение и два ревью).
После мержа каталог доезжает на эдж ≤15 мин ([catalog-rollback.md](catalog-rollback.md)).

**Где запускать.** Аналитика (`antibot-analytics`) и скрипты — на backend+obs VM
(`ubuntu@<BACKEND_VM_IP>`), там же git-чекаут и `gh`. Артефакты —
`state/candidates.json` / `staging-observation.json` / `stale.json`. Зависит от
A11-доставки staging по Channel C (задача 86exrtjpc) — staging реально матчится на
эдже и пишет `staging_match`.

## Предусловия

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls

# Свежий прогон аналитики (one-shot — пишет артефакты + шлёт отчёт; по
# расписанию это делает host-cron в 08:00, см. §Расписание):
docker compose -f infra/demo-backend/docker-compose.backend.yml --profile observability run --rm analytics
ls -l state/candidates.json state/staging-observation.json state/stale.json

# gh авторизован (для PR); git remote доступен:
gh auth status
```

## Промоут (staging → наблюдение → active)

```sh
# 1. HIGH-кандидат из письма / candidates.json. Сухой прогон — увидеть diff и тело PR:
scripts/promote-fp.sh <fp> --reason "impersonator-кампания, маскировка под Chrome + recon /.env" --dry-run

# 2. Открыть PR (status=staging). Смотрит на gates: purity/allowlist — жесткое вето.
scripts/promote-fp.sh <fp> --reason "..."

# 3. Ревью + merge PR. Через ≤15 мин staging доезжает на эдж: матчит, пишет
#    staging_match: ["tls_fp_blocklist:<fp>"], НЕ блокирует. Проверить, что матчится:
python3 infra/demo-stand/scripts/analyze.py --staging-observation-json | \
  python3 -c "import sys,json;[print(o) for o in json.load(sys.stdin)['observations']]"
#    → у нужного fp n_matches растет, human_share=0 → verdict пойдет в activate.

# 4. Наблюдение ≥48ч. Когда verdict=activate (ноль ложняков, ≥10 матчей):
scripts/promote-fp.sh <fp> --activate          # PR-2: staging → active

# 5. Ревью + merge. Эдж начинает эмитить verdict=block, rule=tls_fp_blocklist.
```

Если на шаге 3–4 `verdict=fp_caught` (паттерн задел живой браузер / allowlist) —
**не активировать**, снять: `scripts/demote-fp.sh <fp> --remove`.

## Снятие (обратимо)

```sh
scripts/demote-fp.sh <fp> --reason "false-positive: легит-клиент с тем же fp"   # active → staging
scripts/demote-fp.sh <fp> --reason "campaign over" --remove                      # удалить совсем
```

## Автомат (cron, draft-PR в обе стороны)

```sh
# Что предложит, ничего не делая:
scripts/blocklist-autopilot.sh --dry-run

# Боевой прогон (открывает ТОЛЬКО draft-PR; человек ревьюит/мержит):
#   30 8 * * * cd ~/abuse-controls && scripts/blocklist-autopilot.sh >> ~/autopilot.log 2>&1
```

Автомат собирает все созревшие изменения за прогон в **один draft-PR** (ветка
`blocklist-auto-YYYY-MM-DD`): auto-promote стабильного HIGH (≥3 дня, gates+intent) →
staging; activate staging-записей с verdict=activate; auto-demote молчащих >14д
(active→staging→remove). Идемпотентно: одна ветка на день — повторный прогон в тот же
день no-op. CI на таком catalog-only PR гоняет только `validate-catalogs` (остальные
джобы отфильтрованы по путям, см. `.github/workflows/ci.yml`).

## Расписание (cron на backend-VM)

Аналитика — **cron-driven one-shot** (контейнер не крутит loop): host-cron в 08:00 MSK
делает один прогон `analyze.py` (артефакты + отчёт), затем autopilot читает свежие
артефакты. На `ubuntu@<BACKEND_VM_IP>` (`CRON_TZ` — иначе хост в UTC и `0 8` = 11:00 MSK;
`-T` — cron не выделяет TTY; `PATH` — чтобы cron нашёл `git`/`gh` для autopilot):

```cron
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CRON_TZ=Europe/Moscow
# 08:00 MSK — прогон аналитики (Loki → state/*.json + email)
0 8 * * * cd /home/ubuntu/abuse-controls/infra/demo-backend && /usr/bin/docker compose -f docker-compose.backend.yml --profile observability run -T --rm analytics >> /home/ubuntu/analytics-cron.log 2>&1
# 08:30 — autopilot (опц.): draft-PR по свежим артефактам
# 30 8 * * * cd /home/ubuntu/abuse-controls && scripts/blocklist-autopilot.sh >> /home/ubuntu/autopilot.log 2>&1
```

`run.sh` — дефолтный entrypoint образа (см. #108). Пока образ на VM не пересобран
на one-shot, добавьте `--entrypoint /opt/analytics/run.sh`, чтобы форсировать один
проход (иначе старый loop-образ не завершится).

Старый edge-скрипт `daily-report.sh` удалён (аналитика переехала на backend; на эдже `analyze.py` остался ручным debug-инструментом с `--source docker`).

## Что наблюдать

- После merge staging-PR: на эдже `staging_match` для fp растет, `verdict` остается
  прежним (НЕ block); `analyze.py --staging-observation-json` показывает n_matches>0.
- После merge activate-PR: `/__admin` блоклист +1, запросы с fp → `verdict=block,rule=tls_fp_blocklist`.
- После auto-demote: запись уходит из active (молчит >14д), enforcement снимается.

## Откат

`scripts/demote-fp.sh <fp>` (адресно по fp) или `git revert` PR целиком
([catalog-rollback.md](catalog-rollback.md)). Оба в рамках SLA ≤15 мин на доставку.

## Verified on stand

2026-05-29 (D1 на main `2506c03`, A11 staging-доставка `f984716` уже в main).

- **Producer (backend/Loki).** Контейнер `antibot-analytics` поднят на backend-VM
  (observability-профиль), прочитал **живой Loki** и записал `state/candidates.json`
  (**14 HIGH / 11 MEDIUM / 31 LOW**) + `stale.json` + `staging-observation.json`.
  `infra/demo-stand/scripts/analyze.py --source loki` работает end-to-end.
- **Promote → PR.** `scripts/promote-fp.sh L13d1300_69e852b66fc7_10d89aa70559 --reason "..."`
  открыл чистый staging-PR (#106) от main с evidence-паспортом (score 6 HIGH:
  impersonator go-http-client + leakix recon, multi-IP 13, DC, `human_share 0.0`,
  gates ✓); CI зелёный.
- **Channel C staging-доставка.** После мержа #106 эдж (`/__admin` → Blocklist)
  показывает `L13d1300_69e852b66fc7_10d89aa70559 → staging:block` — запись доехала
  и загружена как match-but-observe (НЕ 403, в отличие от `active:block`-записей,
  которыми эдж в тот момент блокировал live jitsi-scanner). Подтверждает, что
  staging реально доходит до эджа (разрыв, закрытый 86exrtjpc).
- **`staging_match`.** Метрика `antibot_staging_match_total` (observe-only) заведена
  на эдже; инкрементируется при следующем запросе этого fp (зависит от тайминга
  live-трафика конкретного fp — на момент проверки этот fp ещё не делал запрос
  после загрузки).
- **Активация.** Гейтится §D dwell-часами (`staging-since.json`, дефолт 48ч) +
  чистым наблюдением (`human_share=0`): выполняется после окна через
  `scripts/promote-fp.sh <fp> --activate` (или `--force` для демо) → второй PR в `active`.

> Acceptance «≥1 HIGH-кандидат проведён через flow» закрыт по доставке: живой
> HIGH из Loki → promote-PR → merge → загружен на эдж как staging. Реальный
> `verdict=block` наступает после активации (48ч dwell / `--force`).
