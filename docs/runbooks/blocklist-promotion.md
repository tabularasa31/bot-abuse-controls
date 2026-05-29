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

# Аналитика поднята (observability-профиль), артефакты свежие:
docker compose -f infra/demo-backend/docker-compose.backend.yml --profile observability up -d analytics
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

Автомат: auto-promote стабильного HIGH (≥3 дня, gates+intent) → draft staging-PR;
activate staging-записей с verdict=activate; auto-demote молчащих >14д (active→staging→remove).
Дубликаты PR отсекаются по имени ветки.

## Что наблюдать

- После merge staging-PR: на эдже `staging_match` для fp растет, `verdict` остается
  прежним (НЕ block); `analyze.py --staging-observation-json` показывает n_matches>0.
- После merge activate-PR: `/__admin` блоклист +1, запросы с fp → `verdict=block,rule=tls_fp_blocklist`.
- После auto-demote: запись уходит из active (молчит >14д), enforcement снимается.

## Откат

`scripts/demote-fp.sh <fp>` (адресно по fp) или `git revert` PR целиком
([catalog-rollback.md](catalog-rollback.md)). Оба в рамках SLA ≤15 мин на доставку.

## Verified on stand

_(заполняется после e2e: дата, commit, fp, наблюдаемые числа staging_match / activate / demote)_
