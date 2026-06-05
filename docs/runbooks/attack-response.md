# Runbook — что делать при атаке

**Цель.** Что включено всегда, что включать руками под конкретный тип атаки, и
где смотреть, что происходит. Главное правило: **базовая защита работает без
тебя**; рычаги ниже — это усиление под инцидент, а не «включатель защиты».

## Что защищает ВСЕГДА (включать не надо)

- **Не-тенантский трафик режется.** Запрос на не-клиентский Host (голый IP эджа,
  мусорный Host, HTTP/1.0 без Host) → `444` (соединение закрыто) еще до каскада.
  Эдж tenant-only: обслуживаются только зарегистрированные клиентские домены.
- **Боты на клиентских сайтах режутся каскадом.** Для каждого тенант-запроса
  идет каскад: hygiene → reputation (IP/ASN/geo) → tls_fp (блоклист отпечатков) →
  rate_limits → verification (challenge). В `mode=active` вердикты исполняются
  (403/429/challenge). Это и есть постоянная защита.

Проверка, что оно живо: `curl` по IP/чужому Host → 444; в Loki видно `verdict=block`.

## Где смотреть атаку (наблюдаемость)

Все в Loki/Grafana (на эдже HTTP-эндпоинтов наблюдаемости нет — Phase 1).

- **Поток запросов и вердикты** — `{kind="bac_log"}`: поля `host`, `ip`, `asn`,
  `geo_country`, `verdict`, `rule`, `tls_fp`, `ua`, `status`. Так видно, кто бьет,
  по какому хосту, и режется ли (`verdict=block, rule=...`).
- **Агрегатные счетчики эджа** — `{kind="edge_stats"}` (раз в 30с): `requests_total`,
  `verdict_*_total`, `edge_nontenant_dropped_total` (444-дропы по не-тенантам),
  `edge_sni_rejected_total` (TLS-reject, если включен рычаг ниже),
  `rules{}` (срабатывания правил), `catalog_staleness_seconds.*`.
- На самой VM (быстро, без Grafana):
  `ssh ubuntu@<edge>` → `docker logs --since 5m nginx-demo 2>&1 | grep BAC_LOG | tail`
  и `... | grep EDGE_STATS | tail -1`.

## Что включать — по типу атаки

| Симптом | Уже покрыто? | Действие |
|---|---|---|
| Боты/скрейперы по клиентскому сайту (высокий RPS, странные UA/fp) | да — rate_limits + tls_fp + challenge | обычно ничего; для одного клиента под прицелом → **attack_mode** на этот host |
| L7-флуд по **IP эджа** / не-тенантскому Host / no-SNI (как у turbo) | HTTP-444 уже режет | под жестким флудом → **deny_nontenant** (рубит еще на TLS, экономит крипту) |
| Сам антибот сбоит / массовые ложные блоки | — | **kill-switch** (per-stage конкретной стадии или global) |
| Объемный **L3/L4** (SYN-флуд, забивание полосы) | НЕТ — вне зоны антибота | сетевой уровень: SYN-cookies/conn-limit на VM, scrubbing/anycast у провайдера |

## Рычаг 1 — attack_mode (точечно на клиента под прицелом)

Per-host. Под `attack_mode` стадия verification форсит challenge для серых
запросов и укорачивает TTL clearance-cookie (vision §5.3, C7). Не глобально —
не задевает других клиентов. Доставка на эдж ≤30с (Channel C).

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls
TOKEN=$(grep -E '^DASHBOARD_API_TOKEN=' infra/demo-backend/.env | cut -d= -f2- | tr -d '"'\''')
API='https://127.0.0.1:443'; H='Host: antibot.internal'
HOSTQ=<клиентский-домен-под-атакой>
# Включить:
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/merge-patch+json' -d '{"attack_mode":true}'
# Выключить после атаки:
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/merge-patch+json' -d '{"attack_mode":false}'
```

## Рычаг 2 — deny_nontenant (TLS-reject под флудом по IP эджа)

Усиливает защиту собственного IP: не-тенантскую/no-SNI/чужую-SNI сессию рубит
**на TLS-рукопожатии** (до каскада И до серверной крипты). HTTP-слой не-тенанта и
так режет 444 — этот рычаг добавляет более ранний и дешевый отказ под большим
L7-флудом по IP.

Файловый рычаг (Channel A на стенде): правится локальный `kill_switch.local.conf`
на edge-VM (gitignored, переживает авто-деплой) + reload, без передеплоя.

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand/config
# создать/дополнить локальный оверрайд (если файла нет — скопировать из .example):
[ -f kill_switch.local.conf ] || cp kill_switch.local.conf.example kill_switch.local.conf
printf '\n[edge_protection]\ndeny_nontenant = true\n' >> kill_switch.local.conf
docker exec nginx-demo openresty -s reload
# Проверить, что включилось: no-SNI рукопожатие теперь должно отвергаться.
# Выключить после атаки: вернуть deny_nontenant = false (или убрать строку) + reload.
```

> ⚠️ **Побочка — ломает liveness-пробы.** При включенном рычаге health-проверки
> по no-SNI (`curl https://<IP>/__health`) и по SNI=`localhost` будут отвергаться
> на рукопожатии. Поэтому это INCIDENT-рычаг, а не дефолт: включай на время
> флуда, мониторь через Loki (не через `/__health`), и **верни в false** после.
> Если нужен health-чек при включенном рычаге — бей по тенантской SNI
> (`curl --resolve <tenant>:443:<IP> https://<tenant>/__health`).

## Рычаг 3 — kill-switch (аварийный, когда сбоит сам антибот)

Когда проблема не в атакующем, а в каскаде (баг/перф/массовые ложняки). Тот же
`kill_switch.local.conf` + reload (A12, vision §«Аварийные рычаги»).

- **Per-stage** — выключить одну стадию, остальные работают:
  `[kill_switch.per_stage]` → `tls_fp = true` (или `reputation`/`rate_limits`/
  `verification`/`hygiene`/`clearance`).
- **Global** — весь каскад no-op, трафик идет на origin как есть, BAC_LOG не
  пишется: `[kill_switch.global]` → `enabled = true`. Крайняя мера: «защита не
  должна положить сайт».

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand/config
# напр. потушить только tls_fp:
printf '\n[kill_switch.per_stage]\ntls_fp = true\n' >> kill_switch.local.conf
docker exec nginx-demo openresty -s reload
# вернуть в false + reload после починки.
```

## После атаки

Верни все включенные рычаги обратно (`attack_mode:false` через Policy API;
`deny_nontenant = false` / `*_stage = false` / `global.enabled = false` в
`kill_switch.local.conf` + reload). Базовая защита (444 + каскад) остается
включенной всегда.

## Граница (важно, без иллюзий)

Антибот закрывает **прикладной L7** (запросы, боты, флуд по IP на уровне HTTP/TLS).
Он НЕ закрывает **объемный L3/L4** (SYN-флуд, исчерпание полосы/коннектов до
рукопожатия) — там даже 444/TLS-reject уже оплачены accept+handshake. Это
сетевой уровень: лимиты соединений на VM, SYN-cookies, scrubbing/anycast у
провайдера.

## Verified on stand

2026-06-05. На живом стенде наблюдалось в Loki: recon-сканер с `2.57.122.192`
(RO, ASN 47890) по под-домену клиента (`/ollama/api/tags`, `/harbor/api/...`,
`/openai/v1/models`) → эдж режет `verdict=block, rule=tls_fp_blocklist, status=403,
mode=active`. Не-тенант по IP → 444. Рычаг `deny_nontenant` — выключен (дефолт),
подтверждено: no-SNI `/__health` → 200 (рукопожатие проходит).
