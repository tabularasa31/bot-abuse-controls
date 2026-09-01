# Demo stand — abuse-controls antibot

A long-running demo of the production verdict pipeline, designed to be hosted on a VM with a public URL so reviewers (edge admins, security, product) can probe it from their own machine without setting anything up.

The stand defaults to **shadow mode per client** — the cascade computes and logs a would-be verdict for every request, but the only physical exit (tls_fp_blocklist hit in `verdict.lua`) is gated on per-host `policy.mode` (B11). For clients whose Channel C policy says `mode=shadow` (pool default for any unregistered Host), all blocklist hits proxy to origin with the verdict captured in BAC_LOG; for clients with `mode=active` they return 403. The cascade лежит целиком в `infra/demo-stand/lua/` (`hygiene.lua` → `reputation.lua` → `verdict.lua` + `tls_fp.lua` + `rate_limit.lua`, fp compute `ja4_compute.lua` / `ja4_helpers.lua`, policy reader `policy.lua`). The multi-scenario endpoints below front this cascade. To switch a specific Host to active blocking, PATCH `/antibot/v1/policy/<host>` on antibot-backend with `{"mode":"active"}` — Channel C delivers the change to the edge in ≤30s.

## Scenarios a reviewer can probe

| Endpoint | Try with | Expected | What it demonstrates |
|---|---|---|---|
| `/` (and any path) | a real browser | 200, origin page | Cascade passes → request proxied to the tenant's origin. The stand is a real edge in front of the origin. |
| `/` | `curl -k https://<host>/` | 200 (tenant Host) / 444 (non-tenant Host) / 403 (Host with `mode=active` whose fp is in `tls_fp_blocklist`) | For a tenant Host the cascade computes curl's fp and records the would-be verdict; `policy.mode` decides whether it 403's or only logs. A Host that is not a registered tenant is dropped with 444 (tenant-only edge — the bundled landing page was removed). |
| `/` | `python3 -c "import requests; requests.get('https://<host>/', verify=False)"` | 200 | Same — fp computed and logged, then proxied. |
| `/` | `wget -O - --no-check-certificate https://<host>/` | 200 | Same. wget's fp varies by build; visible in the BAC_LOG stream. |
| `/__health` | anything | `ok` | Liveness probe; bypasses verdict. The only operational endpoint on the public edge. |

> **Phase 1 — edge surface shrunk.** `/__fp`, `/__version`, `/__admin`,
> `/__admin/recover_ip`, `/__policy`, `/metrics` and `/baseline/` were removed
> from the public edge. Observability moved to the **stdout → Loki** streams:
> per-request records as `BAC_LOG` and aggregate counters (the old `/metrics`
> set, plus the old `/__version` deploy metadata: `commit` / `cascade_version` /
> `challenge_secret_fp`) as `EDGE_STATS` every 30s (see [edge_stats.lua](lua/edge_stats.lua)).
> Query in Grafana/Loki: `{kind="edge_stats"}` for counters, `{kind="bac_log"}`
> for requests. False-positive recovery is the dashboard's job via the Policy
> API (the edge no longer mutates policy). `/__fp` returns on a controlled
> measurement surface when the browser farm is built (Phase 4).

**Origin (multi-tenant, Policy-driven).** The stand is a real reverse proxy and a **multi-tenant SaaS edge** — it fronts many tenants, not one configured origin. A *tenant* is a host whose Channel C Policy carries a non-empty `origin_ip`; the edge matches the incoming Host against the tenant set and proxies to that tenant's `origin_ip` (the upstream hostname is rewritten to the IP, loop-safe; Host header + SNI sent upstream stay the tenant hostname). A Host that is **not** a tenant — including unregistered hosts and `bac.example.com` itself — is dropped with `444` (the edge is tenant-only; the bundled landing page was removed). `/__health` is the only public local endpoint; every other former `/__*` / `/metrics` path is gone from the public surface (moved to the private `:9090` plane or to Loki). Registering a tenant is one `PATCH /antibot/v1/policy/<host> {"origin_ip": ...}` — no nginx/compose change (ClickUp 86exrefdz). There is no `ORIGIN_URL` / `DASHBOARD_*` env.

**TLS for tenant custom domains (on-demand certs).** The edge terminates client TLS itself (required — the cascade fingerprints the client handshake, `$ssl_*`/JA4 in `tls_fp.lua`; a TLS-terminating proxy in front would hide it and break bot detection). So when a tenant brings its **own** domain, the edge needs a browser-trusted cert for it. This is handled by `lua-resty-acme` (pure-Lua Let's Encrypt, http-01), wired in `lua/tls_autossl.lua` + `nginx.demo.conf`:

- The static `certs/fullchain.pem` stays the **fallback** — every name it already covers (the stand base domain `*.example.com`, the edge IP, `bac`) keeps working with zero ACME.
- A Let's Encrypt cert is issued **only** for a custom tenant domain: `allow_domain(host)` returns true iff `host` is a registered tenant (`policy.origin_ip` non-empty) **and** not under `STAND_BASE_DOMAIN`. This gating is the anti-abuse / anti-rate-limit guard — only deliberately-onboarded hosts get a cert.
- If auto-ssl fails for any reason, the static fallback cert is served (no HTTPS outage for existing tenants).

**Prerequisite:** public inbound `:80` must reach the edge (NAT-forward `:80` → edge), because LE validates via `http://<tenant>/.well-known/acme-challenge/…`. The tenant's DNS must already point at the edge before the first HTTPS hit.

**Onboarding a custom-domain tenant** (end to end):
1. `PATCH /antibot/v1/policy/<host> {"mode":"shadow","origin_ip":"<ip>"}` (routing + makes `allow_domain` pass).
2. Tenant sets DNS: `<host> A → <edge public IP>`.
3. First `https://<host>` hit → auto-ssl issues the cert (≈ a few seconds), then serves normally.

**Bring-up / verify (staging first to avoid burning LE prod rate limits):**
1. Deploy with `AUTO_SSL_STAGING=true` and `ACME_ACCOUNT_EMAIL=<you>` (certs are untrusted but issuance is exercised). Rebuild the image (`--build`) — the Dockerfile vendors `lua-resty-acme` + `lua5.1-filesystem`.
2. `curl http://<edge-ip>/.well-known/acme-challenge/ping` → reachable (not refused) confirms public `:80`.
3. Hit `https://<tenant>/` and watch issuance: `docker logs nginx-demo 2>&1 | grep -i acme` and the storage volume `auto-ssl-storage`; `openssl s_client -connect <tenant>:443 -servername <tenant>` shows the issuer (STAGING on bring-up).
4. When staging issuance works, redeploy with `AUTO_SSL_STAGING` unset (prod CA) → real trusted certs.

Rollback: unset/remove the auto-ssl wiring → the static fallback cert path is exactly the pre-change behaviour.

The `tls_fp_blocklist` catalog ships its content via PRs in `catalogs/tls_fp_blocklist.yaml` (ADR-006). Whether a hit actually blocks the client is a separate, per-Host decision driven by `policy.mode` (B11) — see the section above and `policy.lua`.

## Structured log (Phase 1 schema)

Every request through the pipeline emits exactly one JSON record to docker stdout, prefixed `BAC_LOG `, per the [Phase 1 spec](../../docs/product/phase1-spec.md). View it with:

```sh
docker logs -f nginx-demo 2>&1 | grep --line-buffered 'BAC_LOG ' | sed 's/.*BAC_LOG //' | jq -c .
```

Fields: `request_id` (nginx `$request_id`, unique per request), `timestamp` (ISO 8601 ms, UTC), `edge_id` (`stand-bac`, override via `EDGE_ID`), `host`, `path`, `method`, `status`, `ip`, `asn`, `geo_country`, `ua`, `stage`, `verdict`, `rule`, `action`, `mode`, `strictness`, `latency_ms`, `cascade_ms`, `upstream_response_ms`, `proxy_ms`, `tags`, `staging_match`, plus `resource_id` emitted as `null`.

**Timing fields** (all milliseconds; reverse-proxy = both request and response transit the edge):
- `latency_ms` — whole request lifetime (like nginx `$request_time`): cascade + origin round-trip + **delivery to the end user**. For a slow client / large body this is dominated by the download tail, so it is *not* a measure of our overhead.
- `cascade_ms` — the access-phase antibot overhead only (intake + cascade check), i.e. our work before handing the request to the origin. Exact for `pass`; for `block`/`challenge` (no upstream) it ≈ `latency_ms`.
- `upstream_response_ms` — `$upstream_response_time`: upstream connect → last byte of the origin response (origin round-trip incl. the origin's own think-time), **excluding** delivery to the user. `null` when no upstream was contacted (blocked / challenge).
- `proxy_ms` — `cascade_ms + upstream_response_ms`: request arrival → we hold the full origin response ready to send. This is the request's path through the proxy that adds latency, **without** the slow-client delivery tail (which is `latency_ms − proxy_ms`).

`action` is the effective action the final rule's category implies (kept separate from `verdict`); `mode` / `strictness` are the per-resource business fields read from `policy[Host]` (B11) — unregistered Host falls back to pool default (`mode=shadow, strictness=standard`); `staging_match` is the array of staged-catalog patterns that matched without affecting the verdict — always `[]` until staged catalogs land (A11).

`resource_id` is intentionally left `null` by the edge: the edge works from `Host` only and the backend enriches the record with `resource_id` from its DB on ingest (see vision.md Step 7, [ADR-005](../../docs/architecture-decisions/005-centralized-antibot-backend.md), [config-distribution.md](../../docs/architecture/config-distribution.md)).

The cascade stages (hygiene/reputation/rate_limits — separate tasks) record their outcome via `bac_log.set_verdict()`/`add_tag()`; the final triggering rule wins. The stand's fp-block path is recorded as the Phase 2 `tls_fp` stage through the same contract. TLS-fp data columns and the centralized telemetry sink are out of scope here (separate tasks).

## Quickstart on a fresh VM

```sh
git clone <repo> abuse-controls && cd abuse-controls

# Pin your domain into nginx.demo.conf (one line).
$EDITOR infra/demo-stand/nginx.demo.conf
#   server_name <yourdomain>;

# Drop a real TLS cert in (or symlink your letsencrypt tree).
mkdir -p infra/demo-stand/certs
cp /your/fullchain.pem infra/demo-stand/certs/fullchain.pem
cp /your/privkey.pem   infra/demo-stand/certs/privkey.pem

# No origin env var — tenants are registered in Policy (see below). The
# gitignored .env holds DEMO_BIND_IP / EDGE_ID / Channel C settings.
touch infra/demo-stand/.env

# (Optional, B6) Connect to antibot-backend for live Channel C catalog pulls.
# Without these the stand runs on the static tls_fp_blocklist seed only.
#   ANTIBOT_BACKEND_URL — scheme+host[:port], no trailing slash. UNSET or
#     empty → no timer fires (out-of-box: static seed, clean error.log).
#   ANTIBOT_BACKEND_HOST — Host header override (if URL is an IP).
#   ANTIBOT_BACKEND_CLIENT_CERT / _KEY — paths inside the container; for mTLS
#     install the cert pair via scripts/install-edge-client-cert.sh.
#   ANTIBOT_BACKEND_SSL_VERIFY — set to "false" when backend uses a
#     self-signed cert that the container's CA bundle won't validate.
#     Default true (production-path).
cat >> infra/demo-stand/.env <<EOF
# ANTIBOT_BACKEND_URL=https://antibot.internal:443
# ANTIBOT_BACKEND_CLIENT_CERT=/etc/nginx/certs/edge-client.crt
# ANTIBOT_BACKEND_CLIENT_KEY=/etc/nginx/certs/edge-client.key
# ANTIBOT_BACKEND_SSL_VERIFY=false   # only with self-signed backend cert
EOF

# Bring up. The REVISION env var records the deployed git sha — it shows up in
# the EDGE_STATS dump (`commit` field) so you can confirm what code is live.
REVISION=$(git rev-parse --short HEAD) \
  docker compose -f infra/demo-stand/docker-compose.demo.yml up -d

# Register a tenant so its Host proxies to its backend (Channel C delivers
# it to the edge in ≤30s). Without a tenant row the Host is dropped with 444.
#   PATCH /antibot/v1/policy/<host> {"mode":"active","origin_ip":"203.0.113.9"}

# Smoke from the VM itself.
curl -k https://localhost/__health           # ok
curl -k https://localhost/                   # 444 (localhost is not a tenant — tenant-only edge)
curl -k --resolve <tenant>:443:127.0.0.1 https://<tenant>/   # 200, proxied to the tenant origin_ip
# Counters / deploy metadata are no longer an HTTP endpoint — they ship to Loki
# as EDGE_STATS lines (kind="edge_stats"); on the box you can read the latest via:
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1
```

## Updating a running stand

The Lua and config files are bind-mounted, so most updates are just "pull the
files + reload". [`scripts/update.sh`](scripts/update.sh) does it safely:
fast-forwards `main`, runs `openresty -t` to validate the config, and only then
`openresty -s reload` (no dropped connections). It no-ops when `main` hasn't
moved and is safe to run from cron.

**`nginx.demo.conf` changes need a container recreate, not a reload.** It is
bind-mounted as a **single file**, and `git pull` swaps the file's inode — so
the running container stays pinned to the *old* file and `openresty -s reload`
re-reads the stale content. A new `lua_shared_dict`, `listen`, location, etc.
would silently never take effect (this actually bit PR #32: the `rate_limit`
shared dict didn't deploy until a manual `docker restart`). `update.sh` handles
this automatically: it `--force-recreate`s the container whenever
`nginx.demo.conf`, the `Dockerfile`, or the compose file changed since the last
deploy (otherwise it hot-reloads as before). The recreate path archives the
container's `BAC_LOG` stream to `state/bac-archive/` first, so log history
survives. If you ever edit `nginx.demo.conf` and deploy by hand, use
`docker restart nginx-demo` (or `docker compose ... up -d --force-recreate`) —
a bare `openresty -s reload` will not pick it up.

**Manual:**

```sh
./infra/demo-stand/scripts/update.sh
```

**Auto-pull from `main` every minute (cron on the VM):**

```sh
mkdir -p /home/ubuntu/abuse-controls/state   # the log dir must exist before cron writes to it
crontab -e
```

Add as a **single physical line** (crontab doesn't support `\` line continuation):

```cron
* * * * * /home/ubuntu/abuse-controls/infra/demo-stand/scripts/update.sh >> /home/ubuntu/abuse-controls/state/update.log 2>&1
```

With this, your loop is just `git push` to `main` → edge picks it up within
a minute. Verify what's live via the EDGE_STATS `commit` field
(`docker logs nginx-demo | grep EDGE_STATS | tail -1`), and watch the run log
at `state/update.log`.

`update.sh` requires the checkout on the VM to be a real git working copy of
`main`. If the stand was deployed by copying files (no `.git`), convert it
first — see below.

## Emergency kill-switch

Protection must never take the site down. If the cascade misbehaves — a bug, a
perf regression, a flood of false positives — switch it off. Two levers
(vision.md §"Аварийные рычаги", A12):

- **Global** — the whole cascade goes no-op: traffic proxies straight to the
  origin and **no `BAC_LOG` record is written**. The catastrophe lever (Lua
  crashing workers, mass false positives, a planned maintenance window).
- **Per-stage** — disables one stage; the rest of the cascade keeps running.
  For `tls_fp`: fp is not computed, the blocklist is not consulted (no 403), and
  no `tls_fp:*` tags / soft flags / `tls_*` log fields are written —
  `rate_tls_fp` skips gracefully while the per-IP rate limits still apply. Use
  it when one layer regresses while you ship a hotfix.

`defaults.conf [kill_switch.*]` is the git-tracked baseline (everything `false`).
On the stand you flip the levers **without editing that file and without
recreating the container** — Channel A on the demo is file/mount, no Puppet. Drop
a gitignored override into the mounted config dir and reload:

```sh
cd infra/demo-stand/config
cp kill_switch.local.conf.example kill_switch.local.conf
# edit kill_switch.local.conf — set the toggle(s) you need to true
```

```ini
# whole cascade off:
[kill_switch.global]
enabled = true

# or just one stage (cascade keeps running):
[kill_switch.per_stage]
tls_fp = true
```

```sh
# apply — re-reads the file via init_by_lua, no container recreate:
docker compose -f infra/demo-stand/docker-compose.demo.yml \
    exec nginx-demo openresty -s reload
```

The config dir is a **directory** bind-mount (unlike `nginx.demo.conf`), so a
plain `openresty -s reload` picks the file up — no recreate needed. **Revert** by
setting the toggles back to `false` (or deleting the file) and reloading. Never
commit `kill_switch.local.conf` — it is operational state, gitignored; only the
`.example` template is tracked.

**Verify it took:** with the global kill on, requests through the site produce
no `BAC_LOG` lines (`docker logs --since 1m nginx-demo | grep BAC_LOG`); with the
`tls_fp` kill on, `BAC_LOG` lines drop their `tls_fp` field and `tls_fp:*` tags.

## Challenge HMAC secret (Phase 4)

Phase 4 (L5 active verification) подписывает clearance cookie и self-signed
nonce challenge-страницы локальным HMAC-секретом — без обращения к backend
(vision §«HMAC secret для clearance cookie», §Channel A). Один секрет на весь
эдж-пул; в проде доставляется через Puppet (Channel A), на демо-стенде Channel
A = file mount, как и для `./certs/*.pem` и `kill_switch.local.conf`.

**Файл.** `infra/demo-stand/certs/challenge_secret.key` — одна строка
base64 (32+ байта энтропии). Bind-mount в контейнер на
`/etc/nginx/certs/challenge_secret.key` (override через env
`CHALLENGE_HMAC_SECRET_FILE`). `*.key` уже в `.gitignore` — секрет в репо не
попадёт.

**Генерация.**

```sh
./infra/demo-stand/scripts/generate-challenge-secret.sh
```

Скрипт пишет файл с правами `600` и печатает 8-hex fingerprint — тот же, что
стенд выводит в EDGE_STATS-дампе (`challenge_secret_fp` field, kind="edge_stats"
в Loki). Сам секрет наружу не выводится никогда.

**Ротация = `openresty -s reload`.** `init_by_lua` перезапускается на каждом
reload и перечитывает файл; cookie, подписанные старым секретом, перестают
проходить HMAC verify на L2.1 — клиент идёт через каскад до L5 и получает
новую cookie. Это by-design (vision §«Ротация»: «новая версия через PR +
reload nginx; ротация инвалидирует все ранее выданные cookie разом»).

```sh
rm  infra/demo-stand/certs/challenge_secret.key
./infra/demo-stand/scripts/generate-challenge-secret.sh
docker compose -f infra/demo-stand/docker-compose.demo.yml \
    exec nginx-demo openresty -s reload
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1   # новый challenge_secret_fp
```

**Failure-режим.** Если файла нет — стенд стартует, печатает WARN в
error.log, L2.1 cookie verify и L5 cookie issue откажутся работать (Phase 4
по факту off). Phase 1-3 запросы продолжают идти. При пустом или коротком
(<32 байт) файле — ERR + тот же fail-closed путь. Сам секрет в логах не
светим, только fingerprint.

## Challenge page asset + cascade version pin (Phase 4, C2)

Phase 4 «Ветка A» (vision §5.2) выдает браузеру HTML+JS-страницу, JS считает
`SHA-256(nonce + JS_SECRET)` и POST-ит токен на verify-эндпоинт; edge
подставляет в шаблон одноразовый nonce (TTL 60с, подписан тем же HMAC
secret'ом, что и clearance cookie, см. предыдущую секцию). В C2 на стенд
заехала **только сама эмиссия** (шаблон + nonce + version-pin); привязка к
`verdict=challenge` и серверный verify — за C5.

**Файлы.**

- `infra/demo-stand/challenge/page.html` — единственный шаблон. На render
  подставляются только плейсхолдеры `{{NONCE}}` и `{{EXPIRY}}`. Версия
  каскада зашита в шаблон литералом (в `<meta name="cascade-version">`, в
  HTML-комментарии и в `data-cascade-version`) — НЕ плейсхолдер: это
  source of truth, который сверяется с `CASCADE_VERSION` на init и
  бампается одновременно. Bind-mount в `/etc/nginx/challenge:ro`
  (Channel A на демо = file mount).
- `infra/demo-stand/CASCADE_VERSION` — semver-строка (текущая `0.1.0`).
  Bind-mount в `/etc/nginx/CASCADE_VERSION:ro`. **Bump обязателен** в любом PR,
  который меняет nonce-формат, `JS_SECRET`, поля fingerprint, путь verify или
  ожидаемый контракт ответа. Контракт версия↔шаблон описан в
  [challenge/README.md](challenge/README.md).
- `infra/demo-stand/lua/challenge.lua` — `preload()` сверяет
  `<meta name="cascade-version">` шаблона с содержимым `CASCADE_VERSION` на
  init_by_lua (mismatch валит nginx старт), `render(host)` / `issue_nonce(host)`
  для C5.

**Verify it took.** После старта EDGE_STATS-дамп показывает поле
`cascade_version: "0.1.0"`. Подмена `CASCADE_VERSION` (`echo 0.0.0 > …`) +
`docker compose restart nginx-demo` → контейнер падает с понятной ошибкой
в `docker logs` (`challenge: cascade/template version mismatch …`).

## Migrating a snapshot deploy to a git checkout

If `~/abuse-controls` on the VM is a file copy (no `.git`), turn it into a
fresh `main` checkout so `update.sh` and the cron loop work. In-place
replace keeps the path, compose project name, and certbot hooks unchanged;
only the container recreate is brief downtime.

```sh
cd ~
docker compose -f ~/abuse-controls/infra/demo-stand/docker-compose.demo.yml down
mv abuse-controls abuse-controls.bak.$(date +%F)
git clone https://github.com/tabularasa31/bot-abuse-controls.git abuse-controls
cd abuse-controls

# Certs: repo compose mounts ./certs (not /etc/letsencrypt). Copy current
# certs in as real files, then install the deploy-hook so renewals refresh
# them automatically.
mkdir -p infra/demo-stand/certs
sudo install -m644 /etc/letsencrypt/live/bac.example.com/fullchain.pem infra/demo-stand/certs/fullchain.pem
sudo install -m600 /etc/letsencrypt/live/bac.example.com/privkey.pem  infra/demo-stand/certs/privkey.pem
sudo chown "$USER:$USER" infra/demo-stand/certs/*.pem
sudo install -m755 infra/demo-stand/scripts/sync-demo-certs.sh \
    /etc/letsencrypt/renewal-hooks/deploy/sync-demo-certs.sh

# Bring up from the new checkout. REVISION shows up in EDGE_STATS (`commit`).
REVISION=$(git rev-parse --short HEAD) \
  docker compose -f infra/demo-stand/docker-compose.demo.yml up -d
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1   # confirm commit/cascade_version
```

The `tls_fp_blocklist` content lives in `catalogs/tls_fp_blocklist.yaml` and
arrives via Channel C; per-Host `policy.mode` decides whether a hit blocks
or only logs (B11). Analytics state (`state/`, `reports/`) is gitignored —
copy it from `abuse-controls.bak.*` to keep history, or start clean. Then
install the cron line from "Updating a running stand" above.

## Daily analytics

[`scripts/analyze.py`](scripts/analyze.py) reads the stand's `BAC_LOG`
json (via `docker logs --since 25h nginx-demo`), builds a per-fingerprint
view, scores blocklist candidates, and renders markdown / HTML / a
subject line. fp comes from the record's `tls_fp`; lifetime state lives
in `state/seen-fps.json` (keyed by fp) and `state/ip-cache.json` (ASN
enrichment from the edge-logged fields). Per-day markdown is archived
under `reports/`. Both dirs are gitignored.

That lifetime state would grow unbounded at production scale, so cron runs
[`scripts/rotate-state.py`](scripts/rotate-state.py) **before** `analyze.py`:
it archives the aged-out tail into `state/archive/YYYY-MM.json` and drops
one-off probes, and `analyze.py` lazily restores any key that reappears. TTL
logic and overrides are documented in [`scripts/README.md`](scripts/README.md).

```sh
python3 infra/demo-stand/scripts/analyze.py            # markdown
python3 infra/demo-stand/scripts/analyze.py --html     # HTML for email
python3 infra/demo-stand/scripts/analyze.py --subject  # subject line
```

The scheduled daily run (report email + candidate JSON + state rotation) has
**moved off the edge** onto the backend `antibot-analytics` container, which
reads Loki (7d, all edges) instead of one host's docker logs — see
[`infra/demo-backend/analytics/run.sh`](../demo-backend/analytics/run.sh) and
its compose service. Report addresses (`REPORT_FROM` / `REPORT_TO`) and SMTP
creds are supplied to that container via the backend `.env`. The edge cron
wrapper (`daily-report.sh`) is retired; on the edge, `analyze.py` is just a
manual debug tool (`--source docker` reads the local `nginx-demo`).

Scoring: impersonator +3 · suspicious cipher count +2 · automation UA +1
· multi-IP ≥2 +1 · DC ASN +1 · persistent ≥2 days +1 · recon URI +1.
Tiers: HIGH ≥5 → blocklist candidate · MEDIUM 3-4 → watch · LOW 1-2.

## Shipping logs to backend Grafana

The stand emits two structured stdout streams from `nginx-demo`:
`BAC_LOG {json}` — one line per request ([`lua/bac_log.lua`](lua/bac_log.lua)) —
and `EDGE_STATS {json}` — an aggregate counter/deploy-metadata dump every 30s
([`lua/edge_stats.lua`](lua/edge_stats.lua), the replacement for the removed
`/metrics` and `/__version`). The `observability` profile turns on a small
**promtail** sidecar that tails the container, parses both prefixes, and pushes
them to the **Loki** instance on the antibot-backend VM under a `kind` label
(`bac_log` / `edge_stats`). A pre-provisioned Grafana dashboard at
`https://<backend-host>/grafana/d/bac-raw-logs` renders requests with filters on
`verdict / host / mode / edge_id`; query `{kind="edge_stats"}` for the counters
(edge-deny drops, TLS rejects, cache ratio, fp_unique, commit, cascade_version).
There is no per-request `/__admin` UI — it was removed (Phase 1).

Reuses existing infra:
- Push goes through the same LB-nginx mTLS gate as Channel C
  (`auth/mtls.conf` on backend). No new cert distribution channel —
  the `edge-client.{crt,key}` installed by
  [`scripts/install-edge-client-cert.sh`](scripts/install-edge-client-cert.sh)
  is reused.
- No changes to the Lua cascade: the on-stdout JSON contract from
  Phase 1 is already what promtail consumes.

Setup (after `infra/demo-backend/` has the Loki + Grafana profile up —
see [its README](../demo-backend/README.md#bac-log-viewer)):

```sh
# .env on the edge:
LOKI_PUSH_URL=https://antibot.internal/loki/api/v1/push
# (optional; default true for the demo's self-signed backend cert)
LOKI_PUSH_INSECURE_TLS=true

docker compose -f docker-compose.demo.yml --profile observability up -d
docker logs promtail --tail 30   # expect no "tls bad cert" / 401 / 429
```

Cardinality contract: only `edge_id, host, verdict, stage, mode,
action` are promoted to Loki labels. High-cardinality fields
(`request_id, ip, tls_fp, ua, path`) stay inside the JSON payload —
filter on them via LogQL `| json | <field>="…"`.
[`observability/promtail-config.yaml`](observability/promtail-config.yaml)
spells this out; do not add new labels casually.

When the `observability` profile is **not** enabled (the default),
nothing changes — `docker compose up -d` brings up only `nginx-demo`
and the cascade behaves identically.

## What this does NOT show

- **Hot-reload of the blocklist** (cascade task C1). The demo uses a static blocklist loaded at init.
- **Grey-verdict / sidecar scoring** (cascade task C2). The demo is edge-only.
- **JS challenge issuance** (cascade task A8). The demo blocks or allows; no challenge flow.
- **Rate limiting** (cascade task A3). Each request is independent.
- **UA↔JA consistency** (cascade task A5). The demo's blocklist doesn't include this signal.

The demo is intentionally the **A1 fp blocklist** slice of the cascade only — the part that's production-ready post-PR #3/#4. Other cascade tasks are sequenced after a successful demo + integration with the prod edge.

## Files

```
infra/demo-stand/
├── README.md                       (this file)
├── nginx.demo.conf                 nginx config with all the scenario endpoints
├── docker-compose.demo.yml         stock openresty/openresty:alpine + bind mounts
├── certs/                          TLS material + challenge_secret.key (gitignored)
├── config/                         cascade config files, read at init_by_lua (config.lua)
│   ├── defaults.conf               thresholds, rule toggles, kill_switch baseline (git-tracked)
│   ├── kill_switch.local.conf.example   operator kill-switch template (copy → .local.conf, gitignored)
│   └── …                           IP/UA/ASN lists + tls_fp catalogs
├── lua/
│   ├── verdict.lua                 verdict pipeline (production variant)
│   ├── ja4_compute.lua             fp compute (helpers in ja4_helpers.lua)
│   ├── blocklist.lua               seed automation fps
│   ├── init.lua                    load blocklist, init metrics counters
│   ├── edge_stats.lua              EDGE_STATS stdout dump (counters + deploy metadata → Loki; replaces /metrics + /__version)
│   ├── recent.lua                  last-N request ring buffer (shared_dict; written by log_event)
│   ├── probe.lua                   TLS-fp dump — UNROUTED (returns on a controlled surface in Phase 4)
│   ├── bac_log.lua                 Phase 1 structured-log contract (init/set_verdict/add_tag/emit)
│   ├── log_event.lua               per-request counters + rule/fp metrics + recent ring + structured JSON emit
│   ├── challenge_secret.lua        [C1] Phase 4 HMAC secret loader (file mount → shared_dict)
│   └── challenge.lua               [C2] Phase 4 challenge page renderer + nonce issuer (version-pinned)
├── CASCADE_VERSION                 [C2] semver, сверяется с meta-тегом шаблона на init
└── challenge/                      [C2] HTML+JS challenge page asset (file mount = Channel A на демо)
    ├── page.html                   шаблон с плейсхолдерами {{NONCE}} / {{EXPIRY}}; cascade-version зашит литералом
    └── README.md                   контракт с C5 (verify-эндпоинт) + правила bump'a версии
```

## Talking points for a sceptical reviewer

| Concern | Where to look |
|---|---|
| "Is this AI-generated slop?" | `make ci` passes the full unit suite + 0 lint warnings. ADRs in [`docs/architecture-decisions/`](../../docs/architecture-decisions/) document every non-obvious decision with alternatives explicitly considered. Engineering narrative in [`docs/engineering-narrative.md`](../../docs/engineering-narrative.md) traces the work commit-by-commit. |
| "What if it crashes my edge?" | [`docs/security-review.md`](../../docs/security-review.md) §"Fail-open philosophy" — the pipeline never `ngx.exit(5xx)`s itself. If our Lua throws, the request is served. Worst case: we don't block. We never break. |
| "How much overhead per request?" | PoC #2 ранее измерил ~32 K RPS allow path vs ~40 K baseline on a 4-core MacBook (бенчмарк-стенд из репо выпилен; `/baseline/` passthrough тоже убран в Phase 1). |
| "How do I roll it back?" | Single config-line change (per [ADR-002](../../docs/architecture-decisions/002-spike-2-lua-ssl-vars.md) consequences). Per-Host rollback to observe-only is one PATCH against `/antibot/v1/policy/<host>` flipping `mode` back to `shadow` — Channel C delivers the change to the edge in ≤30s without redeploy. |
| "Why not just use cloudflare/qrator/foxio/etc?" | RFC [`docs/architecture/edge-lua-vs-sidecar.md`](../../docs/architecture/edge-lua-vs-sidecar.md) §A explains: lua-nginx-module is already on the edge; this is additive, not a stack replacement. |
| "What do I monitor?" | The `EDGE_STATS` stdout dump → Loki (`{kind="edge_stats"}`): edge-deny drops, TLS rejects, cache ratio, fp_unique, catalog staleness, `commit` / `cascade_version`. Per-request detail via `{kind="bac_log"}`. Operational procedures (secret rotation, mode toggle, catalog rollback, challenge version pinning) are in [`docs/runbooks/`](../../docs/runbooks/). |

## Divergence WARN triage

При reload edge'a (`nginx -s reload` или recreate-контейнера) можно увидеть в error.log одно из:

```
[demo] tls_fp_blocklist: meta says gen=N but data dict has no matching entries — possibly zone wipe or intentionally-empty Channel C payload. Dropping etag to force next pull to verify…
[demo] verified_bot_ips: meta says gen=N but data dict has no matching entries — …
[demo] tls_fp_catalog: meta says gen=N …
[demo] tls_fp_browser_profiles: meta says gen=N …
```

Это значит: `meta` shared_dict пережил reload с gen=N (Channel C исторически доставлял payload), но соответствующий data dict пуст (нет ни одного `:N` ключа). Два возможных сценария:

1. **Operator resized data dict zone в nginx.conf** (e.g. `lua_shared_dict tls_fp_catalog 1m → 4m`) — nginx пересоздаёт zone, ключи теряются. `meta` (unchanged) сохраняет stale gen+etag.
2. **Backend опубликовал intentional empty payload** — продакт удалил все entries из `catalogs/<name>.yaml`, Channel C доставил пустой ответ. Edge state корректно отражает product intent.

Edge не может различить эти два случая из init.lua, поэтому **не делает re-seed** (это override'нуло бы product intent во втором случае). Действия:

- **Триаж**: `curl <antibot-backend>/catalog/<name>` чтобы увидеть текущий backend payload. Если пусто — сценарий (2), всё корректно. Если есть entries — сценарий (1), wait ≤30s.
- **Auto-recovery**: edge сбрасывает etag → catalog_pull следующего тика (≤30s) делает полный 200 GET → backend re-доставит entries (если они есть) → стенд recovery'нется automatically.
- **Manual override** (если backend ALSO unreachable и intentional-empty НЕ ваш случай): рестарт edge (`docker compose restart` или `nginx -s stop` + `start`) — на полном рестарте `meta` zone re-create'ится, gen-key отсутствует → init.lua идёт cold-start path → локальный seed из `config/tls_fp_blocklist.conf` (для tls_fp_blocklist) или пустое состояние (для других — у них нет file-fallback'а).
- **Между WARN и recovery**: соответствующий rule молча наблюдает (no blocks/challenges). Для tls_fp_browser_profiles cold-start fallback (chrome=15, firefox=16, safari=20, edge=15) применяется только пока `_M._cached_gen_profiles > 0` НЕ выставлен — после первого refresh fallback OFF, observe-only без profiles.
