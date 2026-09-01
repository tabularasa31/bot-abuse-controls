# Runbook — what to do under attack

**Goal.** What is always on, what you enable by hand for a given attack type, and
where to look while it happens. The main rule: **the baseline protection works
without you**; the levers below strengthen it during an incident, they are not a
"turn protection on" switch.

## What protects you AT ALL TIMES (nothing to enable)

- **Non-tenant traffic is cut.** A request for a non-customer Host (the edge's
  bare IP, a junk Host, HTTP/1.0 with no Host) gets `444` (connection closed)
  before the cascade even runs. The edge is tenant-only: it serves registered
  customer domains and nothing else.
- **Bots on customer sites are cut by the cascade.** Every tenant request runs
  the cascade: hygiene → reputation (IP/ASN/geo) → tls_fp (fingerprint blocklist)
  → rate_limits → verification (challenge). In `mode=active` the verdicts are
  enforced (403/429/challenge). This is the standing protection.

To check it is alive: `curl` the IP or a foreign Host → 444; Loki shows
`verdict=block`.

## Where to watch an attack (observability)

Everything is in Loki/Grafana; the edge exposes no observability HTTP endpoints.

- **Request stream and verdicts** — `{kind="bac_log"}`: fields `host`, `ip`,
  `asn`, `geo_country`, `verdict`, `rule`, `tls_fp`, `ua`, `status`. This shows
  who is hitting you, on which host, and whether they are being cut
  (`verdict=block, rule=...`).
- **Aggregate edge counters** — `{kind="edge_stats"}` (every 30 s):
  `requests_total`, `verdict_*_total`, `edge_nontenant_dropped_total` (444 drops
  for non-tenants), `edge_sni_rejected_total` (TLS rejects, if the lever below is
  on), `rules{}` (rule hits), `catalog_staleness_seconds.*`.
- On the VM itself (fast, no Grafana):
  `ssh ubuntu@<edge>` → `docker logs --since 5m nginx-demo 2>&1 | grep BAC_LOG | tail`
  and `... | grep EDGE_STATS | tail -1`.

## What to enable, by attack type

| Symptom | Already covered? | Action |
|---|---|---|
| Bots/scrapers against a customer site (high RPS, odd UA/fp) | yes — rate_limits + tls_fp + challenge | usually nothing; if one customer is singled out → **attack_mode** on that host |
| L7 flood against the **edge IP** / a non-tenant Host / no SNI | HTTP 444 already cuts it | under a heavy flood → **deny_nontenant** (rejects at TLS, saves the crypto work) |
| The antibot itself misbehaves / mass false blocks | — | **kill switch** (per-stage for one stage, or global) |
| Volumetric **L3/L4** (SYN flood, saturated link) | NO — outside the antibot's scope | network layer: SYN cookies / connection limits on the VM, scrubbing/anycast at the provider |

## Lever 1 — attack_mode (targeted, for the customer under fire)

Per host. Under `attack_mode` the verification stage forces a challenge for grey
requests and shortens the clearance cookie TTL (vision §5.3, C7). It is not
global — other customers are untouched. Delivery to the edge takes ≤30 s
(Channel C).

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls
TOKEN=$(grep -E '^DASHBOARD_API_TOKEN=' infra/demo-backend/.env | cut -d= -f2- | tr -d '"'\''')
API='https://127.0.0.1:443'; H='Host: antibot.internal'
HOSTQ=<customer-domain-under-attack>
# Turn it on:
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/merge-patch+json' -d '{"attack_mode":true}'
# Turn it off once the attack is over:
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/merge-patch+json' -d '{"attack_mode":false}'
```

## Lever 2 — deny_nontenant (TLS reject under a flood against the edge IP)

This hardens the edge's own IP: a non-tenant / no-SNI / foreign-SNI session is
cut **during the TLS handshake**, before the cascade and before the server-side
crypto. The HTTP layer already answers non-tenants with 444 — this lever adds an
earlier and cheaper refusal under a large L7 flood.

It is a file lever (Channel A on the stand): edit the local
`kill_switch.local.conf` on the edge VM (gitignored, survives auto-deploy) and
reload, with no redeploy.

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand/config
# Local override (if the file does not exist, copy it from .example, which
# already carries an [edge_protection] section with deny_nontenant = false).
[ -f kill_switch.local.conf ] || cp kill_switch.local.conf.example kill_switch.local.conf
# Edit the line IN PLACE (idempotent) rather than appending — appending produces
# duplicate sections/keys (the parser is last-wins, but the file becomes
# self-contradictory). If the line or section is missing, open the file by hand
# (nano) and set deny_nontenant = true.
sed -i 's/^deny_nontenant = .*/deny_nontenant = true/' kill_switch.local.conf
docker exec nginx-demo openresty -s reload
# Confirm it took effect: a no-SNI handshake should now be rejected.
# Turn it off after the attack: the same sed back to `= false` plus a reload.
```

> ⚠️ **Side effect — it breaks liveness probes.** With the lever on, health checks
> over no-SNI (`curl https://<IP>/__health`) and with SNI=`localhost` are rejected
> at the handshake. So this is an INCIDENT lever, not a default: turn it on for
> the duration of the flood, monitor through Loki (not `/__health`), and **set it
> back to false** afterwards. If you need a health check while it is on, use a
> tenant SNI (`curl --resolve <tenant>:443:<IP> https://<tenant>/__health`).

## Lever 3 — kill switch (emergency, when the antibot itself misbehaves)

For when the problem is the cascade rather than the attacker (a bug, a
performance regression, mass false positives). Same
`kill_switch.local.conf` plus a reload (A12, vision §"Emergency levers").

- **Per-stage** — disable one stage, the rest keep working:
  `[kill_switch.per_stage]` → `tls_fp = true` (or `reputation` / `rate_limits` /
  `verification` / `hygiene` / `clearance`).
- **Global** — the whole cascade becomes a no-op, traffic goes to the origin as
  is, and BAC_LOG is not written: `[kill_switch.global]` → `enabled = true`. A
  last resort: protection must not take the site down.

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand/config
# The .example already carries [kill_switch.per_stage] with every stage = false,
# so edit the relevant line IN PLACE (do not append, to avoid duplicates).
[ -f kill_switch.local.conf ] || cp kill_switch.local.conf.example kill_switch.local.conf
# e.g. disable tls_fp only:
sed -i 's/^tls_fp = .*/tls_fp = true/' kill_switch.local.conf
# global (last resort): sed -i 's/^enabled = .*/enabled = true/' kill_switch.local.conf
docker exec nginx-demo openresty -s reload
# set it back to false plus a reload once the fix is in.
```

## After the attack

Put every lever you enabled back (`attack_mode:false` through the Policy API;
`deny_nontenant = false` / `*_stage = false` / `global.enabled = false` in
`kill_switch.local.conf` plus a reload). The baseline protection (444 plus the
cascade) stays on permanently.

## The boundary (important, no illusions)

The antibot covers the **application layer, L7** (requests, bots, HTTP/TLS-level
floods against the IP). It does NOT cover **volumetric L3/L4** (SYN floods,
bandwidth or connection exhaustion before the handshake) — there, even a 444 or a
TLS reject has already cost you an accept plus a handshake. That is the network
layer: connection limits on the VM, SYN cookies, scrubbing/anycast at the
provider.

## Verified on stand

2026-06-05. Observed live in Loki: a recon scanner from `2.57.122.192` (RO, ASN
47890) hitting a customer subdomain (`/ollama/api/tags`, `/harbor/api/...`,
`/openai/v1/models`) → the edge cuts it with
`verdict=block, rule=tls_fp_blocklist, status=403, mode=active`. A non-tenant on
the IP → 444. The `deny_nontenant` lever was off (the default), confirmed: a
no-SNI `/__health` → 200 (the handshake goes through).
