# Runbook — per-resource mode toggle (shadow ↔ active)

**Goal.** Switch a single resource (domain) between `shadow` (the cascade
computes and logs the would-be verdict but blocks nothing) and `active` (verdicts
are enforced: 403/429/challenge). This is per host, not global to the pool —
turning on enforcement for one customer does not touch the others (vision
§"Operating modes", §Roadmap: "enforcement is enabled together with the
per-resource mode").

**Mechanism.** The mode lives in the `policy` catalog (backend database, not
git). On the edge, [`policy.lua`](../../infra/demo-stand/lua/policy.lua)
`enforce(status)` is the single mode gate: `bac_log.set_verdict` records the
would-be verdict in either mode, but the physical `ngx.exit` only happens when
`mode=active`. The toggle is a write to the policy through the Policy API
(B10/B11); Channel C delivers it to the edge in ≤30 s (vision §Channel C
contract). On the stand the "B11 simulation" is the real Policy API — the same
path the client dashboard will use.

## Procedure (Policy API on the backend VM)

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls
TOKEN=$(grep -E '^DASHBOARD_API_TOKEN=' infra/demo-backend/.env | cut -d= -f2- | tr -d '"'\''')  # strip optional quotes
API='https://127.0.0.1:443'; H='Host: antibot.internal'
HOSTQ=c8-test.example.com     # throwaway resource, leave real customers alone

# 1. Current mode.
curl -ks "$API/antibot/v1/policy/$HOSTQ" -H "$H" -H "Authorization: Bearer $TOKEN"

# 2. shadow → active.
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"mode":"active"}'

# 3. Wait ≤30 s (backend reloader ≤5 s + edge catalog_pull ≤30 s), then check
#    on the edge.
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "docker exec nginx-demo curl -ks 'https://127.0.0.1/__policy?host=$HOSTQ' -H 'Host: $HOSTQ'"
#    → "mode":"active"

# 4. Put it back, active → shadow.
curl -ks -X PATCH "$API/antibot/v1/policy/$HOSTQ" -H "$H" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"mode":"shadow"}'
```

`/__policy?host=<host>` on the edge is a read-only view of the effective policy.
PATCH is idempotent: repeating the same value returns `changed:false`.

## What to watch (shadow vs active contrast)

For a request the cascade marks as blocking (say, a fingerprint present in
`tls_fp_blocklist`):

- `mode=shadow` → a would-be `verdict=block` in BAC_LOG, but physically **200**
  from the origin (the request is proxied).
- `mode=active` → the same `verdict=block`, physically **403**.

You can see this in Loki `{kind="bac_log"}` (filter BAC_LOG by `host` / `mode`:
the same blocklisted fingerprint yields status 200 on a shadow host and 403 on
an active one) and in the response statuses.

## Rollback

Set `mode=shadow` again (step 4). That is the safe default for any resource with
no policy row (pool default = shadow).

## Verified on stand

2026-05-28, commit e3a72f7, throwaway host `c8-test.example.com`:

- `PATCH {"mode":"active"}` → `{"changed":true,"diff":["mode"]}` (the host was
  created by the first mutation); `/__policy` on the edge showed `"mode":"active"`
  within ≤32 s (backend reloader plus edge pull, inside the ≤30 s SLA).
- `PATCH {"mode":"shadow"}` → the edge went back to `"mode":"shadow"` within ≤32 s.
- Idempotency: repeating `{"mode":"shadow"}` → `{"changed":false,"diff":[]}`.
- Enforcement contrast (live traffic, Loki `{kind="bac_log"}`): the same
  blocklisted fingerprint `L13d1900_f3fd9e8f6e2b_fac63a6ff214` produced **403**
  on the active `dashboard.example.com` and **200** on the shadow
  `bac.example.com`.

The host `c8-test.example.com` was left in the policy with defaults
(`mode=shadow`, empty fields) — behaviourally equivalent to having no row at all
(pool default).
