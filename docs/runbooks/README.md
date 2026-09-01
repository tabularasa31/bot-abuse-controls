# Runbooks — demo stand

Operational procedures for the **demo stand** (`infra/demo-stand/`, a
long-running reverse proxy on a VM). Channel A here is a file mount plus
`openresty -s reload`. Every
procedure below has been exercised against the live stand — see the "Verified on
stand" section at the end of each file.

All four mechanisms are implemented in the cascade. These runbooks are the
emergency levers and the drill to run before turning on real verification
(`mode=active`) for a customer.

## Checklist before `mode=active` on a customer

- [ ] **HMAC secret** generated, fingerprint visible in EDGE_STATS
  (`challenge_secret_fp`), rotation exercised → [secret-rotation.md](secret-rotation.md)
- [ ] **Challenge page** version-pinned to the cascade; a mismatch fails startup →
  [challenge-version-pinning.md](challenge-version-pinning.md)
- [ ] **Mode toggle** shadow↔active for a resource reaches the edge in ≤30 s →
  [mode-toggle.md](mode-toggle.md)
- [ ] **Catalog rollback** reversible in both directions in ≤15 min →
  [catalog-rollback.md](catalog-rollback.md)

## Operational workflows

- **Blocklist promotion (D1)** — take a fingerprint from the morning report
  through to enforcement (staging → observation → active) and retire a stale
  one, via a PR with an audit trail →
  [blocklist-promotion.md](blocklist-promotion.md). The decision logic lives in
  [`docs/blocklist-scoring.md`](../blocklist-scoring.md).

## Attacks / emergency levers

- **What to do under attack** — what protects you at all times (444 for
  non-tenants plus the cascade), what you turn on by hand per attack type
  (`attack_mode` for a customer, `deny_nontenant` TLS reject under an IP flood,
  the kill switch if the cascade misbehaves), where to look (Loki
  `{kind="bac_log"}` / `{kind="edge_stats"}`), and the L7 vs L3/L4 boundary →
  [attack-response.md](attack-response.md).

[`docs/product/vision.md`](../product/vision.md): §"Emergency levers",
§"Catalog rollback", §"HMAC secret"/"Rotation" and §"Channel C" (the delivery
contract).

## Stand topology (one place, so it is not repeated in every file)

| Node | SSH | What runs there |
|---|---|---|
| edge | `ubuntu@<EDGE_VM_IP>` | the `nginx-demo` container (the whole cascade), `promtail` |
| backend+obs | `ubuntu@<BACKEND_VM_IP>` | `antibot-backend-1/2` + `antibot-lb` + postgres + loki + grafana + `antibot-analytics` (daily report and blocklist-candidate producer, reads Loki) |

The VM addresses are placeholders, `<EDGE_VM_IP>` / `<BACKEND_VM_IP>`: substitute
your own (this is the only place they are described). The key is
`~/.ssh/gpu-key`. The `nginx-demo` container listens on the LAN IP
(`192.168.10.208:443`), so curl against the public endpoints goes through the
container:

```sh
docker exec nginx-demo curl -ks https://127.0.0.1/__health -H 'Host: bac.example.com'
```

The edge counters and deploy metadata (commit, cascade_version,
challenge_secret_fp, blocklist_entries, catalog_staleness_seconds.*) are no
longer on the public :443 — they go out as an `EDGE_STATS {json}` line on stdout
→ promtail → Loki (`{kind="edge_stats"}`); on the VM:
`docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1`. For an on-demand
snapshot there is a private read-only mgmt plane on :9090 (loopback):
`ssh -L 9090:127.0.0.1:9090 ubuntu@<EDGE_VM_IP>`, then
`curl -s http://localhost:9090/__stats` or `/__policy?host=<host>`.

The backend reads the slow catalogs from the git checkout at
`~/abuse-controls/catalogs` (mounted `:/catalogs:ro`); the Policy API lives
behind `antibot-lb:443` (Host `antibot.internal`), bearer `DASHBOARD_API_TOKEN`
from `infra/demo-backend/.env`.

> These are stand instructions.
