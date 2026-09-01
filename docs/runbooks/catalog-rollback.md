# Runbook — catalog rollback

**Goal.** Roll back a bad PR to a slow catalog — say, a fingerprint shared by
every Chrome build lands in `tls_fp_blocklist` and causes mass false positives.
The rollback is reversible in both directions with no manual work on the edge or
in the database: the atomic `shared_dict` swap works either way (vision
§"Catalog rollback").

**SLA.** A change applies across the edge pool within ≤15 min of the PR merge
(vision §Channel C). On the stand it is roughly a minute in practice: backend
reloader (5 s) plus edge `catalog_pull` (≤30 s).

**Mechanism.** The slow catalogs are a git directory,
[`catalogs/`](../../catalogs/) (ADR-006, the single source of truth). The backend
reads the files from the checkout (`~/abuse-controls/catalogs`, mounted
`/catalogs:ro`, `CATALOGS_DIR=/catalogs`) through `internal/filesource` with an
mtime cache, and serves them to the edge at `/catalog/<name>` with an ETag. The
edge [`catalog_pull.lua`](../../infra/demo-stand/lua/catalog_pull.lua) polls the
backend (`ngx.timer.every(30s)` plus If-None-Match), atomically swaps the
`antibot_*` shared_dict on a change, and fails stale when the backend is
unreachable.

## The production path

1. Product runs `git revert` on the bad PR in the catalogs repository.
2. On merge, the backend (source of truth) rebuilds the catalog from the files.
3. Edges pull the reverted version within ≤15 min and atomically swap the shared_dict.
4. New requests match against the old, working version — the incident is over.

Always roll new patterns out through `status: staging` first (A11 staged
rollout, see [`catalogs/README.md`](../../catalogs/README.md)).

## Which catalogs actually reach the edge (matters for picking a demo subject)

On the stand the edge pulls **five** catalogs over Channel C (EDGE_STATS
`catalog_staleness_seconds.<catalog>`): `tls_fp_blocklist`, `tls_fp_catalog`,
`tls_fp_browser_profiles`, `verified_bot_ips`, `policy`. `ua_blacklist`, `ip_*`
and `asn_datacenters` are loaded from the edge's local config and are **not**
delivered over Channel C. One extra subtlety for `tls_fp_blocklist`: only the
**active** set travels over Channel C (into the `tls_fp_blocklist` shared_dict);
the **staging** set is built from a local file
([`tls_fp.lua`](../../infra/demo-stand/lua/tls_fp.lua) around line 312), so a
staging entry written through the backend never reaches the edge.

So: run the rollback demo against an **active** entry of `tls_fp_blocklist` —
that is exactly the PR-driven catalog from the vision example.

## Demonstration on the stand

The backend reads **files** (by mtime), not git history, so on the stand the same
atomic swap is shown by editing the file directly and then restoring it (the
equivalent of merge → revert at the delivery layer). Use a real HIGH candidate
from the daily analysis (D1, email label `abuse-controls`) — a confirmed bot, not
a legitimate client:

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<BACKEND_VM_IP>
cd ~/abuse-controls

# 0. Blocklist size before the edit (on the edge): N entries. blocklist_entries
#    is a field of EDGE_STATS.
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '\"blocklist_entries\":[0-9]*'"

# 1. Add the HIGH fingerprint as active (the format is <fp>: <status>).
#    FP=… — substitute a REAL fingerprint from the daily analysis (a valid
#    L-prefixed JA4 token); the literal <HIGH-fp> is rejected by backend validation.
FP='L13d3000_bcf826a2cd28_430ec2476535'    # example from the 2026-05-28 report
printf '\n"%s": active\n' "$FP" >> catalogs/tls_fp_blocklist.yaml

# 2. The backend picks it up within ≤5 s, the edge within ≤30 s. Check that the
#    fingerprint arrived. For an on-demand snapshot use the private
#    :9090/__stats (loopback, on the edge VM).
sleep 38
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "curl -s http://127.0.0.1:9090/__stats | grep -o '\"blocklist_entries\":[0-9]*'"
#    → N+1 entries. A request with that fingerprint gives
#      verdict=block,rule=tls_fp_blocklist (403 on an active host, would-be block
#      plus 200 on a shadow host); the fingerprint itself shows up in
#      Loki {kind="bac_log"}.

# 3. Roll back with git checkout (the delivery-layer equivalent of reverting the PR).
git checkout -- catalogs/tls_fp_blocklist.yaml

# 4. Within ≤30 s the fingerprint disappears from the edge (atomic swap back) →
#    N entries again.
sleep 38
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP> \
  "curl -s http://127.0.0.1:9090/__stats | grep -o '\"blocklist_entries\":[0-9]*'"
```

## What to watch

- After step 2: `blocklist_entries` goes N→N+1 (EDGE_STATS / `:9090/__stats`),
  the fingerprint shows up in Loki `{kind="bac_log"}`,
  `verdict=block,rule=tls_fp_blocklist` for requests carrying it, and
  `catalog_staleness_seconds.tls_fp_blocklist` stays low (contact with the
  backend is alive).
- After step 4: the blocklist goes N+1→N and the fingerprint is gone — the edge
  atomically returned to the previous version.
- A broken catalog from the backend (one that fails validation) is **not applied**
  by the edge: it keeps serving from the last valid copy (fail-stale) and ticks
  the rejected-update counter.

## Undoing the demonstration

`git checkout -- catalogs/tls_fp_blocklist.yaml` (step 3) already returns the
stand to its original state. Confirm with a clean `git status`.

## Verified on stand

2026-05-28, commit e3a72f7. Two HIGH candidates from the daily report
(`L13d3000_bcf826a2cd28_430ec2476535`, `L13d1300_69e852b66fc7_10d89aa70559`) were
added as `active` to `catalogs/tls_fp_blocklist.yaml` on the backend:

- Delivery: `blocklist_entries` **7 → 9** (`:9090/__stats`), both fingerprints in
  Loki `{kind="bac_log"}` on the edge after ~38 s (a PR-driven catalog, SLA
  ≤15 min — about a minute on the stand; `staleness=21s`, contact alive).
- Rollback: `git checkout -- catalogs/tls_fp_blocklist.yaml` → the blocklist went
  **9 → 7** and both fingerprints disappeared after ~38 s (atomic swap back).
  `git status` clean.

This confirms reversibility in both directions with no manual work on the edge or
in the database.
