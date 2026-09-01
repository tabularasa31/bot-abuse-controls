# Config distribution — two-channel model

## What this document fixes

How configuration and runtime data get from where they are authored to the edge nginx workers that need them. Two channels, one piece of terminology, one explicit non-decision.

## Topology

```
                                                          ┌────────────────────────────────┐
                                                          │  edge pool                       │
                                                          │  (nginx-only nodes)              │
                                                          │                                  │
[Channel A — static framework, slow] ─────────────────────┼─► nginx + lua-nginx-module      │
 this repo                                                │   ├─ lua/*.lua                   │
   infra/demo-stand/lua/  ──► checkout + reload ──────────┼─►  (verdict.lua, ja4_helpers...)│
   infra/demo-stand/nginx.demo.conf                       │   ├─ nginx antibot sections      │
                                                          │   │  (lua_shared_dict decls,     │
                                                          │   │   init_worker_by_lua,        │
                                                          │   │   access_by_lua_file, log_by)│
                                                          │   └─ kill-switch config          │
                                                          │                                  │
                                                          │  ngx.timer.every(30s)            │
                                                          │   └─► HTTPS pull (ETag)──────────┼──┐
[Channel C — runtime data, fast] ◄────────────────────────┤                                  │  │
 antibot-backend (our infra, centralized)                 └────────────────────────────────┘  │
   GET /catalog/tls_fp_blocklist                                                                  │
   GET /catalog/ua_blacklist                              ◄──────────────────────────────────┘
   GET /catalog/ip_blocklist        ◄── all edges of the pool pull from one backend
   GET /catalog/asn_datacenters
   GET /catalog/verified_bot_ips
   GET /catalog/policy        (host → mode/strictness/origin_ip/rate_rules/...)
   GET /catalog/attack_mode
        │
        ▼
   PostgreSQL  ◄── dashboard (per-resource policy edits)
                ◄── PR / manual curation (blocklists, catalogs)
                ◄── background rDNS worker (verified_bot_ips)
```

There is **no per-edge Go process**. The Go service runs once, centrally, on our infrastructure. Edges pull from it.

There is **no third delivery channel**. Per-resource policy lives in the backend's database, keyed by `Host`, and reaches the edges over Channel C like any other catalog.

## Channel A — the repo (framework)

**Purpose:** ship the static framework that doesn't change per request: Lua source files, nginx config declaring `lua_shared_dict` and registering the Lua hooks, kill-switch config.

**Source of truth:** this repo — `infra/demo-stand/lua/*.lua` for the whole cascade, and `infra/demo-stand/nginx.demo.conf` for the nginx side.

**Distribution:** a checkout on the edge host, mounted into the container. `infra/demo-stand/scripts/update.sh` fast-forwards it, validates the config and reloads.

**Cadence:** human-driven. Minutes between merge and rollout. Acceptable because nothing here changes per request or per customer.

**Failure mode:** a node that fails to update stays on the previous framework version. `nginx -t` blocks a bad config before the reload, so a broken change never reaches a running worker.

**What goes here:**
- `lua/verdict.lua`, `lua/ja4_helpers.lua`, `lua/log_emitter.lua`, etc.
- `50_lua.conf` antibot sections: `lua_shared_dict` declarations, `init_worker_by_lua_block` registering the catalog-pull timer, `access_by_lua_file` hook on the request phase, `log_by_lua_block` for the log line.
- Per-pool kill-switch flag (e.g. `lua_shared_dict antibot_killswitch 1m;` populated by an `init_by_lua` from an env var or a mounted file).

**What does NOT go here:**
- Per-resource policy (lives in Channel C).
- Any blocklist or catalog content (lives in Channel C).
- Anything that needs to change in seconds–minutes (this channel's cadence is wrong for that).

## Channel C — antibot-backend HTTP pull (runtime data)

**Purpose:** deliver everything that can change without a framework rollout: blocklists, per-resource policy, attack-mode flag, verified-bot IP allowlist.

**Source of truth:** PostgreSQL inside the antibot-backend service. Populated by the client dashboard (per-resource policy), PRs (blocklists), or background workers (rDNS verified bots).

**Distribution:** edge Lua calls `ngx.timer.every(30, fetch)` in `init_worker_by_lua_block`. Each tick does conditional `GET` per catalog with `If-None-Match`. On 200 — parse, atomic-swap into `lua_shared_dict` (generation-counter scheme from the design notes). On 304 — no work.

**Cadence:** 30 s. Bounded staleness window. Sufficient for "dashboard slider moved → effect on edge" UX (sub-minute) and for emergency `attack_mode=on` (sub-minute global effect).

**Failure mode:** **fail-stale.** If the backend is unreachable, the next tick logs and skips. The previous good catalog stays in `lua_shared_dict` indefinitely. A `edge_catalog_staleness_seconds` metric per worker per catalog drives alerting. The verdict pipeline never blocks on a missing catalog.

**Auth / transport:** HTTPS. mTLS (preferred) or an IP allowlist for the edge pool's egress range. One cert per pool, rotated through Channel A.

**HA:** ≥ 2 backend instances behind DNS round-robin or a small LB. Backend is stateless beyond its own DB; HA is trivial.

**Load:** pool size × catalog count / 30 s. Conservatively 50 edges × 7 catalogs / 30 s ≈ 12 req/s, of which 90 %+ are 304 with no body. A single small Go instance handles this with two orders of magnitude headroom.

## The "catalog" concept

Each thing pulled in Channel C is a **catalog**: a named, fully-versioned snapshot of one kind of data that lives in exactly one `lua_shared_dict` on the edge.

| Catalog | Shape | shared_dict | Updated by |
|---|---|---|---|
| `tls_fp_blocklist` | map(fp_string → "&lt;status&gt;:block"), status ∈ {active, staging} (A11 staged rollout) | `antibot_tls_fp_blocklist` | PR / future auto-pipeline |
| `ua_blacklist` | object {active: combined regex string, staging: [pattern, …]} (A11 staged rollout) | `antibot_ua_blacklist` | PR |
| `ip_blocklist` | map(CIDR → "&lt;status&gt;:block"), status ∈ {active, staging} (A11 staged rollout) | `antibot_ip_blocklist` | PR + dashboard custom-add |
| `ip_whitelist` | CIDR list | `antibot_ip_whitelist` | PR (monitoring, check services) |
| `asn_datacenters` | set(asn → 1) | `antibot_asn_dc` | PR |
| `verified_bot_ips` | map(ip → "&lt;status&gt;:&lt;family&gt;"), status ∈ {verified, rejected}, family ∈ {google, bing, yandex, ddg}; a missing key means provisional | `antibot_verified_bots` | backend background rDNS (B7) |
| `policy` | map(host → policy json) | `antibot_policy` | client dashboard |
| `attack_mode` | one flag, optionally per host | `antibot_attack_mode` | dashboard toggle |

**What is NOT a catalog:** anything computed/accumulated locally on the edge — `rate_*_counters`, `verdict_cache`, `tls_fp_cache`. These live only in their local `lua_shared_dict` on each worker and are never exposed by the backend.

**Rule of thumb:** if all edges should see the same value at the same time and the source is our backend → catalog. If it's per-edge runtime state → local shared_dict, not catalog.

## Per-resource lookup — keyed by Host, not by cdn_resource_id

Edge has `ngx.var.host` for free. The `policy` catalog is a map `host → policy_json`. No need for an additional `Host → resource_id` lookup, no dependency on the operator's resource registry.

A new pool domain that has not yet been registered in our dashboard simply has no entry in `policy`; the pipeline falls back to the pool default (`mode=shadow`, all rules observe-only).

That removes the question of where a resource id comes from entirely.

## What was rejected and why

| Rejected | Why |
|---|---|
| **Per-edge Go sidecar process** | No heavy scoring logic to justify it. It would put a runtime binary on every edge node, multiply the failure surface and tie the release cycle to the framework rollout cadence. Centralized, the Go side ships independently and edges stay framework-only. |
| **Three-channel model** (the repo + a config-management channel + a per-edge sidecar) | Two of the three would deliver the same kind of data. The config-management route also means extending a contract owned by another team. Channel C does the same work end to end, with a finer cadence. |
| **Lua reading PostgreSQL directly** | Connection pools per edge, schema coupling, no ETag protocol natively, no way to fail-stale cleanly. The catalog HTTP layer is exactly the indirection that gives us those properties for free. |
| **Shipping catalogs as files over Channel A** | Loses sub-minute updates; emergency `attack_mode=on` cannot wait for a framework rollout. Acceptable only as a fallback during prolonged backend outage; not the primary distribution mechanism. |

## Open items

**Channel C network reach.** A firewall rule from the edge egress to the backend, plus the IP allowlist or the mTLS certificate distribution path.

**Integrating into an existing nginx config** — where `access_by_lua` slots into an existing cascade, which `lua_shared_dict` names are chosen, how this Lua coexists with other modules. What this side supplies is the reference implementation, the hook contract (cascade order, phase, the `antibot_*` dict prefix), the catalog HTTP contract and the backend. The fingerprint work assumes TLS terminates at nginx and that `$ssl_*` and `$geoip_*` are available.

## Terminology cleanup

| Term | Meaning |
|---|---|
| **edge** | an edge node. Runs nginx + Lua only. |
| **antibot-backend** | our Go service, centralized on our infra. Hosts the catalog HTTP API, owns the DB, runs background workers (rDNS), receives logs from edges. |
| **catalog** | one named, ETag-versioned data set served by the antibot-backend and held in one `lua_shared_dict` on the edge. |
| **Channel A** | the repo path for framework code and config. Slow, human-driven. |
| **Channel C** | antibot-backend HTTP pull from edge Lua. Fast, automated, 30 s cadence. |
| **sidecar** | **deprecated term.** It referred to a Go process on each edge. That process does not exist: the Go side is centralized. |
| **Channel B** | **does not exist.** An earlier draft had a third channel for per-resource policy; rejected (see the table above). |
