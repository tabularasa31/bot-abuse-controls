# Config distribution — two-channel model

**Status:** accepted 2026-05-18.
**Supersedes:** the implicit three-channel model in earlier drafts (Puppet + prod-edge-salt-pillars + per-edge sidecar HTTP pull).
**Related:** [ADR-001](../architecture-decisions/001-edge-lua-vs-go-sidecar.md), [RFC edge-lua-vs-sidecar.md](edge-lua-vs-sidecar.md).

## What this document fixes

How configuration and runtime data get from where they are authored to the edge nginx workers that need them. Two channels, one piece of terminology, one explicit non-decision.

## Topology

```
                                                          ┌────────────────────────────────┐
                                                          │  CDN operator edge-*           │
                                                          │  (edge-pool edge, template=edge)  │
                                                          │                                  │
[Channel A — static framework, slow] ─────────────────────┼─► nginx + lua-nginx-module      │
 edge-puppet-master (b05)                                  │   ├─ /etc/nginx/lua/nginx2/*.lua │
   modules/nginx/files/lua/nginx2/  ──► Puppet agent ─────┼─►  (verdict.lua, ja4_helpers...)│
   modules/nginx/manifests/prod-edge.pp                        │   ├─ 50_lua.conf antibot sections│
                                                          │   │  (lua_shared_dict decls,     │
                                                          │   │   init_worker_by_lua,        │
                                                          │   │   access_by_lua_file, log_by)│
                                                          │   └─ kill-switch config          │
                                                          │                                  │
                                                          │  ngx.timer.every(30s)            │
                                                          │   └─► HTTPS pull (ETag)──────────┼──┐
[Channel C — runtime data, fast] ◄────────────────────────┤                                  │  │
 antibot-backend (our infra, centralized)                 └────────────────────────────────┘  │
   GET /catalog/fp_blocklist                                                                  │
   GET /catalog/ua_blacklist                              ◄──────────────────────────────────┘
   GET /catalog/ip_blocklist        ◄── all edges of edge-pool pull from one backend
   GET /catalog/asn_datacenters
   GET /catalog/verified_bot_ips
   GET /catalog/policy        (host → mode/strictness/rate_rules/...)
   GET /catalog/attack_mode
        │
        ▼
   PostgreSQL  ◄── client dashboard (per-resource policy edits)
                ◄── PR / manual curation (blocklists, catalogs)
                ◄── background rDNS worker (verified_bot_ips)
```

There is **no per-edge Go process**. The Go service runs once, centrally, on our infrastructure. Edges pull from it.

There is **no prod-edge-salt-pillars extension**. Per-resource antibot policy lives in our backend's DB, keyed by `Host`, and is delivered to edges through Channel C just like any other catalog.

## Channel A — Puppet (framework)

**Purpose:** ship the static framework that doesn't change per request: Lua source files, nginx config snippets declaring `lua_shared_dict` and registering Lua hooks, kill-switch config.

**Source of truth:** our repo (`infra/nginx-lua-poc/lua/*.lua`, `infra/nginx-lua-poc/conf/50_lua.conf` antibot sections), mirrored into edge-puppet's `modules/nginx/files/lua/nginx2/`.

**Distribution:** standard CDN operator Puppet pipeline. PR to edge-puppet → review → agent run on edge-* via their existing cadence.

**Cadence:** human-driven. Minutes between merge and rollout. Acceptable because nothing here changes per request or per customer.

**Failure mode:** if Puppet agent fails on a edge node, that edge node stays on the previous framework version. nginx config tests via `nginx -t` block bad rollouts before reload.

**What goes here:**
- `lua/verdict.lua`, `lua/ja4_helpers.lua`, `lua/log_emitter.lua`, etc.
- `50_lua.conf` antibot sections: `lua_shared_dict` declarations, `init_worker_by_lua_block` registering the catalog-pull timer, `access_by_lua_file` hook on the request phase, `log_by_lua_block` for the log line.
- Per-pool kill-switch flag (e.g. `lua_shared_dict antibot_killswitch 1m;` populated by an `init_by_lua` from an env var or file Puppet drops).

**What does NOT go here:**
- Per-resource policy (lives in Channel C).
- Any blocklist or catalog content (lives in Channel C).
- Anything that needs to change in seconds–minutes (Puppet's cadence is wrong for that).

## Channel C — antibot-backend HTTP pull (runtime data)

**Purpose:** deliver everything that can change without a Puppet rollout: blocklists, per-resource policy, attack-mode flag, verified-bot IP allowlist.

**Source of truth:** PostgreSQL inside the antibot-backend service. Populated by client dashboard (per-resource policy), PRs (blocklists), or background workers (rDNS verified bots).

**Distribution:** edge Lua calls `ngx.timer.every(30, fetch)` in `init_worker_by_lua_block`. Each tick does conditional `GET` per catalog with `If-None-Match`. On 200 — parse, atomic-swap into `lua_shared_dict` (generation-counter scheme from [RFC §В1](edge-lua-vs-sidecar.md)). On 304 — no work.

**Cadence:** 30 s. Bounded staleness window. Sufficient for "dashboard slider moved → effect on edge" UX (sub-minute) and for emergency `attack_mode=on` (sub-minute global effect).

**Failure mode:** **fail-stale.** If the backend is unreachable, the next tick logs and skips. The previous good catalog stays in `lua_shared_dict` indefinitely. A `edge_catalog_staleness_seconds` metric per worker per catalog drives alerting. The verdict pipeline never blocks on a missing catalog.

**Auth / transport:** HTTPS to `antibot.internal:443`. mTLS (preferred) or IP allowlist from CDN operator's egress range. One cert per pool, rotated through Puppet (Channel A).

**HA:** ≥ 2 backend instances behind DNS round-robin or a small LB. Backend is stateless beyond its own DB; HA is trivial.

**Load:** pool size × catalog count / 30 s. Conservatively 50 edges × 7 catalogs / 30 s ≈ 12 req/s, of which 90 %+ are 304 with no body. A single small Go instance handles this with two orders of magnitude headroom.

## The "catalog" concept

Each thing pulled in Channel C is a **catalog**: a named, fully-versioned snapshot of one kind of data that lives in exactly one `lua_shared_dict` on the edge.

| Catalog | Shape | shared_dict | Updated by |
|---|---|---|---|
| `fp_blocklist` | set(fp_string → "block") | `antibot_fp_blocklist` | PR / future auto-pipeline |
| `ua_blacklist` | combined regex string | `antibot_ua_blacklist` | PR |
| `ip_blocklist` | CIDR list → "block" | `antibot_ip_blocklist` | PR + dashboard custom-add |
| `ip_whitelist` | CIDR list | `antibot_ip_whitelist` | PR (monitoring, check services) |
| `asn_datacenters` | set(asn → 1) | `antibot_asn_dc` | PR |
| `verified_bot_ips` | set(ip → "google\|bing\|yandex\|ddg") | `antibot_verified_bots` | backend background rDNS |
| `policy` | map(host → policy json) | `antibot_policy` | client dashboard |
| `attack_mode` | one flag, optionally per host | `antibot_attack_mode` | dashboard toggle |

**What is NOT a catalog:** anything computed/accumulated locally on the edge — `rate_*_counters`, `verdict_cache`, `tls_fp_cache`. These live only in their local `lua_shared_dict` on each worker and are never exposed by the backend.

**Rule of thumb:** if all edges should see the same value at the same time and the source is our backend → catalog. If it's per-edge runtime state → local shared_dict, not catalog.

## Per-resource lookup — keyed by Host, not by cdn_resource_id

Edge has `ngx.var.host` for free. The `policy` catalog is a map `host → policy_json`. No need for an additional `Host → resource_id` lookup, no dependency on CDN operator's resource registry.

A new edge domain that has not yet been registered in our dashboard simply has no entry in `policy`; the pipeline falls back to the pool default (initially `mode=shadow`, all rules observe-only — Phase 1 default).

This collapses the "where does resource_id come from" open question from the Phase 1 spec to nothing.

## What was rejected and why

| Rejected | Why |
|---|---|
| **Per-edge Go sidecar process** (original Phase 1 plan, also implied by ADR-001's wording) | No heavy/ML/grey-verdict logic to justify it. Burden: forces CDN operator to host our runtime binary on every edge node, multiplies failure surface, slows our release cycle to their Puppet cadence. With centralized backend, we ship a Go binary to our own infra and edges stay framework-only. |
| **Three-channel model** (Puppet + prod-edge-salt-pillars + per-edge sidecar) | Two of the three are deployment for the same kind of data (per-resource policy). prod-edge-salt-pillars route requires extending a contract we don't own, coordinated through another team. Channel C does the same work end-to-end on our side, with finer cadence. |
| **Lua reading PostgreSQL directly** | Connection pools per edge, schema coupling, no ETag protocol natively, no way to fail-stale cleanly. The catalog HTTP layer is exactly the indirection that gives us those properties for free. |
| **One-shot Puppet push of catalogs as files** | Loses sub-minute updates; emergency `attack_mode=on` can't wait for Puppet. Acceptable only as a fallback during prolonged backend outage; not the primary distribution mechanism. |

## Open items

**Channel C network reach.** Firewall rule from edge-* egress to `antibot.internal:443`, plus IP allowlist or mTLS cert distribution path. This is the one operational dependency we cannot self-serve and must negotiate with prod-edge.

Nginx-internal questions (where exactly in their cascade `access_by_lua` slots in, what `lua_shared_dict` names are chosen, how our Lua coexists with theirs) are **not on our side** — Phase 1 and Phase 2 specs put integration squarely in prod-edge-admins' zone of responsibility. We supply the reference Lua implementation, the integration spec (cascade order, hook phase, shared_dict prefix `antibot_*`), the catalog HTTP contract, and the backend. They slot it into their nginx config. The Phase 2 fp task is already issued to them on that contract; TLS termination at nginx and availability of `$ssl_*` / `$geoip_*` are already known facts (otherwise Phase 2 spec couldn't have been written).

## Terminology cleanup

| Term | Meaning |
|---|---|
| **edge** | a edge-* server. Runs nginx + Lua only. |
| **antibot-backend** | our Go service, centralized on our infra. Hosts the catalog HTTP API, owns the DB, runs background workers (rDNS), receives logs from edges. |
| **catalog** | one named, ETag-versioned data set served by the antibot-backend and held in one `lua_shared_dict` on the edge. |
| **Channel A** | Puppet path for framework code/config. Slow, human-driven. |
| **Channel C** | antibot-backend HTTP pull from edge Lua. Fast, automated, 30 s cadence. |
| **sidecar** | **deprecated term.** In older docs ([ADR-001](../architecture-decisions/001-edge-lua-vs-go-sidecar.md), [RFC](edge-lua-vs-sidecar.md)) refers to a Go process on each edge. Per this document, that process does not exist; the Go side is centralized. Read "sidecar" in older docs as "antibot-backend". |
| **Channel B** | **does not exist.** Earlier drafts had a salt-pillars channel for per-resource policy; rejected (see above table). |
