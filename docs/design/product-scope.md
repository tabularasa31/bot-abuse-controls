# Product frame — how far we are aiming (post-post-MVP)

> **Status: STRATEGY / horizon.** This document is about the **ceiling of ambition**
> for the product, not a task plan and not a behavioural contract. Nothing below is
> **implemented** or promised for near-term implementation — for the current status
> see [ROADMAP.md](../../ROADMAP.md). The concrete WAF/DDoS roadmap is
> [research/waf-ddos-roadmap.md](../research/waf-ddos-roadmap.md).

## Where this sits on the product timeline

```
MVP                       →  post-MVP                →  post-post-MVP (this document)
vision.md / phase1+2      the D series (scoring,      WAF, L7/L3 DDoS, API/account
the challenge cascade     the blocklist cycle,        protection — new AXES of the
(C series closed)         behavioural signals)        product, adjacent disciplines
[done]                    [in progress]               [horizon / deciding where to grow]
```

- **The MVP is [vision.md](../product/vision.md) plus phase1/phase2 plus the C series.** The
  L1→L5 cascade, the challenge, clearance, Channel C, the policy. Built — see
  [ROADMAP.md](../../ROADMAP.md).
- **post-MVP is the D series.** Deepening the detector: scoring plus the blocklist
  cycle (D1), challenge solve rate, the subnet unit, anti-poisoning, threat intel,
  behavioural signals. This is the **same core** (bot management), done more
  intelligently. It is what we are doing now.
- **post-post-MVP is this document.** Not "a smarter detector" but **new disciplines
  alongside**: WAF, anti-DDoS, API/account protection. A different axis, not a
  continuation of D.

This document answers "what can we credibly aim at at all", so that post-post-MVP is
chosen deliberately rather than drifted into.

## 1. What we are architecturally (and why that sets the ceiling)

The product is a **programmable L7 security edge**: an OpenResty reverse proxy that
**terminates TLS** and runs a verdict cascade, with a Go backend
(`antibot-backend`), catalog delivery over Channel C (ADR-005/006) and a
shadow→staging→active workflow.

The main consequence is that **where we physically sit determines the boundary of the
ambition**:

1. **Anything decidable from the HTTP request after the TLS handshake is our field.**
   The client fingerprint (JA4 — we already compute it), headers, body, behaviour,
   IP/ASN reputation, frequency, challenge outcome. That is an enormous territory.
2. **Anything below that — packet-level and volumetric floods (SYN, UDP,
   amplification) — is NOT ours alone.** By the time traffic reaches nginx the
   handshake has already happened. That is the network layer (eBPF/XDP, anycast
   scrubbing, BGP) — the territory of network infrastructure.

> **The compass for every "could we do…":** *"is this decidable from the request?"* →
> yes, we can take it on; no, we are a signal supplier to the network layer, not the
> one that acts.

## 2. Categories we can credibly take on

The cascade plus Channel C plus shadow/active plus cross-tenancy stretch into adjacent
disciplines with almost nothing reinvented:

| Category | Proximity | What we reuse |
|---|---|---|
| **Bot management** | ✅ this is the product | the whole cascade |
| **L7 anti-DDoS** (application flood) | ✅ half the way there | `rate_limit` (A7/A10) plus `attack_mode` (C7) plus the challenge (C5) |
| **WAF** (SQLi/XSS/path traversal/…) | 🟡 greenfield, the architecture is ready | Channel C, `policy.enforce`, `bac_log`, staged rollout |
| **API security** (endpoint abuse, schema) | 🟡 a natural extension | `rate_api`, per-host policy |
| **Account protection** (credential stuffing, brute force) | 🟡 close | reputation plus rate plus challenge plus fingerprint |
| **Anti-scraping / content** | 🟡 close | fingerprint plus behaviour plus verified bots |
| **A threat-intel network** (the network effect between tenants) | 🟡 already designed | [cross-tenant-threat-intel-design](../research/cross-tenant-threat-intel-design.md) |

**The realistic ceiling** is "an L7 security edge for our niche of tenants": bot
management plus WAF plus L7 DDoS plus API/account protection, under one verdict engine
and one catalog workflow. Not "become the next Cloudflare wholesale", but occupy its L7
security layer for our own customers.

## 3. Where we would overreach (needs a partner / is not us)

- **Volumetric L3/L4** — only in combination with the network layer (network
  infrastructure). OpenResty does not close this alone. Our role is a **signal
  supplier** (an edge-ACL feed: "drop this source at the firewall"), not the one
  executing the drop.
- **Global anycast / scrubbing centres** — operator infrastructure, not our Lua.
- **The CDN cache and content delivery itself** — an adjacent discipline. We are a
  security layer *on top of* a CDN, not a replacement for one.

Per the project scope, everything in this section is **reality level 3**
(the territory of network and infrastructure admins, with no production access). Do not
present it as done; if a production network becomes necessary, that is a separate phase
with access — **ask**.

## 4. Our moat — what to build the ambition on, rather than playing catch-up

Not "yet another WAF" — on bare signatures, mature engines will outrun us. What is
distinctive here:

1. **TLS/JA4 fingerprinting plus behaviour.** Most WAFs do not do this; we already
   compute the fingerprint at the edge (ADR-002/004). It catches bots signatures never
   see.
2. **Channel C plus git catalogs plus shadow→staging→active** (ADR-006). Operational
   maturity in rule delivery, out of the box, is rare. WAF signatures drop into the same
   workflow.
3. **Cross-tenant threat intel.** An attack on one tenant is immunity for the rest. A
   strong and rare lever (reputation is global, the enforcement stance is per tenant).

**Conclusion:** it is worth aiming at a "programmable L7 security edge" differentiated
by fingerprinting plus threat intel, rather than at "replacing the network/CDN/scrubbing",
where we are a signal supplier rather than the one that acts.

## 5. How this document relates to the others

- [vision.md](../product/vision.md) — the behavioural contract of the MVP (what the edge does with
  a request). This document is the **horizon beyond vision**, and does not override it.
- [research/waf-ddos-roadmap.md](../research/waf-ddos-roadmap.md) — the concrete phases
  and tickets for the first two post-post-MVP axes (WAF, DDoS).
- [research/bot-detector-roadmap.md](../research/bot-detector-roadmap.md) — post-MVP
  (deepening the detector, the D series). This document is the **next layer of ambition**
  above it.
