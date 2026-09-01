# Bot detector — directions for development (ideas)

> **Status: PLANNED / research.** This is a snapshot of the brainstorm on "where
> to grow the detector after D1 (scoring plus the blocklist cycle)". None of the
> below is **implemented** in the stand until it has explicitly moved into
> PROGRESS.md → "IN PLACE TODAY". Do not present it as done. The baseline is the
> closed D1 (see [blocklist-scoring.md](../blocklist-scoring.md)).
>
> **Triage complete (2026-05-30): all six ideas worked up into design docs and tickets.**
> #1 [solve-rate](challenge-solve-rate-design.md) (D12) · #2 [positive fp catalog](positive-fp-catalog-design.md)
> (D13, plus spike R2 HTTP/2) · #3 [subnet unit](subnet-unit-design.md) (G1/G2/G3) ·
> #5 [anti-poisoning](scoring-anti-poisoning-design.md) (D18/D19) ·
> #6 [cross-tenant threat intel](cross-tenant-threat-intel-design.md) (G4) ·
> #4 [behavioural signals](behavioral-signals-design.md) — **design frozen,
> implementation DEFERRED** (worst effect-to-accuracy ratio). The priority from
> here is implementing #1/#3/#5, not adding new signals.

## The baseline (what exists today, D1)

The cycle `analyze.py` → staging → active → auto-demote. **The score only ranks**;
admission is decided by the gates (purity veto `human_share≤0.05`, volume,
allowlist/verified, dedup) plus intent (`impersonator OR recon-on-non-generic`).
Confirmation happens by observation in staging, and exit is by inactivity (TTL).
The source is Loki through `antibot-analytics`, and the output is a draft PR
against `catalogs/`.

Three observations that set the direction:
1. The decision rests on **one dimension** — the TLS fingerprint (a JA4-like
   ClientHello). Fingerprints are cheap to rotate.
2. The scoring works on **aggregates per fingerprint**, with no behavioural or
   temporal dimension.
3. **Strong labels are already accumulating that never feed back into the
   scoring** — challenge outcomes (`challenge_issued`/`challenge_solved`),
   clearance results, `staging_match`.

## Directions

### #1 — Feed challenge outcomes back into the scoring  ⭐ priority
A fingerprint that receives challenges en masse and almost never solves them
(`solve_rate≈0` over N issued) is a near-ground-truth bot label, stronger than any
static heuristic. The signal is already emitted (C5:
`antibot_challenge_issued_total` / `solved_total`) but flows nowhere. The idea:
use `solve_rate` per fingerprint as (a) an extra score signal and (b) an
accelerated staging→active gate. This is the cheapest of the lot — an extension of
D1, with no new cascade stages. **The detailed design is in its own document.**

### #2 — Extend the fingerprint beyond TLS
- **HTTP/2 fingerprint** (SETTINGS frame order, WINDOW_UPDATE, pseudo-header
  order) — orthogonal to TLS, and it breaks cheap JA4 rotation. Today this
  dimension does not exist at all.
- It overlaps with the backlog: **D2** (positive fp catalog: known-browser cipher
  hashes plus version), **D3** (UA version versus fp version mismatch), **D4**
  (a headless catalog for Playwright/Puppeteer/UDC). D2+D3 together catch
  home-grown and headless stacks **without** a tool dictionary (mismatch instead
  of impersonator).

### #3 — Raise the unit of analysis above a single fingerprint
Today we block a fingerprint. Introduce correlation across **fp × IP/ASN subnet ×
behaviour**: one fingerprint across a datacenter /24 doing recon is a different
thing from the same fingerprint across thousands of residential IPs. That gives
subnet-level reputation plus protection against fingerprint rotation within a
pool. reputation.lua already knows the ASN and geo — the scoring does not use it.

### #4 — Behavioural / temporal signals
The score is currently binary-additive over static properties. Add inter-request
intervals (rhythm), the absence of human jitter, navigation graphs (a bot walks
the sitemap or recon paths, not links). This moves the detector from
signature-based to behavioural — the lever against low-and-slow bots that stay
under the rate limit and never expose a tool fingerprint.

### #5 — Scoring robustness (anti-poisoning)
The cycle is partly automated (a draft PR on HIGH), so it is an attack surface. An
adversary can drive "human-looking" traffic under a target fingerprint to raise
`human_share` and shield it from a block (or to poison someone else's
fingerprint). To think through: the purity veto's resistance to injection,
diversifying event sources, and a daily-snapshot diff of the evidence chain
(already noted as a future follow-up in blocklist-scoring.md).

### #6 — Cross-tenant threat intel (the network effect)
An attack on one customer is free reconnaissance protecting all the others. The
principle: **the attacker's reputation (fp/subnet/ASN) is global, the enforcement
stance (attack_mode/drop) is per tenant**. The global catalogs (ADR-006:
`tls_fp_blocklist` / `ua_blacklist` / `asn_datacenters`) are already
cross-tenant — that is the slow, PR-gated tier. What is new is a **fast tier**: a
short-TTL hot list of active attackers, auto-published during an attack and
pre-arming ALL edges (challenge-first, a lower threshold), so that when a botnet
pivots from A to B the others react within seconds. The promotion bar is high (a
false positive now hits everyone, which raises the importance of #5). Design: see
the dedicated document. Related to G1 (`subnet_reputation` is worth making global)
and G2 (hot /24s).

## Relation to the existing D-series backlog (PROGRESS.md)
- Already filed: **D2, D3, D4** (catalogs/mismatch), D5 (cache), D6 (metrics), R1 (DBSC).
- New or not yet written up: **#1** (challenge solve rate → scoring), **#2 HTTP/2 fp**,
  **#3 subnet/behavioural unit**, **#4 behavioural signals**, **#5 anti-poisoning**,
  **#6 cross-tenant threat intel**.

Priority by effect over cost: **#1** first (the data is already there), then **D2+D3**.
