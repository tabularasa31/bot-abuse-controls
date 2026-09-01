# Design #3 — the subnet as the unit of analysis (plus auto attack mode)

> **Status: PLANNED / design draft.** Not implemented. This develops idea #3 from
> [bot-detector-roadmap.md](bot-detector-roadmap.md). It builds on D1 (per-fingerprint
> scoring), C7 (attack_mode), B10/B11 (per-host policy) and reputation/geoip
> (asn/hosting).

## The idea in one line

Raise the unit of analysis above a single fingerprint. An adversary rotates
fingerprints cheaply (a fresh JA4 slips under D1's per-fingerprint thresholds), but
**changing the IP pool is expensive** — they are locked into their datacenter /24.
Aggregating by subnet makes the rotation signature visible (many short-lived
fingerprints from one pool) and lets us respond at the pool level.

## What already exists (this is not greenfield)

- A mature **per-fingerprint pipeline** (D1): score, gates, staging, promote.
- Network data is already collected: `enrich_ips` (asn/hosting), `geoip.lua`, the
  `asn_datacenters` catalog, a CIDR-aware `ip_blocklist` (`lua-resty-ipmatcher`) plus
  Channel C.
- **`find_asn_watch_candidates`**
  ([analyze.py](../../infra/demo-stand/scripts/analyze.py)) — ASN aggregation, but
  **report-only and coarse** ("all events bot-like AND ≥2"); it computes `n_fps` and
  then does nothing with it, and is marked "ASN-level challenge, **not hard block**".
  It *sees* rotation without *acting* on it.

## The governing principle (the conclusion of the discussion)

> Permanently: soft only (reputation → points/challenge) and only for datacenters.
> Hard (drop): only for the duration of an attack, against a narrow pool, with
> automatic lifting, and only once a challenge stops paying for itself. **No
> persistent IP block catalogs** (an IP is a shared, reassignable resource; a
> persistent block decays into false positives).

## Telling a datacenter pool from a human one (common to both phases)

Asymmetric, erring on the side of caution (mistaking a residential pool for a
datacenter would mean aggregating real people):
- **The primary gate is the `asn_datacenters` catalog** (curated, PR-reviewed,
  trusted). Only that counts as "definitely a datacenter".
- **The `hosting` flag** from `enrich_ips` (ip-api) is NOT an automatic gate but a
  **candidate supplier**: the analytics proposes new hosting ASNs for the catalog
  (in the report, or as a draft PR) and a human confirms.
- **Mixed ASNs** (one provider serving both hosting and residential) — do not trust
  the ASN level; require **the /24 itself to pass the thresholds** (rotation, recon,
  zero humans).
- **The unit of action is a /24 (v4)**; the ASN is only a datacenter classifier and
  context. **IPv6 is a separate, conservative case** (a datacenter gets a /48, a
  household a /56–/64 → Phase 1 is v4-only).

## Phase 1 — "quiet pool reputation" (always on, soft, blocks nobody)

**The per-/24 decision algorithm** (the slow analytical cycle, over Loki logs):

```
1. Is this a datacenter? (asn_datacenters; for mixed ASNs, judge the /24 itself)
     no   → STOP, we do not score the pool (behind a residential /24 are real people)
     yes  → continue
2. Does it look like a bot farm? Three markers:
     • fingerprint rotation — many distinct fps from one pool (n_fps/churn)
     • almost nobody passes a human check (human_share ≈ 0)
     • plenty of recon URIs (/admin, /.env, …)
3. Markers present → the pool is flagged "suspicious" (reputation):
     (C) every fingerprint from the pool gets +score in the per-fp pipeline (D1 reinforcement)
     (B) optionally, visitors from the pool see a challenge more readily (Strictness↑)
   No markers → nothing happens.
```

**Guarantees:** no blocking (the worst case is one captcha for a real user),
datacenters only, reversible (once a pool goes quiet its reputation decays, like a
fingerprint's auto-demote).

**Output:** a slowly updated list of "suspicious datacenter pools" (an analytics
artifact, served over Channel C as `subnet_reputation`).

## Phase 2 — "hard, but only during an attack" (transient, self-lifting)

This depends on the host being **in attack_mode** (manually or automatically — see
below). The decision is **edge-reactive** (the daily cycle is far too slow for
"right now").

**The per-datacenter-/24 decision algorithm during an attack:**

```
1. A pool under attack gets the usual response — a challenge.
2. Escalate challenge → DROP only once the challenge stops paying for itself:
     (a) the pool's challenge rate hits the edge's CPU/bandwidth budget (volumetric); OR
     (b) the pool's solve_rate ≈ 0 WITH issued >= MIN_SUBNET_CHALLENGES (the D12 guard):
         thousands issued, near zero solved → we are burning CPU for nothing
3. The DROP carries a short TTL:
     • it lifts itself on TTL expiry or when the attack ends
     • it is runtime state (a shared_dict), NOT a catalog entry, with no manual cleanup
```

**A minimum threshold before solve_rate (from review).** Criterion (b) applies only
when `issued >= MIN_SUBNET_CHALLENGES` — otherwise one or two unsolved challenges
from a quiet legitimate subnet would give a formally correct `solve_rate≈0` and a
false DROP. This is the same asymmetric guard as in D12 (`MIN_CHALLENGE_ISSUED`).
Criterion (a), being volumetric, does not fire at small N anyway.

**Protecting edge memory (from review).** Distributed rotation across an enormous
number of /24s could exhaust the `shared_dict` (shared memory exhaustion). Hence a
hard **cap on the number of simultaneously tracked subnets** plus **LRU eviction**
(the ngx shared dict evicts LRU on OOM anyway, but we make the cap explicit for
predictability). Eviction is safe: a /24 dropped from tracking simply returns to the
ordinary challenge path rather than a DROP — fail-open towards leniency. This
overlaps with D7 (bounded state growth).

**The prior:** the Phase 1 list pre-arms hot /24s (a lower threshold and a faster
reaction when attack_mode flips).

**How we know a challenge has become a load (Q1):** the rate of
`antibot_challenge_issued_total` (C5) times its cost against the edge budget, plus
`cascade_ms` (BAC_LOG timing); and `solve_rate≈0` for the pool (D12) — the formal
signal that the challenge here is pure load. Both are observable in
metrics/Grafana.

**Guarantees:** the hard action lives for minutes, not forever; a challenge always
comes first with drop as the fallback; datacenters only; no decaying IP lists.

## A dependency — automatic attack mode (a separate ticket)

The manual attack_mode toggle is the weak point (an attack at night with the
customer asleep means Phase 2 never engages). Automatic attack detection raises the
mode on the customer's behalf, **with their explicit permission**.

**A new per-host flag, `auto_attack_mode`** (in the policy, next to `attack_mode`;
Channel C plus a dashboard PATCH, like C7/B10):
- **`false` (default, conservative):** we never change attack_mode ourselves, only
  the customer does. **But detection still runs, so we alert:** "we detected an
  attack — turn on attack_mode, or grant us the right to turn it on ourselves".
- **`true`:** on detection we raise attack_mode ourselves (with hysteresis and
  automatic lifting); a customer override still wins.

**Detection works on "bad" traffic, NOT on raw volume** (so a flash crowd of real
people is not punished), relative to the host's baseline:
- a spike in bot-like verdicts or challenges issued;
- the host's `solve_rate` falling through the floor (D12);
- **the origin under stress** — rising `upstream_response_ms`/`proxy_ms` (the BAC_LOG
  timing fields already exist).

**Turning ON and OFF use DIFFERENT signals (from review, anti-oscillation):** origin
stress is only valid as an ON signal. It must NOT be used to lift the mode: as soon
as protection engages, load on the origin drops and its metrics normalise → the
system concludes "the attack is over" → switches off → the attack hits the origin
again → on/off oscillation. So **turning OFF is driven strictly by edge metrics**:
the volume of bot-like, challenged and dropped requests falls below a threshold and
stays there for a cooldown window. Origin health plays no part in the decision to
lift.

**Whoever turned it on turns it off:** what was raised automatically is lifted
automatically after the lull (per the edge metrics above); a customer's manual
setting is left alone; a manual action always outranks an automatic one. We record
the "source" of the current attack_mode (auto versus manual) — there is precedent
for distinguishing who and when in C7 (clearance pre/during attack).

**Scope:** automatic attack mode benefits the WHOLE attack path (C4/C5/C7 all hang
off attack_mode), not just Phase 2 → it gets its own ticket, and Phase 2 is a
consumer of it.

## Breakdown into tickets

- **[G1] #3 Phase 1** — subnet reputation (soft, analytics): the datacenter gate,
  /24 aggregation of churn/human_share/recon, +score for the fingerprint, an upgrade
  to `find_asn_watch_candidates`, optionally soft Strictness through the Channel C
  `subnet_reputation`. Does not touch the attack path.
- **[G2] #3 Phase 2** — transient subnet challenge→drop during an attack:
  edge-reactive /24 counters, the attack_mode gate, escalation on budget or solve
  rate, TTL plus automatic lifting, and the prior from G1. Depends on G3.
- **[G3] automatic attack mode** — adaptive attack detection (bad traffic plus
  origin stress), the `auto_attack_mode` flag (default off) with an alert while it
  is off, automatic on/off with a recorded source, and the customer override.

## An honest limitation (both phases)

This closes **cheap datacenter fingerprint rotation** but **not residential proxy
networks** (their IPs are spread across thousands of legitimate residential ASNs
specifically to defeat IP reputation, and they never pass the datacenter gate). That
is the territory of #1 (challenge/solve rate) and #4 (behaviour), not the subnet
unit.

## Non-goals / phase boundaries

- A persistent CIDR block in `ip_blocklist` as an automatic mechanism — **rejected**
  (it decays).
- An IPv6 unit — kept separate and conservative (Phase 1 is v4).
- Behaviour over time (rhythm, navigation) — that is #4, not #3.
