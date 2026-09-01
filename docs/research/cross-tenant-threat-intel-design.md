# Design #6 — cross-tenant threat intel (the network effect)

> **Status: PLANNED / design draft.** Not implemented. This is idea #6 from
> [bot-detector-roadmap.md](bot-detector-roadmap.md). It builds on the global
> catalogs, B9 (the log receiver), Channel C (B5/B6), G1/G2 (the subnet unit) and
> the solve-rate work (solve rate).

## The idea in one line

An attack on one customer is free reconnaissance protecting all the others. When a
botnet hits tenant A, the attacker's reputation (fingerprint/subnet) propagates so
that **every edge is pre-armed**, and when the botnet pivots from A to B the others
react in seconds rather than minutes.

## The governing principle

**The attacker's reputation is global; the enforcement stance is per tenant.**
- The badness of a fingerprint/subnet/ASN belongs to the BOT, not the victim → share
  it globally.
- attack_mode / drop / strictness are the state and risk tolerance of a SPECIFIC
  tenant → do not impose A's wartime posture on B's users.
- Only the attacking side (fp/IP/subnet/ASN) crosses tenants. Tenant A's data (host,
  URL) never reaches B — isolation is preserved.

## Two tiers (by confidence and speed)

| | Slow tier (ALREADY exists) | Fast tier (NEW) |
|---|---|---|
| What | `tls_fp_blocklist` / `asn_datacenters` | the `active_threats` hot list |
| Confidence | high, **human-gated** (PR) | automatic, during an attack |
| TTL | permanent (until auto-demote) | minutes to hours, **self-expiring** |
| Action at the tenant | block/challenge per policy | **pre-arm only** (challenge-first), NOT an auto-block |
| Channel | Channel C (PR, ≤15 min) | Channel C (≤30 s) |

The fast tier is deliberately **softer**: it is generated automatically with no
human in the loop, so it only *pre-arms* rather than blocking. Blocking stays with
the slow, PR-gated tier.

## The full flow

```
1. An attack on tenant A → the edge sees bad fingerprints/subnets (reactive signals, G2)
2. The backend fast aggregator confirms ATTACKER-SIDE BADNESS (a high bar):
     • subnet: datacenter-only + churn + human_share≈0 + participation in an active attack
     • fp: confirmed bad (impersonator / on the blocklist / solve_rate≈0 with volume)
     ← "was present during an attack" is NOT sufficient on its own (a real user
       caught in the attack window must not qualify)
3. Publish into the global active_threats (short TTL) → Channel C
4. ALL edges pull the list (≤30 s)
5. At each tenant, those fingerprints/subnets are PRE-ARMED:
     • +score / a lower threshold / challenge-first
     • a tenant UNDER attack → may escalate to DROP (local G2 logic)
     • a tenant NOT under attack → challenge-first only, NEVER an auto-block
6. Entries expire on their own TTL
     if repeated or confirmed → promoted into the SLOW tier by the usual
     PR-gated pipeline (D1/G1)
```

## The fast aggregator (Q2 — on the backend, speed is the point)

**Stream-driven, not a Loki batch.** The daily `antibot-analytics` is far too slow.
The aggregator **sits on the live log stream that already exists** (the B9 log
receiver takes BAC_LOG as it arrives), keeps a **short rolling window in memory**
(per-subnet and per-fingerprint counters: challenge rate, solve rate, churn,
human_share) and publishes `active_threats` when the thresholds are crossed. It is
fast because there is no round trip to Loki.

Implementation notes:
- The in-memory rolling state is lost on restart — **acceptable** (ephemeral
  short-TTL data, rebuilt within minutes).
- HA backend: with several instances, each needs the full stream OR a shared rolling
  state. The stand runs a single backend, which is fine; HA is a follow-up.

## Propagation (Q1 — Channel C, ≤30 s)

A new `active_threats` catalog over the same Channel C (ETag/If-None-Match, atomic
swap into a shared_dict, like the rest). A ≤30 s pivot window is enough against
manual and semi-manual botnet retargeting. A dedicated "fast channel" would be
over-engineering; we are not building one.

## The action at the tenant (Q3 — pre-arm only)

An entry in `active_threats` does not block automatically at a tenant. It:
- adds **+score** / lowers the threshold / makes those fingerprints and subnets
  **challenge-first**;
- leads to a DROP **only** if the tenant is itself under attack (its own
  attack_mode) AND the local G2 signals agree.

**That is the built-in protection against poisoning (#5):** the worst a poisoned
hot list can do is put a captcha in front of a few tenants, not block them.
Auto-blocking stays with the slow, human-gated tier. Cross-tenancy raises the
leverage of poisoning, which **raises the priority of #5**.

## The promotion bar (higher than for a local action)

A false positive in `active_threats` hits EVERY tenant, so the confidence bar is
above the local one:
- the same purity / human_share / datacenter-only gates as D1/G1, but stricter;
- "an active attack" is context, not a sufficient condition; combine it with
  attacker-side badness.

## Opt-out (Q4 — not needed)

The default is on, and we are not adding an opt-out flag. Only attacker-side
reputation is shared (never tenant data), isolation is not broken, and the value of
the network effect is maximised.

## What this pins down in adjacent tickets

- **G1:** `subnet_reputation` must be designed as a **global** artifact (not per
  host), otherwise cross-tenancy has to break it later. (A comment was added to G1.)

## Non-goals

- HA replication of the aggregator's rolling state — a follow-up (the stand is a
  single instance).
- Auto-blocking from the fast tier — rejected (pre-arm only).
- Sharing anything beyond attacker-side identifiers.

## Dependencies

- B9 (live log ingest) — the stream source for the aggregator.
- Channel C (B5/B6) — propagation of `active_threats`.
- G1 (subnet reputation, global), G2 (reactive attack signals), the solve-rate work (solve rate).
- Reinforces and is reinforced by #5 (anti-poisoning).
