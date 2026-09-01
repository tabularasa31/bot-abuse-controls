# Design #5 — scoring robustness (anti-poisoning)

> **Status: PLANNED / design draft.** Not implemented. This is idea #5 from
> [bot-detector-roadmap.md](bot-detector-roadmap.md). It builds on D1
> (scoring/purity/gates), `enrich_ips` (the hosting flag) and D13/#2 (the positive
> catalog). Cross-tenancy (#6) raised its priority: poisoning now hits every
> tenant.

## The idea in one line

The decision to put a fingerprint on the blocklist is partly automated, so an
attacker will try to fool it. #5 is the set of safeguards around that decision
that make fooling it expensive.

## Threat model

1. **Defensive poisoning** — shielding your own bad fingerprint: inflate
 `human_share`, or trigger `fp_caught` in staging so the fingerprint never
 activates.
2. **Offensive poisoning** — getting someone else's legitimate fingerprint
 blocked (pour recon traffic under their fingerprint).
3. **Cross-tenant amplification (#6)** — the same, but with a blast radius across
 every tenant. **Already mitigated** by the #6 design: the fast tier only
 pre-arms (the worst case is a captcha, not a block).

A metaphor: `human_share` is a "vote that real people are behind this
fingerprint". The attack is ballot stuffing. The safeguards are about **whose
votes count**.

## Finding: purity is easier to poison than it looks

`is_genuine_browser` ([analyze.py:524](../../infra/demo-stand/scripts/analyze.py))
depends on the UA, `cipher_count` and the hashes, but **`cipher_count` and the
hashes are FIXED within a fingerprint** (they are part of the token) — only the UA
varies. Which means:
- for a fingerprint of non-browser shape (a non-browser cipher_count, or a hash in
 the tool dictionary) `human_share` is **structurally 0** and cannot be inflated;
- inflation is only possible for a fingerprint that is **already** browser-shaped —
 and the blocklist is cautious with those anyway (challenge territory, #1).

→ Defensive poisoning of purity is confined to the class of fingerprints where
caution is already warranted.

## The real hole: `is_genuine_browser` does NOT look at the source

`is_genuine_browser` checks UA, cipher and hash, but **not the source IP**. So
"human" votes can be poured **from a datacenter** (where a real human almost never
browses from) or **from a single injector**. This is the main open vector.

## Phase 1 — a weighted human_share (points 2+3; analyze.py only)

`human_share` stops being a plain ratio and is computed **weighted by source**:

```
group events by source (IP; consider ASN or /24)
NUMERATOR (genuine votes):
 weighted_genuine = Σ_source min(genuine_from_source, CAP) × source_weight
 source_weight = W_DC (<1) if hosting else 1 # point 2: SOFT datacenter discount
 min(…, CAP) # point 3: anti-concentration
DENOMINATOR (all traffic):
 capped_total = Σ_source min(total_from_source, CAP) # point 3: cap ONLY, NO W_DC
human_share = weighted_genuine / capped_total
```

- **Point 2 — a soft datacenter discount (decision: not a hard exclusion).** A
 genuine event from a datacenter source counts with weight `W_DC < 1` rather than
 being zeroed. This weakens inflation from datacenters without **cutting off**
 legitimate users behind a corporate or cloud egress (which geolocates as
 hosting) — hence "soft". Full exclusion was rejected because of that edge case.
- **Point 3 — anti-concentration, applied SYMMETRICALLY (numerator AND
 denominator; from review).** One source contributes at most `CAP` to both sides.
 Without a cap on the denominator there was a hole for **offensive framing**:
 pour a large volume (even genuine-looking) from one IP under someone else's
 fingerprint → the numerator sticks at `CAP` while the raw `total_events` grows →
 `human_share` falls below `MAX_HUMAN_SHARE` → the legitimate fingerprint gets
 blocked. Capping the denominator per source closes that.
- **Why `W_DC` is NOT applied to the denominator (a subtlety):** the datacenter
 discount belongs in the numerator only. Discounting the denominator too would
 cancel `W_DC` out (for a fingerprint made of pure datacenter traffic both
 `weighted_genuine` and `capped_total` drop equally → `human_share` is unchanged),
 and the protection against defensive poisoning would vanish. The denominator gets
 the cap only, at full weight.
- **It applies in TWO places:** the promotion purity gate (`human_share` in
 `find_blocklist_candidates`) AND the staging veto (`human_share` among the
 matches in `find_staging_observation`) — otherwise an attacker inflates "human"
 matches in staging → `fp_caught` → the fingerprint never activates.
- **Scope:** `analyze.py` only. `ip_cache` has to be threaded into `human_share`
 (it is not passed today). **Implementation gap (from review):** the
 `--staging-observation-json` path (`find_staging_observation`) currently does
 **NOT call `enrich_ips`** (unlike `--candidates-json` and the default), so
 `ip_cache` carries no hosting data. The implementation must **enrich the IPs** of
 the matches (`staging_match` events / `events_all`) before
 `find_staging_observation`, or the datacenter status in the staging veto will be
 wrong. New constants/flags: `W_DC`, `CAP` (plus `BAC_*` env). Start conservatively
 (W_DC not too small, so nothing is blocked in haste; a sensible CAP).
- **Tests:** genuine-looking injection from a datacenter (numerator discounted), a
 single injector inflating the denominator under someone else's fingerprint (the
 denominator cap defeats framing), mixed traffic, and the staging veto with
 enrichment.

## Phase 2 — separate work (points 4+5)

- **Point 4 — the known-good invariant:** a fingerprint matching the positive
 catalog (#2 / D13) is **never auto-blocked** (framing protection: you cannot
 frame Chrome or Firefox). Depends on D13.
- **Point 5 — a snapshot diff at the boundary:** catch "the evidence jumped right
 before promotion or activation", which is the signature of gaming → pause and
 escalate to a human (already noted as a future follow-up in
 blocklist-scoring.md).

## The final backstop (always)

There is no auto-merge — every promotion goes out as a draft PR and a human looks
at each one. #5 raises the **cost** of deception; it does not make it impossible.

## An honest limitation

A well-funded attacker with a large **residential** proxy pool plus
diversification can still poison slowly (residential IPs are not discounted, and
the concentration is spread out). It is expensive, slow, and caught by a human at
the final step. That is behaviour (#4) and challenge (#1) territory, not purity.

## Cross-links

- **#2** provides point 4 (the known-good invariant) — Phase 2.
- **#6** is already mitigated to pre-arm-only; #5 is the main defence of its fast
 tier against poisoning.
- **#3** datacenter detection (`hosting`) is reused by point 2.

## Non-goals

- Edge changes — none, this all lives in analytics.
- Full datacenter exclusion — rejected (soft discount instead).
- Behavioural modelling against residential pools — that is #4.
