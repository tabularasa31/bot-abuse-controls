# Design #1 — challenge solve rate as a scoring signal

> **Status: IMPLEMENTED (D12).** The signal lives in `analyze.py` plus one line on
> the edge (`attack_mode` in `bac_log`); tests are in `tests/test_analyze.py`. The
> thresholds (`LOW_SOLVE_RATE`/`HUMAN_SOLVE_RATE`) still need calibration against
> real active-staging data (they are env-overridable). This develops idea #1 from
> [bot-detector-roadmap.md](bot-detector-roadmap.md) and builds on D1
> ([blocklist-scoring.md](../blocklist-scoring.md)) and C5 (challenge verify).

## The idea in one line

A fingerprint that receives JS challenges en masse and almost never solves them
(`solve_rate ≈ 0` over N issued) is a near-ground-truth bot label, stronger than any
static heuristic in the score table. The signal is **already emitted** but never
flows into the scoring.

## The key finding: the data is already in Loki, per fingerprint

Both halves are already written to `BAC_LOG` with `tls_fp` and reach Loki (the same
`log_shipper` channel) that `analyze.py` already reads:

| Half | What the event looks like | Where it comes from |
|---|---|---|
| **issued** | `verdict=challenge`, with `tls_fp` | the main flow, verdict.lua Branch A (emitted before `ngx.exit(200)`) |
| **solved** | `verdict=allow`, `rule=challenge_pass`, `tls_fp` set | [challenge_verify.lua](../../infra/demo-stand/lua/challenge_verify.lua) |

> **Correction made during implementation (D12).** The design originally assumed the
> solved half already carried `tls_fp`. That was wrong: `/__challenge/verify` is a
> carve-out without `access_by_lua`, so the L3 `tls_fp` stage never runs there and the
> emit wrote only `challenge_fp` (the browser JS fingerprint) with `tls_fp=null` →
> `_event_from_bac_line` **dropped the event**, leaving `challenge_solved` at 0 for
> everyone. So D12 adds `bac_log.set_tls_fp(ja4.compute())` on the verify path — it is
> the same client over TLS, so its fingerprint matches the issued one. Without this the
> signal would have labelled the humans who solve challenges as bots. (Found in code
> review on the PR.)

So `solve_rate(fp)` is computed **inside `analyze.py`** from halves that already reach
Loki, with no new cascade stages. The Lua change is minimal: `attack_mode` in `bac_log`
(the filter in §C) plus `set_tls_fp` on the verify path (the issued↔solved join above).
This is an extension of D1, not a new subsystem.

> A note on single use: one solved challenge yields a `clearance` cookie, and subsequent
> requests fastpath at L2.1 (`rule=cookie_valid`, also `verdict=allow`). Those must
> **not** count as new "solved" events, or one solve would inflate the numerator. We
> count `solved` strictly by `rule=challenge_pass`, not by any `verdict=allow`.

## What is wrong with the current behaviour (two defects)

`_fp_has_identity_allow` ([analyze.py:589](../../infra/demo-stand/scripts/analyze.py))
returns True for **any** `verdict=allow`, so `challenge_pass` lands in the same bucket
as `ip_whitelist` and `cookie_valid`. The consequences:

1. **One solve shields a fingerprint forever.** A modern headless browser
   (Playwright/UDC) computes `SHA-256(nonce+secret)` trivially. One solved challenge →
   the allowlist gate fails → the fingerprint cannot be auto-promoted, and in staging it
   produces `fp_caught`. The bot buys immunity with a single solve.
2. **The strongest signal goes unused.** "issued=500, solved=0" today contributes
   neither points to the score nor acceleration in staging. Pure information loss.

The root cause is **binarity**: identity-allow treats challenge_pass as harshly as real
identity. The fix is to turn challenge_pass specifically from a binary veto into a
**wager**.

## The proposal

### A. Defining the signal

**Only `mode=active` AND `attack_mode=off` events.** The signal is valid only when the
challenge was issued **as a verdict about the fingerprint itself**, not as a blanket
posture of the host:
- *shadow*: the page is never physically served (C5) → `solved` is always 0 → a false
  "bot" label for everyone. The `mode` field is in the log already (B11).
- *attack_mode=on*: L5 forces a challenge on nearly every non-`allow` request (C4),
  including ordinary browsers. Some real people leave at the unexpected interstitial
  without solving → a legitimate fingerprint accumulates unsolved challenges → a falsely
  low solve rate → the risk of a false promotion. Under attack a challenge is not a
  judgement about the fingerprint, so it stays out of the signal. **This requires logging
  `attack_mode`** (see §C).

The product consequence: the signal only "switches on" for hosts in active enforcement
**outside an attack** — a dependency on the enforcement rollout, not a bug. An attack
produces plenty of challenges, but it is the noisiest period (forced checks plus people
dropping off), so we exclude it deliberately.

**The window is cumulative (lifetime), NOT 24 h.** Challenges are rare, and a
low-and-slow bot never reaches `MIN_CHALLENGE_ISSUED` within a day (from review). So
`issued`/`solved` accumulate per fingerprint in `seen-fps.json` alongside
`count`/`days_seen`: each run increments by the delta from the fresh Loki window (the
dedup watermark already exists for `count`), **counting only active, non-attack events**.
That also removes the dependence on which daily window an event happened to land in.

> The counter is **all-time (lifetime)**, not a sliding window: robust, but slow to react
> to a change in a fingerprint's behaviour (normal for bots). There is no separate
> forgetting — a fingerprint leaves consideration through auto-demote after being silent
> for more than the TTL (14 days).

```
issued(fp)  = cumulative |events: mode==active AND attack_mode==off AND verdict==challenge|
solved(fp)  = cumulative |events: mode==active AND attack_mode==off AND verdict==allow AND rule=="challenge_pass"|
solve_rate  = min(solved / issued, 1.0)   # capped at 1.0 (see below), when issued > 0
```
**The 1.0 cap (from review):** even with cumulative counting, on a fingerprint's very
first load a solved event can fall inside the window while its paired issued event sits
below the retention boundary → `solved > issued`. `min(…, 1.0)` absorbs that, and
accumulation corrects the numbers over time.

The volume threshold for the signal is **asymmetric** (this is the key to correctness at
small N):
- the **score signal** (B1) is only awarded when `issued >= MIN_CHALLENGE_ISSUED`
  (starting at **10**) — we do not conclude "the bot does not solve" from one or two
  challenges.
- the **gate veto** (B2) does NOT ignore human solves even at small N: when
  `issued < MIN`, any `solved > 0` still vetoes (from review). Details in B2.

### B. Two independent applications

**(1) An extra score signal (ranking):**
```
issued >= MIN_CHALLENGE_ISSUED AND solve_rate <= LOW_SOLVE_RATE(0.05)  → +2, reason "challenge not being solved (issued=N, solved=M)"
```
Weight +2: between impersonator (+3) and the weak heuristics (+1) — the signal is strong
(behavioural, hard to fake) but not dictionary-precise like impersonator. It only ranks
and blocks nothing by itself (the D1 invariant: score ≠ admission).

**(2) Refining the gate (admission) — the main change:**
Split `_fp_has_identity_allow` into two classes instead of one `verdict==allow`:
- **hard identity** (`ip_whitelist`, `cookie_valid`, and so on — NOT challenge_pass):
  stays a hard veto, as today.
- **challenge_pass**: no longer a binary veto. A ladder by volume (order matters):
  - `issued < MIN_CHALLENGE_ISSUED` — **too little data to judge by rate**:
    - `solved > 0` → **veto** (a human or client solved a challenge at low volume; we do
      not risk a promotion — from review). The veto cannot be lifted at small N, where
      `solved/issued` is pure noise.
    - `solved == 0` → neutral (this signal does not veto). In practice such a fingerprint
      is almost always cut by the volume gate `n_lifetime >= MIN_EVENTS(20)`, so lifting
      the veto here changes almost nothing.
  - `issued >= MIN_CHALLENGE_ISSUED` — **enough data, judge by rate** (three zones, not
    two):
    - `solve_rate <= LOW_SOLVE_RATE(0.05)` → **no veto** (a bot that does not solve) —
      promotion is allowed **even if there were a few incidental solves** (that is exactly
      the headless case, "solved a couple out of hundreds", and precisely the "one solve
      shields forever" defect this design fixes);
    - `solve_rate >= HUMAN_SOLVE_RATE(0.5)` → **veto** (people really do solve it → there
      are humans or legitimate browsers behind it);
    - `LOW < solve_rate < HUMAN` — **a grey zone → no auto-promotion, but no hard veto
      either**: the signal is inconclusive, so we hand the decision to staging observation
      (below). In practice the fingerprint does **not** become `auto_eligible`, but it is
      an acceptable staging candidate (through a manual promote, or simply by staying in
      the report). Staging is harmless — it only logs and never blocks — so "parking a
      doubtful fingerprint under observation" is safer than either blocking hastily or
      forgiving hastily.

  > The asymmetry is deliberate: a veto can be **added or kept** on the strength of a
  > single solve (protecting humans), while **lifting** a veto requires sufficient
  > `issued`; in between there is neither a block nor a pardon, only observation.

The same split applies in `find_staging_observation`
([analyze.py:964](../../infra/demo-stand/scripts/analyze.py)), and **that is where
`HUMAN_SOLVE_RATE` acquires real meaning** (decision B). Today any identity-allow among
the staging matches gives `fp_caught`. Afterwards it is decided by the solve rate among
the matches (active only):
  - `>= HUMAN_SOLVE_RATE` → `fp_caught` (we caught real people → demote/remove);
  - `<= LOW_SOLVE_RATE` (and the other staging gates pass) → `activate`;
  - the grey zone → `observe` (stay in staging and gather more solvability data — exactly
    "watch longer"). Parking in `observe` is safe: staging does not block.

> **Important — purity does not duplicate this.** Purity (`human_share`) looks at "does it
> look like a browser" via UA, cipher and hash. Solve rate looks at the **ability to pass
> an active check**. A headless browser with a perfect browser fingerprint passes purity
> (its human_share is high), but if it does not solve challenges, the solve rate catches
> it. The signals are orthogonal; both are veto classes, from different directions.

### C. Code changes (scope)

**Edge (one line):** add `attack_mode = p.attack_mode` to the `bac_log` schema
([bac_log.lua](../../infra/demo-stand/lua/bac_log.lua):320-321, next to
`mode`/`strictness`; `p` is already read from `policy.get`). Without that field the
analytics cannot tell an attack challenge from an ordinary one. The `mode` field is
already logged (B11) and needs nothing extra. Acceptance on the backend is lenient (an
unknown field lands in the `raw` jsonb).

**`analyze.py` (the bulk of the work):**
1. `_event_from_bac_line` already has `verdict`/`rule`/`mode` (where present); add reading
   of `mode` and `attack_mode` — needed for the §A filter
   (`mode==active AND attack_mode==off`).
2. **Accumulation in `seen-fps.json`:** alongside the existing per-fingerprint fields
   (`count`/`days_seen`), add `challenge_issued`/`challenge_solved`, incremented by the
   delta on each run **from active, non-attack events only** (`load_seen`/`save_seen`
   already exist, and the watermark dedup is shared with `count`). That is the signal's
   lifetime window (see §A).
3. A pure function
   `solve_signal(seen_entry) -> {issued, solved, solve_rate(capped at 1.0), enough:bool}`
   (`enough = issued >= MIN_CHALLENGE_ISSUED`).
4. `score_fp_candidate`: add the signal branch (B1).
5. Split `_fp_has_identity_allow` → `_fp_hard_identity_allow` (without challenge_pass)
   plus a separate challenge_pass check implementing the §B2 ladder with three outcomes
   (veto / no veto / grey → no auto). Update the callers in `find_blocklist_candidates`
   (the `allowlist` gate plus clearing `auto_eligible` in the grey zone) and
   `find_staging_observation` (the `fp_caught`/`activate`/`observe` outcomes by solve rate
   among active matches).
6. New constants plus flags/env (the D1 pattern): `MIN_CHALLENGE_ISSUED`,
   `LOW_SOLVE_RATE`, `HUMAN_SOLVE_RATE` (plus `BAC_*` env).
7. Tests: a unit test for `solve_signal` (the >1.0 cap; the filter ignoring shadow AND
   attack events) plus the §B2 ladder matrix
   (issued<MIN×{solved 0,1}; issued≥MIN×solve_rate{0, 0.03, 0.3 (grey), 0.9}) plus the
   staging outcomes fp_caught/activate/observe.

An optional edge follow-up (NOT part of this design): an explicit `rule=challenge_issued`
marker instead of inferring from `verdict=challenge`, if we ever want to distinguish a
Branch A render from other challenge paths. Not needed now — `verdict=challenge` suffices.

### D. Anti-gaming / security

- **A bot solving challenges to raise its solve rate and shield its fingerprint.** To get
  past `HUMAN_SOLVE_RATE=0.5` it must solve at least half the challenges issued — already
  expensive, and more importantly it means enforcement is WORKING (it pays CPU for every
  visit). And merely to leave the promotion zone (`>0.05`) it only reaches the grey zone →
  staging observation, not instant forgiveness: getting blocked is hard, but immunity
  cannot be bought with one or two solves either.
- **Poisoning someone else's fingerprint.** The solve rate is per fingerprint; injecting
  non-solves into another fingerprint means sending traffic with the same ClientHello —
  the same threat model as purity poisoning (#5), a separate track.
- **Single use does not inflate solved** — we count strictly `rule=challenge_pass` (see
  above).

## Thresholds (starting values, overridable)

| Parameter | Start | Flag / env |
|---|---|---|
| min issued for the signal | 10 | `--min-challenge-issued` / `BAC_MIN_CHALLENGE_ISSUED` |
| low solve rate (bot) | 0.05 | `--low-solve-rate` / `BAC_LOW_SOLVE_RATE` |
| human solve rate (veto) | 0.50 | `--human-solve-rate` / `BAC_HUMAN_SOLVE_RATE` |
| weight of the signal in the score | +2 | a constant |

## Non-goals

- New cascade stages, changes to the C5 challenge mechanics, binding the nonce to a
  fingerprint.
- HTTP/2 fingerprinting and behavioural signals (#2–#4) — separate tracks.
- Per-fingerprint metrics on the edge (the stand has no per-host metrics infrastructure;
  we compute this in analytics from Loki).

## Questions settled (discussion, 2026-05-30)

1. **The window for issued/solved** → cumulative in `seen-fps.json` (lifetime), not 24 h —
   otherwise a low-and-slow bot never reaches `MIN_CHALLENGE_ISSUED`. See §A/§C.
2. **Shadow versus active** → count strictly by `mode==active`; under shadow the page is
   never served, so `solved` is always 0 and the signal is invalid. Consequence: the signal
   only works on active hosts. §A.
3. **Attack mode** → **exclude attack-mode events** (`attack_mode==off`). Under attack L5
   forces a challenge on everyone (C4) and real people abandon the interstitial → a falsely
   low solve rate. A challenge under attack is the host's posture, not a judgement about the
   fingerprint. The cost: **one extra line on the edge** (`attack_mode` in `bac_log`), so
   "analyze.py only" is no longer accurate. §A/§C.
4. **Branch B/C** (`non_browser_blocked`/`unchallengeable`) → **ignored**: the cascade logs
   them as `verdict=block`, so they never enter the `issued` denominator (which counts only
   `verdict=challenge`); and they are blocked already. The pattern "a browser, but always
   Branch C" is a signal for track #4 (behaviour), not for this one.
5. **Threshold structure** → three zones, not two: the grey zone `LOW<rate<HUMAN` means
   **no auto-promotion and no hard veto**, only staging observation. That is what gives
   `HUMAN_SOLVE_RATE` real meaning (on the staging→active decision). §B2.
6. **Growth of `seen-fps.json`** from the two new fields stays within the existing D7 (state
   rotation) and needs no separate decision.

## Left for calibration (not blocking the code)

- The concrete values of `LOW_SOLVE_RATE` (starting at 0.05) and `HUMAN_SOLVE_RATE`
  (starting at 0.5) — to be tuned against real active-staging data from the stand once it
  accumulates. They are exposed as flags/env and change without touching code.
