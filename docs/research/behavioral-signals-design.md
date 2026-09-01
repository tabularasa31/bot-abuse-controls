# Design #4 — behavioural / temporal signals (DEFERRED)

> **Status: PLANNED / design draft, DEFERRED.** Not being implemented now. This is
> idea #4 from [bot-detector-roadmap.md](bot-detector-roadmap.md). The decision
> (2026-05-30): freeze the design and **do not rush the code** — #4 has the worst
> effect-to-accuracy ratio of the six ideas. The open questions below are NOT
> settled; they get answered when the work is actually picked up.

## Why #4 matters (its strategic role)

It answers the limitation that kept surfacing in #1/#3/#5: a bot on a **residential
proxy pool** with a **perfect browser fingerprint** defeats the fingerprint
signals, the subnet unit and purity alike. Only **behaviour** gives it away — even
with flawless disguise it does not move like a human. #4 is the last lever against
the most sophisticated bots.

## Why we are not rushing

- It is the **noisiest and most false-positive-prone** of the six: humans are
  varied (SPAs, prefetch, API clients, accessibility tooling), so a behavioural
  signal must be **soft (+score/challenge), NEVER a hard block on its own**.
- **Real infrastructure cost:** attributing an actor over time, per-tenant
  specifics, noise.
- It is more valuable to **finish implementing the already-designed** #1/#3/#5
  than to build the least precise signal.

## The core problem — attributing an actor over time (the main fork)

Behaviour has to be tied to an actor across several requests. The available keys
and their weaknesses:
- **IP** — weak (NAT/CGNAT/residential proxies);
- **fingerprint** — rotates;
- **clearance session** — only exists after a challenge, but it is the **most
  reliable** key (a bot that solves the challenge once and then moves
  inhumanly inside the cookie session is caught cleanly).

## What is logged today versus what needs changing

The log records `path`, `method`, `ip`, `ua`, `timestamp`, `request_id`, plus
fingerprint and ASN. **Referer is NOT logged, and there is no stable session id in
the log.**

**Available from the current log (analytics side, → +score):**
- **Asset ratio** — a real browser pulls CSS/JS/images; a scraper takes the HTML
  only. Classify by the `path` extension. A low asset share looks bot-like. *Strong
  and cheap.*
  **Limitation (from review):** if a tenant's assets are served from an external
  CDN or a separate domain (and never traverse our edge), legitimate users will
  also show a near-zero asset ratio → mass false positives. So the signal applies
  **only** where assets really pass through the edge; otherwise calibrate per host
  or do not use it. That is why the asset ratio is contextual (+score), not a
  verdict of its own.
- **Rhythm** — inter-request intervals per actor (timestamps are there):
  metronomic timing or inhuman variance.
- **Breadth/enumeration** — many distinct `path`s, sitemap walking, recon (partly
  covered already by `SUSPICIOUS_URI_RE`).
- **Method distribution** — GET-only, or unusual methods.

**Needs changes (Phase 2):**
- **Navigational coherence** (following links versus hitting endpoints directly) —
  needs **referer** in the log (a small edge change) plus a model of the site
  structure.
- **Session attribution** — expose the clearance session as a key in the log.

## Proposed breakdown (once the work is picked up)

- **Phase 1 — a cheap analytics slice over current data:** asset ratio, rhythm and
  breadth computed **separately per `fp` AND per `IP`/subnet** (NOT a combined
  `fp+IP` key) → **+score only**, in the per-fingerprint pipeline (D1). No edge
  changes. Low risk (soft).
  **Why separately rather than `fp+IP` (from review):** a combined key is blind to
  rotation of either component — a residential proxy (IP changes, `fp` stable) or
  fingerprint rotation on one IP would shatter the actor into singletons and no
  history would accumulate. The `fp` axis catches distributed attacks with a stable
  fingerprint; the `IP`/subnet axis catches fingerprint rotation. This is the same
  multi-axis principle as in #3.
- **Phase 2 — spike/research:** referer logging, navigational coherence and session
  attribution. Plenty of uncertainty and false-positive risk, so spike it first.

## Open questions (NOT settled — decide when the work starts)

1. **The actor for Phase 1:** separate `fp` and `IP`/subnet axes (not a combined
   `fp+IP`, which is vulnerable to rotation of either) for rhythm and asset ratio
   over current data? And the clearance session (the strongest key) in Phase 2?
2. **Phase 1 signals:** asset ratio plus rhythm plus breadth, or narrow it to
   **asset ratio** alone to start?
3. **Shape:** Phase 1 (a D-task, +score) plus Phase 2 (a spike) — or keep all of #4
   as a research spike for now?

## Invariants (whatever we decide)

- Behaviour is **soft only** (+score / challenge), never the sole grounds for a block.
- The final backstop is unchanged: a human-gated draft PR.
- Do not duplicate rate_limit (which is about raw volume and frequency); #4 is about
  the *shape* of behaviour, not the pace.

## Connections

- Closes the "residential / perfect fingerprint" gap from #1/#3/#5.
- Reuses the per-fingerprint scoring (D1) as the injection point for +score.
- The Phase 2 referer/session work shares infrastructure with any future richer
  logging.
