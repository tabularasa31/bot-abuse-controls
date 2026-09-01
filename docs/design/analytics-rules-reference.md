# Analytics and the blocklist — rules reference

The analytics layer's rules in "if condition → action" form. The behaviour contract is
[analytics-spec.md](analytics-spec.md); the entity vocabulary is
[analytics-entities-reference.md](analytics-entities-reference.md).

The rule groups: scoring (ranking), the gates (admission and vetoes), the lifecycle (an
entry's transitions), the autopilot, and anti-poisoning. Plus the reference data sources
(the catalogs) that the scoring and the gates rely on.

---

## 1. Scoring (ranking, additive)

Every rule that fires adds points. The sum ranks the candidates; by itself it blocks
nothing. The tiers: CRITICAL ≥8 · HIGH 5–7 · MEDIUM 3–4 · LOW 1–2.

| # | If | → points | Type |
| --- | --- | --- | --- |
| S1 | the UA claims a browser, but the fingerprint's hashes come from the automation tool dictionary (a disguise) | **+3** (impersonator) | signature |
| S2 | the UA is a browser one AND the cipher count is outside the browser set | +1 (suspicious cipher) | heuristic |
| S3 | the UA is a tool (curl/python/go/okhttp/bot/scanner) | +1 (automation UA) | signature |
| S4 | at least one of the fingerprint's IPs is in a datacenter ASN | +1 (DC ASN) | context |
| S5 | ≥2 distinct IPs under the fingerprint | +1 (multi-IP) | context |
| S6 | the fingerprint is seen on ≥2 distinct calendar days | +1 (persistent) | context |
| S7 | there are requests to recon paths under the fingerprint (`/.env`, `/wp-login`, …) | +1 (recon URI) | behaviour |
| S8 | the fingerprint's hashes matched a headless entry in `tls_fp_catalog` (Playwright/Puppeteer/UCD) | **+3** (headless) | signature |
| S9 | the UA names a browser version that does not match the version in the positive catalog (a UA↔fp mismatch) | **+2** (version mismatch) | signature |
| S10 | rhythmic inter-request intervals / navigation over recon paths rather than links | +1 (behavioural) | behaviour |
| S11 | the signature's share of the daily stream ≥ `share_min` (≥50 events) OR growth ≥ `burst_factor`× against the median of the window's earlier days (≥50 events) | +1 (volume burst) | context |

> The weights: dictionary and catalog matches (S1, S8) are worth +3 — they are exact
> signatures. S9 is worth +2 — exact, but a fresh browser release can temporarily diverge
> from the catalog. The weak heuristics and context (S2, S4–S7, S10, S11) are +1.
> S11 (a volume spike): computed over the window — `today` for the last day, `baseline` =
> the median of the daily values of the window's earlier days, `total_today` = all events
> of that day. It fires by share (`today/total_today ≥ share_min` AND `today ≥ the daily
> minimum`) OR by growth (`baseline > 0` AND `today ≥ burst_factor × baseline` AND
> `today ≥ the daily minimum`). The defaults are `share_min` 6%, `burst_factor` ×10 and a
> daily minimum of 50. Volume alone never blocks: the +1 weight only tops a signature that
> already has other markers up to HIGH; real people are protected by the known-good and
> trusted gates.
>
> The CRITICAL tier invariant (≥8 → straight to `active`, see L0): the threshold of 8 sits
> above the sum of every non-signature signal (S2/S3, S4–S7, S10, S11 — the mutually
> exclusive items give at most 7), so CRITICAL is unreachable without signature evidence
> (S1/S8 +3 or S9 +2). When new light signals are added the CRITICAL threshold must be
> revisited, or the "hard evidence" guarantee breaks.

---

## 2. The gates (admission — veto thresholds, they do NOT add up)

The score can be anything; if even one gate fails there is no promotion. The gates are about
the safety of blocking (will we hit the innocent under the same fingerprint), not about
whether this is a bot — that is what the score computes.

| # | If | → action | Category |
| --- | --- | --- | --- |
| G1 | there are fewer all-time events than the minimum | do not promote (noise) — a manual force can override | volume |
| G2 | there is at least one allow verdict under the fingerprint OR its IP is whitelisted | **veto: do not promote** (legitimate/verified) | allowlist (veto) |
| G3 | the fingerprint is already in the catalog | do not promote (idempotency) | dedup |
| G4 | NOT (impersonator OR (recon AND not generic_honest_tool)) | **veto: do not auto-promote** (a shared tool fingerprint) | justification (intent, veto) |
| G5 | the fingerprint is in the catalog of real browsers | **veto: never block** (a real browser, with real people behind it) | known-good / a real browser (veto) |
| G6 | enough challenges were issued for the fingerprint AND they are being solved (the solve share is NOT ≈ 0) | **veto: do not block** (there are people behind the fingerprint); a low solve share, conversely, accelerates `staging → active` (see L2) | challenge solve rate (veto) |

> G5 (a known-good browser) is itself the "there are real people behind the fingerprint"
> protection: "real people under a signature" equals "its fingerprint is in the browser
> catalog" (the block goes by the exact fingerprint), so no separate share check is needed.
> G4 closes a different risk — "we blocked a shared tool fingerprint". G6 is two-sided:
> solved challenges are a veto (people), unsolved ones accelerate the move to a block; it is
> counted only from events on a host in `active` mode with attack mode off (under attack the
> edge challenges everyone and the solve share loses its meaning).

---

## 3. Reference data sources (the catalogs)

The scoring and the gates rely on reference data. The analytics worker itself populates
(through draft PRs) only `tls_fp_blocklist`. `tls_fp_browser_profiles` (browsers) and
`tls_fp_catalog` (tools) are populated by the fingerprint harvester (see §7), which captures
fingerprints from real clients; hashes are never written by hand. Headless fingerprints are
entries in that same `tls_fp_catalog`; there is no separate catalog. A new unfamiliar
fingerprint from the logs is attributed by a human (a manual investigation).

| Reference data | What it gives | What it feeds |
| --- | --- | --- |
| the tool dictionary (`tls_fp_catalog`) | the hashes of tools (curl/python/go/okhttp) and headless stacks (Playwright/Puppeteer/UCD) | impersonator (S1), automation UA (S3), headless (S8), justification (G4) |
| the positive browser catalog (`tls_fp_browser_profiles`) | a whitelist of real browsers: `the full fp → {family, version}` | known-good / a real browser (G5), version mismatch (S9) |
| challenge issued/solved | the issued and solved challenge counters per fingerprint | the challenge solve rate gate (G6), acceleration of `staging → active` |

---

## 4. The lifecycle of a blocklist entry

| # | If | → action |
| --- | --- | --- |
| L0 | the CRITICAL tier (≥8, that is, there is signature evidence) AND every gate AND justification | activate directly: a PR straight to the `active` status, bypassing `staging` |
| L1 | the HIGH tier (5–7) AND enough days AND every gate AND justification (auto_eligible) | promote: a PR with the `staging` status |
| L2 | an entry has been in `staging` for ≥ the observation window AND matches ≥ the minimum AND the fingerprint is not in the browser catalog AND there are no allowlist hits | activate: a PR moving `staging → active` |
| L3 | an entry is in `staging` but the fingerprint turned up in the browser catalog (the harvester confirmed it) OR there is an allowlist hit among the matches (fp_caught) | do NOT activate; flag it for demote/remove |
| L4 | an entry is in `staging` with too few matches or too little time (observe) | leave it in `staging` and keep observing |
| L5 | an `active` entry has been silent for longer than the TTL | demote: `active → staging` |
| L6 | a `staging` entry (after a demote) is silent again for longer than the TTL | remove: delete it from the catalog |
| L7 | an entry in the catalog with no observation history is silent | do NOT touch it automatically — leave it to a human |
| L8 | the operator confirmed a false block | demote it specifically (`active → staging` or remove), reversibly |

---

## 5. The autopilot (draft PRs)

The run is daily (cron): state rotation → scoring (the report plus the decision artifacts) →
the autopilot collects what matured into one draft PR. The autopilot never edits the catalog
outside a PR and never merges.

| # | If | → action |
| --- | --- | --- |
| A1 | the run produced matured promotes/activates/demotes | collect them ALL into one draft PR (a batch) |
| A2 | nothing matured during the run | do not open a PR (a no-op) |
| A3 | there is already an open PR for the current period | skip (idempotency) |
| A4 | the decision artifacts are older than the freshness threshold | do NOT act (the worker may be down) — exit |
| A5 | any failure midway through applying the edits | roll the catalog edits back to the base |
| A6 | the PR is assembled | leave it as a **draft**; a human reviews and merges — the autopilot does NOT merge |

---

## 6. Anti-poisoning

| # | If | → action |
| --- | --- | --- |
| P1 | an attacker pours "human" traffic under their own fingerprint | pointless: "a real browser" is taken from the catalog (harvested from real browsers), not from traffic — there is nothing to poison |
| P2 | the fingerprint matched the catalog of real browsers (known-good) | never auto-block (see G5) |
| P3 | a bot copies a real browser's TLS handshake exactly | a known limit: its fingerprint lands in the browser catalog and escapes automatic blocking (advanced mimicking bots are not our case) |

---

## 7. The fingerprint harvester

It populates `tls_fp_browser_profiles` (browsers) and `tls_fp_catalog` (tools/headless). A
separate producer, like the autopilot: it never edits the catalogs outside a draft PR and
never merges.

| # | If | → action |
| --- | --- | --- |
| F1 | on schedule (a cron one-shot) | it drives the known set — browsers (Chrome/FF/Edge) and tools (curl/python/go/okhttp/headless) — at `/__fp` and captures the full fingerprint |
| F2 | the browser slice is collected | a draft PR to `tls_fp_browser_profiles` (the allowlist); a human merges |
| F3 | the tools/headless slice is collected | a draft PR to `tls_fp_catalog` (`hash → family`); a human merges |
| F4 | an entry in `tls_fp_browser_profiles` was merged as `staging` | for an allowlist that means "already trusted" → it immediately suppresses the mismatch flag (the inverse of blocklist staging) |
| F5 | a client the harvester cannot provide (LibreWolf/Tor/mobile/something exotic) | a manual entry (a PR) |
| F6 | a frequent fingerprint in the logs that no run produced | NOT automatic; manual attribution by a human |

The cadence follows real TLS drift (Chrome's is set by BoringSSL): roughly once every few
major versions, not monthly.

---

## 8. The invariant

The only way to change enforcement is a merged PR to the blocklist catalog. The scoring, the
gates and the autopilot only propose (a draft PR); the verdict on traffic is issued by the
cascade from the delivered catalog. There is no direct "analytics → blocking" path without a
merged PR and a human.
