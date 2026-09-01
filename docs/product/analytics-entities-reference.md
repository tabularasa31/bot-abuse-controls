# Analytics and the blocklist — entity reference

The canonical vocabulary of the analytics layer's entities, fields and enumerations. The
behaviour contract is [analytics-spec.md](analytics-spec.md); the rules are in
[analytics-rules-reference.md](analytics-rules-reference.md).

---

## 1. The fingerprint and its properties

| Entity | Definition |
| --- | --- |
| **fp (the fingerprint)** | The identifier string of a client's TLS ClientHello (the order of ciphers, extensions and versions), in a fixed format. The key to all of the layer's aggregation. The edge forms it, and the layer receives it ready-made in the log. |
| **cipher_count** | The number of ciphers in the handshake; **fixed within one fingerprint** (it is part of the token). A browser value comes from a narrow set (empirically `{15,16,20}`). |
| **hashes** | The hash components of the token; fixed within a fingerprint. They are compared against the tool dictionary (`tls_fp_catalog`, including the headless stacks) and against the positive browser catalog. |

## 2. Scoring

| Entity | Definition |
| --- | --- |
| **score** | The additive sum of the signals (§rules S1–S11). It **only ranks**, it blocks nothing. |
| **signal** | One addend of the score: impersonator, suspicious cipher, automation UA, DC ASN, multi-IP, persistent, recon URI, headless, version mismatch, behavioural, volume burst. |
| **tier** | The category by score: **CRITICAL ≥8 · HIGH 5–7 · MEDIUM 3–4 · LOW 1–2**. CRITICAL is unreachable without signature evidence (S1/S8/S9) → straight to `active`, bypassing `staging` (see rules L0). |
| **impersonator** | The UA claims a browser but the fingerprint's hashes come from the tool dictionary (a disguise). The heaviest signal (+3); the basis of the justification (intent) gate. |
| **headless** | The fingerprint's hashes matched a headless entry in `tls_fp_catalog` (Playwright/Puppeteer/UCD): automation posing as a browser. A dictionary match, weight +3. |
| **version mismatch** | The UA names a browser version that does not match the version in the positive catalog. A disguise without the tool dictionary, weight +2. |
| **automation UA** | A UA that is itself a tool (curl/python/go/okhttp/bot/scanner). |
| **recon URI** | A request to a typical reconnaissance path (`/.env`, `/wp-login`, `/admin`, …). |
| **behavioural** | Rhythmic inter-request intervals, the absence of human jitter, navigation over recon/sitemap paths rather than links. Weight +1. |
| **volume burst** | An anomalously large share of the daily stream for a signature (`≥ share_min`) OR a sharp day-over-day rise (`≥ burst_factor`× against the median of the window's earlier days), subject to a daily event minimum. Computed over the Loki window, not from the lifetime counter. Weight +1: it tops up to HIGH and never blocks by itself. |

## 3. The gates and related concepts

| Entity | Definition |
| --- | --- |
| **gate** | The admission threshold for blocking: about the safety of a block (will it hit the innocent under the same fingerprint), not about whether this is a bot. Gates do NOT add up and do NOT compensate for one another, and they live in the autopilot's decision (there are no gates on the catalog — a human edits the blocklist themselves). The vetoes (trusted / known-good / challenge solving) guard real people and legitimate traffic: the autopilot never bypasses them, and bypassing one by hand means blocking the innocent — a red line, not something one does (technically nothing stops a human). Volume and duplicate are about data quality: they only hold back an automatic promotion, and a human at review may deliberately let them through. |
| **a real browser** | A signature whose fingerprint is in the catalog of real browsers (`tls_fp_browser_profiles`). The only marker of "there are real people behind the fingerprint": the fingerprint is set by the stack and blocking goes by the exact fingerprint, so no separate "share of real people" is needed. |
| **volume** | A gate: enough lifetime events (on the order of 20). It cuts noise. |
| **allowlist (veto)** | A gate: not a single allow verdict under the fingerprint AND not a single whitelisted IP (a verified bot / a whitelist entry / a valid clearance). |
| **dedup** | A gate: the fingerprint is not in the catalog yet. |
| **justification (intent, veto)** | A gate: `impersonator OR (recon AND NOT generic_honest_tool)`. It closes the "we blocked a shared tool fingerprint" risk. |
| **known-good (veto)** | A gate: the fingerprint is in the catalog of real browsers → **never** block (a real browser, with real people behind it). The only "is this a live browser" check. |
| **challenge solve rate (veto)** | A gate: challenges are being solved under the fingerprint → a veto (there are people behind it). A low solve share with enough issued, conversely, accelerates `staging → active`. Two-sided. Counted only from events on a host in `active` mode with attack mode off: under attack the edge challenges everyone and the solve share loses its meaning. |
| **generic_honest_tool** | A known honest tool that is not an impersonator (an ordinary curl with no browser UA, say). Its shared fingerprint belongs to millions of legitimate clients. |
| **auto_eligible** | Fit for automatic promotion: HIGH (5–7) AND enough days AND every gate AND justification (intent). The CRITICAL tier goes to a direct `activate` instead of a promotion (see `direct-activate`). |
| **direct-activate** | For the CRITICAL tier the `staging` phase is skipped: the PR carries the `active` status immediately. The grounds: CRITICAL requires signature evidence (a fact from reference data, not an inference from traffic). The gates apply as usual; a human merges (rules L0). |

## 4. A catalog entry and the lifecycle

| Entity | Definition |
| --- | --- |
| **catalog entry** | A `fp → status` pair in the blocklist catalog plus the passport comment above it. |
| **status** | `staging` (match-but-observe, does NOT block) \| `active` (enforce, a 403 block). |
| **the passport** | The comment above an entry: the action, the reason, the score and tier, the evidence chain, the review-by date and the lifecycle plan. The audit trail. |
| **promote** | The candidate → `staging` transition (a PR). |
| **activate** | The transition into `active` (a PR): from `staging` on confirmation by observation, or directly from candidate for the CRITICAL tier (see `direct-activate`). |
| **demote** | The `active → staging` transition (lifting enforcement), or removal. |
| **remove** | Deleting the entry from the catalog. |
| **TTL (the inactivity threshold)** | The period of silence after which a fingerprint becomes a retirement candidate. **Not** an enforced expiry on the edge, but the automatic detector's threshold. |

## 5. Observation

| Entity | Definition |
| --- | --- |
| **staging_match** | A marker in the verdict stream: a staged fingerprint pattern matched in observe-only mode (it blocked nothing). The ground truth for `staging → active`. |
| **observation verdict** | The outcome of observing a staging entry: **activate** (clean → activate) \| **fp_caught** (it caught something legitimate → retire) \| **observe** (too little data → wait). |
| **the observation window** | The minimum hours plus the minimum matches needed to judge activation. |

## 6. The daily run, candidates, artifacts and state

| Entity | Definition |
| --- | --- |
| **the daily run** | Once a day, on schedule: state rotation → scoring (the report plus the artifacts) → the autopilot (a draft PR). Every decision of the layer is taken there; the layer has no real-time path. |
| **candidate** | A fingerprint with its score, tier, gates and `auto_eligible` computed, which landed in the report or an artifact. |
| **stale entry** | A catalog entry silent for longer than the TTL — a retirement candidate. |
| **decision artifacts** | Machine-readable slices of the run: the candidates, the staging observation, the retirement candidates. They carry a generation timestamp. |
| **freshness guard** | The autopilot's protection: if the artifacts are older than the threshold, it does not act. |
| **the state accumulator (cold)** | A persistent per-fingerprint slice of what the log store does not remember beyond its horizon: the accumulated event volume and "last seen". JSON files (`seen-fps.json`, an IP cache). |
| **state rotation** | Bounding the accumulator's growth (archiving old data into monthly shards, discarding low-signal entries, lazy restore). **The exception:** fingerprints from the blocklist catalog are exempt from archival. |

## 7. Reference data sources (the catalogs)

Reference data separate from the log stream, which the signals and gates rely on.
`tls_fp_browser_profiles` (browsers) and `tls_fp_catalog` (tools) are populated by the
fingerprint harvester (below); hashes are never written by hand. The layer itself populates
(through draft PRs) only the `tls_fp_blocklist`.

| Reference data | Definition |
| --- | --- |
| **the tool dictionary** (`tls_fp_catalog`) | The hashes of known automation tools (curl/python/go/okhttp) and headless stacks (Playwright/Puppeteer/UCD — there is no separate catalog for them). Populated by the harvester. It underpins impersonator (S1), automation UA (S3), headless (S8) and justification (G4). |
| **the positive browser catalog** (`tls_fp_browser_profiles`) | A whitelist of real browsers: `the full fp → {family, version}`. It feeds known-good / a real browser (G5) and version mismatch (S9). `staging` is inverted here: an entry means "already trusted" and immediately suppresses the flag. |
| **the fingerprint harvester** | A CI cron one-shot: it drives real browsers (Chrome/FF/Edge) and tools (curl/python/go/okhttp/headless) at `/__fp` → the full fingerprint → a draft PR to `tls_fp_browser_profiles` (browsers) and `tls_fp_catalog` (tools). The cadence follows TLS drift (once every few major versions). A human merges; what the harvester does not drive (LibreWolf/Tor/mobile/exotica) and unfamiliar fingerprints from the logs go in through a manual PR. |
| **challenge issued/solved** | The issued and solved challenge counters per fingerprint. They underpin the challenge solve rate gate (G6) and the acceleration of `staging → active`. |

## 8. Storage

| Entity | Definition |
| --- | --- |
| **the log store (hot)** | Loki: the full log stream from the edges, with a retention window of ~7 days, after which a record is cleaned up. The scoring's working material. Ingest: on every edge, promtail pushes the `BAC_LOG` lines to the central Loki on the backend (through the load balancer, along the write path); Loki is not published externally and is readable only by the worker from inside the network. The config and ports live in the infrastructure runbook. |
| **the state accumulator (cold)** | JSON state files next to the layer (see §6). It outlives the Loki window — for decisions beyond that horizon (retirement after 14 days of inactivity, for instance). |

## 9. Enumerations

| Enumeration | Values |
| --- | --- |
| **tier** | `CRITICAL` (≥8) · `HIGH` (5–7) · `MEDIUM` (3–4) · `LOW` (1–2) |
| **status** | `staging` · `active` |
| **observation verdict** | `activate` · `fp_caught` · `observe` |
| **gate verdict** | `pass` · `veto` |

## 10. Constants and knobs (contractual thresholds)

The concrete values are implementation parameters; the contract fixes their meaning and
direction.

| Parameter | Meaning | Ballpark |
| --- | --- | --- |
| the minimum events (volume) | how many lifetime events are needed | tens (≈20) |
| share_min (volume burst) | the minimum share of the daily stream for the "dominance" rule (S11) | 6% |
| burst_factor (volume burst) | the day-over-day growth multiple for the "growth" rule (S11) | ×10 |
| the daily event minimum (volume burst) | the lower bound of daily events for both S11 rules (it cuts shares and multiples computed on tiny numbers) | 50 |
| days before entering staging | the minimum distinct days before a promote | low (entry is cheap — observation in staging) |
| the staging observation window | the minimum hours in staging before activation | at least a day or two (to see traffic across times of day) |
| the minimum staging matches | how many staging_match events are needed to judge | on the order of ten |
| the auto-demote TTL | the silence threshold for retirement | on the order of two weeks (longer than the log store's horizon) |
| the artifact freshness threshold | at what age the autopilot stops acting | on the order of a day |
