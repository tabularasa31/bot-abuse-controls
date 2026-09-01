# Analytics and the blocklist lifecycle (post-MVP)

**Version:** v1.1 · Status: a design contract (target behaviour) · Layer: post-MVP

---

## Overview

### What it is

A background analytics layer that decides which TLS signatures may be blocked and keeps the blocklist current. It works alongside the cascade but never stands in a request's path — all of its work happens offline, over logs that have already been collected.

The cascade decides about each request in microseconds, relying on catalogs already sitting in its memory. Somebody has to fill those catalogs. The analytics layer fills the list of bad TLS signatures (`tls_fp_blocklist`). Once a day it analyses the collected logs, computes for each signature a score for "how much this looks like a bot" and the checks for "is it safe to block" (the scoring), and packages the changes that have matured into a draft PR: which signatures to put under observation, which to switch to blocking, which to retire. A human reviews it and decides to merge; after the merge the updated catalog is delivered to the edge.

The analysis runs by TLS signature (fingerprint) — the short string the edge folds a client's TLS handshake parameters into. The layer receives it ready-made in every log line. Real browsers and automation tools have different signatures, and that divergence is what the layer distinguishes them by: a "browser" in the User-Agent with a non-browser signature is a disguise (an impersonator).

### How it is arranged

```
   the edge (the cascade) ── the verdict stream ──► analytics ──► scoring ──► a decision
        ▲                                                                       │
        │                                                                       ▼
        └──── catalog delivery ◄──── the autopilot + a human ◄── the catalog (a PR)
```

The edge writes a log line per request → the stream flows into the log store → the layer reads it, builds a picture per TLS signature, ranks the suspicious ones, decides through gate checks which are safe to block → and the result travels back to the edge as a finished catalog.

Different parts of that loop run at different speeds:

- **Logs accumulate continuously.** The edge writes every request in real time; the layer only reads them.
- **Decisions are taken once a day.** Once a day the layer recomputes the whole picture and proposes blocklist changes. Every promotion, block and retirement happens in that daily run, not at request time.
- **A human switches blocking on.** The layer only prepares a proposal (a draft PR); the final "yes" is given by a human at review.
- **The change reaches the edge quickly.** After the merge the updated catalog is distributed to the edges within minutes.

So the analysis and the decisions are daily, data collection is continuous, and delivery of an approved catalog is fast. The details of each step are in the sections below.

### Where it runs

The layer runs entirely on the backend side. The analytics worker and the autopilot run as scheduled background jobs in the same place as the log store (Loki) and the git repository of catalogs with the layer's state files. Nothing from this layer runs on the edge itself.

Towards this layer the edge does exactly two things: it writes logs (which go to Loki) and it applies the catalog once delivered. The scoring, the gates, the lifecycle and the state accumulator all live outside the edge and off the request's hot path. Review and merging of the PR live in the git repository and CI; after the merge the catalog is delivered to the edge.

### What it consists of

| Component | Role | Section |
| --- | --- | --- |
| **The analytics worker** | the main process: once a day it reads the logs and the reference data, computes the scoring model, and writes the decisions and the report | "The analytics worker" |
| **The autopilot** | collects the worker's decisions into one draft PR per run and runs an entry's lifecycle (observation → blocking → retirement); it never merges anything itself | "The autopilot" |
| **The fingerprint harvester** | drives real browsers and tools, captures their fingerprints and populates the `tls_fp_browser_profiles` (browsers) and `tls_fp_catalog` (tools/headless) catalogs through draft PRs | "The fingerprint harvester" |
| **The log store (Loki)** | hot storage: the log stream from the edges over a short window (7 days) | "The log store (Loki)" |
| **The state accumulator** | cold storage: long-term memory per signature | "The state accumulator" |

### Related material

- [analytics-rules-reference.md](analytics-rules-reference.md) — every scoring, gate and
  lifecycle rule in "if condition → action" form.
- [analytics-entities-reference.md](analytics-entities-reference.md) — the entity
  vocabulary: the score, the gates, the tiers, a catalog entry, the states, the enumerations.

---

## The analytics worker

The worker is the layer's main process: once a day it runs on the backend, reads the collected logs and the reference data, and computes the decisions from them.

### What it reads as input

The layer consumes one structured log line per processed request. The minimum log fields it needs:

| Field | Why the layer needs it |
| --- | --- |
| `tls_fp` | the key to the whole analysis; all aggregation runs by signature |
| `ip` | the number of unique IPs, the "many IPs" signal, and cross-checking against the trusted list |
| `ua` | classification: a tool / a disguise / a real browser |
| `path` | the reconnaissance signal (requests to typical scanner paths) |
| `verdict` | the cascade's outcome for the request; if even one request under the signature was let through by the cascade as trusted (`allow` — a verified bot / a whitelisted IP / a valid cookie), the signature is not blocked (it feeds the "trusted" gate) |
| `rule` | which cascade rule fired (attribution) |
| `staging_match` | which observed entries the request matched |
| `asn` | the "IP from a datacenter" signal |
| the timestamp | the observation window, the number of distinct days, persistence over time |

### Reference data sources

Besides the log stream the worker relies on reference data. It feeds the score's signals and the gates.

| Reference data | What it is | What it feeds |
| --- | --- | --- |
| the tool dictionary (`tls_fp_catalog`) | hashes of known automation tools and headless stacks (curl/python/go/okhttp; Playwright/Puppeteer/UCD) | the disguise signal, the UA-tool signal, the headless signal (the score), and justification (a gate) |
| the positive browser catalog (`tls_fp_browser_profiles`) | a whitelist of real browsers: the full fingerprint → `{family, version}` | the known-good gate (a real browser → do not block) and the version mismatch signal |
| the challenge counters | how many challenges were issued and solved under the signature | the "challenge solving" gate, and acceleration of the move to blocking |

Who populates them. The catalog consists of handshake hashes and cipher counts, and a fingerprint is captured from a real client. That is the fingerprint harvester's job: it automatically drives a known set and lays the result out into two catalogs through a draft PR — real browsers → `tls_fp_browser_profiles`, tools and headless stacks → `tls_fp_catalog`. A human merges it.

Exceptions:

First, clients the harvester cannot drive itself: browsers and tools outside its set (LibreWolf, Tor, mobile browsers). Their fingerprints are captured and added by a separate PR.

Second, a new unfamiliar fingerprint: analytics highlighted a frequent fingerprint in the logs that is in neither catalog and that no known client produced; then a human works out what it is and decides whether to add it. Product's role is to maintain the list of what to harvest, investigate such unfamiliar fingerprints and review the PRs.

### The daily run

The worker does not work in real time: every decision is taken in a single scheduled run once a day. The order is:

1. **Tidying the long-term memory (rotation).** The layer has long-term memory per signature — the state accumulator (with its own section below). It grows over time, so it is tidied before the scoring: what has not been seen for a long time is archived, and one-off noise is discarded. A purely preparatory step.
2. **Scoring.** The worker reads the last 7 days from Loki and, in a single pass, computes a verdict for every signature at every stage of its lifecycle:

- **new candidates** — the score plus the gates: does it qualify for observation (see "The scoring model");
- **entries under observation** — it runs the activation gates over their events with `staging_match`:
  switch blocking on, retire it, or keep observing (see "The lifecycle");
- **entries in blocking** — have they gone quiet for longer than the deadline (retirement candidates).
 There are two outputs: (a) **machine artifacts** with a verdict per signature (which the autopilot reads at step 3); (b) **a human-readable report** emailed to whoever is responsible. The worker never touches the catalog itself.

3. **The autopilot.** It reads the fresh artifacts the worker left at step 2 and collects every decision that matured during the day into one draft PR: new signatures to observation; observed ones with a clean confirmation to blocking; silent ones to retirement. A human merges it.

What exactly happens to a signature during a run is a transition in its lifecycle (see "The lifecycle of a blocklist entry" below).

### The scoring model

The decision "should this signature be blocked" consists of two independent parts: the score answers "how much does this look like a bot", the gates answer "may this be blocked".

#### The score — how much it looks like a bot

The score is a sum of signals. It exists only to sort the candidates for blocking. By itself the score blocks nothing.

| Signal | Points | What it means |
| --- | --- | --- |
| a disguise (impersonator) | **+3** | the UA claims a browser, but the fingerprint matches an automation tool from our dictionary (curl, python-requests, Go, okhttp) |
| suspicious ciphers | +1 | the UA presents itself as a browser, but the number of offered ciphers is not from a browser's set |
| a tool UA | +1 | the UA honestly names an automation tool rather than a browser (curl/python/go/okhttp/bot/scanner) |
| a datacenter IP | +1 | at least one IP under the signature belongs to a datacenter |
| many IPs | +1 | the same signature arrives from two or more distinct IPs |
| persistence | +1 | the signature is not seen for the first day (visible on two or more distinct days) |
| reconnaissance | +1 | requests to typical scanner paths (`/.env`, `/wp-login`, …) |
| a headless stack | **+3** | the fingerprint matched a headless entry in the tool dictionary (`tls_fp_catalog`): Playwright, Puppeteer, undetected-chromedriver |
| a version mismatch | **+2** | the UA names a specific browser version, but the fingerprint's handwriting belongs to a different version or family (checked against the reference browser catalog) |
| behaviour | +1 | too even a request rhythm, or scanner-like routes (recon/sitemap instead of following links) |
| a volume spike | +1 | over the window the signature accounts for an anomalously large share of all events, or grew sharply day over day — a stream atypical for a single client |

The tiers by total: CRITICAL ≥8, HIGH 5–7, MEDIUM 3–4, LOW 1–2.

The CRITICAL tier means "confidence from hard evidence". The threshold of 8 sits above the sum of every non-signature signal: heuristics, context and behaviour together give at most 7 (a tool UA OR suspicious ciphers, a datacenter, many IPs, persistence, reconnaissance, behaviour, a volume spike — seven mutually exclusive +1 items). So heuristics alone cannot reach CRITICAL — it needs signature evidence (a disguise +3, headless +3 or a version mismatch +2), that is, a match against reference data rather than an inference from behaviour. CRITICAL changes the entry point into the lifecycle: the autopilot proposes blocking straight away, bypassing observation (see "The lifecycle of a blocklist entry"). A maintenance invariant: keep the CRITICAL threshold strictly above the maximum sum of the non-signature signals — when new light signals are added the threshold must be revisited, otherwise CRITICAL stops guaranteeing hard evidence.

One signal is worth spelling out separately — exactly how a volume spike is computed.

**A volume spike (+1).** Computed over the analysis window (7 days from Loki, broken down by calendar day). For a signature we take:

- `today` — its event count over the last day of the window;
- `baseline` — the median of its daily event counts over the window's earlier days (a median rather than a mean: a steady multi-day stream does not inflate the base, while a real jump is still visible);
- `total_today` — the event count of every signature over that same day.

The signal fires if at least one of two rules holds:

1. Dominance: `today / total_today ≥ 6%` AND `today ≥ 50`. The signature holds a noticeable share of the whole day's traffic.
2. Growth: `baseline > 0` AND `today ≥ 10 × baseline` AND `today ≥ 50`. A previously quiet signature grew tenfold or more within a day.

The daily minimum of 50 events is deliberately present in both rules: it is not the scale of an attack but the lower bound of trust in a share or a multiplier — while there are fewer events in a day, neither the share nor the growth lights the signal (four requests overnight, or a 2→20 jump, are nothing to block on). The rules complement each other: the first catches a new signature that appeared as a large stream at once (it has no daily history of its own, `baseline = 0`, so the second rule does not apply to it); the second catches a previously quiet fingerprint that suddenly took off. The source is windowed Loki data rather than the accumulator's lifetime counter: a spike is about recent dynamics. All three numbers (6%, ×10, 50) are configurable thresholds; the defaults were chosen for a daily volume of a few thousand events and are revisited as traffic grows.

The weight of +1 is deliberate: volume alone does not distinguish a bot from a surge of real people (a release, an ad campaign, hitting the front page), so a spike never blocks by itself — it tops a signature up to HIGH when it already has other markers: a disguise, reconnaissance, a datacenter, many IPs. Protection of real people is not weakened: known-good and trusted still veto a block, and justification requires a reason specific to that fingerprint.

#### The gates — is it safe to block

A gate looks at the signature as a bucket of traffic and decides "will we hit somebody we must not", whether the traffic under the signature really is bot-only, with no real people in it. A candidate may be a bot with total certainty — but if there are real people in the same bucket, it cannot be blocked.

Each gate is a checkpoint for "may this signature be blocked". If the condition in the column holds, the gate passes; if even one fails, the autopilot will not propose a block, however high the score. Gates do not add up and do not compensate for one another. In short: **the condition for blocking is that every gate passes simultaneously, plus a high score.**

The "veto" label is about how acceptable it is to bypass a gate by hand:

- **Soft** (volume, duplicate) — about data quality. Carrying a signature past such a gate by hand is a routine, deliberate operator decision (little data, but they are confident).
- **Veto** (trusted, known-good, challenge solving) — about safety: real users and legitimate traffic sit behind them. Bypassing a veto by hand means knowingly blocking the innocent. Technically nothing stops a human, but it is a red line, not a routine operation.

| Check | Blocking is permitted if… | Why it works that way |
| --- | --- | --- |
| **volume** | enough events have accumulated under the signature over all time (on the order of 20) | a couple of random requests is too little to block anyone on — a stable sample is needed |
| **trusted** (veto) | not a single request under the signature was let through as trusted (a search bot by rDNS, a whitelisted IP, a valid clearance cookie) | do not block those the cascade itself has already recognised as legitimate |
| **duplicate** | the signature is not in the blocklist yet | do not add what is already blocked |
| **justification** | there is a reason to block this specific fingerprint: either a disguise, or reconnaissance under a fingerprint that is not a shared tool like curl | a shared tool fingerprint (curl, python) is also used by legitimate clients — it must not be blocked |
| **known-good** (veto) | the fingerprint is not in the catalog of real browsers (`tls_fp_browser_profiles`) | if it is in the catalog it is a real browser with real users behind it; never block it, at any score (see "Protection from poisoning") |
| **challenge solving** (veto) | challenges are almost never solved under the signature | if challenges are being solved there are real people behind the fingerprint; a low solve share, conversely, accelerates the move to blocking (see "The lifecycle of a blocklist entry") |

Every gate is a simple deterministic computation over the signature's events in the analysis window (the last 7 days from Loki). The exception is the "volume" gate: it looks not at the window but at the all-time (lifetime) counter from the accumulator (7 days is too little to judge volume).

**volume.** We check that enough data has accumulated to decide.

- It passes if enough events have accumulated under the signature over all time (the counter from the accumulator; the threshold is configurable, by default on the order of 20); fewer means holding back. This is a soft gate: no decision is taken on a couple of random requests, and the number is chosen so that a real campaign steps over it easily while isolated probes do not.

**trusted** (veto). We check whether the cascade let anyone through under this signature as unambiguously legitimate.

1. Walk every event of the signature and its IPs.
2. It counts as "let through as trusted" if there was at least one: an `allow` verdict for a verified bot (a search engine confirmed by rDNS), for a whitelisted IP or for a valid clearance cookie; or the signature's IP is in the whitelist.
3. It passes if there is no such pass; otherwise it is a veto — you must not block those the cascade itself has already recognised as its own.

**duplicate.** It passes if the signature is not in the blocklist yet; if it already is, we add nothing (we neither create duplicates nor touch a live entry).

**justification.** We check whether there is a reason to block this particular fingerprint rather than a shared tool.

1. Compute three markers over the signature's events: `disguise` (a browser UA on a tool fingerprint), `reconnaissance` (requests to recon paths), and `a shared honest tool` (a fingerprint from the tool dictionary AND not a disguise — that is, an honest curl or python).
2. `justification = disguise OR (reconnaissance AND NOT a shared honest tool)`.
3. It passes if justification exists; otherwise there is no automatic block. The fingerprint of curl or python itself is identical for every user of it in the world (monitoring, CI/CD, legitimate API clients), so blocking it means cutting off all legitimate automation. "Bot-only" does not save you here: there are no browser requests under such a fingerprint at all, its share is 0 and the gate passes easily — yet it still must not be blocked. The autopilot never touches a shared tool; that is a case for a targeted UA or IP rule, decided by a human. (Which is exactly why the disguise and reconnaissance-on-a-non-shared-fingerprint markers exist: only they give a reason specific to that fingerprint rather than to every curl user.)

**known-good** (veto). It protects real browsers from being blocked — the layer's only "is this a live browser" check.

1. Compare the signature's fingerprint against the catalog of real browsers (`tls_fp_browser_profiles`) — the whitelist of fingerprints the harvester captured from real Chrome/Firefox/Edge.
2. It passes if the fingerprint is NOT in the catalog; if it is, that is a veto: this is a real browser and it is never blocked (see "Protection from poisoning").

Why that is enough and no separate "share of real people" check is needed: the fingerprint is set by the TLS stack rather than by a person, and blocking goes by the exact fingerprint. So "there are real people under this signature" is equivalent to "its fingerprint is the fingerprint of a real browser", which is exactly a catalog match. Either the fingerprint is a browser one (a veto, we leave it alone) or it is not — and then there will be no real people under it, because they would have a different fingerprint.

**challenge solving** (veto). We look at whether a client under this signature passes the JS challenge.

1. Take the issued and solved challenge counters for the signature — only from hosts in `active` mode with attack mode off (see the note below).
2. With enough issued, compute the solved share.
3. It passes if the share is low (challenges are almost never solved — which is how a bot behaves). A high share is a veto: challenges are being passed, so there are real people behind the fingerprint. A low share additionally accelerates the `observation → blocking` transition.

A note on attack mode for the "challenge solving" gate. The layer computes the solved share only from events on hosts in `active` mode with attack mode off. Under attack (attack mode on for a host) the edge issues challenges to everyone, real people included — and the solved share stops being a bot marker. Such events do not count.

It is important not to confuse the score with the gates. The score is a sum: the signals add up and one tops up another. Gates do not work that way: they combine with AND — all of them must hold at once, and none compensates for another's failure. So the full condition for blocking is a conjunction: the score reached HIGH (the threshold on the sum of signals) AND every gate passed simultaneously AND the signature has been seen for at least one day.

#### Protection from poisoning

The loop is partly automated, which means someone may try to fool it. What stands against that:

- **The browser catalog is not learned from traffic.** The layer determines "a real browser" not from what the traffic under a signature looks like but from the catalog captured by the harvester from real browsers. So the decision cannot be poisoned by pouring "human" traffic under your own fingerprint — the layer computes no "share of real people" from traffic at all; the fingerprint is either in the catalog or it is not.
- **Known-good.** The autopilot never blocks a fingerprint from the catalog of real browsers — a genuine Chrome or Firefox cannot be framed.
- **A human in the loop.** A high threshold and a manual PR merge are the last line: a false block is expensive, the decision is reversible and it goes through review.

The honest limit: a bot that reproduces a real browser's TLS handshake exactly will match the catalog and escape automatic blocking (its fingerprint is a browser one). That is the same boundary as in "What this layer is not": advanced mimicking bots are not our case.

---

## The autopilot

The autopilot turns the worker's daily decisions into one draft PR per run. It blocks nothing itself — it only prepares the draft; the final "yes" is given by a human.

**What goes into the PR.** The autopilot moves a candidate towards blocking only when everything lines up: the tier is HIGH or above, the signature has been seen for enough days, every gate passed and justification exists. Where exactly depends on the tier: HIGH goes to observation (and to blocking later, after the observation window), while CRITICAL is proposed straight to blocking, bypassing observation (see "The lifecycle of a blocklist entry" below). Everything else (HIGH/CRITICAL without justification or with a failed gate, MEDIUM, LOW) the autopilot leaves alone — it stays in the report for a human to judge. The "how many days before entry" threshold is deliberately low: entry is still only observation rather than blocking (see "The lifecycle of a blocklist entry" below), so checking persistence before entry buys little — the real proving ground is the observation window, and the volume gate cuts one-day accidents.

- **It never merges and never opens a non-draft.** A human reviews and merges.
- **It works in both directions.** One PR carries everything that matured: new signatures to observation, blocking enabled for cleanly observed ones, and retirement for the silent.
- **One PR per run.** Every change is batched into one branch — not dozens of PRs.
- **It is idempotent.** A repeat run in the same period creates no duplicates.
- **It does not act on stale data.** The worker's decisions carry a timestamp; if they are stale (the worker is down), the autopilot does nothing.
- **A clean state whatever happens.** An interruption halfway rolls the edits back.

The PR body is a passport organised into sections (observation / blocking / retirement), each line carrying the score, the tier, the evidence and the review-by date.

### The lifecycle of a blocklist entry

The lifecycle is the set of states a blocklist entry can be in and the rules for moving between them: observation → blocking → retirement.

Every signature travels a managed path from a candidate in the report to blocking and back. By default there is an observation phase on live traffic between the prediction and blocking; the exception is the CRITICAL tier (hard signature evidence), which the autopilot proposes straight to blocking, bypassing observation.

```
   a candidate in the report
        │
        ├─ HIGH: a prediction (the gates + justification) ──► observation
        │                                                   │ observed ≥ the window, zero false positives, ≥ the minimum matches
        │                                                   │ it touched a real browser → flagged for retirement
        │                                                   ▼
        └─ CRITICAL: signature evidence (+ the gates) ─────► blocking
                                                            │ silent > the deadline
                          auto-retirement: blocking → observation → removal
```

#### The states of an entry

The blocklist catalog stores a status per signature: observation or blocking. Above each entry sits a passport comment (the reason, the score, the evidence, the review-by date).

| Status on the edge | The cascade's behaviour |
| --- | --- |
| observation | the edge matches the signature and records the match in the log, but **does not block** |
| blocking | the edge blocks (403) under the `tls_fp_blocklist` rule |
| no entry | the cascade does not know the signature |

#### Candidate → observation

The trigger is the scoring model's verdict that the signature is fit for automatic blocking. That is still a prediction: the conclusion was reached offline over past logs and has not been confirmed on live traffic. The autopilot opens a PR with the "observation" status. After the merge the entry is delivered to the edge and starts matching, without blocking. The point of the phase is to obtain ground truth about false positives before blocking is switched on.

#### Candidate → blocking (the CRITICAL tier)

For the CRITICAL tier the observation phase is skipped: the autopilot proposes a PR with the "blocking" status straight away. The grounds: CRITICAL is unreachable without signature evidence (a disguise or headless — an exact fingerprint match against the tool dictionary, or a version mismatch against the browser catalog). That is not an inference from behaviour but a fact from reference data: there are no real people under the fingerprint of a known tool, and observation would only confirm what the dictionary already asserts — at the cost of a day or two of delay, which is expensive against an active farm.

Every gate still applies as usual (known-good, trusted, justification, duplicate, volume) — CRITICAL skips observation only, not the checks. And the PR is still a draft: a human merges it, which for direct blocking is the only buffer in place of observation. The risk of a bad entry in the tool dictionary is closed the same way as for the browser catalog: the dictionary is populated by the harvester through a manually merged draft PR and cannot be poisoned by traffic (see "Protection from poisoning").

#### Observation → blocking

Observation is automatic, not a manual pause. It works in two beats:

- **The edge, continuously.** Every request whose fingerprint matched an observed entry is marked in the log as `staging_match` without being blocked — ground truth accumulates with no risk of touching anyone.
- **The worker, on every daily run.** It takes the events with `staging_match` for the entry over the observation window and runs the activation gates (below). From the results it issues a verdict, and the autopilot puts it into the daily PR.

Here blocking is switched on by confirmation from live traffic rather than by a prediction. Over the events where the signature matched in observation mode, the following is checked across the observation window:

| Check | Condition | Why |
| --- | --- | --- |
| the window | it has been in observation for at least the minimum number of hours | to catch traffic across different times of day |
| volume | at least the minimum number of matches | otherwise there is nothing to judge |
| zero false positives (veto) | during the observation the fingerprint never turned up in the catalog of real browsers | if it did (the harvester confirmed it as a browser), do not activate — retire it |
| trusted (again) | there are no trusted or verified entries among the matches | a re-check, this time against real traffic |

The outcomes of observation: switch blocking on (all clear), a retirement candidate (observation caught legitimate traffic — we do not propose blocking), or keep observing (too few matches or too little time).

#### Automatic retirement on inactivity

No human tracks which signature stopped being a threat, so the autopilot does it. "Last seen" comes from the state accumulator (which outlives the log store's horizon). If a signature is silent for longer than the set deadline, it becomes a retirement candidate. Retirement is two-step: blocking → observation (if still silent) → removal (if silent again). The autopilot leaves entries with no observation history alone, for a human.

The deadline here is not an expiry of the entry on the edge (the catalog has none) but the inactivity threshold for the automatic retirement detector.

#### Manual retirement

Any transition can be rolled back specifically (retire one signature or return it to observation) or wholesale (revert the PR). All within the catalog delivery SLA.

---

## The fingerprint harvester

**What it is.** A background job (a scheduled CI job) that captures fingerprints from real clients and lays them out into the reference catalogs. Handshake hashes cannot be typed in by hand — the only reliable source of a fingerprint is the client itself, and the harvester automates driving it.

**What it does.**

1. It runs a known set of real clients — Playwright with stable Chrome/Firefox/Edge (the browsers) and automation tools (curl, python-requests, Go, okhttp, plus the headless ones — Playwright/Puppeteer/UCD).
2. With each of them it opens the edge's service endpoint `/__fp` (which returns a ready fingerprint, bypassing the cascade) and captures the full fingerprint.
3. It opens a draft PR. A human merges it.

**What comes out.** Two catalogs:

- **`tls_fp_browser_profiles`** — the whitelist of known-good: the fingerprints of real browsers. The known-good gate and the version mismatch signal read it.
- **`tls_fp_catalog`** — the tool dictionary: the fingerprints of automation and headless stacks. The disguise, tool-UA and justification checks read it.

**How much to drive.** The set is finite and small: Chromium forks (Brave, Vivaldi, Opera, Edge) on one build produce the same fingerprint, so among browsers Chrome, Firefox and Edge-if-it-differs are enough; the tools are a known list. What the harvester cannot provide (LibreWolf, Tor, mobile, exotic tools) is added by hand in a separate PR.

**How often.** Rarely — a TLS stack changes infrequently (Chrome's comes from BoringSSL), so the harvester runs roughly once every few major versions, not monthly.

**What the harvester does not cover.** A new unfamiliar fingerprint from the logs that none of the driven clients produced cannot be attributed by the harvester by definition — that is a manual investigation (see "Reference data sources").

---

## The log store (Loki)

The layer's hot storage is Loki: the logs from every edge flow into it centrally. This is the scoring's working material — the worker builds its per-signature picture here and now from it.

The retention window is short: 7 days, after which a record is cleaned up automatically —
a week-old individual record can no longer be found in Loki. Decisions that need a longer memory (retirement after 14 days of inactivity, the all-time accumulated event volume) are not served by that window — they rely on the cold state accumulator (see "The state accumulator").

How the logs get there: on every edge a collector agent (promtail) picks up the `BAC_LOG` lines and pushes them to the central Loki on the backend (through the load balancer, along the write path). Loki is not published externally — for reads it is reachable only by the worker from inside the network. (The specific addresses, ports and the promtail config live in the infrastructure runbook, not here.)

---

## The state accumulator

Loki remembers logs for 7 days only. The accumulator is a set of JSON state files (`state/seen-fps.json` plus an IP cache) holding exactly what is needed beyond that horizon: the accumulated event volume (for the volume gate) and "last seen" (for retirement on inactivity, whose deadline of 14 days exceeds Loki's 7-day window). The key is the signature.

**Rotation.** The accumulator grows, so it is cleaned: old records are archived, insignificant ones are discarded, and when a signature reappears they are restored as needed. The exception: signatures currently in the blocklist catalog are excluded from rotation. Otherwise a silent blocked entry would drop out of the automatic retirement check (which only looks at the live accumulator), and retirement on inactivity would stop working for precisely the entries it exists for.

---

## Delivery and SLA

The PR is merged → the catalog is distributed to the edge in the background → the edge picks it up. The edge works from the last copy delivered, and a client's request never waits for delivery.

| Metric | Value | What it covers |
| --- | --- | --- |
| report → blocking in production | **≤4 h** | observation + review + switching on + delivery |
| merge → the catalog on the edge | ≤15 min | catalog delivery |
| minimum observation | ≥48 h | the confirmation window before blocking |
| the automatic retirement deadline | ~2 weeks | the inactivity threshold |

---

## Observability and audit

- **The daily report** — ranked HIGH/MEDIUM/LOW candidates with their evidence chain, sent to whoever is responsible.
- **The observation match counter** — how many times an observed entry matched without blocking. The ground truth for moving to blocking.
- **The entry's passport** — in the PR and in the comment above the catalog entry: the action, the reason, the score and tier, the evidence chain, the gates passed, the review-by date and the lifecycle plan. For any blocked entry it is visible why and on what grounds it is there.

---

### What this layer is not

- **Not the hot path.** The layer is never called while a request is processed; its unavailability affects neither the speed, nor the availability, nor the decisions of the cascade — the edge works from the last delivered copy of the catalog.
- **Not a blocker.** The layer blocks no traffic itself: it edits the catalog, and the cascade blocks according to the delivered catalog.
- **Not autonomous.** A human switches blocking on: the autopilot prepares a draft PR and the merge is manual; there is no direct "analytics → blocking" path without a human.
- **Not machine learning.** The decisions are deterministic, based on explainable signals with hard gates; every decision unfolds into a human-readable explanation.

### Guarantees

- **Everything is reversible.** Any transition can be rolled back specifically or wholesale, within the delivery SLA.
- **Blocking from inference happens only after observation.** If bot-ness was inferred from behaviour or context (the HIGH tier), there is always an observation phase on live traffic between the prediction and blocking. Direct blocking with no observation is possible only with hard signature evidence (the CRITICAL tier — a fingerprint match against the tool dictionary), where there is nothing to observe.
- **What the layer deliberately does not do:** it does not block shared tool fingerprints (that is targeted UA/IP work, decided by a human); it introduces no expiry of entries on the edge; and it does not retire entries with no observation history.

---

## Areas of responsibility

| Who | What they do |
| --- | --- |
| **The analytics worker** | reads the verdict stream, computes the score and the gates, writes the decisions, sends the report |
| **The autopilot** | prepares one draft PR per run, in both directions; it never merges |
| **The operator (a human)** | reviews and merges the PR; adds and retires entries specifically; decides contentious justification cases |
| **The cascade (the edge)** | enforces the delivered catalog; writes the verdict stream; matches observed entries without blocking |
