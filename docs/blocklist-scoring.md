# Blocklist scoring and promotion — the decision logic

This document describes **how the system decides** which TLS fingerprint (fp) to
put into `catalogs/tls_fp_blocklist.yaml`, when to move it from `staging` to
`active`, and when to retire it. The operational process (commands, SLA, who does
what) is in [blocklist-promotion.md](blocklist-promotion.md); the on-VM procedure
is in [runbooks/blocklist-promotion.md](runbooks/blocklist-promotion.md).

Implementation: `infra/demo-stand/scripts/analyze.py` (scoring plus the JSON
views), `scripts/promote-fp.sh` / `demote-fp.sh` / `blocklist-autopilot.sh`
(promotion and retirement), `scripts/lib/blocklist_catalog.py` (editing the
catalog).

## What a fingerprint is, and what cipher_count means

Every client sends a TLS ClientHello during the HTTPS handshake: a list of
ciphers, extensions and versions, in a particular order. That handwriting is what
we fold into a fingerprint string
`L<ver><sni><cipher_cnt><alpn>_<hash_b>_<hash_c>`
(`infra/demo-stand/lua/ja4_compute.lua`).

Note: **within one fingerprint, `cipher_count` and the hashes are fixed** — they
are part of the token. Real browsers (Chrome/Firefox/Safari) offer a cipher count
from the set `{15, 16, 20}`; automation tools (curl/python/go) offer something
else. This is empirical, from the stand.

## Two layers of decision: score (ranking) ≠ gates (admission)

**Score — how much this looks like a bot.** An additive sum of signals, used only
to sort the candidates in the morning email. On its own it **blocks nothing**.

| Signal | Points |
|---|---|
| impersonator — browser UA plus the fingerprint of a known tool | +3 |
| suspicious cipher — `cipher_count ∉ {15,16,20}` with a browser UA | +1 |
| automation UA — the UA is a bot by itself (curl/python/go/okhttp/bot/scanner) | +1 |
| DC ASN — at least one IP in a hosting ASN | +1 |
| multi-IP — ≥2 distinct IPs behind the fingerprint | +1 |
| persistent — the fingerprint is seen on ≥2 distinct days | +1 |
| recon URI — `/admin`, `/.env`, `/wp-login`, … | +1 |

Tiers: **HIGH ≥5 · MEDIUM 3–4 · LOW 1–2**.

> suspicious is deliberately worth only +1: it is a weak heuristic that also fires
> on unusual but legitimate browsers. impersonator (+3) rests on a dictionary of
> known tools — high precision.

**Gates — whether it is safe to block this fingerprint.** They do not add up;
they are veto thresholds. The score can be arbitrarily high — if a gate fails,
there is no promotion.

## Two different false-positive risks

This is the key to the whole design. There are two distinct ways to block a
fingerprint by mistake, and they are closed by different mechanisms.

### Risk 1: "an unknown legitimate browser mistaken for a bot" → the purity veto

We measure the share of a fingerprint's events that look like a **real browser**.
An event is a *genuine browser* when all of the following hold:

1. the UA says browser (Chrome/Firefox/Safari);
2. the cipher count is a browser one (`∈ {15,16,20}`);
3. the fingerprint hashes are **not** in the tool dictionary.

`human_share = genuine_browser / total`. The **purity** gate is
`human_share ≤ 0.05` (flag `--max-human-share`). Above that threshold you must not
block, whatever the score: real people browse behind that fingerprint.

Why all three conditions together: a UA is easy to fake (a bot claims "I am
Chrome"), the handshake handwriting is harder. We believe it is a human only when
the UA is a browser AND the handwriting is a browser AND it is not a recognised
tool. If the UA says Chrome while the handwriting says curl (conditions 1 and 2
disagree), that is **impersonation**, and it does NOT count as a human.

### Risk 2: "we blocked a tool's shared fingerprint" → the intent rule

The fingerprint of `curl` itself (or python-requests) is **shared by every user of
that tool** in the world: monitoring, CI/CD, health checks, legitimate API
clients. Recon URIs from one actor **do not make a shared fingerprint safe** —
purity does not save you here (there are no browser events behind curl, so
`human_share = 0`). Blocking curl's fingerprint means cutting off all legitimate
automation.

So an automatic block is only justified when the **intent is specific to the
fingerprint itself**:

- **impersonator** — a browser UA on a tool fingerprint. The combination is
  anomalous by itself: a real user never does that. Such a pretender's fingerprint
  is specific, so blocking is safe.
- **recon on a non-generic fingerprint** — recon URIs under a fingerprint that is
  **not** a known honest tool (`generic_honest_tool = known_tool AND NOT
  impersonator`). An unknown scanner fingerprint doing recon is a specific
  signature, and blocking is safe.

`intent = impersonator OR (recon AND NOT generic_honest_tool)`. An honest curl
doing recon gives `intent = false` → automation leaves it alone; that is a case
for `ua_blacklist` / `ip_blocklist`, decided by a human.

### The remaining gates

- **volume** — `n_events_lifetime ≥ 20` (`--min-events`) and `n_ips ≥ 1`. Cuts
  noise from one-off requests. A manual promote can override it with
  `--force-low-volume`.
- **allowlist/verified (hard veto)** — no IP of the fingerprint is in
  `ip_whitelist`, and no event of the fingerprint was an identity allow
  (verified bot / ip_whitelist / cookie_valid in the log).
- **dedup** — the fingerprint is not in the catalog yet.

## Auto-promote (the autopilot trigger)

`auto_eligible = tier==HIGH AND days_seen≥1 (--min-days-promote) AND all gates AND
intent`. The autopilot opens a **draft PR** to `staging`, never straight to active
and never auto-merged.

The `days_seen` threshold is deliberately low (1): **staging is observe-only** (it
matches without blocking), so checking for "persistence" before entry buys little
— the real proving ground is the 48-hour `staging → active` window below, and
one-day blips are cut by the volume gate (`MIN_EVENTS`). Entry into staging is
cheap and fast; the strictness lives at activation.

## staging → active — confirmation by observation

A promote sets `staging`: the edge matches and writes
`staging_match: ["tls_fp_blocklist:<fp>"]` into bac_log
(`infra/demo-stand/lua/bac_log.lua`) but **does not block**. That gives ground
truth about false positives before enforcement. We activate on evidence, not on
the original prediction.

Over the events carrying `staging_match ⊇ tls_fp_blocklist:<fp>` during the
observation window:

| Gate | Condition | Why |
|---|---|---|
| window | in staging for ≥ `--min-staging-hours` (48 h) | traffic varies across the day |
| volume | ≥ `--min-staging-matches` (10) | otherwise there is nothing to judge |
| zero false positives (VETO) | `human_share` among the matches = 0 | it touched a real browser → do NOT activate |
| allowlist re-check | no whitelist/verified among the matches | a re-check against real traffic |

Verdicts: `activate` (all clear → flip to active), `fp_caught` (caught something
legitimate → a candidate for demote/remove, activation is not offered), `observe`
(too few or too soon → keep watching).

## Auto-demote — retirement on inactivity

No human tracks which fingerprint stopped being a threat, so the autopilot does
it. "Last seen" is `max(days_seen)` from the `seen-fps.json` accumulator (which
outlives Loki's 7-day retention). If `days_silent > TTL_DAYS` (14, flag
`--ttl-days`), it becomes a retirement candidate. This is two-step:
`active → staging` (still silent) → `staging → remove` (silent again). Also a
draft PR.

> The `seen-fps.json` accumulator is rotated (D7, `rotate-state.py`), but
> fingerprints **that are in the blocklist catalog are exempt** from archival and
> dropping — otherwise a silent enforced fingerprint would be archived away and
> fall out of this check (which only reads the live `seen-fps.json`). That keeps
> the auto-demote signal alive for blocklisted fingerprints. Rotation details:
> [`infra/demo-stand/scripts/README.md`](../infra/demo-stand/scripts/README.md).

> The TTL here is **not** an enforced expiry on the edge (the catalog has none); it
> is the inactivity threshold for the automatic retirement detector.

## The full lifecycle

```
candidate in the email
   │ promote (prediction: HIGH + gates + intent)
   ▼
 staging ──observed ≥48 h, FP=0, ≥10 matches──► activate (confirmed) ──► active
   │ touched a real browser → flagged demote/remove                      │ silent >14 d
   └──────────────────────────────────────────────◄──────────────────────┘
                                       auto-demote: active → staging → remove
```

Entry is by confirmation, exit is by inactivity, and both directions go through a
draft PR plus human approval.

## Constants (defaults, overridable by flags/env)

| Parameter | Default | Flag / env |
|---|---|---|
| purity threshold | 0.05 | `--max-human-share` / `BAC_MAX_HUMAN_SHARE` |
| min events (lifetime) | 20 | `--min-events` / `BAC_MIN_EVENTS` |
| min days for auto-promote (entry into staging) | 1 | `--min-days-promote` / `BAC_MIN_DAYS_PROMOTE` |
| inactivity TTL (days) | 14 | `--ttl-days` / `BAC_TTL_DAYS` |
| staging observation window (h) | 48 | `--min-staging-hours` / `BAC_MIN_STAGING_HOURS` |
| min staging matches | 10 | `--min-staging-matches` / `BAC_MIN_STAGING_MATCHES` |

## Where this is computed

The analytics lives on the **backend+obs VM** (the `antibot-analytics` container)
and is sourced from **Loki** (7 days of history from every edge, in-network). See
[config-distribution](architecture/config-distribution.md) and
the design decision. The container
writes JSON artifacts into `state/`; the host-side `blocklist-autopilot.sh` turns
them into draft PRs.
