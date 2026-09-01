# WAF and DDoS — directions for development (research / roadmap)

> **Status: PLANNED / research.** This is a snapshot of the brainstorm on "where to
> grow the product after closing the C series (challenge) and D1 (scoring)" towards
> WAF and anti-DDoS. Nothing described below is **implemented** in the stand until
> it has explicitly moved into [ROADMAP.md](../../ROADMAP.md) → "IN PLACE TODAY".
> Do not present it as done. The WAF engine is deliberately left as a
> **research/ADR candidate** (build versus buy is unresolved) — see §3. Volumetric
> L3/L4 is included in the roadmap on request, but honestly marked as **outside the
> OpenResty stand** (reality level 3 per the project scope) — see §4.3.
>
> **What has already moved into the backlog since the first version:**
> connection/protocol-level DDoS (slow attacks E1–E3, HTTP/2 DoS E4–E5) is filed as
> tickets (§4.2). The **API/account** axis is laid out in §5 (the `P` series —
> candidates, no tickets yet).
>
> **Where this sits on the product timeline:** WAF/DDoS is **post-post-MVP** (new
> axes alongside the detector), not a continuation of the D series. The broad frame
> of what we are aiming at is in
> [../product/product-scope.md](../design/product-scope.md).

## 1. The baseline — what we already have (and what we do not)

The cascade in `infra/demo-stand/lua/` today is **bot abuse control (BAC)**, not a
WAF and not anti-DDoS. The stages (see [ROADMAP.md](../../ROADMAP.md) "IN PLACE
TODAY"):

| Layer | What it does | Relation to WAF/DDoS |
|---|---|---|
| **L1 hygiene** (`hygiene.lua`) | method whitelist, `ua_blacklist`, header anomalies | protocol hygiene — adjacent to WAF, but not content inspection |
| **L2 reputation** (`reputation.lua`, `verified_bots.lua`, `clearance.lua`) | IP allow/block, geo/ASN, verified bots, clearance cookie | the reputation layer — a shared foundation for both directions |
| **L3 tls_fp** (`tls_fp.lua`) | JA4 fingerprint (blocklist plus soft flags) | anti-bot, orthogonal to WAF |
| **L4 rate_limits** (`rate_limit.lua`) | GCRA: `rate_ip`/`rate_ip_ua`/`rate_api`/`rate_tls_fp`/`rate_scan_urls`, 10 s/60 s windows | **the core of L7 anti-DDoS**, already here |
| **L5 verification** (`verification.lua`, `challenge*.lua`) | JS challenge, Strictness, `attack_mode`  | **L7 anti-DDoS**: the challenge as a filter under load |

Three conclusions that set the direction:

1. **L7 anti-DDoS already partly exists.** L4 rate limits plus `attack_mode` plus the
   challenge are working protection against an application-layer flood. Development
   here means **deepening what exists**, not a new discipline.
2. **The WAF is not implemented anywhere.** There is no inspection of request bodies,
   query/POST parameters or headers against signatures (SQLi/XSS/path
   traversal/RCE/SSRF), and no virtual patching. In [vision.md](../product/vision.md)
   DDoS is an explicit goal (§"cutting off DDoS bots") while WAF is mentioned only
   indirectly (XSS, as the reason for `HttpOnly` on the cookie). This is **greenfield**.
3. **The delivery and observability infrastructure is reusable.** Channel C
   (`catalog_pull.lua`, the ADR-006 git catalogs), shadow/active mode
   (`policy.enforce`), staged rollout (staging→active), the structured log
   (`bac_log.lua`), the metrics and the kill switch  all get reused for both WAF
   signatures and DDoS rules, with nothing to reinvent.

## 2. The principle: WAF and DDoS are two new **axes**, not new stages "instead of"

The cascade remains a single decision point (L5 `verification` folds the flags into a
verdict). WAF and DDoS add **sources of flags**, not parallel pipelines:

- **WAF** → a new content-inspection stage that accumulates flags (`waf:sqli`,
  `waf:xss`, …) and in active mode may block on its own for critical rules — by
  analogy with the way a `tls_fp_blocklist` hit calls `policy.enforce(403)` directly.
- **L7 DDoS (rate-based)** → not a new stage and **not a new axis**: it is adaptivity
  in the existing L4/L5 (rate-limit thresholds plus automatic `attack_mode`), already
  scoped in the G series (G1–G4, §4.1).
- **Connection/protocol-level DDoS (slow attacks, HTTP/2 DoS)** → this **is genuinely
  new scope**, and it does **not fit the cascade** at all: slowloris, slow POST, slow
  read and Rapid Reset live BELOW `access_by_lua` (at the connection and frame level,
  before HTTP semantics). They are handled by nginx directives and the build version,
  with Lua only observing and feeding reputation. Scoped as E1–E3 / E4–E5 (§4.2).

This preserves the rules-reference invariant: "the only decision point is L5", and
flags do not issue verdicts themselves (apart from the explicit hard-block exit points
under `policy.enforce`).

## 3. WAF — L7 content inspection (build versus buy NOT decided → an ADR candidate)

### 3.1 What is in the MVP scope
A minimal useful WAF at the edge:
- inspection of the **query string and the POST body** (form-urlencoded plus JSON;
  multipart is phase 2);
- inspection of **headers and the path** (path traversal, null bytes, protocol
  anomalies);
- a signature set for the **OWASP Top 10 core**: SQLi, XSS, path traversal, command
  injection, obvious SSRF/LFI;
- **virtual patching** — a targeted rule for a specific CVE or customer endpoint (a
  fast PR-driven catalog, like `tls_fp_blocklist`);
- shadow mode by default (like the whole cascade) plus per-host on/off through the
  policy.

Out of MVP scope: ML anomaly detection on bodies, full CRS paranoia level 3+, and
anti-evasion normalisation of every conceivable encoding (a long tail, added
iteratively).

### 3.2 The engine fork — needs a spike plus an ADR (decision deferred)

**Option A — integrate [Coraza](https://github.com/corazawaf/coraza) plus OWASP CRS.**
Coraza is a Go implementation of ModSecurity seclang, with
[coraza-proxy / openresty bindings](https://github.com/corazawaf). The OWASP Core Rule
Set is a set proven over years.
- **+** Instant Top 10 coverage, maintained rules, seclang familiar to operators.
- **−** Someone else's rule model, outside our Channel C / shadow mode / `bac_log`;
  we either pull it in as a Go service (another `auth_request` hop — which we already
  rejected in ADR-001 in favour of edge Lua) or look for a Lua binding of questionable
  maturity. Body-inspection latency on every request needs measuring. CRS is famous for
  false positives and would need tuning that does not fit our staging→active workflow
  out of the box.

**Option B — our own ruleset in the style of the cascade.**
A `waf.lua` stage with our own signatures; catalogs (`waf_rules.yaml`) over Channel C
exactly like `tls_fp_blocklist`; shadow/active through `policy.enforce`; flags in
`bac_log`; staged rollout and `git revert` for free (ADR-006).
- **+** One architecture: the same log, metrics, kill switch, mode gate, PR workflow
  and CI validation of rules. Controlled latency (we inspect exactly what we chose to).
- **−** We own completeness and anti-evasion ourselves. Coverage grows slowly. The risk
  of "inventing our own CRS, worse than CRS".

**Option C (a compromise) — our own execution engine plus an import of a subset of CRS
signatures** as data in our catalog format. We take proven patterns but run them
through our machine and workflow.

**Recommendation: spike before committing.** Run a research spike (modelled on
`infra/nginx-lua-poc/spikes/` from ADR-002): (1) measure per-request body-inspection
latency for a Coraza integration versus native Lua inspection on a representative body;
(2) assess whether CRS tuning fits shadow→staging→active; (3) estimate the size of our
own signature core for the Top 10. Then write **ADR-007 "WAF engine: build vs buy"**.
No code lands before that ADR.

### 3.3 Open questions for the WAF
- Body inspection requires **buffering** it (`lua_need_request_body` / reading
  `request_body`), which conflicts with proxying large uploads; we need a size limit and
  a bypass for media/upload endpoints.
- Where normalisation happens (URL decode, unicode, comment stripping) — a shared
  preprocessor ahead of the signatures, otherwise evasion is trivial.
- A per-host WAF profile (paranoia level, disabled rules) — an extension of `policy`
  (the B10 Policy API already handles PATCH of scalars and JSONB arrays).

## 4. DDoS — three layers at different maturity

> **A correction after checking against the backlog.** DDoS splits into three
> layers for us, not one:
> - **§4.1 L7 rate-based** — already scoped in the G series (G1–G4), not duplicated here.
> - **§4.2 connection/protocol level (slow attacks, HTTP/2 DoS)** — genuinely new scope,
>   filed as E1–E3 / E4–E5; it lives in nginx directives and the build version, NOT in
>   the cascade.
> - **§4.3 volumetric L3/L4** — outside the OpenResty stand (reality level 3), only the
>   edge-ACL feed contract.

### 4.1 L7 application layer — already scoped in the G series (not duplicated)
Everything I originally sketched as "DDoS phase 1/2" turned out, on checking the
backlog, to be already-filed tickets (the G series plus one signal from layer D):

| Idea | Where it already lives (backlog / research) |
|---|---|
| Automatically raising `attack_mode` on "bad" traffic (not raw volume), hysteresis, manual precedence over automatic, the per-host `auto_attack_mode` flag | (backlog, design ready) — detection by bot rate / solve rate / origin latency relative to the host baseline |
| Subnet/ASN reputation for datacenter pools (soft, analytics) | (backlog) plus [subnet-unit-design.md](subnet-unit-design.md) |
| Transient subnet challenge→drop during an attack | (backlog) |
| A fast hot list of attackers (pre-arming edges when a botnet pivots) | (backlog) plus [cross-tenant-threat-intel-design.md](cross-tenant-threat-intel-design.md) |
| Solve rate as a bot signal under a flood (the ticket itself is **layer D**, the detector; the G series reuses it) | (review) plus [challenge-solve-rate-design.md](challenge-solve-rate-design.md) |

**Conclusion:** the L4 (`rate_limit`) and L5 (`attack_mode`/challenge) mechanisms exist,
and deepening them adaptively is the G series, which we are doing anyway. There is no
new scope in **rate-based** L7 DDoS — it is covered by finishing G1–G4. We are not
filing duplicate tickets. What is new in DDoS is **not rate-based** but
connection/protocol level: §4.2.

### 4.2 Connection/protocol level — slow attacks and HTTP/2 DoS (genuinely new, NOT in the cascade)
This is what rate-based L7 (§4.1) fundamentally cannot catch: attacks at the connection
and HTTP/2 frame level. They all live **below `access_by_lua`** — the cascade never sees
them, so the cure is in nginx directives plus the build version, with Lua only observing
and feeding reputation (the pattern: nginx mitigates → Lua logs → reputation/edge ACL
escalates).

| Threat | Why §4.1 misses it | Where it is handled | Tickets |
|---|---|---|---|
| **slowloris / slow POST / slow read** | GCRA counts requests; here there are few requests and many idle connections, and a challenge never reaches a client that does not finish its request | `client_*_timeout`, `limit_conn`, `keepalive_*` in nginx plus a `log_by_lua` shim → `bac_log` → reputation | **[E1]** baseline, **[E2]** observability, **[E3]** a policy knob (optional) |
| **HTTP/2 Rapid Reset (CVE-2023-44487) and relatives** | frame level, below HTTP semantics; the stream is reset before Lua ever sees the request | a patched build (nginx ≥1.25.3) plus `http2_max_concurrent_streams` | **[E4]** a mitigation audit; **[E5]** h2 abuse as a reputation signal (depends on R2) |

Fundamentally: **neither E1–E3 nor E4–E5 add a stage to `verdict.lua`** — a slow client
and a reset stream never get there. Our BAC contribution here is observability plus
feeding reputation (G1) and escalating into the edge-ACL feed (§4.3), not a new decision
point.

> ⚠️ **E4 ≠ R2.** R2 is HTTP/2 **fingerprinting** (detecting and identifying a client,
> anti-JA4-rotation). E4 is HTTP/2 **DoS mitigation** (Rapid Reset). Different layers of
> the problem; the boundary is spelled out explicitly in the tickets.

### 4.3 Volumetric L3/L4 — the network layer (⚠️ OUTSIDE the OpenResty stand)
**The honest boundary:** SYN floods, UDP/amplification and packet floods **cannot be
cured in OpenResty/Lua** — by the time traffic reaches nginx the TCP handshake has
already happened. This is the network layer: edge ACLs, conntrack/iptables rate limits,
eBPF/XDP drops, BGP blackholing, anycast spreading. Per
the project scope this is **reality level 3** — the territory of the
production edge's network and infrastructure admins, which we have no production access
to.

What we **can** do within our scope, without reaching into someone else's
infrastructure:
- **design the contract** between our L7 detector and the network layer: when L7 sees a
  hopeless source (a crude flood, zero solve rate, the edge budget exhausted), emit a
  "drop this at L3/L4" signal (format, transport) for the network layer to execute. This
  is an **edge-ACL feed**, an analogue of `ip_blocklist` but for a firewall rather than
  for Lua;
- write a **research ADR/design** for eBPF/XDP dropping as a future phase, without
  implementing it in production.
- do NOT assume an integration with a production edge's configuration management.
  If a production network layer becomes necessary, that is a separate phase.

## 5. API security / account protection — an adjacent axis (0 tickets in the backlog)

The third new axis alongside WAF (§3) and DDoS (§4). **Closer to the existing core than
WAF** — nearly all the foundation (rate/reputation/challenge/fingerprint) is already in
the code, so it is cheaper.

### 5.1 The key limitation — the edge is identity-blind
`verdict.lua` sees the IP, fingerprint, UA, Host, path and headers, but **not "which
account" and not "which API key"**. `rate_limit.lua` keys on IP / IP+UA / fingerprint /
URI bucket. To do per-account or per-key control we need a **new identity-extraction
stage** (the username from a login form, the token from `Authorization`, the API key
from a header or query) → a key for rate limiting and reputation, exactly as
`rate_tls_fp` keys on the fingerprint. Without it the axis cannot be built.

A second cross-cutting point: the strongest auth-abuse signal is the **share of failed
logins**, which the edge sees only from the origin's response (`$status` 401/403 in the
log or header phase). That is the same feedback pattern as **the solve-rate work (challenge solve
rate)**.

### 5.2 Scope — two clusters

**Account protection:**
| Threat | What the edge can do | Fit |
|---|---|---|
| Credential stuffing | volume plus per-username/per-IP rate limits plus challenge plus bot score plus failed-ratio feedback | ★★★ |
| Brute force (one account) | per-account rate limits plus challenge escalation | ★★★ |
| Fake registration | rate limits on /signup plus challenge plus fingerprint/reputation | ★★★ |
| Account takeover (ATO) | context signals only (fingerprint/geo/ASN); the decision belongs to the **backend** (the edge does not know the history) | ★ partial |

**API security:**
| Threat | What the edge can do | Fit |
|---|---|---|
| API scraping / abuse | partly covered by `rate_api`  and `rate_scan_urls`; new: per-API-key quotas | ★★★ |
| API key brute force / leaked key | rate limits plus reputation per key | ★★★ |
| Enumeration / BOLA probing | overlaps with `rate_scan_urls` (recon URIs) | ★★ |
| Schema/contract enforcement | partly hygiene, partly **WAF** (§3) — the boundary goes in an ADR | ★★ |
| Business-logic abuse (coupons, scalping) | needs application context → **backend**, not the edge | ★ out of scope |

### 5.3 What gets reused
`rate_limit.lua` (the GCRA engine plus keying — we add account/api_key/endpoint-class
keys), `is_api_path()`/glob matching, `policy` plus the B10 Policy API (per-host auth
paths and quotas), `reputation` (per key / per account), `challenge`/`attack_mode` (a
step-up on auth), `bac_log` plus tags, and the the solve-rate work pattern (response-phase feedback for
the failed-login ratio).

### 5.4 The `P` series — the first wave (auth abuse plus quotas), filed
P covers the auth-credential-abuse and rate/quota domains. Tickets are in §7.
1. **The identity-extraction stage** — username/token/API key → keys. ⚠️
   **PII/security**: hash the username, **never log or store passwords**, and do not
   inspect the password body.
2. **Per-credential / per-key GCRA profiles** (`rate_login_per_account`, `rate_api_key`).
3. **A failed-auth feedback loop** — origin 401/403 → a counter → reputation/challenge
   (modelled on the solve-rate work).
4. **Auth-endpoint policy config** — declaring login/register/API paths plus per-host
   quotas.
5. *(optional, possibly backend)* **a breached-credential / disposable-email signal** — a
   catalog like `ip_blocklist`; the edge does not validate passwords.

### 5.5 The honest boundaries
- **ATO** (an anomalous successful login) — the edge does not know the account history;
  the decision belongs to the backend.
- **Business-logic abuse** — needs application context, outside the edge.
- **Credential stuffing** at the edge means volume plus failed ratio plus bot score,
  **not** checking a password against a breach list (the edge never touches passwords).
- **Schema enforcement** partly bleeds into WAF (§3) — pin the boundary in an ADR so it
  does not duplicate the W series.

### 5.6 The `Q` series — the second wave (API contract / governance / transport), filed
P covers only the abuse-control slice (auth plus quotas). Full API protection is broader;
the second wave adds what is edge-reachable but was not in P (domains 4/7/8 plus part of
1/3). This is a **positive model** (an allowlist of what is permitted), complementary to
the negative WAF model (§3, the `W` series); the Q↔W boundary goes in an ADR. Tickets are
in §7.

| Ticket | What | OWASP API |
|---|---|---|
| **Q1** | a positive per-endpoint contract (allowlisting method/CT/parameters) | API5 (the BFLA slice) |
| **Q2** | body schema validation (an OpenAPI subset) over Channel C | API3 input (mass assignment) |
| **Q3** | resource limits: body size plus JSON depth / GraphQL cost | API4 |
| **Q4** | edge JWT/token validation (signature plus exp/aud/iss) | API2 |
| **Q5** | mTLS / client certificates for the API (optional, per tenant) | API2 |
| **Q6** | transport hygiene: HSTS/CORS plus banner stripping plus error masking | API8 |
| **Q7** | API inventory: shadow endpoints from the log plus enforcement of deprecated versions | API9 |

The DAG rests on the P foundation — `P4` holds up Q1/Q7, `P1` holds up Q4; within Q:
Q1→Q2, Q3→Q2. Early and cheap: Q3, Q6 (and the spike-sized Q5).

**A hard boundary (⛔ backend, not edge):** object and function authorisation (full
BOLA/BFLA), semantic mass assignment, business logic and PII in responses all need
identity plus ownership plus business rules, which the edge does not have. The edge
supplies a signal (ID enumeration, a bot score), not a decision. One nuance: for APIs you
**cannot rely on the challenge** (the C series is browser-based) — enforcement rests on
rate limits, key auth, reputation and mTLS.

## 6. Proposed ordering (by effect over cost)

The starting point: post-MVP (the D-series detector) plus the rate-based G series still
in flight, which **on its own closes L7 DDoS** (G1–G4). Post-post-MVP adds **new axes**
that are absent from the backlog entirely:

1. **Slow-attacks baseline** (§4.2, [E1]) — the cheapest and most urgent: the stand is
   currently vulnerable to slowloris out of the box (no `limit_conn`, no timeouts). Pure
   nginx config.
2. **The WAF spike plus ADR-007** (§3.2) — research, does not block the D series, can
   start early.
3. **API security / account protection** (§5) — cheaper than WAF because it is closer to
   the core (rate/reputation/challenge/fingerprint). The foundation is
   identity-extraction (§5.4).
4. **WAF MVP** (§3.1) — after the ADR, along whichever path it chooses.
5. **HTTP/2 DoS audit** (§4.2, [E4]) — targeted, depends on the build version.
6. **The DDoS L3/L4 contract** (§4.3) — design the edge-ACL feed; implementing the
   network-level drop is a future phase with production access.
7. **Rate-based L7 DDoS** — deliberately NOT tracked as a separate item here: that is
   G1–G4 in the G series.

## 7. Relation to the existing backlog and research
- **Rate-based L7 DDoS — already in the backlog (layer G):** (subnet
  reputation), (transient drop), (automatic attack
  mode), (cross-tenant). It uses the solve-rate signal from layer D
  () and rests on `attack_mode`  plus `rate_limit` , which
  are already in the code.
- **Connection/protocol-level DDoS — filed (§4.2):** [E1] (slow-attacks
  baseline), [E2] (observability), [E3] (a policy knob,
  optional); [E4] (HTTP/2 DoS mitigation audit), [E5] (h2 abuse
  as a signal, depends on R2 ). Reuses `bac_log`, the metrics, G1 reputation
  and the edge ACL.
- **WAF — there is NO such axis in the backlog** (checked: 0 tasks on WAF/SQLi/XSS).
  Proposed as a `W` series: W1 spike/ADR-007, W2 the engine, W3 the signature catalog
  over Channel C, W4 a per-host WAF profile in the policy, W5 virtual patching. Reuses
  ADR-006 (git catalogs), B10 (the Policy API) and `policy.enforce` (the mode gate),
  plus `bac_log` and the metrics.
- **API security / account protection — filed (§5.4, the `P` series):** [P1] (identity extraction), [P2] (per-key/per-account profiles), [P3]
  (failed-auth feedback), [P4] (auth-endpoint policy config),
  [P5] (optional breached credentials). Closer to the existing core than WAF.
- **API contract / governance — filed (§5.6, the `Q` series):** [Q1] (per-endpoint contract), [Q2] (schema validation), [Q3] (resource limits), [Q4] (edge JWT), [Q5] (mTLS, optional), [Q6]
  (transport hygiene), [Q7] (API inventory). A positive model,
  complementary to WAF (`W`).
- **Volumetric L3/L4** — outside the stand repo's scope; present as a contract plus
  research, not as an implementation (reality level 3).

## 8. What we are NOT doing at this step
- No WAF code lands before ADR-007 (build versus buy is settled by the spike).
- No more **rate-based** L7 DDoS tickets — that is the G series (G1–G4), already in the
  backlog.
- Slow attacks and HTTP/2 DoS are not added as cascade stages — they sit below
  `access_by_lua` (nginx directives plus the build plus a log shim; E1–E3 / E4–E5).
- We do not reach into the network layer (eBPF or routing on live edges) — a
  separate phase.
