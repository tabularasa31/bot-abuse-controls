# WAF — L7 content inspection — specification (post-MVP)

**Version:** v1.0 · Status: a design contract (target behaviour) · a post-MVP layer

This document describes the target behaviour of the WAF layer as a separate layer on top
of the cascade. The engine choice (build versus buy) is deliberately left open, to be
settled by a spike and an architectural decision (see §4); no code is committed before
that decision.

**Related material:**

[waf-rules-reference.md](waf-rules-reference.md) — the rules and signatures in
"if condition → verdict" form; [waf-entities-reference.md](waf-entities-reference.md) —
the vocabulary (the stage, the `waf_rules` catalog, tags, log fields, enumerations);
[waf-config-templates.md](waf-config-templates.md) — the format of the signature catalog
and the per-host WAF profile.

---

## 1. What it is

A layer that inspects the content of an HTTP request against attack signatures (a
negative security model): SQL injection, XSS, path traversal, command injection, obvious
SSRF/LFI, plus virtual patching — targeted shield rules for a specific CVE or customer
endpoint.

The WAF is a negative model (we look for known-bad patterns). Its complement is the
positive model of an API contract (what is permitted), see [api-spec.md](api-spec.md).
The boundary between the two models is pinned down by the same architectural decision as
the engine choice.

## 2. Why

The cascade today does not inspect request bodies, query/POST parameters or headers
against signatures. [vision.md](../product/vision.md) names DDoS as an explicit goal and mentions
WAF only indirectly (XSS as the reason for `HttpOnly` on the cookie). This is greenfield:
a whole class of application-level attacks (the OWASP Top 10 core) currently passes
straight through the cascade to the origin.

## 3. Where it sits in the cascade

The WAF adds a new content-inspection stage (`waf`) that accumulates flags (`waf:sqli`,
`waf:xss`, …) and, for critical rules, can block on its own — by analogy with the way a
TLS fingerprint blocklist hit calls `policy.enforce(403)` directly.

```
hygiene → [contract] → reputation → tls_fp → [WAF inspection] → rate_limits → verification
```

The cascade invariant is preserved ([rules-reference.md](../product/rules-reference.md)): the single
point where flags are consolidated is L5 (`verification`), and rules do not issue verdicts
themselves apart from the explicit hard-block exit points under `policy.enforce`. The WAF
sits after the cheap identity checks and the positive contract, before the expensive
behavioural ones (rate_limits) — the exact position is pinned down at implementation time.

## 4. The engine fork — a spike plus an architectural decision (deferred)

The WAF engine is deliberately left unresolved: build versus buy has not been chosen.

- **Option A — Coraza plus OWASP CRS.** A Go implementation of ModSecurity seclang plus a
  Core Rule Set proven over years.
  - **+** instant Top 10 coverage, maintained rules, familiar seclang.
  - **−** someone else's rule model, outside our catalog delivery / shadow mode / log;
    either a separate Go service (an extra internal hop, previously rejected in favour of
    edge Lua) or an immature Lua binding; body-inspection latency needs measuring; CRS
    false positives need tuning that does not fit our staging→active out of the box.
- **Option B — our own ruleset in the style of the cascade.** A `waf.lua` stage with our
  own signatures; the `waf_rules` catalog delivered like the TLS fingerprint blocklist;
  shadow/active through `policy.enforce`; flags in the log; staged rollout and
  `git revert` for free.
  - **+** one architecture (log, metrics, kill switch, mode gate, PR workflow, CI
    validation), controlled latency.
  - **−** we own completeness and anti-evasion; coverage grows slowly; the risk of "our own
    CRS, worse than CRS".
- **Option C — a hybrid:** our own execution engine plus an import of a subset of CRS
  signatures as data in our catalog format.

**The recommendation is to spike before committing:** (1) measure per-request
body-inspection latency for Coraza versus native Lua on a representative body; (2) assess
whether CRS tuning fits shadow→staging→active; (3) estimate the size of our own signature
core for the Top 10; (4) pin down the boundary with the positive contract model. The
result is an architectural decision, "WAF engine: build vs buy".

## 5. How — the components

### 5.1 MVP scope

- Inspection of the query string and the POST body (form-urlencoded plus JSON; multipart
  is phase 2).
- Inspection of headers and the path (path traversal, null bytes, protocol anomalies).
- Signatures for the OWASP Top 10 core: SQLi, XSS, path traversal, command injection,
  SSRF/LFI.
- Shadow by default (like the whole cascade), plus per-host on/off through the policy.

Out of MVP scope: ML anomaly detection on bodies, CRS paranoia 3+, full anti-evasion
normalisation of every encoding.

### 5.2 The inspection engine

A `waf.lua` stage along whichever path is chosen: a normalisation preprocessor plus
signature matching; flags into the log; critical rules → `policy.enforce`. Metrics:
`antibot_rule_total{stage="waf",...}`.

### 5.3 The `waf_rules` signature catalog

Delivered like the TLS fingerprint blocklist: git is the single source of truth, PR-only
plus CODEOWNERS, staged rollout (staging→active, `staging_match` in the log),
`git revert`. The rule format follows from the chosen engine. CI validation (syntax and
compilation) runs before a merge.

### 5.4 The per-host WAF profile

An extension of the policy: `waf_enabled`, `waf_paranoia` (the level) and
`waf_disabled_rules` (an array of disabled rule ids, for one customer's false positives),
edited through the per-host policy (PATCH). Mode and strictness are independent of the
profile.

### 5.5 Virtual patching

A targeted shield rule for a specific CVE or customer endpoint — technically an entry in
`waf_rules` with a fast PR workflow (like a HIGH blocklist candidate → a PR to the
catalog). The fast-rollout runbook: PR → staging (observation) → active; with a fast
revert. It closes the hole at the edge within minutes while the origin is being patched.

## 6. Open questions

- **Body buffering** (`lua_need_request_body`/`request_body`) conflicts with large uploads
  → a size limit (see the resource limits in [api-spec.md](api-spec.md)) plus a bypass for
  media and uploads.
- **Normalisation** (URL decode, unicode, comment stripping) — a shared preprocessor ahead
  of the signatures, otherwise evasion is trivial.
- **Latency** of body inspection on every request — measured in the spike (§4).

## 7. What we reuse

The slow-catalog delivery (PR-only git catalogs), the per-host policy, `policy.enforce`
(the mode gate / shadow→active), the log and the metrics, the kill switch, staged rollout,
the blocklist promotion pattern, and CI validation of catalogs.

## 8. Technical boundaries

- The WAF (a negative model) does not replace the positive API contract — they are
  different models and are applied together.
- Until the engine is chosen, no code is committed (a status invariant).
- Signature completeness and anti-evasion are a long tail, filled in iteratively
  (especially under option B).

## 9. Components and rollout order

| Component | The gist | Depends on |
| --- | --- | --- |
| The spike plus the engine decision | build versus buy plus the boundary with the positive contract | — (the flagship, can start early) |
| The `waf.lua` engine | inspection of body/query/headers, the Top 10 | the engine decision |
| The `waf_rules` catalog | signatures through catalog delivery, staged | the engine |
| The per-host WAF profile | paranoia / disabled rules / on-off | the engine |
| Virtual patching | a shield rule for a CVE or endpoint | the catalog |
