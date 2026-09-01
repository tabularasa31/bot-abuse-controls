# WAF — catalog of content-inspection rules (the W series)

The complete list of WAF rules in "if condition (a signature match) → then verdict/flag"
form. The source of truth for behaviour is [waf-spec.md](waf-spec.md); this document is
the flat reference for "what fires on what". The entity vocabulary is
[waf-entities-reference.md](waf-entities-reference.md), and the catalog and profile
formats are in [waf-config-templates.md](waf-config-templates.md).

**Status:** a design contract (target behaviour); the engine (build versus buy) is not
chosen and remains open (settled by a spike plus an architectural decision). The rule
semantics below are described at the contract level and hold regardless of the engine
choice; the internals of the signatures (concrete regexes or seclang) are deliberately
abstract and are pinned down together with the engine.

**How to read it.** The WAF is a negative model (we look for known-bad patterns). Its
complement is the positive model of an API contract (what is PERMITTED), described in a
separate spec and applied together with the WAF rather than instead of it. Every WAF rule
lives on one cascade stage, `waf`. Each rule either accumulates a challenge flag
(`waf:sqli`, `waf:xss`, …) consolidated at L5 (`verification`), or — for the critical
classes — performs a hard block itself through `policy.enforce` (by analogy with the way a
`tls_fp_blocklist` hit returns 403 directly). The cascade invariant is preserved: the
single point where flags are consolidated is L5; rules do not issue verdicts themselves
apart from the explicit hard-block exit points under `policy.enforce`.

Notation:

- **Category** — `blocking critical` (a critical rule → a direct hard block through
  `policy.enforce`) or `soft flag` (accumulates a challenge flag, with the final decision
  at L5).
- **Inspection target** — what exactly is checked: the query string, the body, the
  headers, the path.
- **Source** — where the signatures come from (the `waf_rules` catalog, delivered over
  Channel C).
- **Stage** — for every WAF rule this is the `waf` stage.

All the rules run only when `waf_enabled=true` in the per-host WAF profile; by default the
stage is in shadow (like the whole cascade) — a match is logged but not physically enforced
until `mode=active`.

---

## Signature classes (the OWASP Top 10 core)

| # | If… (a signature match) | Then… | Category | Inspection target | Source | Stage |
| --- | --- | --- | --- | --- | --- | --- |
| W1 | After normalisation, a SQL injection (SQLi) signature is found in the query string or the request body (form-urlencoded / JSON) | the flag `waf:sqli` (consolidated at L5); for critical SQLi rules → `policy.enforce` (a hard block) | soft flag / blocking critical | query, body | `waf_rules` | `waf` |
| W2 | After normalisation, an XSS signature is found in the query string, the body or the headers (script injection or an HTML context) | the flag `waf:xss` (consolidated at L5); for critical XSS rules → `policy.enforce` (a hard block) | soft flag / blocking critical | query, body, headers | `waf_rules` | `waf` |
| W3 | A path-traversal signature is found in the path, the query or the body (`../`, null bytes, directory escapes, protocol anomalies in the path) | the flag `waf:path_traversal`; critical rules → `policy.enforce` (a hard block) | soft flag / blocking critical | path, query, body | `waf_rules` | `waf` |
| W4 | A command-injection signature is found in the query, the body or the headers (shell command injection, metacharacters, backticks, pipes) | the flag `waf:command_injection`; critical rules → `policy.enforce` (a hard block) | soft flag / blocking critical | query, body, headers | `waf_rules` | `waf` |
| W5 | An SSRF/LFI signature is found in the query, the body or the headers (an attempt to reach internal addresses or local files) | the flag `waf:ssrf_lfi`; critical rules → `policy.enforce` (a hard block) | soft flag / blocking critical | query, body, headers | `waf_rules` | `waf` |

**A note on categories.** One attack class is covered by a set of rules of differing
criticality: unambiguous exploit patterns run as `blocking critical` (a direct
`policy.enforce`), while noisier heuristics run as `soft flag` and accumulate for the L5
decision alongside the cascade's other signals. Exactly which rule is critical is part of
the `waf_rules` catalog's content and is calibrated through staged rollout, not baked into
this reference.

---

## Virtual patching — shield rules

Targeted rules for a specific CVE or a customer's vulnerable endpoint. Technically these
are ordinary entries in the `waf_rules` catalog, but with a fast PR workflow (modelled on a
HIGH candidate for `tls_fp_blocklist`). They close the hole at the edge within minutes
while the origin is being patched.

| # | If… (a signature match) | Then… | Category | Inspection target | Source | Stage |
| --- | --- | --- | --- | --- | --- | --- |
| W6 | A request to a specific vulnerable endpoint or path matched a virtual-patch signature for a known CVE (a customer's targeted shield rule) | the flag `waf:virtual_patch`, or a direct `policy.enforce` — specified in the rule | soft flag / blocking critical | path, query, body, headers | `waf_rules` (a virtual-patch entry) | `waf` |

A virtual-patch rule goes through the same cycle as any catalog entry: PR → staging
(observation) → active, with a fast `git revert` available. Its criticality (a flag versus
`policy.enforce`) is set in the rule itself — for an acute CVE shield it is usually
`policy.enforce` straight after a short staging observation.

---

## Category summary

| Category | What it does | Where it is enforced |
| --- | --- | --- |
| `blocking critical` | A direct hard block through `policy.enforce` (403) at the `waf` stage itself, without waiting for L5 | the `waf` stage (an exit point) |
| `soft flag` | Accumulates a `waf:*` challenge flag; the final decision (challenge/pass/permissive) is taken at L5 (`verification`) | the flag is set at `waf`, the decision happens at L5 |

Every match (critical or soft, active or staging) lands in `bac_log` and increments the
`antibot_rule_total{stage="waf",...}` metric. Staging matches are additionally written to
`staging_match` and never lead to a hard block, even in `mode=active` (see
[waf-config-templates.md](waf-config-templates.md)).
