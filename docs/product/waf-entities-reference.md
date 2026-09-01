# WAF — entity reference (the W series)

Terms and definitions of the WAF axis, plus entity tables: the `waf` stage, the
`waf_rules` catalog, tags and flags, the per-host WAF profile fields, log fields and
enumerations. The source of truth for behaviour is [waf-spec.md](waf-spec.md). The rule
list is [waf-rules-reference.md](waf-rules-reference.md), and the formats are in
[waf-config-templates.md](waf-config-templates.md).

**Status:** a design contract (target behaviour); the engine (build versus buy) is not
chosen and remains open (settled by a spike plus an architectural decision). The names of
the stage, catalog, flags and fields are contractual and hold regardless of the engine
choice.

---

## Terms

| Term | Definition |
| --- | --- |
| **WAF** | L7 content inspection against attack signatures — a negative security model (we look for known-bad patterns). It adds the `waf` stage to the cascade. |
| **Negative model** | The "block the known bad" approach. This is exactly what the WAF implements. Its complement is the positive model (an API contract: what is PERMITTED), described in a separate spec; the models are applied together and the WAF does not replace it. |
| **The `waf` stage** | A new content-inspection stage of the cascade. It accumulates `waf:*` flags and, for critical rules, performs a hard block itself through `policy.enforce` (by analogy with `tls_fp_blocklist`). It sits after the cheap identity checks and the positive contract, before rate_limits. |
| **The `waf.lua` engine** | The implementation of the stage: a normalisation preprocessor plus signature matching. The implementation path (our own Lua / Coraza+CRS / a hybrid) is chosen by a spike plus an architectural decision; no code is committed before it. |
| **The `waf_rules` catalog** | The set of attack signatures delivered to the proxy over Channel C exactly like `tls_fp_blocklist`: git is the single source of truth, PR-only plus CODEOWNERS, staged rollout, `git revert`. The rule format follows from the chosen engine. |
| **Signature** | One pattern rule inside `waf_rules` for a specific attack class or CVE. It has an id, a class, a criticality and a status (staging/active). The internals (regex/seclang) stay abstract until the engine is chosen. |
| **Flag (`waf:*`)** | The challenge flag a soft WAF rule places on a request (`waf:sqli`, `waf:xss`, …). It does not block by itself — it accumulates and is consolidated at L5, like the cascade's other soft flags. |
| **Critical rule** | A signature of the `blocking critical` category: on a match it performs a direct hard block through `policy.enforce`, without waiting for L5. |
| **Per-host WAF profile** | An extension of a domain's policy: `waf_enabled`, `waf_paranoia`, `waf_disabled_rules`. Edited through the per-host policy (PATCH). Independent of `mode`/`strictness`. |
| **Paranoia** | The WAF sensitivity level (`waf_paranoia`): how many rules are enabled and how aggressively. The analogue of CRS paranoia levels. It affects signature coverage, not the mode gate. |
| **Virtual patching** | A targeted shield rule for a specific CVE or customer endpoint — an entry in `waf_rules` with a fast PR workflow. It closes the hole at the edge while the origin is being patched. |
| **Normalisation** | The shared preprocessor that runs BEFORE the signatures (URL decode, unicode, comment stripping), without which evasion is trivial. It is applied to the inspection target before matching. |
| **mode gate (`policy.enforce`)** | The shadow→active mechanism: in shadow the WAF verdict is logged but not physically enforced; in active the critical rules really block. Reused from the cascade unchanged. |

---

## The stage

| Name | Corresponds to | What it does | Data source |
| --- | --- | --- | --- |
| `waf` | a new content-inspection stage | Normalises and matches the inspection targets (query/body/headers/path) against signatures; sets `waf:*` flags; critical rules → `policy.enforce` | `waf_rules` |

The order in the cascade:
`hygiene → [contract (Q)] → reputation → tls_fp → [waf] → rate_limits → verification`.
The exact position is pinned down at implementation time; the invariant is: after the
cheap identity checks and the positive contract, before the expensive behavioural limits.

---

## The catalog

| Name | What is inside | Who populates it | Delivery | Precedent |
| --- | --- | --- | --- | --- |
| `waf_rules` | Attack signatures (SQLi, XSS, path traversal, command injection, SSRF/LFI) plus virtual-patch rules; each entry with an id, class, criticality and status | Product / the team, through PRs (CODEOWNERS) | Channel C (git → proxy), like `tls_fp_blocklist` | `tls_fp_blocklist` — a blocking catalog through PRs plus staged rollout |

**Staged rollout** for `waf_rules`: new signatures are added as `staging` — they match and
are written to `staging_match`, but never lead to a hard block, even in `mode=active`.
After calibration (no false positives) a separate PR moves them to `active`. CI validation
(syntax and compilation) runs before a merge.

---

## Flags (the WAF challenge flags) — they accumulate in `flags` and are consolidated at L5

| Code | Attack class | Where it is set | What it means |
| --- | --- | --- | --- |
| `waf:sqli` | SQL injection | the `waf` stage | An SQLi signature in the query or body |
| `waf:xss` | XSS | the `waf` stage | An XSS signature in the query, body or headers |
| `waf:path_traversal` | path traversal | the `waf` stage | A directory-escape signature, null bytes or protocol anomalies in the path |
| `waf:command_injection` | command injection | the `waf` stage | A shell command injection signature |
| `waf:ssrf_lfi` | SSRF/LFI | the `waf` stage | A signature of reaching internal addresses or local files |
| `waf:virtual_patch` | a virtual patch (CVE) | the `waf` stage | A match against a targeted shield rule for a specific CVE or endpoint |

Soft WAF rules accumulate these flags in the log's `flags` field; critical rules of the
same classes call `policy.enforce` instead of setting a flag. The decision on soft flags is
taken by L5 (`verification`), as with the cascade's other soft signals.

---

## Per-host WAF profile fields (inside a domain's policy)

| Field | Type | Description | Default |
| --- | --- | --- | --- |
| `waf_enabled` | boolean | Whether WAF inspection is on for the domain. `false` skips the `waf` stage entirely | `false` |
| `waf_paranoia` | enum | The sensitivity level (see the enumeration below) — how many rules are enabled and how aggressively | `low` |
| `waf_disabled_rules` | array of string | The ids of rules from `waf_rules` disabled for this domain (targeted suppression of one customer's false positives) | `[]` |

They are edited through the per-host policy (PATCH). They do not depend on
`mode`/`strictness`: `mode` governs shadow versus active enforcement, while the WAF profile
governs inspection coverage.

---

## Log fields relating to the WAF

The WAF writes into the shared `bac_log` JSON log and reuses the cascade's existing fields.
Class specifics are reflected in the flags and markers; no dedicated WAF fields are
introduced beyond what is necessary.

| Field | Type | How the WAF fills it |
| --- | --- | --- |
| `stage` | string (enum) | `waf` — when the final (critical) rule fired at this stage |
| `verdict` | string (enum) | `block` — when a critical WAF rule fired (`policy.enforce`); otherwise L5 determines the verdict |
| `rule` | string | The id of the critical WAF rule that fired |
| `flags` | array of string | The accumulated `waf:*` soft flags (alongside the cascade's other soft flags) |
| `staging_match` | array of string | WAF staging signatures that matched, in the form `waf_rules:<rule_id>` — they lead to no verdict and exist for promotion analytics |

Metric: `antibot_rule_total{stage="waf",...}` increments on every match (active and
staging).

---

## Enumerations

### `waf_paranoia` — the WAF sensitivity level

| Value | Behaviour |
| --- | --- |
| `low` *(default)* | Only the core of unambiguous signatures is enabled; minimal false positives. The starting level for a new domain. |
| `medium` | Plus heuristics of medium aggressiveness. A balance of coverage and false positives. |
| `high` | The most aggressive set. The analogue of high paranoia in CRS; it needs tuning through `waf_disabled_rules`. CRS paranoia 3+ is out of MVP scope. |

Which rules correspond to which level is part of the `waf_rules` content and is calibrated
through staged rollout.

### The WAF rule category

| Value | What it does |
| --- | --- |
| `blocking critical` | A direct hard block through `policy.enforce` (403) at the `waf` stage, without waiting for L5 |
| `soft flag` | Sets a `waf:*` challenge flag; the final decision is taken at L5 (`verification`) |

### Signature status (staged rollout)

| Value | Behaviour |
| --- | --- |
| `staging` | The signature matches and the hit is written to `staging_match`, but it never leads to a hard block, even in `mode=active` |
| `active` | A fully operational rule: a critical one blocks through `policy.enforce`, a soft one sets a flag |
