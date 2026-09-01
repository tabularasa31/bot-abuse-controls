# WAF — config templates (the W series)

Illustrative templates for the formats of the WAF axis: the `waf_rules` signature catalog,
the per-host WAF profile in the policy, the staged rollout conventions and a
virtual-patch rule template. The source of truth for behaviour is [waf-spec.md](waf-spec.md).
The rule list is [waf-rules-reference.md](waf-rules-reference.md), and the entity
vocabulary is [waf-entities-reference.md](waf-entities-reference.md).

**Status:** a design contract (target behaviour); the engine (build versus buy) is not
chosen and remains open (settled by a spike plus an architectural decision). The exact signature syntax is pinned down together with the
engine (our own Lua / Coraza+CRS seclang / a hybrid). The templates below deliberately
describe the structure and semantics at the contract level — the entry's fields, statuses,
inspection scope, the mode gate — so that they hold regardless of the engine
choice. The internals of the signatures (regex/seclang) are shown as abstract
placeholders.

**Format:** shown as YAML with comments for readability. What matters is the
data structure and the semantics of the fields, not the exact syntax.

> **Precedent.** `waf_rules` is delivered over Channel C exactly like
> `tls_fp_blocklist`: git is the single source of truth, PR-only plus
> CODEOWNERS, staged rollout (`staging`/`active`), `git revert`, CI validation
> (syntax and compilation) before a merge. The blocklist-catalog contract is the same;
> only the content of an entry differs (a signature instead of a fingerprint string).

## The WAF config hierarchy

```
waf_rules/                  ← the signature catalog (PR-populated, over Channel C, with staging)
  sqli.yaml                 ← SQL injection signatures
  xss.yaml                  ← XSS signatures
  path_traversal.yaml       ← path traversal signatures
  command_injection.yaml    ← command injection signatures
  ssrf_lfi.yaml             ← SSRF/LFI signatures
  virtual_patch.yaml        ← targeted shield rules for customers' CVEs and endpoints
policy/<host>.yaml          ← the per-host WAF profile (part of the policy, per host)
```

The split across files is illustrative; the actual layout (one file or
several) is settled at implementation time. The contract is the entry format, not the file.

---

## 1. `waf_rules` — the signature catalog

Each entry is one signature for an attack class. The entry's fields are contractual
(`id`, `class`, `category`, `targets`, `status`); the signature body (`signature`)
is an abstract placeholder whose syntax is set by the chosen engine.

```yaml
# waf_rules — the signature catalog (over Channel C, PR-only, with staged rollout)
# The signature body (signature) is a placeholder; the real syntax is set by the chosen engine.

rules:
  - id: sqli_union_select_001          # a stable id, written to rule / staging_match
    class: sqli                        # sqli | xss | path_traversal | command_injection | ssrf_lfi | virtual_patch
    category: blocking_critical        # blocking_critical | soft_flag
    flag: "waf:sqli"                   # which challenge flag a soft rule sets (for soft_flag)
    targets: [query, body]             # inspection targets: query | body | headers | path
    paranoia: low                      # from which waf_paranoia level the rule is enabled
    status: active                     # staging | active (see staged rollout below)
    signature: <ABSTRACT>              # the signature body — syntax per the chosen engine
    reason: "UNION SELECT exfil pattern"

  - id: sqli_boolean_blind_014
    class: sqli
    category: soft_flag                # a noisy heuristic → a flag, decided at L5
    flag: "waf:sqli"
    targets: [query, body]
    paranoia: medium
    status: staging                    # a new signature — observation first
    signature: <ABSTRACT>
    reason: "boolean-based blind heuristic"

  - id: xss_script_tag_002
    class: xss
    category: blocking_critical
    flag: "waf:xss"
    targets: [query, body, headers]
    paranoia: low
    status: active
    signature: <ABSTRACT>
    reason: "inline <script> injection"

  - id: path_traversal_dotdot_003
    class: path_traversal
    category: blocking_critical
    flag: "waf:path_traversal"
    targets: [path, query, body]
    paranoia: low
    status: active
    signature: <ABSTRACT>              # directory escapes / null bytes / protocol anomalies in the path
    reason: "../ directory traversal + NUL byte"
```

**Semantics of the entry's fields:**

- `id` — a stable signature identifier. It is written to the log's `rule` (on a
  critical match) and to `staging_match` (in the form `waf_rules:<id>`). It is used
  in `waf_disabled_rules` for targeted suppression.
- `class` — the attack class (the OWASP Top 10 core plus `virtual_patch`). It determines which
  class flag is set.
- `category` — `blocking_critical` (a direct hard block through `policy.enforce`) or
  `soft_flag` (accumulates a challenge flag, decided at L5). One attack class is
  covered by a set of rules of differing criticality; the split is part of the catalog's
  content and is calibrated through staged rollout.
- `targets` — what is inspected: `query`, `body`, `headers`, `path`. Body inspection
  requires buffering (`lua_need_request_body` / `request_body`), so a body size
  limit applies along with a bypass for media and uploads (see the open questions in the spec).
- `paranoia` — from which `waf_paranoia` level of the per-host profile the rule is enabled
  (`low`/`medium`/`high`). Which rules belong to which level is the catalog's content.
- `status` — `staging` or `active` (staged rollout).
- `signature` — the signature body. It is applied AFTER the shared normalisation
  (URL decode, unicode, comment stripping) — otherwise evasion is trivial. The syntax is set by the chosen engine.

---

## 2. The per-host WAF profile (inside `policy/<host>.yaml`)

An extension of a domain's policy. It is edited through the per-host policy (PATCH) and reaches
the proxy over Channel C as part of the `policy` catalog. It is independent of
`mode`/`strictness`: `mode` governs shadow versus active enforcement (the
`policy.enforce` mode gate), while the WAF profile governs inspection coverage.

```yaml
example.com:
  # ... the rest of the domain's policy (mode, strictness, rate_rules and so on) ...

  # --- the per-host WAF profile ---
  waf_enabled: true                    # boolean, default false — the waf stage is skipped entirely
  waf_paranoia: low                    # low | medium | high (default low)
  waf_disabled_rules:                  # ids of waf_rules entries disabled for THIS domain
    - sqli_boolean_blind_014           # targeted suppression of one customer's false positive
    - xss_attribute_ctx_021
```

**Semantics:**

- `waf_enabled=false` (the default) — the `waf` stage is skipped entirely for the domain
  and no inspection runs.
- `waf_paranoia` — how many rules are enabled and how aggressively. `low` is
  the starting level for a new domain (only the core of unambiguous signatures, minimal
  false positives); `high` is the most aggressive set and needs tuning through
  `waf_disabled_rules`. CRS paranoia 3+ is out of MVP scope.
- `waf_disabled_rules` — targeted suppression of signatures by `id` for one
  domain, without touching the global catalog. For false positives specific to one customer.

**Interaction with the mode gate.** Under `mode=shadow` a match of any WAF rule is
written to `bac_log` (and increments `antibot_rule_total{stage="waf"}`), but is
not physically enforced. Under `mode=active` critical rules really block
through `policy.enforce(403)`; soft flags go on to be consolidated at L5.

---

## 3. Staged rollout conventions (as for `tls_fp_blocklist`)

The same rules that apply to the cascade's other PR catalogs apply to
`waf_rules`:

1. **New signatures are always added with `status: staging`.** In that status the
   rule matches and the hit is written to the log's `staging_match` (in the form
   `waf_rules:<rule_id>`), but it never leads to a hard block, even in `mode=active`.
2. The observation period is at least 24 hours after delivery to the proxy (a representative
   sample in the logs).
3. After the observation, with no false positives, a separate PR moves it to
   `status: staging` → `status: active`.
4. If the signature produced a false positive during the `staging` period, revert the original
   PR (do not leave it in staging, so that forgotten entries do not pile up).

Promoting a signature is a separate, deliberate step, never automatic. CI validation
(rule syntax and compilation) is a mandatory gate before merging any PR into
`waf_rules`.

---

## 4. A virtual-patch rule template

A targeted shield for a specific CVE or a customer's vulnerable endpoint — technically an ordinary
entry in `waf_rules` of class `virtual_patch`, but with a fast PR workflow (modelled
on a HIGH blocklist candidate → a PR to `tls_fp_blocklist`). It closes the hole at the
edge within minutes while the origin is being patched.

```yaml
rules:
  - id: vpatch_cve_2026_XXXX_login     # the CVE or incident is referenced in the id
    class: virtual_patch
    category: blocking_critical        # an acute CVE shield — usually a hard block right away
    flag: "waf:virtual_patch"
    targets: [path, query, body, headers]
    paranoia: low                      # the shield works at every level
    status: staging                    # a short observation, then a fast promotion to active
    scope_host: example.com            # optional: restrict the shield to one domain or endpoint
    scope_path: /vulnerable-endpoint   # optional: narrow it to the vulnerable path
    signature: <ABSTRACT>              # the exploit signature for that specific CVE
    reason: "virtual patch for CVE-2026-XXXX until origin is patched"
```

**The fast-rollout runbook:**

1. A PR with the virtual-patch entry (`status: staging`) → delivery over Channel C.
2. A short observation through `staging_match` (confirming it does not touch legitimate traffic).
3. A PR promoting it to `status: active` — the shield starts blocking at the edge.
4. Once the origin is patched, a fast `git revert` of the entry.

Criticality (`soft_flag` versus `blocking_critical`) is set in the rule itself; for an
acute CVE shield it is usually `blocking_critical` straight after a short staging period.

---

## 5. What the format does NOT contain (the boundaries)

- **The syntax of the signature body** — not fixed until the engine is chosen (`signature:
  <ABSTRACT>`). It depends on the engine choice (our own Lua / CRS seclang / a hybrid).
- **The positive model (the API contract)** — a separate axis with a separate format; the WAF
  (a negative model) does not replace it, see [waf-spec.md](waf-spec.md) §1 and
  the API contract spec.
- **Multipart body inspection, ML anomalies, full anti-evasion across every encoding**
  — out of MVP scope; they are not baked into the entry format beyond `targets` and normalisation.
