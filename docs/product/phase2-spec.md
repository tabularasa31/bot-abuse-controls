# Bot & Abuse Controls — Phase 2: TLS fingerprinting

## Context

This continues the L1 MVP task, where the classic cascade is implemented: method,
IP/ASN/geo, rate limits. That is enough to cut off mass noise, but not enough against
modern targeted bots — they disguise themselves as browsers, arrive from residential IPs
at a normal rate, and L1–L3 cannot tell them from real users.

Phase 2 closes that gap with TLS fingerprinting: computing the client's signature from
the TLS handshake. The signature is determined by the client's TLS stack (Chrome NSS /
Firefox NSS / OpenSSL / LibreSSL / Go crypto/tls and so on) and does not change when the
User-Agent is spoofed: a bot can send "Chrome 148" in its UA, but if it is really
python-requests, its TLS fingerprint gives it away.

The task is to embed the TLS fingerprint into the Phase 1 cascade as a separate layer L3
(between reputation and rate_limits, see below) and to collect structured logs enriched
with the fingerprint, for populating catalogs and blocklists later.

The stack is the same — nginx plus OpenResty plus Lua.

## Areas of responsibility

- **Admins** — implementing the fingerprint computation module, embedding the stage into
  the cascade, maintaining the configs through PRs, enriching the logs with TLS fields.
- **Product manager** — framing the task, maintaining the fingerprint catalog and the
  blocklist from log analysis, acceptance.
- **Development** — not involved at this stage.

## What matters about Phase 2

- **Phase 2 does not replace Phase 1, it is added on top.** The four-stage cascade from
  Phase 1 stays as it is, and the TLS fingerprint is inserted between the `reputation`
  and `rate_limits` stages — after the cheap IP/ASN/geo checks, before the expensive rate
  counters.
- **The fingerprint itself does not block — the derived signals do.** The fingerprint is
  a client identifier. Rules operate on top of it (impersonator detection, a blocklist by
  signature, suspicious cipher count).
- **Every Phase 1 principle is preserved:** the cascade only observes (no physical
  blocking in the MVP), rule categories (blocking/allow/soft), one final verdict in the
  log, the kill switch.
- **The main output** is logs enriched with `tls_fp` and informational tags in the
  `tls_fp:*` namespace. From them product maintains the fingerprint catalog and the
  blocklist; when enforcement mode arrives (together with the per-resource shadow_mode in
  a separate task), that data becomes the basis for real blocking.

## Open questions for the admins (before we start)

- **Availability of the required variables in `access_by_lua` on the production
  OpenResty.** We need `$ssl_protocol`, `$ssl_ciphers`, `$ssl_curves`,
  `$ssl_alpn_protocol`, `$ssl_server_name`. If any are missing, we discuss the options (a
  different build, a patch).
- **Where to keep per-fingerprint state in a distributed production.** The fingerprint
  cache and the per-fingerprint counters are a per-proxy `shared_dict`. That is enough for
  the MVP, but a bot that hops between proxies resets its limits. Centralised state (Redis
  or similar) is a separate task; see "Out of scope".

## Where the new stage sits in the cascade

Phase 1 left us a four-stage cascade. Phase 2 adds one stage. Stages are identified by
stable string codes (not ordinal numbers) so that adding or reordering stages in future
does not shift the existing codes and old logs stay interpretable.

| Stage (code) | Purpose | Status |
|---|---|---|
| `hygiene` | Resource identification and basic hygiene | Phase 1, unchanged |
| `reputation` | Source reputation (IP / ASN / geo) | Phase 1, unchanged |
| `tls_fp` | TLS fingerprinting | **NEW — Phase 2** |
| `rate_limits` | Behavioural limits | Phase 1, logic unchanged (one new profile `rate_tls_fp` is added, see below) |
| `egress` | Passing through to the customer's origin | Phase 1, unchanged |

Why between `reputation` and `rate_limits`:

- The fingerprint is cheaper than the rate limits: one `shared_dict` lookup versus N
  counters across windows.
- The fingerprint changes the weight of the rules that follow: if the `tls_fp` stage
  marks a client as an impersonator, it makes sense to apply stricter rate limits at the
  `rate_limits` stage. So the fingerprint has to be computed before the rate limits.
- The fingerprint is more expensive than basic hygiene and IP/ASN (it needs a sha256 hash
  and parsing of the cipher list), so it comes after them.

## Stage `tls_fp` (new). TLS fingerprinting

### What it does

For every request it computes a fingerprint and enriches the request with markers. The
fingerprint by itself leads to no block — it becomes a signal for rules.

### Signal sources

From stock nginx variables in `access_by_lua`:

- `$ssl_protocol` — the TLS version.
- `$ssl_ciphers` — the list of offered ciphers.
- `$ssl_curves` — the list of offered EC curves.
- `$ssl_alpn_protocol` — the negotiated ALPN.
- `$ssl_server_name` — the SNI.

### What has to be computed

**Fingerprint = `L<ver><sni_flag><cipher_cnt><alpn>_<hash_b>_<hash_c>`**, where:

- `ver` — `12` for TLS 1.2, `13` for TLS 1.3.
- `sni_flag` — `d` when SNI is present, `i` when it is not.
- `cipher_cnt` — the number of ciphers after stripping GREASE (RFC 8701: values of the
  form `0x?A?A` where the `?`s match are grease and are discarded).
- `alpn` — a two-letter designation (`h2`, `h1`).
- `hash_b = sha256(the sorted cipher list after stripping GREASE)[:12]` — hex.
- `hash_c = sha256(curves_after_grease + alpn + ver)[:12]` — hex.

An example of the resulting fingerprint for a real Chrome:
`L13d15h2_1ed0482b9b4c_b50336ab2a86`.

Requirements on the computation:

- The fingerprint is computed once per request (or once per TLS connection with caching —
  at the implementation's discretion).
- Stripping GREASE is mandatory — without it the fingerprint is unstable between
  connections (Chrome rotates GREASE).
- The result is a deterministic string, identical for one and the same TLS stack.

### Rules of the stage

| Rule | Signal | Category |
|---|---|---|
| `tls_fp_blocklist` | The client's fingerprint is in `tls_fp_blocklist.conf`. | blocking |
| `tls_fp_impersonator` | The UA family claims X (say Chrome) while `hash_b` matches a known automation signature Y. The signature catalog is `tls_fp_catalog.conf`. | soft |
| `tls_fp_suspicious_ciphers` | The UA looks like a browser but `cipher_cnt` does not match the expected value for that browser. The profiles are in `tls_fp_browser_profiles.conf`. | soft |
| `tls_fp_dc_browser` | The fingerprint looks like a browser (family by cipher profile) but the IP is in a datacenter ASN (`asn_datacenters.conf`) — real users do not browse from a public datacenter. | soft |

The `blocking`, `allow` and `soft` categories are the same as in Phase 1 (see "Concept:
rules, categories, logs" in the Phase 1 spec).

The log additionally carries informational tags (not rules, they lead to no verdict and
exist only for analytics):

- `tls_fp:automation_ua` — the UA carries explicit automation markers (the same thing
  `ua_blacklist` will catch at the hygiene stage once its catalog is populated). In
  Phase 1/2 `ua_blacklist` is empty, so this tag is the primary UA automation signal until
  it is filled in. The duplication is also convenient for filtering logs by TLS fields.
- `tls_fp:no_sni` — the client arrived without SNI.

**Examples** (in the MVP nothing physically happens to the request, only a log record):

- A browser Chrome, fingerprint `L13d15h2_<browser_hash_b>_<browser_hash_c>`, no catalog
  match → `verdict=pass`, no tags.
- `User-Agent: Mozilla/5.0 ... Chrome/148` but a fingerprint with `cipher_cnt=11` (instead
  of the expected `15` for Chrome) → `verdict=challenge`,
  `rule=tls_fp_suspicious_ciphers` (a `soft` category → `verdict=challenge` in the log,
  for analytics).
- `User-Agent: Mozilla/5.0 ... Chrome/148` with `hash_b` matching the `python-requests`
  signature in the catalog → `verdict=challenge`, `rule=tls_fp_impersonator`.
- The client's fingerprint is in `tls_fp_blocklist.conf` → `verdict=block`,
  `rule=tls_fp_blocklist`.

### Behaviour

- The fingerprint is computed for every request that enters the cascade. It is cached in
  `tls_fp_cache` (a `shared_dict`) with a short TTL, so that repeat requests with the same
  fingerprint do not recompute the hash.
- `tls_fp` and the informational tags are always written to the log, regardless of the
  rules' mode — that is precisely the calibration data.
- In the MVP the cascade only observes, inherited from Phase 1. Every TLS fingerprint rule
  fires and the hit is logged, but nothing physically happens to the request. Enforcement
  mode (physical blocking) arrives together with the per-resource shadow_mode in a separate
  task.

### Suitable OpenResty mechanisms

- `ngx.shared.DICT` for `tls_fp_cache` (the per-fingerprint cache) and `tls_fp_blocklist`
  (a static list).
- `access_by_lua_file` — the stage's entry point (after the `reputation` stage).
- `init_by_lua_file` — loading the catalog and the blocklist at worker startup.
- `ngx.sha256_hex` for the hashes.

## Effect on the `rate_limits` stage (behavioural limits)

After Phase 2 the `rate_limits` stage can use `tls_fp` as one of its rate-limit keys, in
addition to IP and IP+UA. That closes the class of attacks where a bot rotates IPs while
its TLS stack stays the same.

A new limit profile (added to the existing ones from Phase 1):

| Profile | Key | 10 s window | 1 min window | Rule code | Category |
|---|---|---|---|---|---|
| per fingerprint | `tls_fp` | 50 req | 300 req | `rate_tls_fp` | blocking |

The starting thresholds are deliberately high; the goal is to gather the distribution in
the logs and lower them from data. If `tls_fp_cache` missed (the fingerprint could not be
computed for some reason), the `rate_tls_fp` rule does not fire and only the per-IP and
per-IP+UA limits from Phase 1 apply.

The sliding-window semantics (GCRA) come from Phase 1 and do not change.

## Staged rollout for PR catalogs (new in Phase 2)

**The problem.** The catalogs populated through PRs (`tls_fp_blocklist`,
`tls_fp_catalog`, `tls_fp_browser_profiles`, plus `ua_blacklist` and `ip_blocklist`)
contain patterns and signatures. If product adds a new entry through a PR and it goes
straight to the proxies, hits appear in the logs immediately. If the pattern turned out to
be too broad and touched a legitimate browser, that is a mass false positive (blocking in
enforcement mode; in Phase 1/2 only noise in the logs, but undesirable all the same).

**The solution — a staging status for patterns.** Every catalog entry has a `status`
field with two values:

- `staging` — the pattern is loaded on the proxy, the proxy matches it and records the hit
  in a dedicated log field (`staging_match`), but it never leads to `verdict=block`, even
  in enforcement mode. In effect the request continues through the cascade as usual.
- `active` — the pattern works fully: a match → `verdict=block` or `verdict=challenge`
  (depending on the rule's category), like an ordinary rule.

**The product workflow for adding a new pattern:**

1. **A PR with the pattern in `staging`.** Through the standard config delivery mechanism
   the pattern reaches the proxies.
2. **Observation from the logs.** How many times the new pattern fired (`staging_match`),
   on which customers, with what traffic profile.
3. **A decision from the results:**
   - An acceptable false-positive rate → a separate PR moving the pattern from `staging`
     to `active`. The pattern starts firing for real, with `verdict=block/challenge`.
   - A high false-positive rate → revert the PR from step 1. The pattern disappears from
     the proxies.

**The `pattern_id` format per catalog** (used when writing to `staging_match`, in the form
`<catalog>:<pattern_id>`):

- `tls_fp_blocklist` — `pattern_id` is the fingerprint token itself. For example,
  `staging_match: ["tls_fp_blocklist:L1300_a8b9c..._d4e5f..."]`.
- `tls_fp_catalog` — `pattern_id` is the catalog's `hash_b` entry. For example,
  `staging_match: ["tls_fp_catalog:1ed0482b9b4c"]`.
- `tls_fp_browser_profiles` — `pattern_id` is the `browser_family`. For example,
  `staging_match: ["tls_fp_browser_profiles:chrome"]`.
- `ua_blacklist` — `pattern_id` is the regex pattern itself. For example,
  `staging_match: ["ua_blacklist:(?i)\\bAhrefsBot\\b"]` (the hygiene stage).
- `ip_blocklist` — `pattern_id` is the CIDR/IP entry from the catalog. For example,
  `staging_match: ["ip_blocklist:198.51.100.0/24"]` (the reputation stage).

The `pattern_id` is stable across catalog releases (the same pattern → the same ID).

**Delivering staging to the edge.** All three catalogs travel over Channel C from
`catalogs/<catalog>.yaml` (A11):

- `tls_fp_blocklist` — a composite `<status>:block` (backend
  `store.buildTLSFPBlocklist`); the edge builds the staging set from the pulled snapshot
  in `tls_fp.refresh()`.
- `ip_blocklist` — a map `{cidr: "<status>:block"}` (`store.buildIPBlocklist`);
  `reputation.refresh()` rebuilds the active and staging matchers from the snapshot.
- `ua_blacklist` — an object `{"active": "<combined-regex>", "staging": ["<pattern>", …]}`
  (`store.buildUABlacklist`); `hygiene.refresh()` takes the combined regex for active and
  the pattern list for staging (pattern by pattern, so that the pattern_id in
  `staging_match` is specific).

On the edge, `ua_blacklist` and `ip_blocklist` keep a cold-start seed from the local conf
(gen 0 in `init.lua`) until the first pull; after that Channel C is the source of truth
(gen 1+).

`ip_whitelist` and `asn_datacenters` also travel over Channel C (B12) — they are flat
lists without a `status` (staged rollout does not apply to them):

- `ip_whitelist` — an array of CIDRs (`store.buildIPWhitelist`);
  `reputation.refresh_whitelist()` rebuilds the allow matcher from the snapshot.
- `asn_datacenters` — a map `{asn: 1}` (`store.buildASNDatacenters`);
  `reputation.refresh_asn()` rebuilds the membership set behind the `reputation:asn_dc`
  tag.

Both follow the same model as `ip_blocklist`: a cold-start seed from the local conf (gen 0
in `init.lua`) until the first pull, then Channel C (gen 1+).

**A new log field: `staging_match`** — an array of `<catalog>:<pattern_id>` strings. Empty
when nothing matched in staging. It does not affect `verdict`/`rule` — a separate slot for
promotion analytics.

## Extending the log schema

From Phase 1 a log record carries `request_id`, `resource_id`, `host`, `ip`, `asn`, `ua`,
`stage`, `verdict`, `rule`, `tags`, `latency_ms`. Phase 2 extends the schema — fields are
added and nothing existing breaks:

- `tls_fp` — the computed fingerprint. Always populated when the request reached the
  `tls_fp` stage.
- `tls_cipher_count` — the number of ciphers after stripping GREASE. Useful for analysing
  "new browser versions".
- `tls_alpn` — the negotiated ALPN (`h2`, `http/1.1`).
- `tls_sni_present` — `true|false`, whether SNI was present.
- `tags` — an array of tags from every layer sharing a namespace prefix
  (`tls_fp:automation_ua`, `tls_fp:no_sni`, plus tags from other layers such as
  `reputation:asn_dc`). Empty when no tag fired.
- `staging_match` — an array of staging patterns that matched (see the previous section).
  Empty when nothing matched in staging.
- `flags` — an array of accumulated challenge flags. In Phase 2 these are the soft tls_fp
  rules (`tls_fp_impersonator`, `tls_fp_suspicious_ciphers`). The difference from `rule`:
  `rule` is the one terminal rule, `flags` are all the soft signals along the way, for
  analytics. Empty when there were no flags.

When one of the `tls_fp` stage rules fires, the `rule` field takes a value from the table
above and `stage=tls_fp`. For `tls_fp_blocklist` it is `verdict=block`. For the soft rules
(`tls_fp_impersonator`, `tls_fp_suspicious_ciphers`) it is `verdict=challenge` (a soft
category → `verdict=challenge` in the log, for the "we would have sent it to verification"
analytics). In the MVP nothing physically happens to the request (inherited from Phase 1:
the cascade only observes).

The complete list of new Phase 2 rule codes:

| Code | Stage | Category |
|---|---|---|
| `tls_fp_blocklist` | `tls_fp` | blocking |
| `tls_fp_impersonator` | `tls_fp` | soft |
| `tls_fp_suspicious_ciphers` | `tls_fp` | soft |
| `rate_tls_fp` | `rate_limits` | blocking |

## Configuration

In the proxy config repository (next to the Phase 1 configs):

- `tls_fp_blocklist.conf` — [empty at launch] — the list of blocked fingerprints.
  Populated through PRs based on log analysis. Supports staged rollout.
- `tls_fp_catalog.conf` — [empty at launch] — the catalog of known `hash_b` signatures for
  known automation types (curl, python-requests, go-http-client, okhttp, known bots).
  Populated through PRs based on log analysis — product correlates the observed
  fingerprints with reference traffic (curl/python/go) and records the mapping in the
  catalog. Supports staged rollout.
- `tls_fp_browser_profiles.conf` — [populated with a baseline] — the expected
  `cipher_cnt` per browser family. The starting set (supplied by product):
  - `chrome: 15`
  - `firefox: 16`
  - `safari: 20`
  These values are corrected as new browser versions appear, based on log analysis.
  Supports staged rollout (for careful updates on new browser releases).
- Additions to the existing `defaults.conf` (from Phase 1) — four new rules in the
  corresponding category sections (blocking / soft), and the parameters of the new
  `rate_tls_fp` rate-limit profile.

Changes go through a PR with product review. They are applied without a redeploy and
without losing customer traffic (the Phase 1 mechanism is inherited).

**Cross-proxy consistency.** The same as in Phase 1: after a PR is merged, delivery
through Puppet takes minutes, and during that window different edge nodes may see
different catalog versions. That is acceptable.

## Operations

- The Phase 1 principles are preserved: the cascade only observes, and there are no
  per-rule enforce switches in the MVP. Enforcement mode is the next iteration, in step
  with the per-resource shadow_mode.
- The kill switch exists separately for the whole cascade and for the `tls_fp` stage (in
  case of trouble with that particular layer, so the whole cascade need not be disabled).
- Config changes (`tls_fp_blocklist.conf`, `tls_fp_catalog.conf`,
  `tls_fp_browser_profiles.conf`) go through a PR with product review, applied without a
  redeploy and without losing traffic.

## Acceptance criteria

1. On the stand the cascade with the `tls_fp` stage enabled processes a test set of
   requests (curl, python-requests, a real browser — the set will be assembled
   separately), and for each request the log carries the expected `tls_fp`,
   `tls_cipher_count`, `tls_alpn`, `tls_sni_present`, the correct `tags` (if any) and,
   where applicable, `rule` and `verdict`.
2. Real customer traffic keeps reaching the origin regardless of whether TLS fingerprint
   rules fired — the Phase 1 behaviour is inherited (the cascade only observes).
3. The log records contain every new TLS field and arrive at the same telemetry sink as
   the Phase 1 logs; the format allows filtering and grouping by `tls_fp`, `tags` and
   `staging_match`.
4. The initial contents of `tls_fp_browser_profiles.conf` (supplied by product) are
   accepted into the repository and the proxies start the `tls_fp` stage with that data.
   The `tls_fp_catalog.conf` catalog and the `tls_fp_blocklist.conf` blocklist are empty
   at launch.
5. The `rate_tls_fp` rule at the `rate_limits` stage correctly uses `tls_fp` as its key;
   on exceeding the limit it logs `verdict=block, rule=rate_tls_fp`.
6. **Staged rollout works:** an entry with `status=staging` matches and lands in the
   `staging_match` field but does NOT trigger `rule` or `verdict`. An entry with
   `status=active` behaves like an ordinary rule.
7. The kill switch for the `tls_fp` stage disables it completely (no fingerprint is
   computed, no tags are written, no rule of the stage fires) while the rest of the cascade
   keeps working.

## Out of scope (for later iterations)

- **A verified-crawler whitelist** (Googlebot, Bingbot, Yandex, by reverse DNS or
  published IP ranges). Without it, impersonator tags can fire falsely on legitimate
  crawlers. In the MVP that creates no risk (the cascade only observes), but for a future
  enforcement mode this whitelist is mandatory.
- **Broader TLS signal coverage.** The current fingerprint uses only the `$ssl_*`
  variables from stock nginx, which covers the main elements of the TLS handshake but not
  the full list of extensions and signature algorithms (nginx does not expose them in
  `access_by_lua`). The available ways to extend it (a raw ClientHello parser, extra nginx
  modules) are a separate task. The current coverage is enough for the bulk of
  impersonator cases.
- **Automatically populating the blocklist by scoring.** In the MVP blocklist candidates
  are surfaced by analytics and entry into the blocklist is a manual product decision
  through a PR. Automatic promotion of HIGH candidates is a separate task with its own
  false-positive guarantees.
- **HTTP/2 fingerprinting.** An additional client signal — the order of SETTINGS frames,
  window updates, priority frames. Layer L4, but independent of the TLS fingerprint. A
  future task.
- **Behavioural ML over sessions** (mouse movement, timings, URL sequences). Layer L6 of
  the protection pyramid; it needs a JS beacon on the client and is a separate product
  scenario.
- **Per-resource TLS fingerprint policies.** Today the catalog and the blocklist are
  shared across all resources. Differentiation (a B2B API customer expects different TLS
  stacks than a public website) is the next iteration, in step with the per-resource
  policies from the Phase 1 roadmap.
- **Centralised fingerprint state across proxies.** Each proxy keeps its own
  `tls_fp_cache` and per-fingerprint counters. Centralised state (through Redis, say) is a
  separate infrastructure task; without it a bot that hops between proxies resets its
  limits.
- **Active verification** (a JS challenge, mTLS, API keys, a crawler whitelist) — a single
  task shared with Phase 1, not duplicated here. It will be implemented in later phases.
