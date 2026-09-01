# Bot & Abuse Controls — entity reference

Terms and definitions of the base concepts, plus alphabetical and grouped tables of
every entity: catalogs, rules, tags, log fields and enumerations.

---

## Terms

| Term | Definition |
| --- | --- |
| **Cascade** | The ordered chain of check layers (L1–L5) every request passes through, on a "cheapest first" principle. A request walks the layers until one of them issues a terminal verdict or it reaches the end. |
| **Layer / stage** | One step of the cascade with its own purpose and a stable string code (`hygiene`, `reputation`, `tls_fp`, `rate_limits`, `verification`, plus `egress` / `cold_start`). The L number (L1–L5) is a visual hierarchy; the stage code is what goes into the log. |
| **Rule** | One named check inside a layer, with a condition and a category. When it fires it either issues a verdict or marks the request with a flag. It has a short identifier (`ip_blocklist`, `rate_ip` and so on) that is written to the log's `rule` field. |
| **Rule category** | How the rule affects the request: `blocking` (→ `verdict=block`), `allow` (→ `verdict=allow`, a fastpath), `soft` (issues no verdict of its own — it marks the request with a challenge flag, and L5 decides). |
| **Verdict** | The final decision about a request: `block` / `allow` / `challenge` / `permissive` / `pass`. Exactly one per request in the log (the last rule that fired). |
| **Flag (challenge flag)** | A mark on a request saying "looks suspicious, a candidate for verification", placed by soft rules. On its own it neither blocks nor allows; flags accumulate along the cascade and L5 decides on them. |
| **Tag** | An informational mark on a request set by a condition (for example `reputation:asn_dc`) that affects NEITHER the verdict nor verification. It accumulates in the log's `tags` field for analytics. The difference from a rule: a rule changes the request's fate, a tag only describes it. |
| **Catalog** | A named data set the backend delivers to the proxy (IP lists, UA patterns, TLS signatures, policy and so on). The proxy caches a catalog locally and reads it on the hot path. Catalogs are either shared (curated by product, for all customers) or per resource (the policy of one domain). |
| **Policy** | The protection settings of one domain (keyed by Host): mode, Strictness, custom UA/ASN/rate rules, IP whitelist, attack_mode. It affects only its own domain. |
| **Mode** | `shadow` (observation, no physical action) or `active` (verdicts are enforced). Set in the domain's policy. |
| **Strictness** | A binary toggle in the policy (`Standard` / `Permissive`) that determines whether soft flags trigger a challenge at L5. |
| **attack_mode** | A per-host emergency toggle: while under attack, everything that reaches L5 goes to verification. |
| **Fastpath** | Skipping layers for a trusted client. A full fastpath (skipping L3/L4/L5, `verdict=allow`) applies to verified bots and the IP whitelist (explicit trust). The clearance cookie gives a partial one: it skips only L3 and L5 (we do not re-challenge), while L4 (rate limits) still applies. |
| **shadow / observe-only** | Synonyms: the cascade computes and logs a verdict but physically does nothing to the request. |

---

## Catalogs (data stores in the backend → delivered to the proxy)

| Name | What is inside | Who populates it | Used at (stage) | Delivery SLA |
| --- | --- | --- | --- | --- |
| `policy` | Map `host → policy_json`: mode, Strictness, custom UA regex, custom ASN block, custom rate rules, attack_mode, the customer's IP whitelist | The customer dashboard | Stages 2.3, 2.5, 2.6, 4 (client rules), 5.1 (Strictness), 5.3 (attack_mode) | ≤ 30 seconds |
| `bot_verification_status` | Map `ip → {status: verified \| rejected, bot_family, verified_at}` (TTL 1 h for both categories; absence means unknown). For `verified`, `bot_family` is the confirmed family (`googlebot`/`bingbot`/`yandexbot`/`duckduckbot`); for `rejected` it is the UA-claimed family (what the client called itself in the UA) — useful in analytics, where you can see "this IP claimed to be Googlebot but failed rDNS" | The backend's background rDNS worker | Stage 2.2 | |
| `ua_blacklist` | The global set of UA patterns (a combined regex, or otherwise). Ships empty and is populated through PRs based on log analysis | Product, through PRs | Stage 1 | ≤ 15 minutes |
| `ip_blocklist` | A set of IPs/CIDRs of known bad addresses | Product, through PRs | Stage 2.4 | ≤ 15 minutes |
| `ip_whitelist` *(system)* | A set of IPs/CIDRs for our monitoring, check services and trusted system clients. Not to be confused with the customer's per-resource IP whitelist inside `policy` | The internal team, through PRs | Stage 2.3 | ≤ 15 minutes |
| `asn_datacenters` | A set of ASN numbers of large public datacenters (Hetzner, OVH, DigitalOcean, AWS, GCP, Azure) | Product, through PRs | The trigger for the `reputation:asn_dc` tag (stage 2) | ≤ 15 minutes |
| `tls_fp_blocklist` | A set of TLS fingerprints explicitly marked as bots | Product, through PRs | Stage 3, rule `tls_fp_blocklist` | ≤ 15 minutes |
| `tls_fp_catalog` | Map `hash_b → automation family` (curl, python-requests, Go, okhttp). Needed for impersonator detection | Product, through PRs | Stage 3, rule `tls_fp_impersonator` | ≤ 15 minutes |
| `tls_fp_browser_profiles` | Map `browser_family → expected cipher_cnt` (chrome: 15, firefox: 16, safari: 20) | Product, through PRs | Stage 3, rule `tls_fp_suspicious_ciphers` | ≤ 15 minutes |

**Staged rollout** for the PR-driven catalogs: new patterns can be added with `staging`
status — they match and are recorded in `staging_match`, but never lead to
verdict=block. After calibration they are promoted to `active`. Supported for
`ua_blacklist`, `ip_blocklist`, `tls_fp_blocklist`, `tls_fp_catalog` and
`tls_fp_browser_profiles`.

---

## Rules (rule codes) — they emit a verdict into the log

| Code | Stage | Category | What it checks | Data source |
| --- | --- | --- | --- | --- |
| `method_not_allowed` | `hygiene` | `blocking` | The HTTP method is not in the whitelist (by default GET, HEAD, POST, OPTIONS) | Cascade config |
| `ua_blacklist` | `hygiene` | `blocking` | The UA matches the combined regex from the catalog | `ua_blacklist` |
| `cookie_valid` | `reputation` | `allow` | The `tf_clearance` cookie has a valid HMAC signature, a matching client binding (TLS fingerprint plus IP subnet) and an unexpired TTL. Not a lookup but a Lua computation. Skips L3 and L5, but NOT L4 — rate limits apply to the cookie holder as well | The HMAC secret (Channel A) |
| `bot_verified` | `reputation` | `allow` | The IP is in the catalog with status `verified` (a confirmed search engine) | `bot_verification_status` |
| `bot_verified_pending` | `reputation` | `allow` | An IP with a search engine UA that is absent from the catalog → a provisional fastpath. It fires for every request from that IP until the backend publishes verified or rejected (the proxy keeps no per-IP state) | `bot_verification_status` (via the absence of a record) |
| `ip_whitelist` | `reputation` | `allow` | The IP is in the system whitelist OR in the customer's per-resource IP whitelist | `ip_whitelist` plus `policy` |
| `ip_blocklist` | `reputation` | `blocking` | The IP is in the blocklist | `ip_blocklist` |
| `asn_customer` | `reputation` | `blocking` | The request's ASN is in the customer's per-resource ASN block | `policy` |
| `geo_blocklist` | `reputation` | `blocking` | The country is not in the customer's per-resource country whitelist | `policy` plus MaxMind GeoIP |
| `tls_fp_blocklist` | `tls_fp` | `blocking` | The client's TLS fingerprint is in the blocklist | `tls_fp_blocklist` |
| `tls_fp_impersonator` | `tls_fp` | `soft` | A UA family ↔ fingerprint mismatch (for example, UA Chrome but a python-requests fingerprint) | `tls_fp_catalog` |
| `tls_fp_suspicious_ciphers` | `tls_fp` | `soft` | The UA looks like a browser but cipher_cnt does not match the expected value for the family | `tls_fp_browser_profiles` |
| `tls_fp_dc_browser` | `tls_fp` | `soft` | The fingerprint looks like a browser but the IP is in a datacenter ASN (cross-layer: the L3 fingerprint plus L2 reputation) | The L3 fingerprint plus `asn_datacenters` |
| `rate_ip` | `rate_limits` | `blocking` | The per-IP threshold was exceeded (100/600 over 10 s/60 s windows) | Local proxy counters |
| `rate_ip_ua` | `rate_limits` | `blocking` | The per-IP+UA threshold was exceeded (100/600) | Local proxy counters |
| `rate_api` | `rate_limits` | `blocking` | The per-IP threshold on API endpoints was exceeded (50/300) | Local proxy counters |
| `rate_tls_fp` | `rate_limits` | `blocking` | The per-fingerprint threshold was exceeded (50/300). Phase 2+. Does not fire when no fingerprint was computed | Local proxy counters |
| `rate_scan_urls` | `rate_limits` | `blocking` | The per-IP unique-URL threshold was exceeded (50/200) — a scraping indicator | Local proxy counters |
| `non_browser_blocked` | `verification` | `blocking` | A non-browser client (its UA does not look like a browser) reached L5 with challenge flags and holds no whitelist trust | The L5 decision (branch B) |
| `unchallengeable_request` | `verification` | `blocking` | The request is protocol-incompatible with a JS challenge: a non-GET method, a WebSocket upgrade, an `Accept` without `text/html`. The UA may still be a browser one | The L5 decision (branch C) |
| `rate_custom` | `rate_limits` | `blocking` or `soft` (depending on the customer rule's action) | A customer rate rule fired. Per path: rps, burst, action (`block`/`challenge`/`log_only`), set by the customer in the dashboard. The log additionally carries `client_rule_name`, the human-readable rule name from the dashboard | `policy` |

**A hint:** a rule's category determines which verdict it emits:

- `blocking` → `verdict=block`
- `allow` → `verdict=allow`
- `soft` → emits no verdict of its own, accumulates a challenge flag — the final
  decision is taken by L5 (stage 5)

---

## Tags (informational) — they emit no verdict, they accumulate in `tags`

| Code | Where it appears | What it means | Source |
| --- | --- | --- | --- |
| `hygiene:header_anomaly` | L1 | A header combination a real browser never sends but lazy automation does. The base case: HTTP/2 without `Accept`. Catches bots with a browser-faked UA but an unrealistic header set | Header checks in Lua |
| `reputation:asn_dc` | L2 | The request IP belongs to a large public datacenter ASN (Hetzner, OVH, DO, AWS, GCP, Azure) | `asn_datacenters` |
| `tls_fp:automation_ua` | L3 | The UA carries explicit automation markers (curl, python-requests and so on). It duplicates what `ua_blacklist` catches, but is handy as a primary automation signal and for filtering logs by TLS fields. Useful for analytics and for calibrating `ua_blacklist` patterns | Logic on the UA plus the L3 stage |
| `tls_fp:no_sni` | L3 | The client sent no SNI in the TLS handshake | TLS handshake data |

**Tag format:** `<stage>:<short_name>`. Namespacing by stage lets other layers add tags
without name collisions. All tags are written into a single `tags` field (an array) in
the JSON log.

---

## JSON log fields

| Field | Type | Description | When it is populated |
| --- | --- | --- | --- |
| `request_id` | string | A unique request identifier | Always |
| `timestamp` | string (ISO 8601 with milliseconds, e.g. `2026-05-18T14:30:00.123Z`) | When the request was received | Always |
| `edge_id` | string | The identifier of the proxy node that handled the request (values like `edge-042` / `stand-bac`). The field name is an inherited token; the product term is proxy | Always |
| `resource_id` | string | The customer's resource ID in the platform. The proxy does not fill this in — it does not know the resource_id and works with `host` alone. The field is added by the backend when it ingests the log | Filled in by the backend after ingesting the log from the proxy |
| `host` | string | The HTTP Host header | Always |
| `path` | string | The request path | Always |
| `method` | string | The HTTP method | Always |
| `status` | int | The HTTP status code of the response | Always |
| `latency_ms` | float | Time spent traversing the cascade, in milliseconds | Always |
| `ip` | string | The client IP | Always |
| `asn` | string | The client ASN (per MaxMind) | Always |
| `geo_country` | string | The client's country (ISO 3166-1 alpha-2) | Always |
| `ua` | string | The full User-Agent | Always |
| `tls_fp` | string | The computed TLS fingerprint, in the form `L<ver><sni_flag><cipher_cnt><alpn>_<hash_b>_<hash_c>` | When the request reached stage 3 (Phase 2+) |
| `tls_cipher_count` | int | The number of ciphers after stripping GREASE | Phase 2+ |
| `tls_alpn` | string | The negotiated ALPN (h2, http/1.1) | Phase 2+ |
| `tls_sni_present` | boolean | Whether SNI was present in the handshake | Phase 2+ |
| `stage` | string (enum) | The stage at which the final rule fired | Always |
| `verdict` | string (enum) | The decision of the final rule that fired | Always |
| `rule` | string | The code of the final rule that fired | Empty when `verdict=pass` |
| `action` | string (enum) | What should have happened (block / challenge / allow / log_only / pass) | Always |
| `mode` | string (enum) | The resource's mode at the time of the request (shadow / active) | Always |
| `tags` | array of string | Every informational tag that fired, with its namespace prefix | Always (may be `[]`) |
| `flags` | array of string | Every challenge flag accumulated along the way (soft rules: `tls_fp_impersonator`, `tls_fp_suspicious_ciphers`, `tls_fp_dc_browser`, and customer rate rules with `action=challenge`). The difference from `rule`: `rule` is the one terminal rule, `flags` are all the soft signals along the way, for analytics | Always (may be `[]`) |
| `staging_match` | array of string | Staging patterns from PR catalogs that matched (they produce no verdict; they exist for promotion analytics). The record format is `<catalog>:<pattern_id>`, for example `ua_blacklist:new_pattern_2026_05_18`. For the concept see "Staged rollout for PR catalogs" in vision.md | Always (may be `[]`) |
| `rule_source` | string (enum) | Disambiguates rules that share a code but differ in source: `system` (a shared catalog) or `per_resource` (`policy[host]`). Applies to `ip_whitelist` (the system `whitelist_ip.conf` versus `policy[host].ip_whitelist`) and to `ua_blacklist` (the global list versus the customer's custom patterns). Empty for every other rule | When `rule=ip_whitelist` / `rule=ua_blacklist` |
| `client_rule_name` | string | The human-readable name of a customer rate rule from the dashboard (for example "Login Protection"). Any UTF-8 (non-Latin scripts and emoji are allowed). On save, the backend validates: length ≤ 64 characters; control characters stripped; leading and trailing whitespace trimmed; uniqueness within the host (case-insensitive after Unicode NFC normalisation and trimming — `"Login Protection"` and `"login protection"` count as duplicates, and the dashboard returns an error on an attempt to create a second one). Duplicates across different hosts are allowed | When `rule=rate_custom` |

---

## Enumerations

### `stage` — where processing stopped

| Value | Corresponding layer | Description |
| --- | --- | --- |
| `hygiene` | L1 | Basic hygiene (method, UA blacklist) |
| `reputation` | L2 | Source reputation (cookie, verified bot, IP, ASN, geo) |
| `tls_fp` | L3 | TLS fingerprinting *(Phase 2+)* |
| `rate_limits` | L4 | Behavioural limits |
| `verification` | L5 | Active verification *(Phase 4+)* |
| `egress` | — | The request traversed the whole cascade with no blocking or allow rule firing, and continues into the CDN flow (cache/origin). Emitted on `verdict=pass` (no rule fired) or `verdict=permissive` (soft flags were raised but Permissive suppressed the challenge). For `verdict=block`/`allow`/`challenge`, `stage` is the layer where the final rule fired (`hygiene`/`reputation`/`tls_fp`/`rate_limits`/`verification`) |
| `cold_start` | — | The proxy has just started and the catalogs have not loaded yet. The request skipped the checks; see the fail modes in Channel C |

Stage codes are stable across iterations — they are not renamed and do not shift when
new layers are added.

### `verdict` — the cascade's decision

| Value | What it means |
| --- | --- |
| `pass` | No rule fired and the request traversed the cascade. `rule` is empty |
| `block` | A final rule of the blocking category fired. `rule` holds its name |
| `challenge` | L5 decided to issue a challenge based on the accumulated soft flags. `rule` holds the name of the last soft flag that led to the decision |
| `allow` | A final rule of the allow category fired (a fastpath). `rule` holds its name |
| `permissive` | System soft flags accumulated but Strictness=Permissive suppressed the challenge, so the request went through. `rule` holds the name of the last soft flag that would have triggered a challenge under Standard, which preserves the "why it did not fire" in the logs. Physically equivalent to `pass` (the request continues into the CDN flow) |

In shadow mode the verdict has no physical effect on the request (it is only logged); in
active mode it is enforced. The `challenge` and `permissive` verdicts, along with the
`non_browser_blocked` and `unchallengeable_request` rules, belong to layer L5
(verification).

### `action` — what should have physically happened

| Value | Semantics |
| --- | --- |
| `block` | 403 Forbidden (or 429 Too Many Requests with Retry-After for rate rules) |
| `challenge` | Serve a JS challenge / collect a challenge flag for L5 |
| `allow` | Fastpath — let it through and skip the remaining layers |
| `log_only` | Log only, with no effect on the later stages (used in customer rate rules for testing) |
| `pass` | The request continues; no rule fired decisively |

### `mode` (per resource) — the cascade's mode on a specific resource

| Value | Description |
| --- | --- |
| `shadow` | The default for every new domain in the pool and for free customers. The cascade only observes and blocks nothing physically. Synonyms in prose: "observe-only", "shadow mode". |
| `active` | Paid protection: blocking rules really block, soft flags trigger verification, allow rules give a fastpath. Synonym in prose: "enforcement mode". |

### `Strictness` (per resource) — the L5 sensitivity threshold

| Value | L5 behaviour when challenge flags are present |
| --- | --- |
| `Standard` *(default)* | Any system challenge flag → issue a challenge |
| `Permissive` | System challenge flags do not trigger a challenge — `verdict=permissive` is logged. For domains with an unenumerable amount of legitimate non-browser traffic. |

**A notation convention.** In prose we write `Strictness` / `Standard` / `Permissive`
(concept names, capitalised). In the YAML configs (the `policy[host].strictness` field)
they are lowercase (`strictness: standard`, `strictness: permissive`). The same goes for
`mode`: `mode=shadow` / `mode=active` in prose, and lowercase values in YAML.

### `category` (of rules) — the rule taxonomy

| Value | What it emits |
| --- | --- |
| `blocking` | `verdict=block` |
| `allow` | `verdict=allow` (a fastpath) |
| `soft` | Accumulates a challenge flag (L5 takes the final decision) |

### `attack_mode` (per host, lives in `policy[host]`)

| Value | Effect |
| --- | --- |
| `false` *(default)* | The cascade behaves normally |
| `true` (Under Attack mode) | Every request that reaches L5 for this host is forced into verification (a browser → a challenge; a non-browser → block `non_browser_blocked`; a protocol-incompatible request → block `unchallengeable_request`). Cookie verify at L2.1: cookies issued before the attack started do not fastpath (those issued during the attack do). Verified search bots and the IP whitelist keep fastpathing, so SEO and trusted integrations are unaffected. |

---

## Glossary of key terms

- **Edge pool** — the dedicated pool of CDN edge nodes the cascade runs on
- **antibot-backend** — the service on our infrastructure. It hosts the catalogs,
  ingests logs and performs rDNS checks
- **Channel A** — delivery of the framework (Lua code, configs, the HMAC secret, the
  HTML+JS challenge template) through the edge pool's Puppet
- **Channel C** — delivery of runtime data (the catalogs) from the backend to the proxy
- **Hot path** — the hot path of a request: everything that happens between accepting it
  and answering. The proxy makes no network calls on the hot path
- **Fail-stale** — the proxy's behaviour when the backend is unreachable: it keeps
  working from the last catalogs it loaded
- **Provisional fastpath** — a lenient one-off allow for an IP with a search engine UA,
  until the backend has verified it through rDNS
- **Challenge flag** — an internal flag set by rules of the soft category. L5
  consolidates every accumulated flag and takes the decision
- **Staged rollout** — the mechanism for safely adding new patterns to the PR catalogs:
  first `staging` status (the pattern matches while the request is processed and the hit
  is recorded in the log's `staging_match` field, but it never leads to verdict=block,
  even in `mode=active`), then — after analysing the statistics gathered from the logs
  for the absence of false positives — a separate PR promotes the pattern to `active`
  (real blocking). Applies to the `ua_blacklist`, `ip_blocklist`, `tls_fp_blocklist`,
  `tls_fp_catalog` and `tls_fp_browser_profiles` catalogs. See "Staged rollout for PR
  catalogs" in vision.md for more

---
