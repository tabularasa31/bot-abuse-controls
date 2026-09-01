# Bot & Abuse Controls — catalog of every cascade rule

The complete list of rules in "if condition → then verdict" form, in the order the
layers L1→L5 are traversed. The source of truth for behaviour is
[vision.md](vision.md); this document is the flat reference for "what fires on what".

**How to read it.** Each rule emits one of the verdicts `block` / `allow` /
`challenge` / `permissive` (or nothing, for tags). The rule category (blocking / allow /
soft) determines which verdict it can produce. Whether a verdict is physically enforced
depends on the host's mode.

Notation:

- **Category** — `blocking` (→ verdict=block), `allow` (→ verdict=allow, a fastpath),
  `soft` (→ accumulates a challenge flag, with the final decision at L5).
- **Source** — where the data for the check comes from.

---

## L1 — Hygiene (stage `hygiene`)

Basic request hygiene. Cheap checks, run first.

| # | If… | Then… | Category | Source |
| --- | --- | --- | --- | --- |
| 1 | The HTTP method is not in the whitelist (by default `GET`, `HEAD`, `POST`, `OPTIONS`) — for example `TRACE`, `PUT`, `DELETE` | `verdict=block, rule=method_not_allowed` | blocking | Cascade config (`defaults.conf`) |
| 2 | The request's User-Agent matches a pattern in the global `ua_blacklist` (automation, scanners, known bad bots) | `verdict=block, rule=ua_blacklist` (field `rule_source=system`) | blocking | The `ua_blacklist` catalog (populated by PR, staged rollout) |
| 2a | The User-Agent matches a customer's own pattern (the customer added strings or regexes in the dashboard; the "Block known bad bots" toggle applies the global list to the resource, plus a textarea for their own patterns) | `verdict=block, rule=ua_blacklist` (field `rule_source=per_resource`) | blocking | The `policy` catalog (the customer's custom patterns) |

---

## L2 — Reputation (stage `reputation`)

Reputation of the source. The allow rules (fastpaths) live here too. `bot_verified` and
`ip_whitelist` give a full fastpath (skipping L3/L4/L5). `cookie_valid` is partial: it
skips L3 and L5, but L4 (rate limits) still applies.

### Allow rules (fastpath, checked first)

| # | If… | Then… | Category | Source |
| --- | --- | --- | --- | --- |
| 3 | The request carries a `tf_clearance` cookie with a valid HMAC signature, a matching client binding (TLS fingerprint plus IP subnet) and an unexpired TTL, AND (for this host `attack_mode=off` OR the cookie was issued during the attack, with a short TTL) | Skips L3 and L5, but NOT L4 (rate limits still apply). If L4 is clean → `verdict=allow, rule=cookie_valid`; otherwise the L4 rule wins | allow | The HMAC secret (Channel A) plus the Lua check |
| 4 | The request IP is in the `bot_verification_status` catalog with status `verified` (rDNS confirmed a search engine bot) | `verdict=allow, rule=bot_verified` — a fastpath | allow | The `bot_verification_status` catalog (the rDNS worker) |
| 5 | The request UA looks like a search engine bot (Googlebot/bingbot/YandexBot/DuckDuckBot) but the IP is absent from `bot_verification_status` (neither verified nor rejected) | `verdict=allow, rule=bot_verified_pending` — a provisional fastpath on EVERY request until the backend publishes a final status | allow | The `bot_verification_status` catalog (via the absence of a record) |
| 6 | The request IP is in the system `ip_whitelist` (monitoring, check services) OR in the customer's per-resource IP whitelist (`policy[host].ip_whitelist`) | `verdict=allow, rule=ip_whitelist` (field `rule_source` = `system` or `per_resource`) — a fastpath | allow | The `ip_whitelist` catalog plus `policy` |

### Blocking rules

| # | If… | Then… | Category | Source |
| --- | --- | --- | --- | --- |
| 7 | The request IP is in the `ip_blocklist` catalog | `verdict=block, rule=ip_blocklist` | blocking | The `ip_blocklist` catalog (populated by PR, staged rollout) |
| 8 | The request ASN is in the customer's per-resource ASN block (`policy[host].asn_block`) | `verdict=block, rule=asn_customer` | blocking | The `policy` catalog |
| 9 | The request's country (by MaxMind GeoIP) is not in the customer's per-resource whitelist of allowed countries (when they set one) | `verdict=block, rule=geo_blocklist` | blocking | `policy` plus MaxMind GeoIP |

---

## L3 — TLS fingerprint (stage `tls_fp`)

The signature of the client's TLS stack. The fingerprint itself does not block —
the derived rules do.

| # | If… | Then… | Category | Source |
| --- | --- | --- | --- | --- |
| 10 | The computed TLS fingerprint is in the `tls_fp_blocklist` catalog | `verdict=block, rule=tls_fp_blocklist` | blocking | The `tls_fp_blocklist` catalog (empty at launch, PR-driven, staged rollout) |
| 11 | The UA family claims one thing (say Chrome) while the fingerprint's `hash_b` matches a known automation signature (curl/python-requests/Go/okhttp) from `tls_fp_catalog` | accumulates the challenge flag `tls_fp_impersonator` (decided at L5) | soft | The `tls_fp_catalog` catalog (PR, staged rollout) |
| 12 | The UA looks like a browser but the fingerprint's `cipher_cnt` does not match the expected value for that browser family (`tls_fp_browser_profiles`: chrome=15, firefox=16, safari=20) | accumulates the challenge flag `tls_fp_suspicious_ciphers` (decided at L5) | soft | The `tls_fp_browser_profiles` catalog (PR, staged rollout) |
| 13 | The fingerprint looks like a browser (family by cipher profile) but the IP is in a datacenter ASN (`asn_datacenters`) — real users do not browse from a public datacenter | accumulates the challenge flag `tls_fp_dc_browser` (decided at L5) | soft | The L3 fingerprint plus the `asn_datacenters` catalog |

---

## L4 — Rate limits (stage `rate_limits`)

Behavioural limits. Customer rules are checked first, then the system profiles — the
first match wins.

### Customer rules (checked FIRST)

| # | If… | Then… | Category | Source |
| --- | --- | --- | --- | --- |
| 13 | The request matched a customer rate rule (by path/method/key) and exceeded its limit (rps/burst) | The `verdict` depends on the rule's `action`: `block` / `challenge` / log only (`log_only`). `rule=rate_custom`, with the field `client_rule_name` holding the name from the dashboard | blocking or soft | The `policy` catalog (the customer's rules) |

### System profiles (checked when no customer rule matched)

The order is `rate_ip → rate_ip_ua → rate_api → rate_tls_fp → rate_scan_urls`. Two
windows per profile (10 s and 60 s); the rule fires if either is exceeded. The
implementation is GCRA.

| # | If… | Then… | Category | Source |
| --- | --- | --- | --- | --- |
| 14 | One IP sends > 100 requests in 10 s OR > 600 in 60 s | `verdict=block, rule=rate_ip` | blocking | Local proxy counters |
| 15 | One IP+UA pair sends > 100 in 10 s OR > 600 in 60 s | `verdict=block, rule=rate_ip_ua` | blocking | Local proxy counters |
| 16 | One IP sends > 50 in 10 s OR > 300 in 60 s on API paths (patterns from `defaults.conf`) | `verdict=block, rule=rate_api` | blocking | Local proxy counters |
| 17 | One TLS fingerprint sends > 50 in 10 s OR > 300 in 60 s (only when the fingerprint was computed; otherwise the rule is skipped) | `verdict=block, rule=rate_tls_fp` | blocking | Local proxy counters |
| 18 | One IP hits > 50 unique URLs in 10 s OR > 200 in 60 s (a scraping indicator) | `verdict=block, rule=rate_scan_urls` | blocking | Local proxy counters |

---

## L5 — Verification (stage `verification`)

Consolidates the accumulated challenge flags and decides what to serve the client.

### `should_challenge` — a computed function, not a config flag

It is not a value stored somewhere and not a separate toggle. It is a function L5
evaluates on every request from three inputs: `attack_mode[host]`, the set of
accumulated challenge flags, and `Strictness[host]` (taking the flag type into account —
system versus a customer rule). The flags at L3/L4 never issue a challenge themselves;
they only mark the request. The single point where "issue verification or not" is
decided is this call at L5.

`should_challenge` returns `true` if any of the following holds:

| Input | Condition → `true` |
| --- | --- |
| `attack_mode` | `attack_mode[host]=on` → `true` for any request that reaches L5, regardless of flags and Strictness |
| System challenge flags plus Strictness | At least one system flag accumulated (`tls_fp_impersonator`, `tls_fp_suspicious_ciphers`, system L4 rate rules with action=challenge) AND `Strictness[host]=Standard` |
| A customer rate rule | A customer rate rule with `action=challenge` fired — always `true`, even under `Strictness=Permissive` (an explicit customer setting is respected) |

`should_challenge` returns `false` if:

| Input | Condition → `false` |
| --- | --- |
| Permissive suppressed it | Only system flags accumulated AND `Strictness[host]=Permissive` → `false`, logged as `verdict=permissive, rule=<name of the last soft flag>` |
| No reason | No challenge flags accumulated AND `attack_mode=off` → `false`, `verdict=pass` |

### What happens next (stage 5.1 → 5.2)

- `should_challenge=false` → `verdict=pass` or `verdict=permissive` (see above), and
  the request continues into the CDN flow.
- `should_challenge=true` → routed into branches A/B/C by client type (below).

### Issuing branches (stage 5.2) when `should_challenge=true`

| # | If… | Then… | Category |
| --- | --- | --- | --- |
| 19 | The client looks like a browser (UA Mozilla/Chrome/Safari/Firefox/Edge plus basic header checks) | **Branch A:** `verdict=challenge` — a JS challenge page is served | — |
| 20 | The client is not a browser (UA curl/python/Go/SDK, or the standard browser headers are missing) | **Branch B:** `verdict=block, rule=non_browser_blocked` | blocking |
| 21 | The request is protocol-incompatible with a JS challenge: a non-GET method, a WebSocket upgrade, an `Accept` without `text/html` (the UA may still be a browser one) | **Branch C:** `verdict=block, rule=unchallengeable_request` | blocking |

### Under Attack mode (stage 5.3)

| If… | Then… |
| --- | --- |
| `attack_mode=on` for the host | Cookie verify at L2.1: cookies issued before the attack started do not fastpath (those issued during the attack do); verified bots and the IP whitelist keep fastpathing; everything that reaches L5 goes into branches A/B/C; new cookies are issued with TTL=1 h |

---

## Informational tags (NOT rules — they emit no verdict)

These accumulate in the log's `tags` field and affect neither the verdict nor
verification; they exist for analytics and interpretation (signal co-occurrence in the
logs helps calibrate the rules).

| # | If… | Then the tag… | Where | Source |
| --- | --- | --- | --- | --- |
| T0 | A header combination a real browser never sends but lazy automation does (the base case: HTTP/2 without `Accept`) | `hygiene:header_anomaly` | L1 | Header checks in Lua |
| T1 | The request IP belongs to a large public datacenter ASN (Hetzner/OVH/DO/AWS/GCP/Azure) | `reputation:asn_dc` | L2 | The `asn_datacenters` catalog |
| T2 | The UA carries explicit automation markers (curl/python-requests and the like) | `tls_fp:automation_ua` | L3 | A UA check in Lua |
| T3 | The client sent no SNI in the TLS handshake | `tls_fp:no_sni` | L3 | TLS handshake data |

---
