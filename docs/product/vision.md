# Bot & Abuse Controls — product description

**Version:** v0.5 · Status: an internal document · Date: 2026-05-21 · Previous version: v0.4 (2026-05-18). What changed is in the "What is new in v0.5" section at the end.

---

## Product overview

### What it is

A service protecting customer sites from bots and abuse, running at the CDN's proxy layer. It stands in the path of HTTP traffic ahead of the customer's origin: every incoming request goes through a chain of checks and receives a verdict — let it through, block it, or send it to verification — before it ever reaches the customer's site.

The goal is to cut off harmful automated traffic (scrapers, brute force, scanners, DDoS bots) without getting in the way of real users and legitimate bots (search engines, monitoring, payment webhooks).

### What it consists of

Two parts with a division of responsibility: the proxy makes the traffic decisions, and the backend supplies the proxy with data and collects the results.

#### The proxy (nginx + Lua)

The layer in the traffic path where the whole check cascade runs — on the hot path, within microseconds, before the request leaves for the customer's origin. All the data needed for decisions sits locally in memory, with no outbound network calls while a request is being processed.

#### The backend

The server side, separate from the proxy and off the hot path. A user's request never waits for it. It has three functions:

- The catalog server — stores and serves the catalogs to the proxy (lists of bad IPs, bot patterns, TLS signatures, domain policies and so on), which the proxy caches locally.
- The log receiver — collects structured logs from every proxy node, enriches them and stores them in telemetry for analytics.
- The rDNS worker — checks in the background that IPs claiming to be search engine bots really belong to them (protecting SEO).

If the backend is unavailable, the proxy keeps working from the last catalogs it loaded, and traffic is unaffected.

### What "the cascade" means

The cascade is an ordered chain of check layers every request passes through, on a "cheapest first" principle: light checks earlier, expensive ones later. A request walks the layers until one of them issues a terminal verdict (block, or let through on a fastpath) or until it reaches the end.

| Layer | What it checks |
| --- | --- |
| L1 — Hygiene | Basic hygiene: the HTTP method, the User-Agent blacklist |
| L2 — Reputation | Source reputation: the IP (lists), ASN, geo, verified bots, the clearance cookie |
| L3 — TLS fingerprint | The signature of the client's TLS stack — it recognises automated clients disguised as browsers |
| L4 — Rate limits | Behaviour over time: request frequency across different keys (IP, IP+UA, TLS fingerprint, unique URLs) |
| L5 — Verification | Active verification: a JS challenge for browsers, a block for non-browser clients |

Inside a layer the checks are performed by individual rules. A rule is one named check with a condition and a category (for example "the method is not in the whitelist", "the IP is on the blocklist", "the TLS signature does not match the claimed browser"). When it fires, a rule either issues a verdict (block, or let through on a fastpath) or marks the request with a flag. Every rule has a short identifier (for example `ip_blocklist`) that is written to the log, so you can see exactly which rule fired.

A flag (a challenge flag) is a mark on a request saying "this looks suspicious, a candidate for verification". A flag by itself neither blocks nor allows the request: the marks accumulate along the cascade, and the final decision on them is taken at the last layer, L5. That is how the "soft" rules work — signs of automation in the TLS signature, for instance, mark the request with a flag rather than blocking it outright.

Besides rules there are tags. A tag also fires on a condition but, unlike a rule, affects neither the verdict nor verification — it only describes the request (for example "the IP is in a datacenter") and accumulates in `tags` for analytics. In short, a rule changes the request's fate (through a verdict or a flag) while a tag only labels it.

The accumulated flags are consolidated at the final layer, L5, which decides whether to send the request to verification. Every request produces exactly one log record on the way out, with the final verdict and every signal that fired (the rule, the flags, the tags).

### Catalogs, policies and modes

The data the cascade runs on comes in two kinds:

- Shared catalogs — maintained by product and effective for every customer at once: lists of bad IPs, patterns of bad User-Agents, datacenter ASNs, TLS signatures of known bots and automation. They are updated through PRs based on log analysis.
- Customer policies — the settings of one domain, affecting only that domain and no one else.

A domain's policy includes: the operating mode, rule thresholds, the customer's custom rules (their own UA patterns, ASN blocks, per-path limits), a list of trusted IPs and the heightened-protection toggle.

Operating modes:

- shadow — the cascade computes and logs a verdict but physically blocks nothing. Used for observation and calibration against real traffic.
- active — verdicts are enforced (a block or a challenge).
- attack_mode (Under Attack) — an emergency toggle for a domain: while under attack, everything that reaches verification is sent to a challenge.

### Who needs it

- The site is under load from bots and scanners — it runs slower and the hosting bill grows
- A login or registration form is being brute-forced
- An API is overloaded with illegitimate requests
- A search page or a catalog is being scraped by competitors
- Periodic traffic spikes (attacks, sudden mentions) take the origin down

### What it is not

This is baseline protection, not an enterprise solution in the class of Cloudflare Bot Management or DataDome. The service will not handle:

- Advanced bots that emulate browser behaviour (Puppeteer/Playwright in stealth mode)
- Residential proxy networks (the traffic comes from legitimate home IPs)
- Bots that deliberately adapt to our checks
- Behavioural session analysis

The product covers roughly 80% of the typical abuse scenarios for small and medium businesses.

### What this document describes, and the related material

The document describes the end-to-end path of an HTTP request that arrived at the proxy for a protected customer domain — from acceptance after the TLS handshake to delivery to the client (from cache or from the origin), or to returning a 403/429 if the request was cut. This is the "under the hood" part of the product.

**Cascade diagrams** (a visual commentary on this section): [cascade-diagrams.md](cascade-diagrams.md) — Mermaid diagrams: the main flow, the L5 decision tree, the mode × Strictness × verdict matrix, the data flow into the log.

**Entity reference** (a glossary plus tables): [entities-reference.md](entities-reference.md) — tables of every catalog, rule, tag, JSON log field and enumeration (verdict / stage / mode / Strictness / category / attack_mode). A quick reference for the teams.

**Config templates** (illustrative): [config-templates.md](config-templates.md) — the structure and semantics of every cascade config file (defaults.conf, the whitelist/blocklist/ua/asn/tls_fp catalogs, policy/.yaml, challenge_secret) with examples and the staged rollout conventions. The format is at the admins' discretion.

**Catalog of every rule** (a flat reference): [rules-reference.md](rules-reference.md) — every cascade rule in "if condition → then verdict" form, in layer order L1–L5, with its category, data source and phase. Plus the informational tags and a summary of which rule is live in which phase.

---

## Operating modes

Every site has two modes: shadow (the default, free) and active (paid, with real blocking). This is the same `mode` field in the per-resource policy.

### Shadow *(the default, for everyone)*

The cascade observes traffic and writes verdicts to the log, with no physical action on the request. The customer sees bot-traffic analytics in the dashboard ("X% of your requests look like bots") but has no real protection yet.

This is the default mode for every new domain in the pool and for all free customers. It is enabled automatically, with nothing for the customer to do.

For us it is the monetisation hook: we show the customer what we see in their traffic and sell them the active mode.

### Active *(paid)*

Full protection: blocking rules really block (403 / 429 with Retry-After), soft signals trigger verification through L5 (a JS challenge), and verified crawlers fastpath. Everything that "would have been blocked" in shadow is now really blocked.

Inside active there is the emergency Under Attack toggle (`attack_mode=true`) — per host, enabled by the customer for their domain. With it on, L5 forces `should_challenge()=true` for every request that reaches it: browsers go to the JS challenge, non-browser clients are blocked as `non_browser_blocked` (branch B), and protocol-incompatible requests as `unchallengeable_request` (branch C). Verified search bots and IP whitelist holders keep fastpathing at L2 (SEO and trusted integrations are unaffected). Clearance cookies issued BEFORE the attack started do not fastpath while `attack_mode=on` (an attacker could have stockpiled them in advance) — such a request goes through the cascade to L5 for a challenge. Cookies issued during the attack (after re-solving the challenge) fastpath as usual, so a real user solves one challenge per attack rather than one per request. Use it during an ongoing attack, or pre-emptively ahead of expected load.

---

## Protection layers — the L1–L6 pyramid

The cascade's principle: each successive layer is more expensive and/or richer in state. Cheap checks come first, so that bad traffic is cut as early as possible and does not consume resources.

The L numbers in this table are a visual hierarchy of layers by complexity and cost. In the cascade text below and in the JSON log we use the stage names (`hygiene`, `reputation`, `tls_fp`, `rate_limits`, `verification`) — they are the same everywhere. Think of the L number as "the layer's position in the pyramid" and the stage name as "the stage's code in the code and in the log".

| Layer | Stage | Signal | Cost | State | Where |
| --- | --- | --- | --- | --- | --- |
| **L1** | `hygiene` | Method whitelist, UA blacklist | nanoseconds | static config | proxy |
| **L2** | `reputation` | Clearance cookie verify (HMAC), the verified-bot allowlist (rDNS), IP whitelist/blocklist, customer/datacenter ASN, geo | μs | stateless HMAC + static lists + MaxMind + rDNS verdicts from the backend | proxy |
| **L3** | `tls_fp` | Fingerprint computation, the fingerprint blocklist, impersonator, suspicious ciphers | ~μs | catalog + a per-fingerprint cache | proxy (computation) + backend (the catalog) |
| **L4** | `rate_limits` | per IP, per IP+UA, per API, per fingerprint, rate_scan_urls — sliding 10 s/60 s | μs | per-proxy counters | proxy |
| **L5** | `verification` *(roadmap)* | Issuing the JS challenge, issuing the clearance cookie, Under Attack mode | seconds to issue | a stateless HMAC secret | proxy (issuing) |
| **L6** | *(out of scope in v1)* | Mouse, timings, URL sequences — behavioural ML over sessions | needs a JS beacon | full sessions | future |

**v1 = L1–L5.** L6 is a different product already.

**The stage-code contract: stable across iterations.** If a new cascade layer appears in future it gets a new stage code, and the existing ones (`hygiene`, `reputation`, `tls_fp`, `rate_limits`, `verification`, `egress`) are neither renamed nor shifted. This keeps old logs and the analytics over them interpretable after any extension.

---

## How it works

An end-to-end walk through the request processing stages — from acceptance after the TLS handshake, through the cascade layers, to delivery to the client or a 403/429. Stages 1–5 correspond to the cascade layers L1–L5; stages 0, 6 and 7 are pre- and post-processing (acceptance, handing over to the CDN flow, writing the log).

### The architectural principle on one screen

- **The proxy runs the ENTIRE L1–L5 cascade** on every request. All the data needed for decisions is already prepared locally in memory, with no network calls to the backend on the hot path.
- **The antibot backend** does only three things, and never on the hot path: (1) it supplies catalogs to the proxy, (2) it accepts an asynchronous log stream, (3) it runs the background rDNS worker for verified bots.
- Catalogs are refreshed on the proxy in the background, with two delivery SLAs:
  - **≤ 30 seconds** for the fast catalogs: the per-resource `policy` (a change made by the customer in the dashboard, including the `attack_mode` toggle) and `bot_verification_status` (the rDNS worker).
  - **≤ 15 minutes** for the PR catalogs: `tls_fp_blocklist`, `tls_fp_catalog`, `ua_blacklist`, `ip_blocklist`/`ip_whitelist`, `asn_datacenters`, `tls_fp_browser_profiles` (updated by product through PRs).
- If the backend is unavailable, the proxy keeps working from the last copy it loaded successfully (fail-stale), and a client's request never waits for the backend. The concrete delivery mechanism (pull/push/etag/etc.) is the backend team's choice.

In other words, for the cascade the backend is a source of configuration and a sink for logs, not a compute service.

**The scope is every domain served by the edge pool.** The cascade runs on all such requests automatically, with no per-domain onboarding. If the domain has an entry in the `policy` catalog, the cascade uses it as an override of the defaults (mode, Strictness, custom rules, attack_mode). If there is no entry, the pool's system defaults apply: `mode=shadow`, `Strictness=Standard`, no custom rules, `attack_mode=false`. So any new domain in the pool immediately gets observe-only protection, and there is no "not connected" state inside the edge pool.

What this document does not cover (those are separate tasks):

- The dashboard UI: how the customer sees their analytics, buys protection, configures Strictness and rules. We assume the customer has already bought, their policy is in our database and it has reached the proxy.
- Analytics widgets for the customer and for product (exactly how we show "X% of your traffic is bots").

What is described here:

- **What sits on the proxy by the time a request arrives** — the data already prepared locally so that the cascade runs in microseconds.
- **The request's path: from TLS to the origin or the cache** — step by step, the main flow.
- **What runs in the background and in parallel** — the supporting systems that keep this working: catalog updates, bot verification, log delivery, the kill switch and attack mode.

---

### What sits on the proxy by the time a request arrives

By the time the TLS handshake is finished and nginx has accepted the request, the worker's local memory on the edge node already holds everything the cascade needs:

- **The per-resource policy** for every customer domain served by this pool. For each domain (`Host`): `mode` (shadow / active), Strictness, custom UA patterns, the customer's ASN block, custom rate-limit rules, the attack_mode flag (meaningful only under mode=active), and the IP whitelist of legitimate server-side integrations (used at stage 2.3, so that server integrations and API clients from known IPs fastpath before they reach the challenge at L5).
- **The shared catalogs:** `tls_fp_blocklist`, `tls_fp_catalog` (known automation signatures by TLS fingerprint), `ua_blacklist` (a combined regex over the UA — system automation signatures plus a curated bad-bot list), `ip_blocklist`, `ip_whitelist`, `asn_datacenters`, `bot_verification_status` (the three-state catalog of search engine bots: `verified` / `rejected` / absent — see stage 2.2), and `tls_fp_browser_profiles` (the expected cipher_cnt per browser family).
- **The HMAC secret for the clearance cookie** — a single string shared across the whole edge pool, needed to sign the cookie at L5 (issued after a challenge, stage 5.2), to verify the cookie at L2 (stage 2.1) and to sign the challenge page's self-signed nonce — all without touching the backend. It is delivered through Puppet (Channel A) and loaded on the proxy at startup. Rotation:
  - *Scheduled* (quarterly) — through a PR to the Puppet repo, a Puppet run and an nginx reload across the pool. The inconsistency window (some proxies on the new secret, others on the old) is a few minutes; during it, clients holding a cookie issued under one secret may get "invalid" on a proxy holding the other and re-solve the challenge. That is a one-off UX annoyance and is acceptable from a product standpoint.
  - *Emergency* (a compromised secret) — escalated to the edge admins through a separate incident procedure. That is neither our channel nor our SLA; the admin team works to its own playbook. The inconsistency window is the same, but the rollout pace is chosen by the admin team according to the severity of the incident.
  Rotation invalidates every previously issued cookie — that is by design (part of the point of rotating).

This data is refreshed by a background process — see the "What runs in the background" block below. It has no effect on the request path itself: every lookup in the cascade goes to the proxy's local memory, with no network calls and no waiting.

---

### The request's path: from TLS to the origin or the cache

The cascade's principle is simple: each successive layer is more expensive and/or richer in state, so the cheap checks go first and obviously bad traffic is cut as early as possible without spending resources on expensive checks.

#### Stage 0 — the TLS handshake and accepting the request

The client establishes a TLS connection with the proxy. After the handshake, the data about it (the TLS version, the cipher list, the curves, the ALPN, the SNI) must be available to the cascade through nginx's native variables — `$ssl_protocol`, `$ssl_ciphers`, `$ssl_curves`, `$ssl_alpn_protocol`, `$ssl_server_name`. L3 computes the TLS fingerprint from exactly those; that allows the fingerprint to be computed in pure Lua, with no patches to nginx or OpenSSL. The requirement on the environment is that these variables are exposed in `access_by_lua` (availability to be confirmed with the admins). The later cascade stages run for requests to protected customer domains.

#### Stage 1 — Hygiene (the method, the UA blacklist)

**What we check:**

- **The request method** — is it in the whitelist (GET, HEAD, POST, OPTIONS by default). A request using TRACE or PUT is almost always a scanner; there is no legitimate reason for such methods on the pool's sites.
- **The User-Agent against the UA blacklist.** Matching the UA string against a set of patterns. One mechanism, two sources of patterns merged into a single `ua_blacklist` catalog:
  1. **The global list** — maintained by product and populated through PRs to the repository based on log analysis. Example patterns: automation (curl, wget, python-requests, scrapy, go-http-client), known bad bots (AhrefsBot, SemrushBot, MJ12bot), vulnerability scanners (nikto, sqlmap, masscan), scrapers (ScrapeBot, DataForSeoBot).
  2. **The customer's custom patterns** — the customer adds their own strings or regexes for their resource through the dashboard. They are stored in the per-resource policy and applied on top of the global list.
  In the customer's dashboard: a "Block known bad bots" toggle applies the global list to the resource, plus a textarea for their own patterns.
  The `ua_blacklist` catalog ships empty and is populated by product through PRs as patterns become visible in the logs; until then the rule blocks nobody.
- **Header sanity — the informational tag `hygiene:header_anomaly`, not a blocking rule.** It checks for header combinations a real browser never sends but lazy automation does. The base case: an HTTP/2 request with no `Accept` header (a real browser over HTTP/2 always sends `Accept`). It catches automation that faked a browser UA without bothering with a realistic header set — a UA blacklist would miss that. The tag emits no verdict of its own (header heuristics easily produce false positives on unusual but legitimate clients) and does not affect the verdict — it only accumulates in `tags` for analytics (from the accumulated statistics one can later extend `ua_blacklist` or the rules by hand).

**Where the data comes from:** the static config (the method whitelist), the `ua_blacklist` catalog (a combined regex from the backend, the global list), the `policy` catalog (the customer's custom patterns) and header checks in Lua (header sanity).

**Cost:** nanoseconds — a set-membership lookup for the method, and for the UA a single comparison against a pre-built combined regex regardless of the list's size.

**What happens when it fires:** the blocking category → `verdict=block, rule=method_not_allowed | ua_blacklist`. In shadow it is logged only; in active it is a 403 immediately.

**Safely adding new UA patterns** — through staged rollout (see "Staged rollout for PR catalogs" below). A new pattern is first added as `staging`; the proxy matches it and logs the hit but does not block. After calibration against real traffic the pattern is promoted to `active`.

**Examples:**

- `TRACE /admin HTTP/1.1` → `verdict=block, rule=method_not_allowed`.
- `User-Agent: AhrefsBot/7.0` → `verdict=block, rule=ua_blacklist`.

#### Stage 2 — Reputation (the cookie, verified bots, IP, ASN, geo)

**What we check, in order:**

1. **The clearance cookie (HMAC verify).** If the request carries a `tf_clearance` cookie, the client has solved a JS challenge at some point and is considered trusted for the TTL (24 hours in normal mode, 1 hour if the cookie was issued while `attack_mode=on` for that same domain). The TTL values (24 h / 1 h) are system constants in `defaults.conf`; the customer does not configure them in the dashboard. The choice between them is made per request when the cookie is issued at L5, based on the `attack_mode` state of exactly the host the request came to. Customer A enabling `attack_mode` on `example-a.com` does not affect the TTL of cookies issued for other customers: the cookie is scoped `Domain=example-a.com` and is never sent on requests to other hosts. The proxy verifies the cookie's HMAC signature locally, using the secret from local memory (loaded at startup through Channel A, shared across the pool), and checks that the cookie is presented by the same client it was issued to (identity binding — the TLS fingerprint and the IP subnet: /24 for IPv4, /64 for IPv6). If the signature is valid, the binding matches and the TTL has not expired, the client is considered a trusted browser: layers L3 (TLS fingerprint) and L5 (the challenge) are skipped for it — there is no point recomputing the fingerprint or re-challenging someone who has already passed. But L4 (rate limits) still applies: the clearance cookie proves "I am not a JS-incapable bot", not "I am allowed to abuse" — and a client who solved the challenge can still brute-force a login or scrape a catalog. If L4 is clean → `verdict=allow, rule=cookie_valid`; if a rate limit fired, the L4 rule wins (`verdict=block/challenge, rule=rate_*`). If the signature is broken, the binding does not match or it has expired, the cookie is ignored and we continue down the cascade. Cost: microseconds (one HMAC operation, no network calls, no database lookups).

**The exception: `attack_mode=on` for this host.** Under attack, L2.1 does not trust clearance cookies issued BEFORE the attack started — an attacker could have stockpiled them ahead of the main wave. Such cookies do not fastpath: the request goes through the cascade to L5 (a challenge for a browser, or the corresponding block for non-browser and unchallengeable clients). Cookies issued during the attack (after re-solving the challenge, TTL=1 h) fastpath as usual — so a real user solves one challenge per attack rather than one per request. Telling "issued before the attack" from "issued during the attack" is done from the cookie's own metadata (the issue time and/or the TTL type); the concrete mechanism is up to the implementation. The other L2 checks (verified bots, the IP whitelist) work as usual under `attack_mode=on` — SEO and trusted server integrations are unaffected.
  Unlike the other L2 rules, the cookie verify is a cryptographic check in Lua code rather than a catalog lookup. So it has no separate registration in the config's `[allow]` section — its parameters (the cookie name, the source of the HMAC secret, the TTL) are parameters of the Lua logic itself. The verdict is emitted directly from the code.
   The cookie is bound to the domain (the domain is part of the signature), so a cookie from `site-a.ru` will not work on `site-b.ru`. When the cookie was issued, a self-signed nonce with a 60 s TTL was used (signed with the same HMAC secret as the cookie, so any proxy in the pool validates it with no shared state); once the TTL expires the nonce is rejected and a replay is impossible. More on issuing the cookie in stage 5.
2. **The verified-bot allowlist (search crawlers).** The Google, Bing, Yandex and DuckDuckGo bots must not be blocked or indexing collapses. But their User-Agent is trivial to fake: any script can write "Googlebot" into its UA. So the check is two-step (PTR plus forward DNS) and is moved into the background rDNS worker on the backend — there is no DNS on the proxy's hot path.
  The `bot_verification_status` catalog carries three states for an IP with a search engine UA:
- `verified` — the backend confirmed through rDNS that this is a real bot. TTL ~1 hour.
- `rejected` — the backend checked and refused (the PTR does not match, or the forward DNS returned a different IP, or there was no PTR at all). This is an impersonator. TTL ~1 hour, symmetric with `verified`.
- **absent** — the backend has not managed to check yet (the first appearance of an IP with a search engine UA in our pool, or the previous record's TTL expired).
 The L2.2 logic on the proxy for a UA claiming to be a search engine bot:

| The IP's state in the catalog | Verdict | What happens next |
| --- | --- | --- |
| `verified` | `allow, rule=bot_verified` | A whitelist fastpath; the remaining layers are skipped (including the TLS fingerprint, rate limits and attack mode). |
| `rejected` | No fastpath, we continue down the cascade | It will be handled as an ordinary request — most likely it will trip `tls_fp_impersonator` or hit the rate limits, and then L5. |
| absent *(there is no record for this IP in the catalog)* | `allow, rule=bot_verified_pending` | **A provisional whitelist** — we let it through leniently, so as not to break SEO before the backend has had a chance to check. The proxy keeps no per-IP state: pending is issued for every request from that IP until the backend publishes verified or rejected into the catalog. Through the log receiver the backend sees the first pending request and adds the IP to the rDNS worker's queue; usually within seconds or minutes a final status appears in the catalog, and every subsequent request from that IP meets either `verified` or `rejected`. |

   **The price of the provisional fastpath.** The "free pass" window is not "exactly one request" but "until the rDNS worker publishes a result". For an impersonator posing as Googlebot from a new IP, that means it gets a handful of requests through before landing in `rejected`. After that it is `rejected` (TTL 1 h) and is caught normally. For a distributed attack with mass IP rotation this is not a problem: the per-domain rate limits at L4 catch that pattern, and isolated "free" requests are background noise. The price is acceptable in exchange for the guarantee that a genuinely new Googlebot IP never gets a challenge before we have checked it.
   **On the proxy this is a simple lookup in local memory (nanoseconds); there is no DNS on the hot path.**
3. **The IP whitelist** — two sources, checked together:

- **System** — the IPs of our monitoring, check services and trusted system clients (the shared `ip_whitelist` catalog).
- **Per resource** — the IPs of the customer's legitimate server-side integrations, registered in advance in the dashboard (part of the per-resource `policy`). This is the main way for API clients, server-to-server integrations and backend cron jobs to avoid the challenge at L5.
 A hit from either source is the allow category → `verdict=allow, rule=ip_whitelist`. In active it is a fastpath and the remaining layers are skipped; in shadow it is logged only and the cascade continues.

1. **The IP blocklist** — IPs we already know to be bad (added from log analysis or complaints). The blocking category → `verdict=block, rule=ip_blocklist`.
2. **The customer's ASN block.** An ASN (Autonomous System Number) is the number of the autonomous system an IP belongs to. Every large hosting provider, cloud or VPN has its own ASN. *A practical scenario:* an attack comes from IPs in different countries, but they all belong to one cloud (AWS, DigitalOcean, Hetzner) or VPN service — one ASN number closes the provider's whole range with a single rule. The customer enters the ASN numbers in the dashboard and they land in the per-resource policy. On a match it is the blocking category → `verdict=block, rule=asn_customer`.
3. **Geo.** If the resource has a country whitelist and the request's country is not in it, this is the blocking category → `verdict=block, rule=geo_blocklist`.

**L2 informational tags** (not rules, they lead to no verdict and exist for analytics):

- `reputation:asn_dc` — the IP belongs to a large public datacenter ASN (Hetzner, OVH, DigitalOcean, AWS, GCP, Azure). The tag by itself blocks nothing and triggers no challenge — a legitimate API client can perfectly well come from a datacenter. It is used for analytics ("what share of our traffic comes from datacenters"). It does not affect the verdict; its combination with other signals in the logs helps interpretation (a datacenter IP together with a fired `tls_fp_impersonator` is a clear indicator of a Chrome disguise), but that is analysis, not a runtime decision.

The data source for the tag is the `asn_datacenters` catalog.

**Where the data comes from:** static lists in the config (the system datacenter ASNs) plus the MaxMind GeoIP/ASN databases (already present on the edge proxy) plus per-resource customisations through the `policy` catalog (the customer's custom ASN block, their custom geo whitelist).

**Cost:** microseconds — CIDR matching and a hash lookup.

#### Stage 3 — the TLS fingerprint

**What we check:** the client's unique signature, computed from its TLS handshake. It is determined by the real TLS stack (Chrome NSS, Firefox NSS, OpenSSL, Go crypto/tls, python ssl) and does not change when the User-Agent is spoofed.

**How it is computed:** from the very same `$ssl_*` variables nginx filled in after the handshake:

```
fp = L<ver><sni_flag><cipher_cnt><alpn>_<hash_b>_<hash_c>
```

The fingerprint is a short string in two parts: a human-readable prefix and two hashes. The prefix is assembled from the handshake parameters and can be read at a glance:

| Part | What it means | Example |
| --- | --- | --- |
| `L` | a fixed prefix of our format | `L` |
| `<ver>` | the TLS version: `12` = TLS 1.2, `13` = TLS 1.3 | `13` |
| `<sni_flag>` | whether the client sent SNI: `d` — yes, `i` — no | `d` |
| `<cipher_cnt>` | how many ciphers the client offered (after stripping GREASE, see below) | `15` |
| `<alpn>` | the negotiated protocol: `h2` or `h1` | `h2` |

After the `_` come two hashes, which compress the exact lists into a compact form (we take SHA-256 and keep the first 12 hex characters):

- `hash_b` — a hash of the **sorted cipher list** (after stripping GREASE). It answers "exactly which set of ciphers the client offered".
- `hash_c` — a hash of the **curve list plus ALPN plus the TLS version**. An additional discriminator over the handshake's other parameters.

An example of the resulting fingerprint for a real Chrome: `L13d15h2_1ed0482b9b4c_b50336ab2a86`.

**On stripping GREASE (RFC 8701).** GREASE is the random filler that browsers (Chrome, Safari) mix into the cipher and curve lists on every connection, deliberately, so that the values vary. If it is not cut out before hashing, the same browser's fingerprint differs on every request and the signature catalog becomes meaningless. So stripping GREASE is mandatory — with it, the fingerprint is stable and identical for one TLS stack.

The resulting fingerprint is cached locally on the proxy for 60 seconds, so that repeat requests from the same client do not recompute the hash.

**The checks based on the fingerprint:**

1. **The client's fingerprint is in the `tls_fp_blocklist` catalog** (the blocking category) → `verdict=block, rule=tls_fp_blocklist`. Fingerprints land there once we know them to be bots, from analytics.
2. **A UA family ↔ fingerprint mismatch.** The `tls_fp_catalog` catalog records which cipher hashes correspond to which known automation families (python-requests, curl, Go, okhttp). If the UA says "Chrome" while the fingerprint matches the python-requests hash, this is an impersonator. The soft category → `verdict=challenge, rule=tls_fp_impersonator`.
3. **The cipher count falls outside the browser profile.** The `tls_fp_browser_profiles` catalog holds the expected `cipher_cnt` per browser family (Chrome: 15, Firefox: 16, Safari: 20). If the UA looks like Chrome but cipher_cnt=11, that is suspicious. The soft category → `verdict=challenge, rule=tls_fp_suspicious_ciphers`.
4. **A browser fingerprint from a datacenter.** The fingerprint looks like a browser (family by cipher profile) but the IP belongs to a datacenter ASN (`asn_datacenters`) — an anomaly: real users do not browse from a public datacenter. The soft category → `verdict=challenge, rule=tls_fp_dc_browser`. It fires after the L2 allow fastpaths, so verified bots and the customer's registered IP whitelist (legitimate cloud integrations, server-to-server) are untouched. Detecting a headless engine inside a real browser, and behavioural session analysis, are post-MVP (L6, see the comparison with Cloudflare).

**L3 informational tags** (not rules, they lead to no verdict and exist for analytics):

- `tls_fp:automation_ua` — the UA carries explicit automation markers;
- `tls_fp:no_sni` — the client arrived without SNI.

All the tags (from every layer) land in a single `tags` log field with a namespace prefix — see the JSON schema in stage 8.

**Cost:** fractions of a microsecond — one sha256 over ~50 bytes plus two sorted-membership lookups.

#### Stage 4 — Rate limits (behavioural)

**Where we are in the cascade.** Every previous layer (L1–L3 plus the passive allow rules at L2) is an identity check: they answer "who is this client" (UA, IP, ASN, geo, TLS fingerprint, whether there is a cookie or a whitelist entry). Static comparisons of a single request against lists and signatures we already know. L4 covers an orthogonal class of signals — behaviour over time: how many requests the client makes, across which paths, with what regularity. This is no longer "who" but "what they are doing". The identity can be spotless (a legitimate Chrome from a residential IP with the right TLS fingerprint) while the client brute-forces `/login` or scrapes the catalog — only L4 will catch that. Without this layer the cascade misses a whole class of attacks where identity signals are not enough.

**What we check:** sliding counters across various keys, GCRA-style (the generic cell rate algorithm — a compact sliding-window implementation that stores no per-request timestamps). Two windows run in parallel on every profile — a short one (10 s) and a long one (1 min); the rule fires if either is exceeded. Why two: the short one catches a burst (a bot makes 500 requests in 5 seconds and leaves), the long one catches "slow" scrapers that sit just below the burst threshold for hours. GCRA was chosen for its cost: one 64-bit state cell per key, updated in a single arithmetic operation — which matters at hundreds of thousands of distinct keys per edge node.

##### System profiles (always applied)

| Profile | Counter key | 10 s | 1 min | Category | What it catches |
| --- | --- | --- | --- | --- | --- |
| **rate_ip** | IP | 100 | 600 | blocking | A general per-IP limit |
| **rate_ip_ua** | IP+UA | 100 | 600 | blocking | One client using several UA variants |
| **rate_api** | IP (on API paths only) | 50 | 300 | blocking | Overloading the API |
| **rate_tls_fp** | TLS fingerprint | 50 | 300 | blocking | A bot rotating IPs while its TLS stack stays the same |
| **rate_scan_urls** | IP (unique URLs) | 50 | 200 | blocking | Scraping — many distinct URLs from one IP |

**Graceful degradation for `rate_tls_fp`.** If for some reason no TLS fingerprint was computed at stage 3 (a handshake without SNI, a non-standard TLS client, a computation error), the `rate_tls_fp` rule simply does not apply to that request. The other rate rules (rate_ip, rate_ip_ua, rate_api, rate_scan_urls) keep working. So a missing fingerprint does not fail the cascade; that particular counter key is just not used.

##### Customer per-path rules (applied on top)

In the dashboard the customer sets their own rules: on which paths, with what limit, and what to do when it is exceeded. Each rule is:

- **path** — a pattern (`/login*`, `/api/*`, `/search`)
- **methods** — HTTP methods (optional)
- **rps** — the average request rate per second from one IP
- **burst** — the permitted short spike
- **action** — `block` | `challenge` | `log_only`

**The order of application at L4: customer rules first, then the system ones.** The customer's rate rules for this host are checked first, in the order of the customer's list; the first match wins (its action — `block`/`challenge`/`log_only` — becomes L4's result for that request, and the system rules are not run). If no customer rule matched (by path/method/key), the system profiles run in the order `rate_ip → rate_ip_ua → rate_api → rate_tls_fp → rate_scan_urls`, and the first breach wins. The logic: in their own dashboard the customer knows the specifics of their domain better than system heuristics do, and an explicit setting should outweigh a default.

So that a customer does not have to configure everything from scratch, the dashboard offers presets (a UI-layer feature, not a separate cascade entity). A preset is a template that, when chosen, expands into an ordinary `policy[host].rate_rules` entry. The preset never reaches the proxy as an object; a finished rule does. The preset catalog is stored in the frontend or the dashboard backend (whichever suits the team) and is not delivered to the proxy:

| Preset | Default path | RPS | Burst | Action | Purpose |
| --- | --- | --- | --- | --- | --- |
| Login Protection | `/login*` | 5 | 10 | challenge | Protection from brute force |
| Registration Protection | `/register*` | 3 | 5 | block | Protection from mass registration |
| API Protection | `/api/*` | 20 | 40 | block | An API limit |
| Search Protection | `/search*` | 10 | 20 | challenge | Protection from scraping |
| General Limit | `/` | 50 | 100 | log_only | A general limit over all traffic |

The customer applies a preset → adjusts the path to their site's structure (`/login` → `/account/sign-in`) → done.

##### What each `action` does when the limit is exceeded

- `block` — the blocking category → `verdict=block, rule=rate_*`. In active a 429 Too Many Requests is returned with `Retry-After`. The cascade ends and the request never reaches L5.
- `challenge` — the soft category → the request is marked "needs verification".
- `log_only` — a log record only, with no effect on the later stages.

##### Where the counters live

Locally in each proxy's memory, per proxy worker. This is a deliberate v1 compromise: when traffic is spread across several proxies, the total permitted RPS is proportionally higher (each proxy sees only its share of the traffic and counts only that). A globally exact rate limit would require shared storage between proxies — that is v2.

**Cost:** microseconds — a sliding window counter increment plus a comparison against the threshold.

#### Stage 5 — Verification (active)

**Where we are in the cascade.** This is the cascade's final layer: the request has passed every identity check (L1–L3, plus the passive allow rules at L2) and the behavioural checks (L4). It only gets here if nothing cut it outright as a `block` and nothing gave it an `allow` fastpath. Along the way it may have accumulated challenge flags from the soft-category rules:

- `tls_fp_impersonator`, `tls_fp_suspicious_ciphers`, `tls_fp_dc_browser` (stage 3) — soft
- L4 customer rules with `action=challenge` (stage 4) — soft

L5 is the executor: the single point that looks at the accumulated challenge flags plus attack_mode plus Strictness and decides what to serve the client. No earlier layer issues a challenge itself — they only set flags.

The passive allow rules (the clearance cookie, verified bots, the IP whitelist) live earlier, at L2 (stages 2.1–2.3) — clients with a valid cookie, confirmed crawlers and registered server IPs never get here at all, because L2 already gave them `verdict=allow`.

**Where L5 physically runs.** Entirely on the proxy, with no call to the backend. The whole challenge lifecycle — serving the HTML page, generating the nonce, checking the client's answer, signing the cookie with HMAC — works locally, on the same primitives as the cookie verify at stage 2.1: the HMAC secret from the proxy's local memory. The backend does not intervene on the hot path. The only thing that leaves for the backend asynchronously is the log with the challenge-pass event and the collected browser fingerprint (for analytics).

**What will be checked (in order):**

##### 5.1. The verification decision

Whether active verification is needed right now is decided by `should_challenge()`. It is a function computed at L5 on every request, from three inputs:

1. **The `attack_mode` toggle** for this host (per host). When it is on, every request that reaches L5 requires verification regardless of every other signal. See Under Attack mode below.
2. **The accumulated challenge flags** from the earlier layers (tls_fp_impersonator / tls_fp_suspicious_ciphers / tls_fp_dc_browser from L3, rate rules with action=challenge from L4). The request reached L5, so at least one flag has already fired.
3. What happens next is determined by the Strictness toggle in the dashboard, which is binary:

| Strictness | What L5 does when challenge flags have accumulated |
| --- | --- |
| **Standard** *(the default for every new customer)* | Any system challenge flag (`tls_fp_impersonator`, `tls_fp_suspicious_ciphers`, `tls_fp_dc_browser`, L4 rate rules with action=challenge) → issue a challenge. The standard behaviour for sites with no special requirements. |
| **Permissive** *(enabled by the customer in the dashboard)* | System challenge flags do not trigger a challenge — the client passes through L5 and the request physically continues into the CDN flow. The log records `verdict=permissive, rule=<name of the last soft flag>` — a separate verdict is needed so that analytics immediately shows "this would have fired under Standard, but Permissive suppressed it". A profile for domains where legitimate non-browser traffic cannot be enumerated one by one (see "Why Permissive exists" below). |

**The default for every new domain is `Strictness=Standard`.** That means a customer works at the standard verification thresholds from the moment they connect to Bot & Abuse Controls. Switching to Permissive takes an explicit action in the dashboard.

**An important exception to both modes: customer rate rules with `action=challenge` are always respected.** If the customer configured "Login Protection: 5 RPS, challenge" in their dashboard themselves, the challenge is issued on a breach even under Permissive. The Strictness toggle affects only the system soft signals (the heuristics the antibot computes), never the customer's explicit settings.

**Permissive is not "protection turned off".** The blocking rules (ua_blacklist, ip_blocklist, asn_customer, geo_blocklist, tls_fp_blocklist, system rate rules with action=block, rate_ip and the rest) keep blocking as usual — Strictness affects only the verification of soft flags. If the customer wants no real blocking at all (for testing, say), they switch `mode=active → shadow`, and the cascade only observes.

**Why Permissive exists.**

Strictness is a domain-level toggle (in Bot & Abuse Controls a connection is made at the second-level domain, and subdomains are not registered separately). It affects all of the customer's traffic.

Targeted cases — known API partners, specific webhook sources, individual paths — are already handled by the cascade's other mechanics:

- The IP or ASN of a known integration → `whitelist_ip` or the per-resource IP whitelist → L2 fastpaths them before Strictness ever applies;
- Per-path limits and blocks → the customer's L4 rate rules and the L1 blocking rules with a path matcher;
- Bots with rDNS (Googlebot, Bingbot and the like) → `bot_verification_status` → L2 fastpaths them automatically.

**A customer needs Permissive when those targeted rules are not enough:** there are many legitimate non-browser sources, they are not known in advance, and enumerating them in a whitelist is unrealistic. Typical situations:

- **Preview bots of social networks and messengers** (Telegram, Slack, Discord, FB, LinkedIn, Twitter), RSS aggregators, uptime monitors — numerous, heterogeneous, many of them absent from `bot_verified_ips`, with changing IP ranges. For media and content platforms, losing them means losing link previews in chats.
- **A B2B domain with a variety of server-side clients** — dozens of partner integrations from their own ASNs and IPs, with no browser UA; whitelisting them one by one is expensive and does not scale.
- **The calibration period after onboarding** — the customer first watches the logs to see which system soft flags fire often on their real traffic, then switches to Standard (plus targeted whitelists where they are needed).

**When Permissive is NOT justified** (despite mixed traffic):
- The browser side of the domain carries the main revenue (e-commerce checkout, payments, the account area) — losing even a fraction of a percent of real users is worse than letting some bots through. Better Standard plus targeted whitelists for the API partners.
- Under an active attack, `attack_mode=on` is used. Note: Permissive simply does not apply under attack (it does not weaken the protection).

##### 5.2. Choosing and issuing the verification

When `should_challenge()=true` we do NOT always issue a JS challenge. Not all legitimate traffic comes from a browser — API clients, mobile apps, server-to-server integrations and IoT do not execute JS. Issuing them a JS challenge would block the customer's legitimate non-browser requests.

So when `should_challenge()=true` the cascade chooses the verification mechanism by client type:

**Branch A: the client looks like a browser** (the UA contains Mozilla/Chrome/Safari/Firefox/Edge and it passes the basic header checks) → a JS challenge:

- The browser is shown an interstitial page, "Checking your connection…". The HTML+JS template of that page is delivered to the proxy as part of the cascade's Lua code through Channel A (Puppet); the JS version always matches the version of the cascade serving it. The proxy substitutes a self-signed nonce into the template — a token signed with the same HMAC secret as the clearance cookie, carrying a `timestamp`, `domain` and `expiry` (TTL 60 s). Since the secret is identical across the pool, any proxy can verify such a nonce — a client can receive the challenge on proxy A and answer through proxy B, and it all validates with no shared state and no call to the backend. Replay protection comes from `expiry`: if the nonce is older than 60 s, the proxy rejects it.
- The page runs a JavaScript task:
  - **Proof of execution** — the browser solves a computational task over a one-time token (the nonce) the server issued. A real browser does it imperceptibly, in a fraction of a second; a bot that does not execute the page will not solve it, and a large farm pays a noticeable price per request — which makes cheap brute force unprofitable. The verification endpoint itself is protected from abuse: the nonce is burned on the very first verification attempt, successful or not (on a failure the client takes a new one), and `/__challenge/verify` is rate-limited — so one harvested nonce cannot be turned into a stream of verifications loading the proxy.
  - **An optional checkbox**, "Confirm you are human", shown when suspicion is high.
  - **A browser fingerprint** — on success the client's characteristics are collected (UA, screen, Canvas, WebGL, timezone, language). They are checked for consistency using high-confidence signals: the challenge fails only on a gross contradiction (say, a Chrome UA over a TLS fingerprint of the python-requests family), while values randomised or hidden by private browsers and extensions (Canvas/WebGL and the like) are accepted — so as not to penalise privacy-conscious users. The same fingerprint travels with the challenge-pass event into telemetry (event_type=`challenge_pass`, along the same path as ordinary logs) for long-term analytics: the distribution of legitimate fingerprints, spotting headless-tool patterns, and a dataset for future L6 ML models.
- After passing, the browser receives a clearance cookie (HMAC-signed, see stage 2.1) and is redirected to the requested URL. The pass is bound to the client that earned it: it cannot be handed over or reused on another client.
**Attributes of the `tf_clearance` cookie:**
  - `HttpOnly=true` — JS on the customer's page cannot read the cookie (protection from theft through XSS).
  - `Secure=true` — sent over HTTPS only (our edge pool is HTTPS-only anyway).
  - `SameSite=Lax` — sent on top-level navigation to this domain, not on cross-site subrequests. Enough to fastpath ordinary navigation, and it does not leak to other sites.
  - `Path=/` — valid across the whole domain.
  - `Domain=<host>` — strictly this host, with no leading dot. A cookie from `example-a.com` does not work on `example-b.com` and does not work on `*.example-a.com` subdomains. Every protected host has its own independent pass.
- **What a real user sees:** a page with an animation that disappears within one or two seconds; they will not see it again for 24 hours.
- **What a bot disguised as a browser sees:** HTTP 303 → the page with the task. It does not execute it, so it does not pass. It fakes the browser's characteristics, so the check does not add up. It solves the task en masse, so it pays for every request and cannot spread one earned pass across its farm.

**Branch B: the client is plainly not a browser** (the UA contains curl/python-requests/Go-http-client/a mobile SDK/etc., or the standard browser headers are missing) → issuing a JS challenge is pointless, it will not pass by design. And it has nothing left to identify itself with: every trust mechanism (the clearance cookie, the IP whitelist) was already checked at L2 and none of them fired — otherwise the request would not have got here.

So → the blocking category → `verdict=block, rule=non_browser_blocked`. We block it as suspicious.

**When branch B fires.** Only when `should_challenge()=true` at stage 5.1 — that is, either `attack_mode` is on, or the client is on Standard Strictness and has accumulated system challenge flags. Under Permissive, branch B does not fire: there `should_challenge()` returns false for system flags, the request never reaches branch B and physically continues through the cascade. The log then records `verdict=permissive, rule=<name of the last soft flag>` — which is the whole point of Permissive (not getting in the way of non-browser clients without clear need), while the separate verdict lets analytics see "Standard would have blocked here".

**The false-positive recovery loop.** A blocked request lands in the log with all the details (the IP, the UA, which challenge flags fired, exactly which rules carried it to L5, the fingerprint). In the dashboard the customer sees that block in the "Blocked requests" widget and can:

- Add the IP to the per-resource IP whitelist in one click (stage 2.3) — if they are confident those server integrations are legitimate;
- Leave it as is — keep blocking.

**How the change reaches the proxy.** The per-resource IP whitelist is part of the per-resource `policy` (a fast catalog). The flow: a click in the dashboard → the backend API → a write to the database → the `policy` catalog is refreshed → delivery to every `edge-*` proxy in the pool. The product SLA is ≤ 30 seconds from the click until any proxy in the pool starts fastpathing that IP at L2.3. Every request from that IP that arrives during the delivery window is handled under the old state (it keeps being blocked); after it applies, it is a fastpath. Removing an entry from the whitelist (if it was a mistake) is the reverse editing operation in the same dashboard interface: click "delete" → the backend API → the record disappears from the database → the `policy` catalog is rebuilt → delivery to the proxies. The SLA is the same: ≤ 30 seconds from the click until every proxy in the pool stops fastpathing that IP. There is no separate undo mechanism.

Once it applies, the next request from that client fastpaths at L2.3 and never reaches L5. This is the main mechanism for dealing with false positives in branch B.

**Branch C: the request is protocol-incompatible with a challenge.** A JS challenge works only for GET requests from a browser expecting HTML: the proxy returns an HTML page with JS, the browser computes the token, receives the cookie and makes a fresh GET to the same URL. That mechanic breaks if:

| Property of the request | Why the JS challenge will not work |
| --- | --- |
| The method is not GET (POST/PUT/PATCH/DELETE) | After passing the challenge, the JS does `window.location = <original_url>` — which is a GET. The original POST/PUT body is stored nowhere (a 303 redirect drops the body; a 307 breaks the challenge page). "Store the body and resend it" could only be implemented with a client SDK carrying an XHR/fetch interceptor, and we do not have one. |
| `Upgrade: websocket` (a WebSocket handshake) | The client is waiting for `101 Switching Protocols`. An HTML response breaks the upgrade and the connection is never established. |
| `Accept` explicitly excludes `text/html` (for example `application/json`, `application/grpc`, `image/*`) | The client is not a browser, will not render an HTML page and will not execute the JS. It receives HTML instead of the expected JSON or binary and breaks while parsing. The default when there is no `Accept` header is to treat it as `*/*` (not html) → unchallengeable. (The product team may adjust this during implementation if they find a practical counter-example.) |

Branch C's decision when `should_challenge()=true`: `verdict=block, rule=unchallengeable_request`. The recovery loop is the same as branch B's — the customer sees the block in the dashboard and can add the IP to the per-resource IP whitelist.

**Why a separate `unchallengeable_request` rule rather than the general `non_browser_blocked`.** It is useful for the customer in the dashboard to distinguish two different reasons for a block:

- `non_browser_blocked` — the UA does not look like a browser (curl/python/an SDK). Cured by whitelisting the IP or ASN of known server integrations.
- `unchallengeable_request` — the UA may well be a browser one, but the request is protocol-unchallengeable (a POST from a browser, a WebSocket from a browser). Cured either by whitelisting the source or by moving the domain to Permissive (if there are many such requests and they are legitimate).

**In v1 that is all.** Full alternative verification mechanisms for non-browser traffic (mTLS, an OAuth check, a mobile SDK with a signed attestation token) are not in v1.

**A recommendation for a customer with an API-heavy site:** register the IP ranges of legitimate server integrations in the dashboard in advance — they will fire at stage 2.3 and never reach L5. If an integration's IP was not added in advance, you will see the block in the dashboard and can unblock it after the fact (see the recovery loop above).

##### 5.3. Under Attack mode

A forced mode, toggled by `attack_mode` per host (its own toggle for each protected domain). There is no global "attack_mode for the whole pool" toggle.

With `attack_mode=on` for a domain:

- **Every request that reaches L5 is forced into verification** regardless of Strictness and the accumulated flags. The branch routing at L5 is preserved: a browser → a JS challenge (branch A); a non-browser → `verdict=block, rule=non_browser_blocked` (branch B); a protocol-incompatible request → `verdict=block, rule=unchallengeable_request` (branch C). So attack_mode does not cancel L5's protective blocks; it forces `should_challenge()=true` for everyone.
- **Cookie verify at L2.1: cookies issued before the attack started do not fastpath** — the attacker could have stockpiled them in advance on freshly issued IPs, so we do not trust them. Real users re-solve the challenge once and receive a fresh cookie with TTL=1 h, which fastpaths for the rest of the attack (see below).
- **Verified search bots (stage 2.2) and the IP whitelist (stage 2.3) keep fastpathing** — SEO and the server integrations the customer has explicitly trusted are unaffected.
- The L4 rate limits apply as usual to everything that reaches L4 — including clearance cookie holders (the cookie skips L3 and L5 but not L4, see L2.1). A full bypass of L4 belongs to verified bots and the IP whitelist only.
- **The clearance TTL for new cookies drops to 1 hour** (instead of the usual 24) while `attack_mode=on`. Old 24-hour cookies are not physically invalidated, but with `attack_mode=on` they do not work anyway (see above); once attack_mode is switched off they start fastpathing again until their expiry.

**When to enable it:**

- A DDoS or bot attack against this domain is in progress
- There is a sharp rise in load on the customer's origin
- Pre-emptively, ahead of expected viral traffic on the domain (a launch, a publication, a PR campaign)

**Where it lives:** the `attack_mode` toggle for a specific `host` in the `policy` catalog → to the proxy through Channel C (≤ 30 seconds to propagate).

**The cost of L5 overall:** issuing the challenge takes seconds on the client (executing the JS). On the proxy it is serving the page and signing the cookie with HMAC — microseconds.

#### Stage 6 — Handing the request over to the standard CDN flow

If the cascade got here with no blocking hit, the request continues along the usual CDN flow (cache lookup, origin fetch, delivering the response).

No new headers from the antibot are added towards the origin: the customer's origin should neither see nor depend on the fact that something checked the request before it. Nor are there any antibot headers in the response to the client — the user should not see any "traces" of the cascade.

**An important property of the stage order:** the antibot is applied before the request enters the CDN flow (including before the cache lookup). So even cached responses are protected from junk requests — if a bot came for a "cheap" cached image and the cascade did not let it through, the CDN never sees that request. Bot & Abuse Controls protects not only the customer's origin (from load) but our own cache layer too.

#### Stage 7 — Writing the log

After delivering the response, the proxy assembles one structured JSON record with the final verdict and every signal that fired along the way:

```json
{
  "request_id": "...",
  "timestamp": "2026-05-18T14:30:00.123Z",   // ISO 8601 with milliseconds
  "edge_id": "edge-042",                // the identifier of the proxy node that handled the request (for aggregation)
  "resource_id": "...", "host": "...", "path": "...",
  "method": "...", "status": ..., "latency_ms": ...,
  "ip": "...", "asn": "...", "geo_country": "...",
  "ua": "...",
  "tls_fp": "L13d15h2_1ed0482b9b4c_b50336ab2a86",
  "tls_cipher_count": 15, "tls_alpn": "h2", "tls_sni_present": true,
  "tags": ["reputation:asn_dc"],  // the merged array of tags from every layer, with a namespace prefix
  "flags": ["tls_fp_impersonator"],  // every challenge flag accumulated along the way (the soft rules that fired). Empty when there were none
  "stage": "rate_limits",       // the stage where the final rule fired
  "verdict": "block",           // pass | block | challenge | allow | permissive
  "rule": "rate_ip",            // the code of the FINAL (terminal) rule, empty on pass
  "action": "block",            // what should have happened: block | challenge | allow | log_only | pass
  "mode": "shadow",             // the resource's mode at the time of the request: shadow | active
  "staging_match": []           // the array of staging patterns that matched on the request (without affecting the verdict). Empty when nothing matched
}
```

**The final `verdict` and `rule` are the terminal decision, exactly one per request.** The `rule` field holds the code of the **last (terminal)** rule that fired. On `verdict=pass` it is empty; on `verdict=permissive` it holds the name of the last soft flag that would have triggered a challenge under Standard.

**But nothing that fired along the way is lost — it lives in the arrays.** The cascade short-circuits only on a terminal (blocking or allow) rule; up to that point the soft flags and tags accumulate and are logged in full:

- `flags` — every accumulated challenge flag (the soft rules: `tls_fp_impersonator`, `tls_fp_suspicious_ciphers`, `tls_fp_dc_browser`, customer rate rules with `action=challenge`).
- `tags` — every informational tag that fired.

An example: `tls_fp_impersonator` (soft) fired at L3 and then `rate_ip` (blocking) at L4. In the log: `verdict=block, rule=rate_ip` (the terminal one), `flags=["tls_fp_impersonator"]` (the accumulated flag preserved for analytics). Rules that never ran because of the short circuit (L5 after a block at L4, say) must not be logged — they physically did not execute.

The record is sent from the proxy to the antibot backend asynchronously, and customer requests are not blocked by it. The details of delivering a log from the proxy to the telemetry sink are in the "What runs in the background" block below.

#### What happens when the cascade gives `verdict=block` or `verdict=challenge`

The flow stops at the corresponding cascade stage — before the cache lookup, before the origin, before delivering a normal response. Then:

- `verdict=block` → the client receives a 403 (for rate limits, a 429 with a `Retry-After` header). The cache is untouched. The origin is not loaded. A log record with `verdict=block` is still written.
- `verdict=challenge` → the client receives the HTML page of the JS challenge. If the client solves the JS task, it receives a clearance cookie and repeats the request; this time the cookie fastpaths it at stage 2.1 and the cascade runs to the end. If it does not, it is stuck on the challenge page.

---

### What runs in the background and in parallel

Three kinds of background system keep the main flow from the previous section fast and reliable.

#### Continuous background processes (they run all the time by themselves)

**Refreshing the catalogs on the proxy.** The backend and the proxy continuously synchronise the catalogs in the background. The product contract:

- **Fast catalogs** (`policy`, `bot_verification_status`) — a change applies across the proxy pool with a delay of no more than 30 seconds.
- **PR catalogs** (`tls_fp_blocklist`, `tls_fp_catalog`, `ua_blacklist`, `ip_blocklist`/`ip_whitelist`, `asn_datacenters`, `tls_fp_browser_profiles`) — a change applies across the proxy pool with a delay of no more than 15 minutes from the PR merge.
- Swapping the data on the proxy is atomic, with no locks and no traffic loss.
- If the backend is unavailable, the proxy keeps working from the last successfully loaded copy of the catalogs for as long as necessary (fail-stale). A client's request never waits for a catalog refresh.
- A metric for "how long since the proxy last received fresh catalogs" alerts when the SLA is breached.

The concrete synchronisation mechanism (a pull timer from the proxy, a push from the backend, server-sent events, anything else) is the team's choice; the product requirement is only what is listed above.

**The reverse-DNS worker for verified bots.** A background goroutine on the antibot backend checks the IPs that appeared in the logs with a UA containing `Googlebot/bingbot/YandexBot/DuckDuckBot`. The scheme: a PTR query → forward DNS → both must resolve to the search engine's official domain (`.googlebot.com`, `.search.msn.com` and so on).

The trigger for a check is the log stream itself: the worker sees a record with a search engine UA and an IP that is not yet in the `bot_verification_status` catalog (neither as `verified` nor as `rejected`) and queues it. So it is reactive, with no pre-emptive sweeping.

Both outcomes of the check are published into the `bot_verification_status` catalog:

- `verified` — both DNS steps agreed (TTL ~1 hour).
- `rejected` — the PTR and forward lookups disagreed, or DNS returned junk (TTL ~1 hour, symmetric with `verified`).

Both categories reach the proxy — that is what the L2.2 provisional fastpath needs (see stage 2.2): an IP with a search engine UA that is in the catalog under neither status gets a lenient pass, for every request, until the backend's rDNS worker publishes verified or rejected. Once the final status is published, every subsequent request from that IP meets either `verified` (a full fastpath) or `rejected` (ordinary cascade processing with no fastpath).

On the proxy it is only a set-membership lookup, with no DNS on the hot path.

**Delivering logs from the proxy to the telemetry sink.** The route is proxy → backend → the telemetry sink (ClickHouse, or whatever we choose). The proxy never talks to the telemetry sink directly — the backend is the proxy's only outbound integration with our infrastructure.

Why delivery is two-step:

- The proxies hold no telemetry credentials and do not know its endpoint — the backend is the single point of integration; when the storage changes, the proxies are untouched.
- The backend is the single buffering point should the sink become unavailable. Buffering independently on dozens of proxies would be less reliable (the buffer is lost when an edge node reboots).
- The backend enriches the record (adding the customer's `resource_id` from its own database by `host`, for instance).

The product contract:

- Delivery does not block the request's hot path on the proxy.
- If the telemetry sink is unavailable, logs are not lost (the backend buffers them until it recovers; the buffer is persistent).
- If the proxy cannot reach the backend, it has a local in-memory buffer covering a short window (seconds to minutes). Nothing is lost during brief backend outages. During a prolonged one (the buffer overflows) the oldest records are dropped — processing requests takes priority, and the hot path must not suffer for the sake of logs. A metric for "the share of logs lost on the proxy" alerts if losses become regular.

#### Catalog and policy updates (triggered by a customer or by product)

These are the routine day-to-day configuration changes. They all travel the same catalog delivery channel as the continuous processes — only the source of the change differs.

**A per-resource policy change** *(triggered by the customer in the dashboard).* The customer adjusted Strictness, added a custom UA pattern, added an ASN to the blocklist, toggled `attack_mode` for their domain. The flow: the dashboard → the backend API → a write to the database → the `policy` catalog is refreshed → the change applies on the proxies within 30 seconds. With no redeploy.

**Curating the shared catalogs** *(triggered by product through a PR).* Product regularly reviews the analytics and updates the catalogs shared by all customers: a new fingerprint added to `tls_fp_blocklist`, `tls_fp_catalog` extended with automation signatures, `ua_blacklist`/`ip_blocklist`/`asn_datacenters`/`tls_fp_browser_profiles` updated. A PR to our repo → merge → the backend refreshes the catalog → it applies on the proxies within 15 minutes.

New patterns (which may produce false positives on legitimate traffic) are added through staged rollout: first a PR with `staging` status (the pattern matches and is logged but does not block), then observation from the logs, then a separate PR promoting it to `active`. See "Staged rollout for PR catalogs" in Configuration.

**A catalog rollback** *(triggered by product when something went wrong).* A recent PR turned out to be bad (mass false positives after publication — for example a fingerprint shared by every Chrome landed in `tls_fp_blocklist`). The cure:

1. Product reverts the PR in the catalog repository.
2. The backend (the source of truth) rebuilds its version of the catalog — effectively returning to the previous state.
3. The proxies (which hold a local replica of the catalog in memory for the hot path) pull the reverted version from the backend within 15 minutes and atomically swap the shared_dict.
4. From that moment every new request on the proxy matches against the old, working version — the incident is over.

No manual operations on the proxies or in the database — the atomic data swap works in either direction.

#### Emergency levers (out-of-the-ordinary situations)

**The attack mode toggle.** The customer enables "Under Attack" for their domain in the dashboard (per host; there is no pool-wide toggle) — the record lands in `policy[host].attack_mode=true` → it applies on the proxies within 30 seconds. From then on, every request to that domain that reaches L5 goes through stage 5.3 (a challenge for browsers, a block for non-browser and unchallengeable clients). The cookie verify at L2.1 is skipped for that host; verified search bots and the IP whitelist keep fastpathing.

**The kill switch.** Two toggles always live on every proxy:

- **The per-stage kill switch** — disables one cascade stage (only the `tls_fp` layer, say) when a bug or a performance problem is found in it. The rest of the cascade keeps working.
- **The global kill switch** — disables the whole cascade; the Lua module becomes a no-op and traffic bypasses the checks (there are no antibot logs). Insurance against a catastrophe in the cascade itself.

**Who flips it.** The kill switch is an infrastructure-level operational mechanism, and the operator is always an admin. The Bot & Abuse Controls product team has no self-service button — during an incident the antibot team escalates to the admins with a description of exactly what to disable. A decision that protects or disables the whole pool has to go through the people responsible for the infrastructure.

**How it is delivered.** Channel A — Puppet (see the "Configuration" section). A change to `defaults.conf` → a Puppet run across the pool → an nginx reload. The SLA is as fast as the admin team can run the procedure.

**When to use it:**

- A regression in the cascade's logic after a release (a bug in Lua, not in the data) — the per-stage kill switch for the affected layer while we ship a hotfix.
- A performance degradation on a specific layer (CPU or latency grew after rolling out a new layer) — per-stage until it is investigated.
- A mass inadequate reaction whose source cannot be localised in reasonable time — the global kill switch: unblock the customers and investigate the logs at a calm pace.
- A catastrophic failure (Lua crashing workers, OOM, an infinite loop) — the global kill switch immediately.
- Planned maintenance (a major rollout, a catalog format migration) — global, for the planned window.

Bot protection must not take customers' sites down: if something goes badly wrong, we switch ourselves off rather than blocking ordinary traffic.

---

## Architecture — where everything lives

Three execution components, cleanly separated. Fundamentally: the entire hot path is on the proxy. The backend takes no part in processing an individual request.

### The proxy — THE WHOLE CASCADE

**What the proxy does on every request:**

- L1 Hygiene (the method, the UA blacklist)
- L2 Reputation (the cookie verify, the verified-bot lookup, the IP whitelist/blocklist, ASN, geo)
- L3 Identity (computing the TLS fingerprint plus the catalog checks)
- L4 Behavioural rate limits (sliding-window counters, locally)
- L5 Active verification (serving the challenge page, checking the JS task, signing the cookie)
- Assembling the final JSON log and sending it asynchronously to the backend

All the data needed for the decisions is already prepared in the proxy's local memory. Not a single network call to the backend per request. The HMAC secret for signing and verifying the cookie also sits on the proxy.

**What is not on the proxy:** none of our Go processes, no sidecar, nothing "next to nginx". Only the Lua cascade inside nginx itself.

**Area of responsibility:** the admins.

### The antibot backend — CATALOGS, LOGS AND rDNS ONLY

**What it is:** a service deployed on our infrastructure. Not on the proxy. Not on the hot path. The proxy can fail to reach it for an arbitrarily long time (fail-stale on the last catalogs).

**Three functions, nothing more:**

1. **The catalog server.** It stores every catalog (`tls_fp_blocklist`, `tls_fp_catalog`, `ua_blacklist`, `ip_blocklist`, `ip_whitelist`, `asn_datacenters`, `tls_fp_browser_profiles`, `bot_verification_status`, `policy`) and supplies them to the proxies. The product contract: a change applies within ≤ 30 s for the fast catalogs (`policy`, `bot_verification_status`) and ≤ 15 min for the PR catalogs (everything else); the swap is atomic with no traffic loss; the proxy fails stale when the backend is unavailable. The concrete mechanism (the database, the delivery protocol, caching) is the backend team's call.
2. **The log receiver.** It accepts the stream of JSON lines from the proxies, validates it, batches it and sends it to the telemetry sink (ClickHouse, or whatever we choose). An internal disk queue covers the case where telemetry is down — logs are not lost.
3. **The rDNS worker.** The backend's only active computational task. A background goroutine checks IPs with search engine UAs through `PTR + forward DNS` and publishes the result (`verified` or `rejected`) into the `bot_verification_status` catalog. The proxy uses that at L2.2: `verified` is a full fastpath, `rejected` is ordinary processing, and absent is a provisional fastpath (see stage 2.2). Not on the hot path.
  **The end-to-end SLA is best effort, with no strict number.** "The time from the first pending request from a new IP to the publication of a final verified/rejected in the catalog" is typically seconds to minutes, but there is no strict product SLA. Protection against a late check is already built into the design: the provisional fastpath does not block traffic while the status is unknown. If the worker degrades, that shows up as a rising share of `bot_verified_pending` in the logs and is alerted on through operational metrics.
   The dedup and retry semantics for the worker (how to deduplicate IPs in the queue, what to do with NXDOMAIN / SERVFAIL / a timeout, the retry policy) are the backend team's call.

**What the backend does NOT have in v1:**

- Per-request scoring (the grey-verdict callouts, §C2 of the RFC) — unused
- ML / heavy analytics
- Per-request verification of anything — it all happens on the proxy

**Area of responsibility:** the backend team.

### The customer dashboard

**What it is:** the platform's customer portal — a component external to the antibot.

**What we add for Bot & Abuse Controls:** a resource settings page (Challenge / Rate Limit Rules / Bot Lists / ASN Blocking) and analytics widgets. The detailed UI design is a separate task and is not covered in this document.

**What it does:** it edits the per-resource policy through its own API. The changes land in the backend database → the `policy` catalog → and apply on the proxies within 30 seconds.

**Area of responsibility:** the frontend team.

---

## Configuration — the two-channel model

Two independent delivery channels, with different rhythms.

### Channel A — Puppet (the framework, slow)

It carries:

- The cascade's Lua source files (`verdict.lua`, `ja4_helpers.lua`, `log_emitter.lua` and so on)
- The nginx configuration sections registering the cascade's hooks and the local storage for the catalogs
- The kill switch config (global and per stage)
- **The HTML+JS template of the challenge page** — a static asset the proxy serves when issuing a challenge; it changes rarely and its version is kept in step with the Lua cascade
- **The HMAC secret for the clearance cookie** — shared across the pool, loaded into the proxy when nginx starts; rotation is a new version through a PR plus an nginx reload, and it invalidates every previously issued cookie at once

It carries no binaries (there are none on the proxy — no antibot runtime processes beyond nginx with Lua itself).

The rhythm: a PR to the edge's puppet repo → review → a Puppet agent run on the edge nodes. Minutes to hours. That is fine — the framework does not change per request or per customer.

The failure mode: if the Puppet agent fails on an edge node, that node keeps the previous version of the framework. `nginx -t` blocks broken configs before a reload.

### Channel C — catalogs from the backend to the proxy (runtime data, fast)

It carries everything that can change without a redeploy: blocklists, the per-resource policy, attack_mode, verified-bot IPs.

**The product contract:**

- A change applies on the proxies within no more than 30 seconds for the fast catalogs (`policy`, `bot_verification_status`) and no more than 15 minutes for the PR catalogs (`tls_fp_blocklist`, `tls_fp_catalog`, `ua_blacklist`, `ip_blocklist`/`ip_whitelist`, `asn_datacenters`, `tls_fp_browser_profiles`) — counted from the change in the backend or the PR merge.
- Replacing the data on the proxy is atomic, with no locks and no traffic loss.
- If the backend is unavailable, the proxy keeps working from the last successfully loaded copy of the catalog for as long as necessary (fail-stale). A client's request never waits for an update.
- **A broken catalog from the backend → fail-stale on the last working version.** If the backend sent a catalog that fails the proxy's validation (a broken schema, an incomplete field set, obviously bad data — a million entries instead of the expected thousands, say), the proxy must NOT apply it. It keeps working from the last successfully validated copy and increments a "rejected catalog updates" metric; the backend team sees an alert.
- **Cold start (the proxy has just started and the catalogs have not been pulled yet).** In the window between nginx starting and the first successful catalog load from the backend, the cascade works in "let through and log" mode: the request bypasses the checks into the standard CDN flow, and the log records a special stage=`cold_start`, verdict=`pass`. That window is milliseconds to tens of seconds and is acceptable from a product standpoint. The alternative (waiting synchronously for the catalogs to load) makes service startup worse during backend incidents.
- A staleness metric alerts when the delay exceeds the corresponding SLA.
- **The per-host policy is delivered as deltas.** The `policy` catalog is a map `host → policy_json` with potentially tens of thousands of entries. When one host's policy changes, the backend publishes only that entry (or a small batch of recently changed ones) and the proxy applies the delta into its shared_dict — with no full re-publication of the whole catalog. That guarantees that one customer's change is not delayed by the catalog's size, and that one host's bad entry does not block the propagation of the rest. The PR catalogs stay monolithic (they are smaller and change less often).
- **Cross-proxy consistency is eventual, within the SLA window.** Inside the SLA window (≤30 s for the fast catalogs, ≤15 min for the PR ones) different proxies in the pool may see different catalog versions — that is acceptable and by design. Strict "all proxies at once" atomicity is not required. After the SLA window every proxy holds the same version. The practical consequence: after a customer clicks in the dashboard there can be a brief phase where the same IP is blocked on some proxies and fastpathed on others; within 30 seconds the state converges.

The concrete mechanism (a pull timer from the proxy / a push from the backend / SSE / anything else; HTTP/gRPC/something else; ETag/a version vector/something else) is the team's call.

### Which catalogs exist and what is in them

The full list of what the backend has to supply to the proxy. Each catalog is a named data set, updated and applied independently.

| Catalog | What is inside | Who populates it | At which stage it is used | When it is updated |
| --- | --- | --- | --- | --- |
| `policy` | A map `host → policy_json`. For every protected domain: `mode` (shadow/active), `strictness` (standard/permissive), the list of custom UA regexes, the list of custom ASN blocks, the list of custom rate rules, the `attack_mode` flag (meaningful only under mode=active), and the IP whitelist of legitimate server-side integrations. | The customer dashboard → the backend API → a write to the database. | Everywhere there is per-resource behaviour: 2.3 (the IP whitelist), 2.5 (the custom ASN block), 2.6 (geo), stage 4 (custom rate rules), 5.1 (strictness), 5.3 (attack_mode). | On every change in the dashboard. |
| `tls_fp_blocklist` | A set of TLS fingerprints explicitly marked as bots. | Product, through PRs (based on analytics). | Stage 3 (L3 TLS fingerprint), the rule `tls_fp_blocklist`. | On merging a PR that changes this catalog. |
| `tls_fp_catalog` | A map `hash_b → automation family` (curl, python-requests, Go-http-client, okhttp). Needed for impersonator detection. | Product, through PRs. | Stage 3, the rule `tls_fp_impersonator`. | On merging a PR that changes this catalog. |
| `tls_fp_browser_profiles` | A map `browser_family → expected cipher_cnt` (chrome: 15, firefox: 16, safari: 20). Updated as new browser versions appear. | Product, through PRs. | Stage 3, the rule `tls_fp_suspicious_ciphers`. | On merging a PR that changes this catalog. |
| `ua_blacklist` | The global set of UA patterns (automation, known bad bots, scanners, scrapers). It ships empty and is populated by product through PRs as patterns become visible in the logs. The concrete format is the backend's business (a combined regex, or otherwise). | Product, through PRs based on log analysis. | Stage 1 (Hygiene), the rule `ua_blacklist`. | On merging a PR that changes this catalog. Until it is populated, the rule blocks nobody. |
| `ip_blocklist` | A set of IPs/CIDRs explicitly marked as bots. | Product, through PRs (based on analytics or complaints). | Stage 2.4, the rule `ip_blocklist`. | On merging a PR that changes this catalog. |
| `ip_whitelist` *(system)* | A set of IPs/CIDRs of our monitoring, check services and trusted system clients. This is the shared catalog; do not confuse it with the customer's per-resource IP whitelist, which lives in `policy`. | The internal team, through PRs. | Stage 2.3. | On merging a PR that changes this catalog. |
| `asn_datacenters` | A set of ASN numbers of large public datacenters (Hetzner, OVH, DigitalOcean, AWS, GCP, Azure). | Product, through PRs (stable, rarely changed). | The L2 informational tag `reputation:asn_dc` (not a rule, it emits no verdict). | On merging a PR that changes this catalog. |
| `bot_verification_status` | A map `ip → {status: verified \| rejected, bot_family, verified_at}`. Three states for every IP with a search engine UA: `verified` (TTL ~1 hour), `rejected` (TTL ~1 hour), absent (the provisional fastpath at L2.2). | The background rDNS worker on the backend, triggered by the log stream from the proxies. | Stage 2.2, the rules `bot_verified` / `bot_verified_pending`. | As the worker publishes results. |

All these catalogs are read-only on the proxy side. The proxy never writes to a catalog. The data flow: a PR or the dashboard → the backend's database → delivery to the proxy → the cascade reads locally on the proxy.

`attack_mode` is per host only. There is no global "attack_mode for the whole pool" toggle; it is enabled separately for each domain through `policy[host].attack_mode=true`. For an infrastructure-level attack affecting the whole pool we have the kill switch (see below) and escalation to the edge admins — that is not attack_mode's job.

### Staged rollout for PR catalogs

**The problem.** Some PR catalogs contain patterns (UA regexes, fingerprint signatures, cipher counts) that can produce false positives on legitimate traffic. If product adds a new UA regex through a PR and 15 minutes later it reaches the proxies, it immediately starts blocking every customer in `mode=active`. If the pattern turned out to be too broad and touched a legitimate browser, that is a mass false positive across paying customers all at once.

**The solution — a staging status for patterns.** Every catalog entry has a `status` field with two values:

- `staging` — the pattern is loaded on the proxy, the proxy matches it and logs the hit (in a dedicated field, for example `staging_match: ["ua_blacklist:pattern_123"]`), but it never leads to `verdict=block`, even in `mode=active`. So such a request's verdict in the log stays what it would have been without that pattern. In effect the request continues through the cascade as usual.
**The `pattern_id` format** — a stable identifier for a catalog entry that product specifies in the PR. The convention per catalog:
  - `ip_blocklist`, `ip_whitelist` — `pattern_id` is the IP/CIDR itself (`ip_blocklist:192.0.2.5`, `ip_whitelist:10.0.1.0/24`).
  - `ua_blacklist` — `pattern_id` is a human-readable ID (product writes it in the PR, for example `ua_blacklist:scrapy_v2_2026_05`).
  - `tls_fp_blocklist` — `pattern_id` is the fingerprint token itself (`tls_fp_blocklist:L1300_a8b9c..._d4e5f...`).
  - `tls_fp_catalog` — `pattern_id` is the `hash_b` entry (the same hash_b as in the catalog).
  - `tls_fp_browser_profiles` — `pattern_id` is the `browser_family` (`tls_fp_browser_profiles:chrome`).
  - `asn_datacenters` — `pattern_id` is the ASN number itself (`asn_datacenters:AS16509`).
  The backend guarantees that a `pattern_id` is stable across catalog releases (the same pattern → the same ID).
- `active` — the pattern works fully: a match → `verdict=block` in `mode=active`, exactly as today.

**The product workflow for adding a new pattern:**

1. **A PR with the pattern in `staging`.** Fifteen minutes and the pattern has reached the proxies.
2. **Observation from the logs.** How many times the new pattern fired (`staging_match`), on which customers, with what traffic profile, and whether it looks genuinely bad or like a false positive.
3. **A decision from the results:**
  - An acceptable false-positive rate → a separate PR moving the pattern from `staging` to `active`. Another 15 minutes and the pattern starts blocking.
  - A high false-positive rate → revert the PR from step 1. The pattern disappears from the proxies.

**Which catalogs support staged rollout:**

| Catalog | Staging | Why |
| --- | --- | --- |
| `ua_blacklist` | ✅ | A new UA regex can touch a legitimate browser or SDK |
| `ip_blocklist` | ✅ | A new IP can turn out to be a legitimate API client |
| `tls_fp_blocklist` | ✅ | A new fingerprint can turn out to be a new version of a real browser |
| `tls_fp_catalog` | ✅ | A new impersonator signature can falsely match a browser |
| `tls_fp_browser_profiles` | ✅ | Changing the expected cipher_cnt can touch current browsers |
| `asn_datacenters` | ❌ | It feeds the informational `reputation:asn_dc` tag, not a rule. The tag does not block, so staged rollout is unnecessary. |
| `ip_whitelist` (system) | ❌ | A whitelist lets through rather than blocking — low risk |
| `policy` (per resource) | ❌ | The customer tests it themselves with a temporary `mode=shadow` for their resource |
| `bot_verification_status` | ❌ | Not a pattern (it is populated automatically by the rDNS worker) |

**Logging semantics on a staging match:**

The request goes through the cascade as usual — a staging pattern does NOT interrupt the flow, does NOT block and does NOT affect the `verdict`. But the log gains an additional `staging_match` field listing the staging patterns that fired:

```json
{
  "verdict": "pass",
  "rule": "",
  "staging_match": [
    "ua_blacklist:new_pattern_2026_05_18",
    "tls_fp_blocklist:fp_L13d11h2_xxx"
  ],
  ...
}
```

That lets product build analytics from the logs: "the new pattern `ua_blacklist:new_pattern_2026_05_18` matched N times over a day, X of them on paying customers, a ratio of Y% against their total traffic" — and make an informed promotion decision.

**What staged rollout does not cover:**

- **Very rare patterns** (firing once a week) — a day of observation may yield no statistics at all. Here product decides from confidence in the pattern's source rather than from statistics.
- **Per-resource situations** — staging applies globally. If a pattern produces false positives for one specific customer only, that is visible in the logs and the customer can add an exclusion to their `policy` (a custom whitelist), but staging itself does not separate that case.

### The lookup key is the Host, not a resource_id

The request's `Host` is available directly on the proxy (from the HTTP header). The `policy` catalog is a map `host → policy_json`. The lookup is trivial and needs no additional `Host → resource_id` map on top.

### What is NOT a catalog

**Rate counters, the verdict cache and the TLS fingerprint cache** are local per-proxy state: they live only in each proxy's memory and are never centralised. The rule is simple: if every proxy should see the same value at the same moment → a catalog. If it is per-proxy runtime state → local to the proxy, never published as a catalog.

---

## Roadmap

| Phase | What | Status | Actions | Who |
| --- | --- | --- | --- | --- |
| **Phase 1** | An observe-only cascade, L1–L2 plus L4 (no TLS fingerprint, no active verification). Logs into the telemetry sink. | In flight | We observe and block nothing. We calibrate the thresholds from the logs. | the edge admins (per the Phase 1 spec) |
| **Phase 2** | L3 is added — the TLS fingerprint on top of the cascade. Observe-only, like Phase 1. | In flight | The same logs plus tls_fp, and new tags in the `tags` field with the `tls_fp:*` namespace. We populate the fingerprint catalog and the blocklist through PRs. | the edge admins (per the Phase 2 spec) |
| **Phase 3** | The antibot backend plus catalog HTTP plus the dashboard. The per-resource policy over Channel C. The backend's rDNS worker populates the `bot_verification_status` catalog (the verified-bot allowlist at L2 becomes genuinely operational; until then the catalog is empty). Still shadow by default. | Next | The backend, the dashboard UI, migrating Lua from local configs to pulling from the catalog. | the backend and frontend teams plus the edge admins (per the integration spec) |
| **Phase 4** | L5 active verification implemented: issuing the JS challenge, the clearance cookie HMAC verify and Under Attack mode. Additional artifacts are delivered to the proxy over Channel A: the HMAC secret and the HTML+JS template of the challenge page. Technical readiness for enforcement mode. | Future | Real physical actions for the first time — but only for pilot customers in `mode=active` (enabled by the team by hand for a shakedown). Free and non-pilot customers stay in shadow. | the same |
| **Phase 5** | Opening mode=active to everyone who wants it, and monetisation. It starts after Phase 4 has been proven on the pilots, the product has been tested and the decision to hand it to customers has been made. It is not tied to a calendar date — the gate is readiness plus a product decision. | Future | Billing, marketing, support for switching, an SLA on the team's response. | product plus billing plus support |
| **v2** | A globally exact rate limit (cross-proxy shared storage), HTTP/2 fingerprinting, extended TLS coverage. | Out of scope for v1 | — | — |
| **A different product** | L6/L7 — behavioural ML over sessions, a mouse/timing beacon. | Out of scope | — | — |

**The key thing to understand about the phases:** enforcement mode is switched on in step with the per-resource `mode=active/shadow`. Enabling enforce globally without that separation is impossible — it would affect every customer at once, free ones included. So Phase 4 is impossible without Phase 3, and Phase 5 is a product decision about a commercial launch rather than the next technical step.

---

## Technical guarantees and limitations

### Latency

- **The verdict pipeline on the proxy:** ~µs to tens of µs (the HMAC verify, a shared_dict lookup, GCRA).
- **The catalog pull:** in the background, off the hot path. The proxy does not block request processing on a pull.
- **The challenge (L5):** 1–3 seconds in the browser to execute the JS task.

### False positives

The JS challenge can misfire on:

- Headless browsers in legitimate scenarios (e2e tests, uptime monitoring)
- Corporate proxies that modify headers
- Very old browsers with no Canvas / WebGL support

The TLS fingerprint impersonator rule can misfire on:

- New browser versions with an updated TLS stack (the cipher_cnt shifted) — until `tls_fp_browser_profiles` is updated
- Corporate proxies with their own TLS stack

The cure: switch Strictness to Permissive (system soft flags then do not trigger a challenge), and add the customer's IP or fingerprint to the per-resource whitelist.

### Availability

**The proxy:** if our cascade code fell over (a bug, an exception while processing a request), the global kill switch disables the whole cascade and traffic bypasses the checks.

**The antibot backend:** if it is unavailable, the proxy keeps working from the last good catalog (fail-stale). Staleness metrics provide alerting. Two or more backend instances make this mode rare.

**The proxy → backend network:** an interrupted connection is the same fail-stale. No effect on the hot path.

### Data

IP addresses, User-Agents, TLS fingerprints and request metadata are processed in memory on the proxy. They are not stored on the proxy long term. The clearance cookie lives only in the user's browser.

Logs travel to the backend → the telemetry sink (ClickHouse or equivalent), and are retained per the retention policy.

The browser fingerprint collected during the JS challenge (User-Agent, screen resolution, Canvas, WebGL, AudioContext) is checked for consistency at the moment the challenge is passed, and then travels to the backend as part of the challenge-pass event and is stored in the same telemetry. It is not used to verify subsequent requests (the clearance cookie does that job) nor to track users across sites — after the consistency check it is collected as a dataset for long-term analytics and future ML models (L6, out of scope for v1).

---

## Comparison with Cloudflare

| Capability | Bot & Abuse Controls | Cloudflare Free | Cloudflare Pro+ |
| --- | --- | --- | --- |
| A JS challenge with a clearance cookie | ✅ | ✅ | ✅ |
| TLS fingerprinting | ✅ | ❌ | ✅ |
| Per-path rate limiting | ✅ | ❌ | ✅ |
| A verified-bot allowlist (reverse DNS) | ✅ | ✅ | ✅ |
| A curated bad-bot blocklist | ✅ | ✅ | ✅ |
| ASN blocking | ✅ | ✅ | ✅ |
| Under Attack mode | ✅ | ✅ | ✅ |
| Headless browser detection | ❌ | ❌ | ✅ |
| Behavioural session analysis | ❌ | ❌ | ✅ |

---

## Team responsibilities (for handover)

| Team | What they do | Input artifacts |
| --- | --- | --- |
| **The admins** | Implementing the Lua cascade, integrating it into their nginx config on the edge pool, maintaining the configs through Puppet/Salt, enriching the logs with TLS fields | The Phase 1 spec (ready), the Phase 2 spec (ready), the integration spec for the pull channel (to be written as part of Phase 3) |
| **The backend team** | The antibot backend: the catalog store and its delivery to the proxies (the mechanism is the team's choice, the product contract is in the "Channel C" section), the background rDNS worker, the log receiver, HA, deployment | This document plus the catalog contract spec (TBD, as the first Phase 3 artifact) |
| **The frontend team** | The per-resource policy UI (Strictness, rate rules, ASN, custom UA, the attack_mode toggle) and analytics | This document plus the page design (mockup TBD) |
| **Product** | The default policies, populating the fingerprint catalog and the UA blacklist through PRs, calibrating the thresholds from the logs, acceptance | This document as the reference point |

---

## What is explicitly out of v1, and why

Recorded here so that nobody expects otherwise:

- **Headless browser detection (L6+).** It needs a JS beacon with behavioural signals (mouse, timing) — a different product.
- **Residential proxy detection.** The traffic comes from legitimate home IPs and differs only in behaviour — that needs L6+.
- **Behavioural ML over sessions.** L6+. Out of scope for v1.
- **HTTP/2 fingerprinting.** An additional client signal — the order of SETTINGS frames, window updates, priority frames. The analogue of L3 for the HTTP/2 layer. A future task, not v1.
- **A globally exact cross-proxy rate limit.** In v1 the limits are per proxy (per worker). Global accuracy needs a Redis Cluster or equivalent — v2.
- **Per-request callouts from the proxy to the backend to compute a verdict.** v1 has no heavy or ML logic, so a per-request call from the proxy to the backend is unnecessary. If one ever appears it will require revisiting the architecture (probably adding a thin per-proxy sidecar for that layer). Not needed now.
- **Per-resource TLS fingerprint policies.** In v1 the fingerprint catalog is shared across all resources. Differentiation (a B2B API customer expects different TLS stacks than a public site) is for later iterations.
- **Automated ML verification.** All the challenge signals are manual or rule-based for now. Automatic promotion of HIGH candidates into the blocklist is a separate task with its own false-positive guarantees.
- **An API key whitelist for non-browser clients.** In v1 the only way for a customer's server-side or mobile integration to avoid the challenge is to add its IP to the IP whitelist (stage 2.3). For customers with dynamic IPs (containers, serverless, mobile apps) that is inconvenient. An API key whitelist (the customer creates a secret key in the dashboard, their integrations send it in an HTTP header, and the proxy fastpaths them) is a candidate for the next iteration. It requires: the backend (generating, storing, hashing, rotating and revoking keys), dashboard UI (creation, listing, revocation), masking the keys in logs, and customer documentation. The complexity is comparable to the policy page itself.

---

## What is new in v0.5 (changelog from v0.4)

An iteration on top of v0.4 following a discussion. The positioning, the modes and the business semantics are preserved; the contentious points are clarified, a high-level overview has been added and the terminology has been aligned across the documents.

The main points:

1. **A "Product overview" section has been added** at the start — a high-level description for colleagues: what this is, what it consists of (the proxy plus the backend), what the cascade is, what a rule and a tag mean in our terminology, the policies and the modes. Plus "who needs it" and "what it is not".
2. **`attack_mode` is per host only.** There is no longer a pool-wide toggle (for the infrastructure level there is the kill switch). Under attack, clearance cookies issued before the attack started do not fastpath (those issued during it do); verified bots and the IP whitelist do fastpath. Non-browser and protocol-incompatible requests are blocked under attack (branches B/C) rather than going to a challenge.
3. **A new `permissive` verdict.** When system soft flags are suppressed by Strictness=Permissive, the log records `verdict=permissive, rule=<the last soft flag>` — distinguishing "it passed because of Permissive" from "it passed because it was clean".
4. **`should_challenge()` is described as a function computed at L5** (from attack_mode plus the accumulated flags plus Strictness), not as a stored flag.
5. **A new `unchallengeable_request` rule** (branch C): the request is protocol-incompatible with a JS challenge (not a GET, a WebSocket, an `Accept` without `text/html`).
6. **A new `hygiene:header_anomaly` tag** (L1): anomalous header combinations (HTTP/2 without `Accept`). Informational, it blocks nothing.
7. **Rate limits — GCRA is fixed.** Customer rate rules are checked before the system ones; the rule code `rate_custom` plus the log field `client_rule_name` (unique within a host).
8. **The clearance cookie's attributes** are stated explicitly (HttpOnly / Secure / SameSite=Lax / Path / Domain). Cross-proxy challenges through a self-signed nonce. HMAC secret rotation: scheduled through Puppet plus an emergency admin playbook. The cookie TTL is a system constant (24 h / 1 h under attack).

8b. **The `flags` log field.** The log gained an array of every challenge flag accumulated along the way (the soft rules) — separately from the terminal `rule`. It fulfils the overview's promise of "a log record with the rule, the flags and the tags" and gives analytics the co-occurrence of signals.
8a. **The clearance cookie is a partial fastpath, not a full one.** A holder of a valid cookie skips L3 (the TLS fingerprint) and L5 (the challenge) but goes through L4 (rate limits) — a cookie confers no right to abuse (brute force, scraping). A full fastpath (skipping L3-L5) remains with verified bots and the IP whitelist only. It closes the "solve one challenge → hammer rate-free for the cookie's whole TTL" hole.
9. **rDNS clarified:** `rejected` TTL 5 min → 1 h; `bot_family` for rejected is the UA-claimed one; `bot_verified_pending` fires on every request until the backend publishes a status.
10. **`resource_id`** is filled in by the backend when it ingests the log (the proxy works with `Host` alone).
11. **Scope: edge pool domains with no policy entry** run on the system defaults (shadow), and the policy is an override. The per-host policy is delivered as deltas; cross-proxy consistency is eventual within the SLA.
12. **Failure behaviour:** cold start is let-through plus a log (stage `cold_start`); a broken catalog from the backend means working from the last good version.
13. **The kill switch** is an operational mechanism of the edge admins (not a product self-service button).
14. **The related documents are aligned:** [rules-reference.md](rules-reference.md) (the flat rule catalog) and [config-templates.md](config-templates.md) (the config templates) have been added. The policy field `asn_blocklist` was renamed to `asn_block`. The backlog was synchronised on `attack_mode` and the rDNS TTL.

---

## What is new in v0.4 (changelog from v0.3)

The document iterates on top of v0.3 — the positioning, the modes and the business semantics of every feature are preserved. The main structural change: the document is now focused on the under-the-hood end-to-end traffic path (from accepting a request on the proxy to delivering it to the client from cache or from the origin) — which is what the teams need to design the backend and the proxy integration.

The customer dashboard's UI (how the customer sees their analytics, buys protection and configures Strictness) is a separate task and is not covered here. We assume the customer has already bought, their policy is in our database and it has reached the proxy.

What changed:

1. **The architecture was rethought.** v0.3 described a monolithic sidecar process on every proxy that nginx called on every request. That is obsolete. A clean separation: the proxy runs the ENTIRE L1–L5 cascade locally on every request; the antibot backend is only a source of catalogs, a log receiver and a background rDNS worker. The backend is not on the hot path. No mentions of the obsolete architecture remain in the text.
2. **A six-level protection model, L1–L6, has been added.** Previously the features were a flat list; now each one clearly belongs to a layer, and it is visible where v1's scope stops (L5) and what was left out (L6+).
3. **The "How it works" section was rewritten as an end-to-end traffic flow.** From the TLS handshake → the L1–L5 cascade → the cache lookup → the origin fetch → delivering the response → writing the log. It explicitly shows that the antibot is applied before the cache lookup, and that the edge pool is a full CDN rather than just a proxy. It describes what happens on `verdict=block/challenge` (the flow stops, 403/429/the challenge page). The scope is explicitly narrowed: we consider only traffic to protected customer domains; other traffic is the edge admins' territory.
4. **The "Features" section was removed.** Every product feature (Scoring/Strictness, rate limit presets, the JS challenge, the clearance cookie, verified bots, the bad-bot blocklist, ASN blocking, Under Attack mode, TLS fingerprinting) is described inside the corresponding cascade stage.
5. **TLS fingerprinting (Phase 2)** was added as cascade layer L3. v0.3 had no such layer.
6. **The "How it looks in the dashboard" section was removed.** The UI scope moves to a separate task; this document only notes that a dashboard exists.
7. **The "What runs in the background and in parallel" section** was gathered into one place, in three categories: continuous background processes (the catalog pull, the rDNS worker, log delivery), catalog and policy updates triggered by the customer or product (a policy change, curation, a rollback), and the emergency levers (attack mode, the kill switch). Previously all of it was scattered across sections.
8. **The phasing was explained** (Phase 1 observe-only → Phase 2 TLS fingerprint → Phase 3 backend plus dashboard → Phase 4 active verification → Phase 5 enforcement plus monetisation). v0.3 described the product as already working; now it is explicit that in Phase 1/2 the cascade only observes.
9. **Configuration — the two-channel model** (the Puppet framework plus our catalog HTTP pull). Lookup by `Host`, not by `resource_id`. It closes the open question from Phase 1.
10. **Team responsibilities** — a new dedicated section, so that the document can be handed over for review with an explicit statement of who does what.
11. **The technical section on resource consumption** was rewritten for the new topology: we run no Go processes on the proxy.
12. **The comparison with Cloudflare** gained a row about TLS fingerprinting.

What did not change:

- The positioning ("not an enterprise antibot, ~80% of typical SMB cases")
- The shadow / active modes (previously Off / Standard / Under Attack — simplified to two, plus a separate Under Attack toggle as a flag on top of active)
- The business semantics of every feature (though they moved into "How it works", each to its own layer)
- What is explicitly out of v1 (extended, but not shortened)

What was moved to other tasks:

- The customer dashboard's UI and the analytics widgets
- The feedback loops (how product calibrates thresholds from the logs, how the customer sees their analytics)

---

*Document version: v0.5 | Date: 2026-05-21 | Previous: v0.4 (2026-05-18)*
