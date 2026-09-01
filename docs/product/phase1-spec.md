# Bot & Abuse Controls — Phase 1: MVP L1–L3

## Context

The platform's proxies are the first point where customer traffic is received. The
antibot cascade has to be built into them so that we can:

1. cut off obviously bad traffic cheaply and early, before it reaches the customers'
   origins;
2. collect structured logs the product manager can use to analyse traffic, calibrate
   rules and design the customer-facing feature over the following iterations.

This is the internal MVP of the first layer. No customer portals, APIs, dashboards or
customer-facing contracts at this stage — the focus is a working cascade and good logs.
The stack is nginx plus OpenResty.

## Areas of responsibility

- **Admins** — implementing the cascade in nginx/OpenResty, maintaining the configs in
  the repository, shipping structured logs to the agreed telemetry sink.
- **Product manager** — framing the task, the default policies, maintaining the configs
  through PRs, log analysis, feedback on the rules, acceptance.
- **Development** — not involved at this stage.

## What matters about the MVP frame

- Customers see and receive nothing: no portal, no metrics, no new origin behaviour.
  From a customer's point of view everything is as it was.
- No per-resource policies. The cascade applies one shared policy to all traffic.
  Differentiation is the next iteration.
- No external feeds and no central services. Everything is local to the proxy: static
  lists, GeoIP/ASN databases, shared dicts.
- **In the MVP the cascade only observes, it blocks nothing.** Every rule fires and
  records the fact in the logs, but nothing physically happens to the request — it always
  reaches the customer's origin. Real blocking arrives in the next iteration, together
  with the per-resource business mode (see "Out of scope").
- The main output of the MVP is logs, not actions. Actions are enabled selectively, once
  the logs justify them.

## Open questions for the admins (before we start)

- **The telemetry sink** — where to send the structured log stream: which service and
  format is already in use, or whether something new has to be stood up.

## Concept: rules, categories, logs

**In the MVP the cascade only observes, it blocks nothing.** Every rule fires and the
hits are written to the logs, but nothing physically happens to the request — it goes to
the customer's origin as usual. This is a deliberate limitation: without a per-resource
business mode, switching on real blocking would affect every customer at once, which is
not what the MVP needs.

Every rule has a category, defined by the structure of the config section it lives in;
no separate attribute is needed:

- **Blocking** (most of them: `method_not_allowed`, `ip_blocklist`, `geo_blocklist`,
  `rate_ip`, `rate_api`, `rate_scan_urls`) — in a future iteration, once enforcement
  mode exists, these will block the request (429 with Retry-After for rate limits, 403
  for the rest). They log `verdict=block`.
- **Allow** (`ip_whitelist`) — in a future enforcement mode these give a fastpath: the
  request is let through and the remaining stages are skipped. They log `verdict=allow`.
- **Soft** — in the future these will issue a challenge or verification (not a hard
  block). They log `verdict=challenge`, which is critical so that analytics can tell "we
  would have blocked hard" from "we would have sent it to verification".

In the MVP the category distinction is metadata for analytics: the logs show exactly
which action would have fired had the cascade been in enforcement mode. We calibrate the
rules and thresholds from that data.

Each request produces one final log record with two key fields:

- `verdict` — the decision of the final rule that fired: `pass | block | challenge |
  allow`. This is a hypothetical decision: in the MVP it leads to no physical action and
  is simply recorded.
- `rule` — the code of that final rule (empty when `verdict=pass`).

If several rules fired along the way (for example the informational tag
`reputation:asn_dc` at the reputation stage and then `rate_ip` at rate_limits), the log
records only the final one (`verdict=block, rule=rate_ip`). Informational tags, on the
other hand, all accumulate and land in the `tags` field.

**Actual physical behaviour in the MVP:** always pass-through — every request reaches
the customer's origin. The `verdict` field shows "what would have happened had the
cascade been running in enforcement mode".

**Schema forward compatibility.** The log schema and the enums are stable across
iterations: when new stages, verdicts and fields are added in Phase 2+, the existing
codes are not renamed and do not shift. Specifically:

- The `stage` enum may gain `tls_fp` (Phase 2), `verification` (Phase 4) and
  `cold_start` (Phase 3, once Channel C exists).
- The `verdict` enum may gain `permissive` (Phase 4, once the customer-facing
  Strictness=Permissive exists).
- The optional fields `rule_source`, `client_rule_name`, `staging_match` and `flags` may
  appear in Phase 2/3 — Phase 1 does not write them (there are no soft rules to populate
  `flags` in Phase 1).

## The four-stage cascade

Every request goes through the cascade, which is built on a "cheapest first" principle:
the lighter the check, the earlier it runs. At each stage the log records the `verdict`
and the rule that fired.

### Stage `hygiene` (resource identification and basic hygiene)

**Signals:**

- The `Host` determines the `resource_id` (the DNS+CDN resource in the platform the
  domain is attached to) through the platform's internal mapping; how it is obtained is
  up to the admins. If the domain is attached to no resource (including the case where
  there is no Host header at all), the request never enters the cascade and its further
  fate is out of scope for this task.
- A method outside the whitelist (default: `GET, HEAD, POST, OPTIONS`) → the rule
  `method_not_allowed` (blocking).
- The User-Agent matches the blacklist of bad UA patterns → the rule `ua_blacklist`
  (blocking). The list is empty at launch and is populated through PRs based on analysis
  of the top UAs in the logs. The rule itself is wired into the config so that it can be
  switched on without rework. Future sources of patterns (once the backend exists in
  Phase 3): automation (curl, wget, python-requests), known bad bots (AhrefsBot,
  SemrushBot, sqlmap, nikto), scrapers — but all of it is filled in reactively from the
  logs, not hardcoded at launch.
- Header sanity → the informational tag `hygiene:header_anomaly`, not a rule. It checks
  for header combinations a real browser never sends but lazy automation does (the base
  case: an HTTP/2 request with no `Accept` header). It emits no verdict and blocks
  nothing — it goes into the log's `tags` field. It catches bots with a browser-faked UA
  but an unrealistic header set (which a UA blacklist would miss). Header heuristics
  easily produce false positives on unusual but legitimate clients, which is why this is
  a tag rather than a block: it does not affect the verdict and only accumulates in
  `tags` for analytics.

**Where the data comes from:** the config; for header sanity, checks on the request
headers in Lua.

**Examples:**

- A browser UA and a normal Host for a customer resource → `verdict=pass`.
- `TRACE /admin HTTP/1.1` on a normal Host → `verdict=block, rule=method_not_allowed`
  (the request still physically reaches the origin — there is no blocking in the MVP).

### Stage `reputation` (source reputation)

**Signals:**

- The IP or subnet is in the whitelist (monitoring, check services) → the rule
  `ip_whitelist` (category `allow`). In a future enforcement mode this is a fastpath and
  the remaining stages are skipped. In the MVP the log records
  `verdict=allow, rule=ip_whitelist` and the cascade continues (no fastpath is physically
  applied).
- The IP or subnet is in the blocklist → the rule `ip_blocklist` (blocking).
- The ASN is a datacenter (Hetzner, OVH, DigitalOcean, AWS, GCP, Azure) → the
  informational tag `reputation:asn_dc`, not a rule. It emits no verdict, blocks nothing
  and triggers no challenge. It is simply written into the log's `tags` field and used
  for analytics (the share of traffic from datacenters); it does not affect the verdict.
- The geography is outside the shared list of allowed regions (when one is set) → the
  rule `geo_blocklist` (blocking).

**Where the data comes from:** static lists in the config, MaxMind GeoIP/ASN.

**Suitable OpenResty mechanisms:** `lua-resty-ipmatcher`, `shared dict`.

### Stage `rate_limits` (behavioural limits)

**Sliding window semantics — GCRA.** The sliding counters are implemented as GCRA (the
generic cell rate algorithm), a compact sliding-window implementation that stores no
per-request timestamps. One 64-bit state cell per key, updated in a single arithmetic
operation. That matters at hundreds of thousands of distinct keys per edge node — a
naive implementation holding a list of timestamps in a shared_dict does not scale. The
concrete mechanism is either `lua-resty-limit-req` (already GCRA-based) or an
implementation of our own on top of `shared_dict`, at the admins' discretion.

**Why two windows.** One window does not cover the picture:

- The short one alone (10 s) misses "slow" scrapers that sit just below the burst
  threshold for hours and drain the whole catalog over a day. Every 10 seconds their
  counter looks healthy, while the cumulative pressure is anomalous.
- The long one alone (1 min) misses sharp spikes: a bot manages 500 requests in 5
  seconds and leaves without reaching the per-minute threshold.

So we count over both windows in parallel: a rule fires if either window is exceeded.
The short one (10 s) catches bursts, the long one (1 min) catches sustained pressure.

A sliding window means the counter is recomputed continuously rather than reset at a
minute boundary. When a request arrives, we take the interval "the last 60 seconds from
now", not "since the start of the minute". That removes the classic vulnerability of
fixed-bucket limiters: an attacker cannot deliberately place 2×limit requests across the
seam of two buckets and formally stay within the limit.

Both windows apply to every profile, independently. The thresholds below are starting
values, deliberately high; we calibrate them from the logs.

**Profiles and starting thresholds** (deliberately high; the goal is to gather the
distribution in the logs and lower them from data — if the admins have an estimate of
current load, we use theirs):

| Profile | Key | 10 s window | 1 min window | Rule code | Category |
| --- | --- | --- | --- | --- | --- |
| General per IP | IP | 100 req | 600 req | `rate_ip` | blocking |
| per IP+UA | IP+UA | 100 req | 600 req | `rate_ip_ua` | blocking |
| API endpoints | IP | 50 req | 300 req | `rate_api` | blocking |
| Unique-URL scan | IP | 50 unique URLs | 200 unique URLs | `rate_scan_urls` | blocking |

Why `rate_scan_urls` is blocking rather than soft: legitimate search crawlers
(Googlebot, Bingbot, Yandex) will not pass a JS challenge — they are headless HTTP
clients. The right way to protect legitimate crawlers is a separate feature (a whitelist
by IP / reverse DNS), which this MVP does not have. Until it exists — when enforcement
mode arrives — `rate_scan_urls` must be enabled with particular care so as not to hurt
SEO.

Which endpoints count as "API" is set in `defaults.conf` (path patterns).

In a future enforcement mode, exceeding a limit will return `429 Too Many Requests` with
`Retry-After`, not a 5xx. In the MVP it is only a `verdict=block` log record.

**Suitable OpenResty mechanisms:** `lua-resty-limit-req` / `lua-resty-limit-count`,
`shared dict`.

### Stage `egress` (passing through to the customer's origin)

The request goes to the origin as before. This MVP adds no new headers towards the
origin — we do not yet want the customer to see or depend on anything new. The final log
record is composed here.

## Logging — the main deliverable of this task

One structured JSON record per request. The schema is pinned down in this task
(extending it later is fine, breaking it is not).

**Fields:**

- `request_id` — a unique request identifier.
- `timestamp` — ISO 8601 with milliseconds.
- `edge_id` — the identifier of the proxy node that handled the request (the field name
  is an inherited token; the product term is proxy).
- `resource_id` — the identifier of the (DNS+CDN) resource in the platform that the
  requested domain is attached to. It is determined proxy-side from the `Host` by
  whichever method the admins chose (in Phase 1, a local mapping; in Phase 3 the field is
  filled in by the backend, with no change to the schema). It is needed to label and
  group logs during analysis.
- `host`, `path`, `method`, `status` — the basic request parameters.
- `ip`, `asn`, `geo_country` — the source.
- `ua` — the full User-Agent.
- `stage` — the stage where processing ended. A stable string code:
  `hygiene | reputation | rate_limits | egress`. The codes are stable across iterations:
  adding new stages neither renames nor shifts the existing ones. *(Phase 2 adds
  `tls_fp`, Phase 4 adds `verification`, Phase 3 adds `cold_start` for the period before
  the catalogs are pulled from the backend.)*
- `verdict` — the hypothetical decision of the final rule that fired:
  `pass | block | challenge | allow`. In the MVP this decision leads to no physical
  action — the request always reaches the origin. The field shows "what would have
  happened had the cascade been in enforcement mode": `pass` when no rule fired; `block`
  when the final rule was a blocking one; `challenge` when the final rule was soft (we
  would have sent it to verification, not blocked it hard); `allow` when the final rule
  was of the `allow` category. *(Phase 4 adds `permissive` to the enum.)*
- `rule` — the code of the final rule that fired. Empty when `verdict=pass`.
- `latency_ms` — time spent traversing the cascade.
- `tags` — an array of informational tags with a namespace prefix (for example
  `["hygiene:header_anomaly", "reputation:asn_dc"]`). They lead to no verdict and exist
  for analytics only.

**The complete list of `rule` codes in the MVP:**

| Code | Stage | Category |
| --- | --- | --- |
| `method_not_allowed` | `hygiene` | blocking |
| `ua_blacklist` | `hygiene` | blocking (wired in, the list is empty at launch) |
| `ip_whitelist` | `reputation` | allow |
| `ip_blocklist` | `reputation` | blocking |
| `geo_blocklist` | `reputation` | blocking |
| `rate_ip` | `rate_limits` | blocking |
| `rate_ip_ua` | `rate_limits` | blocking |
| `rate_api` | `rate_limits` | blocking |
| `rate_scan_urls` | `rate_limits` | blocking |

**Log requirements:**

- Every request → exactly one final record with the full picture.
- The log stream goes to the telemetry sink (the address and format are agreed with the
  admins before we start — see "Open questions").

## Configuration

In the proxy config repository:

- `defaults.conf` — [populated] — the base cascade config, without which it does not
  start. It contains: the HTTP method whitelist, the API endpoint patterns, the
  rate-limit profiles with their thresholds, and the assignment of each rule to a
  category (blocking / allow / soft), expressed by the structure of the config sections
  rather than a separate attribute. In the MVP the cascade only observes, so there are no
  per-rule enforce switches — every rule records its hit in the log and takes no physical
  action.
- `whitelist_ip.conf` — [populated] — the IPs of our monitoring and check services,
  needed so that the corresponding rule produces meaningful hits in the logs from day
  one.
- `asn_datacenters.conf` — [populated with a baseline] — a public list of the main
  datacenter ASNs (Hetzner, OVH, DO, AWS, GCP, Azure). The list is stable and is needed
  so that the corresponding rule produces meaningful hits immediately. Supplied by
  product.
- `blocklist_ip.conf` — [empty at launch] — populated from log analysis.
- `ua_blacklist.conf` — [empty at launch] — populated through PRs based on analysis of
  the top UAs in the logs. In later phases this may hold both system automation
  signatures and a curated bad-bot list.

Changes go through a PR with product review.

**Cross-proxy consistency.** After a PR is merged, the new config version is delivered
to the proxies over Channel A — not instantly, but with the delay of a rollout across
the pool (typically minutes). During that window different edge nodes may see different
config versions, which is acceptable and by design. After the rollout window every
proxy is on the same version.

## Operations

- The defaults live in `defaults.conf`.
- In the MVP the cascade only observes — there are neither per-rule switches nor a global
  shadow/enforce toggle. Every rule always works in "fire → log → let the request
  through" mode. Enforcement mode (per-rule enforce) arrives in later iterations, in step
  with the per-resource business mode.
- A **global kill switch** for the whole cascade sits with the admins, for an incident
  with the cascade itself (a bug, a performance problem). Requests bypass it and no logs
  are written.
- Config changes (thresholds, lists, new rules) go through a PR with product review.
  They are applied without a redeploy and without losing customer traffic. The concrete
  mechanism (reload, hot reload, something else) is up to the admins.

## Acceptance criteria

1. On the stand, the cascade runs all four stages against the test requests from the
   "Examples" sections (a set will be assembled separately), and for each request exactly
   one log record appears with the expected `stage`, `verdict` and `rule`.
2. Real customer traffic behaves as before — every request reaches the customer's origin
   regardless of whether rules fired. The logs, meanwhile, correctly show `verdict=block`
   (for blocking rules), `verdict=challenge` (for soft rules) and `verdict=allow` (for
   allow rules) wherever the rules fired.
3. The log records contain the full field set from the schema and arrive at the agreed
   telemetry sink. The sink's table schema supports forward compatibility (see the
   corresponding section): an extensible enum for `verdict`/`stage`, and optional columns
   added without a migration.
4. The initial contents of `whitelist_ip.conf` and `asn_datacenters.conf` (supplied by
   product) are accepted into the repository and the proxies start the cascade with that
   data. The method of deriving `resource_id` from `Host` is agreed with the admins and
   implemented.
5. The global kill switch disables the cascade completely — all traffic bypasses the
   checks and no logs are written.

## Out of scope

Recorded here so that nobody expects otherwise:

- Per-resource policies, whitelists and blocklists.
- **Enforcement mode (physical blocking and fastpaths) and the per-resource business mode
  `shadow_mode`** — a single next task. In the MVP the cascade only observes and logs,
  with no physical actions. Moving to real blocking needs two components that only make
  sense together:
  1. Per-rule enforce — the ability to switch on real action for specific rules as they
     are calibrated.
  2. Per-resource shadow_mode — the ability to keep some customers in shadow (showing
     them analytics for free) and others in active (really blocking, after payment). This
     requires extending the platform's resource registry with an "antibot mode"
     attribute, which is a development task, not the proxy admins' responsibility.
     Without per-resource shadow_mode, any enforce switch would affect every customer at
     once, so we do not ship an enforce mechanism at all in the MVP. Onboarding paying
     customers with differentiated behaviour is impossible in the MVP — that is the next
     iteration.
- The customer portal, the settings API, customer dashboards.
- `X-Antibot-*` headers towards the customer's origin.
- External reputation feeds (residential proxies, Tor, regularly updated "known bad"
  lists).
- A central antibot service for verdicts.
- Active verification for soft rules. In the MVP such rules only record the hit in the
  logs (`verdict=challenge`, with nothing physically issued). The verification mechanism
  itself is a separate task and, most likely, a family of mechanisms for different
  classes of traffic:
  - A JS challenge with a signed cookie — for browser traffic.
  - A whitelist by IP or API key — for server-side API clients in datacenters.
  - A verified-crawler whitelist (by IP / reverse DNS for Googlebot, Bingbot, Yandex and
    so on) — for legitimate search crawlers. When enforcement mode arrives, `rate_scan_urls`
    must be enabled carefully without that whitelist, so as not to hurt SEO.
- Duplicating the cascade's data into separate Prometheus metrics proxy-side — every cut
  we need can be extracted from the structured logs in the telemetry sink.
- Checking header and body sizes ourselves — nginx already does that with its standard
  directives (`client_max_body_size` and friends), and duplicating it in the cascade is
  unnecessary.
- A ready-made `ua_blacklist`. The rule mechanism is implemented, but populating the list
  is a separate activity after the first wave of logs.
- A ready-made IP blocklist. The file is created empty and populated by a separate
  activity based on log analysis.
- Any customer communication about this feature.
