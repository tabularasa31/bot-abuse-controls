# Bot & Abuse Controls — config templates

Illustrative templates for every configuration file mentioned in [vision.md](vision.md) and the Phase 1/2 specs.

**Format:** shown as YAML with comments for readability. What matters is the data structure and the semantics of the fields, not the exact syntax.

> **The real implementation of the slow catalogs (Phase 1+, as it exists in the repo):**
> the files live in [`../../catalogs/`](../../catalogs/) (`tls_fp_blocklist.yaml`,
> `ua_blacklist.yaml`, `ip_blocklist.yaml`, `ip_whitelist.yaml`,
> `asn_datacenters.yaml`, `version`). The format differs from the illustrative
> `.conf` below: a compact YAML map `<entry>: <status>` is used
> instead of sections. The staged rollout contract (`active`/`staging`),
> the validation (regex/CIDR/uint32) and Channel C are the same. See
> [ADR-006](../architecture-decisions/006-slow-catalogs-as-files.md).

## Config hierarchy

```
defaults.conf            ← the main cascade config (rule registration, thresholds, categories)
whitelist_ip.conf        ← the system IP whitelist (monitoring, check services)
blocklist_ip.conf        ← the curated IP blocklist (PR-populated)
ua_blacklist.conf        ← UA patterns (PR-populated, with staging)
asn_datacenters.conf     ← datacenter ASN numbers for the reputation:asn_dc tag
tls_fp_blocklist.conf    ← TLS fingerprints of bots (Phase 2+, PR-populated, with staging)
tls_fp_catalog.conf      ← automation signatures for impersonator detection (Phase 2+, with staging)
tls_fp_browser_profiles.conf ← cipher_cnt per browser (Phase 2+, populated with a baseline)
challenge_secret         ← the HMAC secret for the clearance cookie (Phase 4+, delivered through a Puppet env var or file)
policy/<host>.yaml       ← per-resource policy (Phase 3+, arrives from the backend over Channel C, not stored locally as a file)
```

---

## 1. `defaults.conf` — the base cascade config

The main config, without which the cascade does not start. The structure of the sections defines each rule's category.

```yaml
# defaults.conf — the base cascade config (Phase 1+)

# L1 Hygiene
hygiene:
  method_whitelist:
    # Standard REST verbs — tenants behind the edge serve mutating APIs.
    # TRACE/CONNECT are intentionally excluded (blocked).
    - GET
    - HEAD
    - POST
    - PUT
    - PATCH
    - DELETE
    - OPTIONS
  api_path_patterns:
    # What counts as an "API endpoint" for the rate_api rule
    - /api/*
    - /graphql

# The blocking category — rules that emit verdict=block
rules:
  blocking:
    method_not_allowed:
      stage: hygiene
      source: built-in              # hardcoded in the proxy code

    ua_blacklist:
      stage: hygiene
      source: ua_blacklist.conf
      enabled: true                 # Phase 1: the catalog is empty, the rule is wired in

    ip_blocklist:
      stage: reputation
      source: blocklist_ip.conf
      enabled: true

    asn_customer:
      stage: reputation
      source: policy[host].asn_block
      enabled: true                 # only active when the policy holds entries

    geo_blocklist:
      stage: reputation
      source: policy[host].geo_whitelist  # inverted logic
      enabled: true

    tls_fp_blocklist:                 # Phase 2+
      stage: tls_fp
      source: tls_fp_blocklist.conf
      enabled: true

    rate_ip:
      stage: rate_limits
      key: ip
      window_10s: 100
      window_60s: 600

    rate_ip_ua:
      stage: rate_limits
      key: ip+ua
      window_10s: 100
      window_60s: 600

    rate_api:
      stage: rate_limits
      key: ip
      paths: ${hygiene.api_path_patterns}
      window_10s: 50
      window_60s: 300

    rate_tls_fp:                      # Phase 2+
      stage: rate_limits
      key: tls_fp
      window_10s: 50
      window_60s: 300
      fallback: skip                  # if no fingerprint was computed, the rule does not fire

    rate_scan_urls:
      stage: rate_limits
      key: ip
      metric: unique_urls
      window_10s: 50
      window_60s: 200

    non_browser_blocked:              # Phase 4+, L5 logic
      stage: verification
      source: built-in

  # The allow category — rules that emit verdict=allow (a fastpath)
  allow:
    cookie_valid:                     # Phase 4+, not a lookup but an HMAC verify
      stage: reputation
      source: built-in                # Lua logic
      # IMPORTANT: cookie_valid is a PARTIAL fastpath. It skips L3 (tls_fp) and L5 (verification),
      # but NOT L4: rate limits apply to the cookie holder. verdict=allow,rule=cookie_valid
      # is only set when L4 is clean; otherwise the L4 rule that fired wins.
      # A full fastpath (skipping L3/L4/L5) belongs to bot_verified and ip_whitelist only.
      cookie_name: tf_clearance
      secret_source: challenge_secret # see the separate file
      # Client binding: the cookie is issued against the TLS fingerprint plus the IP subnet (/24 for IPv4, /64 for IPv6) of the client
      # that solved the challenge, and at L2.1 it fastpaths only when both match —
      # a stolen cookie, or one handed to another client, does not work.
      ttl_seconds_normal: 86400       # 24 hours — normal mode
      ttl_seconds_under_attack: 3600  # 1 hour — under attack_mode=on
      # The TTL values are system constants shared across the pool; the customer does not configure them in the dashboard.
      # The per-request choice at L5: the proxy looks at attack_mode for EXACTLY the host the request came to.
      #   attack_mode[host]=on  → issues a cookie with ttl_under_attack
      #   attack_mode[host]=off → issues a cookie with ttl_normal
      # Enabling attack_mode for one customer does not affect other customers' cookie TTLs:
      # the cookie is scoped Domain=<host> and is not sent on requests to other hosts.
      # Previously issued 24-hour cookies are not invalidated when attack_mode is enabled — they live out their TTL.

    bot_verified:                     # Phase 3+, a catalog lookup
      stage: reputation
      source: catalog.bot_verification_status
      ua_pattern: "Googlebot|bingbot|YandexBot|DuckDuckBot"
      provisional_pending: true       # issue bot_verified_pending when there is no record

    ip_whitelist:
      stage: reputation
      source:
        - whitelist_ip.conf           # the system one
        - policy[host].ip_whitelist   # per-resource (Phase 3+)

  # The soft category — rules that accumulate a challenge flag
  soft:
    tls_fp_impersonator:              # Phase 2+
      stage: tls_fp
      source: tls_fp_catalog.conf

    tls_fp_suspicious_ciphers:        # Phase 2+
      stage: tls_fp
      source: tls_fp_browser_profiles.conf

    tls_fp_dc_browser:                # Phase 2+
      stage: tls_fp
      source: built-in                 # cross-layer: L3 fp + asn_datacenters.conf

# Informational tags (not rules, they emit no verdict)
tags:
  - id: hygiene:header_anomaly
    stage: hygiene
    source: built-in                 # a Lua header check (e.g. HTTP/2 without Accept)

  - id: reputation:asn_dc
    stage: reputation
    source: asn_datacenters.conf

  - id: tls_fp:automation_ua         # Phase 2+
    stage: tls_fp
    source: built-in                 # a Lua check for automation UA patterns

  - id: tls_fp:no_sni                # Phase 2+
    stage: tls_fp
    source: built-in                 # from the TLS handshake data

# Kill switch — the levers for incidents
kill_switch:
  global:                            # disables the whole cascade
    enabled: false                   # by default the switch is NOT engaged
  per_stage:                         # disables one layer
    hygiene: false
    reputation: false
    tls_fp: false                    # Phase 2+
    rate_limits: false
    verification: false              # Phase 4+

# attack_mode is per host only and lives in policy[host].attack_mode.
# There is no global toggle for the whole pool. For infrastructure-level incidents, use the kill switch.
```

---

## 2. `whitelist_ip.conf` — the system IP whitelist

A list of the IPs and CIDR subnets of our monitoring, check services and trusted system clients. Used by the `ip_whitelist` rule (category `allow`).

```
# whitelist_ip.conf — the system IP whitelist (Phase 1+)
# Populated at launch. Changes go through a PR.

# Internal monitoring services
10.0.1.0/24   # the monitoring subnet
10.0.2.5      # health-checker

# External uptime monitoring (with written agreement)
# UptimeRobot:
69.162.124.0/24
63.143.42.0/24

# Healthchecks.io:
# (add the current CIDR when onboarding)
```

---

## 3. `blocklist_ip.conf` — the curated IP blocklist

Empty at launch. Populated through PRs from log analysis or complaints. Used by the `ip_blocklist` rule (category `blocking`).

```
# blocklist_ip.conf — IP-blocklist (Phase 1+)
# Empty at launch. Additions go through a PR, always via staged rollout (see below).

# Format:
# <ip-or-cidr>  status=staging|active  reason=<short>

# Examples (after the first PRs):
# 203.0.113.42  status=active  reason=brute-force /login
# 198.51.100.0/24  status=staging  reason=scanner-pattern
```

**Staged rollout:** new IPs are first added with `status=staging` — they match and are written to the log's `staging_match`, but block nothing. After 24–48 h of false-positive analysis (no hits on legitimate traffic), a separate PR moves them to `status=active`.

---

## 4. `ua_blacklist.conf` — UA patterns

Empty at launch. Populated through PRs from analysis of the top UAs in the logs. Supports staged rollout.

```
# ua_blacklist.conf — UA patterns (Phase 1+)
# Empty at launch. Additions go through a PR, always via staged rollout.

# Format:
# <regex-pattern>  status=staging|active  reason=<short>

# Examples (after the first PRs):
# (?i)\bsqlmap/[\d\.]+   status=active  reason=SQL-scanner
# (?i)\bAhrefsBot\b      status=staging  reason=SEO-crawler-competitor
```

**A hint on writing them:** on the backend side the patterns are joined into one combined regex for O(1) matching on the proxy. That format lives on the backend side.

---

## 5. `asn_datacenters.conf` — datacenter ASN numbers

Populated at launch with a stable baseline list. Used for the `reputation:asn_dc` tag (informational, not a rule).

```
# asn_datacenters.conf — datacenter ASNs (Phase 1+)
# Populated with a baseline. Rarely changes (new providers or transferred numbers).
# Source: public data.

# Cloud providers
14618    # Amazon AWS
16509    # Amazon AWS
8075     # Microsoft Azure
8068     # Microsoft Azure
15169    # Google Cloud / GCP
396982   # Google Cloud
14061    # DigitalOcean
24940    # Hetzner Online
16276    # OVH SAS
20473    # Choopa / Vultr
63949    # Linode
14955    # Linode

# Alternative clouds and VPS providers
51167    # Contabo
197540   # netcup
210558   # 1984 Hosting

# The list is changed through a PR.
```

---

## 6. `tls_fp_blocklist.conf` — TLS-fingerprint blocklist (Phase 2+)

Empty at launch. Populated through PRs. Supports staged rollout.

```
# tls_fp_blocklist.conf — TLS fingerprints of known bots (Phase 2+)
# Empty at launch. Additions go through a PR, via staged rollout.

# Format:
# <fp-string>  status=staging|active  reason=<short>

# Examples (after the first PRs):
# L12d11h1_abc123def456_xyz789  status=active  reason=scrapy-3.x
# L13d15h2_qweasdzxc987_lmnopq  status=staging  reason=newly-seen-pattern
```

---

## 7. `tls_fp_catalog.conf` — automation signatures for impersonator detection (Phase 2+)

Empty at launch. A map `hash_b → automation family`. Used by the `tls_fp_impersonator` rule.

```yaml
# tls_fp_catalog.conf — Phase 2+
# Empty at launch. Additions go through a PR, via staged rollout.

# Each entry:
# hash_b: <12-hex-chars>
# family: <name>
# status: staging | active

entries:
  # - hash_b: 1ed0482b9b4c
  #   family: python-requests
  #   status: active

  # - hash_b: a1b2c3d4e5f6
  #   family: curl
  #   status: staging
```

---

## 8. `tls_fp_browser_profiles.conf` — expected cipher_cnt per browser (Phase 2+)

Populated with a baseline at launch. Used by the `tls_fp_suspicious_ciphers` rule.

```yaml
# tls_fp_browser_profiles.conf — Phase 2+
# Populated with a baseline set. Corrected as new browser versions appear.

profiles:
  chrome:
    expected_cipher_cnt: 15
    status: active

  firefox:
    expected_cipher_cnt: 16
    status: active

  safari:
    expected_cipher_cnt: 20
    status: active

  proxy:
    expected_cipher_cnt: 15           # usually matches Chrome
    status: active
```

If a browser's version updates and its cipher_cnt shifts, product first adds the new value with `status: staging` (for testing alongside the old one) and promotes it after calibration.

---

## 9. `challenge_secret` — the HMAC secret for the clearance cookie (Phase 4+)

Not a list file — a single secret string. Delivered through Puppet (Channel A) as an env variable or a protected file. One secret shared across the whole edge pool.

```bash
# An example of delivery through env (on the proxy at nginx startup):
# CHALLENGE_HMAC_SECRET=<32-bytes-base64-encoded-random-string>

# Or through a file (Puppet stores the content encrypted):
# /etc/antibot/challenge_secret.key
# (chmod 600, readable only by the nginx user)
```

**Rotation:** in brief:

- *Scheduled* — quarterly, through a PR to Puppet plus an nginx reload across the pool.
- *Emergency* (compromise) — escalated to the edge admins through the incident procedure.
Any rotation invalidates every clearance cookie issued so far (by design).

---

## 10. `policy/<host>.yaml` — per-resource policy (Phase 3+)

**It is not stored on the proxy as a file** — it arrives from the backend over Channel C as part of the `policy` catalog. The catalog is a map `host → policy_json`. What follows is the structure of one entry in that map, for information.

**Domain coverage (parent-domain fallback).** An entry for a domain also covers its subdomains: when reading the policy for a host, the edge first looks for an exact entry and, failing that, walks up the domain labels to the first one that exists (`www.example.com` → `example.com`). So registering `example.com` automatically protects `www.example.com`, `app.example.com` and so on with the same `mode`/`strictness`/`origin_ip`. A more specific entry (`api.example.com`) overrides the parent. The walk-up does not leak into a public suffix (`com`, `co.uk`) — only entries that really exist are matched.

```yaml
# An example per-resource policy for one domain
# The format inside the backend catalog; it arrives at the proxy as part of the policy catalog

example.com:
  mode: active                       # shadow | active
  strictness: standard               # standard | permissive
  attack_mode: false                 # the "Under Attack mode" toggle

  # origin_ip — the bare IPv4/IPv6 of the customer's backend. The marker of a proxied tenant
  # (multi-tenant routing): the edge matches the incoming Host against the policy
  # entry and proxies to this IP (the upstream hostname is substituted with the IP,
  # loop-safe; the Host and SNI sent upstream stay example.com). Empty means the host is
  # not a tenant and is not proxied (the edge is tenant-only: a non-tenant is dropped
  # with 444). No CIDR — this is the destination of a single
  # backend. The upstream scheme is https/443 (per-host scheme/port is a separate ticket).
  origin_ip: 203.0.113.9

  # The IP whitelist of the customer's legitimate server-side integrations
  ip_whitelist:
    - 203.0.113.10/32                # the customer's backend
    - 198.51.100.0/24                # the pool of their microservices

  # The customer's ASN block
  asn_block:
    - 12345                          # an ASN the customer chose to block
    - 67890

  # A country whitelist (when set, every other country is blocked by geo_blocklist)
  geo_whitelist:
    - RU
    - BY
    - KZ
    # empty means all countries are allowed

  # The customer's custom UA patterns (applied on top of the global ua_blacklist)
  custom_ua_blacklist:
    - "(?i)\\bcompetitor-scraper\\b"

  # Customer rate rules (per path)
  rate_rules:
    - path: /login*
      methods: [POST]
      rps: 5
      burst: 10
      action: challenge              # block | challenge | log_only

    - path: /api/*
      rps: 20
      burst: 40
      action: block

    - path: /search
      rps: 10
      burst: 20
      action: challenge

  # A custom API key header name — for a customer who needs an integration with their own auth
  # (out of scope in v1, but the slot is reserved in the schema)
  # api_key_header: X-Client-Token
```

---

## Staged rollout conventions

For every catalog with a `status` field (ua_blacklist, ip_blocklist, tls_fp_blocklist, tls_fp_catalog, tls_fp_browser_profiles):

1. **New patterns and entries are always added with `status: staging`.**
2. The observation period is at least 24 hours after delivery to the proxy (anything shorter gives an unrepresentative sample).
3. After the observation, a separate PR moves `status: staging` → `status: active`.
4. If the pattern produced a false positive during the `staging` period, revert the original PR (do not leave it in staging, so that forgotten entries do not pile up).

Promoting a pattern is a separate, deliberate step, never automatic.

---
