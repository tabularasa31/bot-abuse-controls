# catalogs/ — the slow Channel C catalogs

This directory is the **single source of truth** for the slow catalogs
product maintains. The backend reads it on every reloader tick
(5 s by default) and serves it to the edge through `/catalog/<name>`. The SLA from a PR merge to
application across the edge pool is **≤ 15 minutes** (see [vision.md](../docs/product/vision.md)
§"Catalog and policy updates").

See also the design decision
on why the slow catalogs live in git rather than in the database.

## The files

| File                              | What is inside                                          |
|-----------------------------------|---------------------------------------------------------|
| `version`                         | the payload schema semver, sent in `X-Catalog-Version`. |
| `tls_fp_blocklist.yaml`           | TLS fingerprints → status. `verdict=block` for active.  |
| `ua_blacklist.yaml`               | RE2 regexes over the User-Agent → status. Folded into a combined regex. |
| `ip_blocklist.yaml`               | CIDR → status. `verdict=block` for active.              |
| `ip_whitelist.yaml`               | CIDR (no status). The system allow list.                |
| `asn_datacenters.yaml`            | uint32 ASNs. The reference for the `reputation:asn_dc` tag. |
| `tls_fp_catalog.yaml`             | hash_b → { family, status }. The tls_fp_impersonator rule. |
| `tls_fp_browser_profiles.yaml`    | family → { expected_cipher_cnt, status }. The tls_fp_suspicious_ciphers rule. |

What is **not** here:
- `policy/<host>` — customer settings; they live in the database and are edited through the dashboard.
- `verified_bot_ips` — runtime state from the rDNS worker; it lives in the database.

## How to make a change

1. **Create a feature branch** (never edit `main` directly).
2. **Open a PR** amending the relevant file. CODEOWNERS requires a
   product review.
3. **CI validates**: the regex compiles (`regexp.Compile`), the CIDR parses, the
   ASN is within uint32 range, and status ∈ `{active, staging}`. One broken record
   means fail-stale and the backend does not pick it up (the Store is not updated and
   `antibot_backend_catalog_reload_failures_total` ticks).
4. **After the merge** the backend picks it up within `CATALOG_RELOAD_INTERVAL`
   (5 s) and the edge within `+30 s` (the Channel C poll). Around a minute in total on the
   stand; the product SLA of `≤ 15 min` leaves plenty of room.

## Staged rollout

For the catalogs with a status (`tls_fp_blocklist`, `ua_blacklist`, `ip_blocklist`)
the A11 staged rollout applies:

1. **PR 1**: add the entry with `status: staging`. The edge matches it and writes
   `staging_match: ["<catalog>:<pattern>"]` into bac_log, and **does not block**.
2. **Observation** (24–48 h): confirm the entry fires only
   on the expected traffic (no false matches on legitimate clients).
3. **PR 2**: change `status: staging` → `status: active`. The edge starts
   emitting `verdict=block`.

To roll back, `git revert` the PR within the same SLA.

## The YAML format

The files are parsed through `gopkg.in/yaml.v3` in strict mode (`KnownFields(true)`).
A typo in a field name fails the load rather than being silently ignored.

An empty file, or one holding only comments, means an empty catalog.
