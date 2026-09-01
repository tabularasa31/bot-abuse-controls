# Design #2 / Phase 1 — a positive catalog of browser fingerprints  plus hash mismatch

> **Status: PLANNED / design draft.** Not implemented. This develops idea #2 from
> [bot-detector-roadmap.md](bot-detector-roadmap.md). Related to backlog items D2/D3/D4.

## The idea in one line

Invert the detection model: instead of a **blacklist** of known tools
(`tls_fp_catalog`, endlessly enumerating curl/python/go), keep a **whitelist** of
real browsers. The question changes from "do we know this bad fingerprint?" to
"does this fingerprint look like a known-good browser?". A whitelist is finite, and
it catches **new, home-grown and headless** stacks that appear in no tool dictionary.

## What exists today (and its ceiling)

- **`tls_fp_impersonator`** ([tls_fp.lua](../../infra/demo-stand/lua/tls_fp.lua),
  catalog `catalogs/tls_fp_catalog.yaml`): `hash_b → known tool`. A blacklist,
  enumerated by hand, forever playing catch-up.
- **`tls_fp_suspicious_ciphers`** (catalog `catalogs/tls_fp_browser_profiles.yaml`):
  `family → expected_cipher_cnt` (15/16/20). There is a positive signal here, but a
  **coarse** one — a cipher count per family, with no hashes and no versions. A
  headless browser with `cipher_cnt=15` and non-Chrome hashes sails through.
- **`classify_ua`** returns only the family (chrome/firefox/safari/edge/other), **not
  the version** → "Chrome 120 with a Chrome 99 handshake" is not caught today (that
  is Phase 2).

## Phase 1 — desktop, family level, no versions

The cheapest slice with the fastest payoff: exact hash comparison instead of the
coarse `cipher_cnt`, plus a sharpened purity gate from #1 .

### How the harvester works — no new edge code

The fingerprint dump lives in
[probe.lua](../../infra/demo-stand/lua/probe.lua): it returns the `fp` plus the raw
components and bypasses the verdict. The module is **not routed** — the public
surface carries no such endpoint — so the farm needs it exposed on a controlled
listener first. Given that, a browser driven at the endpoint reads back the same
`fp` the cascade computes, and the farm does not have to reimplement the logic.

### Components

1. **The harvester (the farm), cron one-shot.** Playwright plus real stable Chrome /
   Firefox / Edge (desktop), auto-updated to the current stable. Each browser → `/__fp`
   → take the **full `fp`** (`L<ver><sni><cnt><alpn>_<hash_b>_<hash_c>`, exactly as
   `probe.lua` returns it). The output is `{full_fp → {family, status}}`. This reuses
   the cron plus draft-PR pattern of `antibot-analytics`. The cadence is calibrated
   against real drift (Chrome's TLS comes from BoringSSL and changes rarely — probably
   "every few majors", not monthly).
2. **The positive catalog** — a **new file**, `catalogs/tls_fp_browser_known.yaml`:
   **`full_fp → {family, status}`** (a mirror of `tls_fp_catalog`, but known-good).
   PR-only, with `status: active|staging` like every slow catalog (ADR-006).
   *Decision 1: a new file rather than an extension of
   `tls_fp_browser_profiles.yaml` — a different key (the full fingerprint, not
   `family`) and inverted semantics.*
3. **The edge — strengthen `tls_fp_suspicious_ciphers`**
   ([tls_fp.lua](../../infra/demo-stand/lua/tls_fp.lua)): UA says browser AND the
   request's **full fp** is **not** in the known-good set → a soft flag. **The check is
   membership by the FULL fingerprint** (not by `hash_b`, and WITHOUT comparing
   families): the question is "is this the handshake of a real browser at all?".
   **Why the full fingerprint rather than `hash_b` (caught in review by Codex):**
   `hash_b` is computed from the sorted ciphers ALONE (`ja4_compute.lua`), while
   curves/ALPN/TLS version live in `hash_c` and the prefix. Membership by `hash_b`
   alone would be the same cipher-list check, only subtler: a headless browser that
   copied Chrome's ciphers but carries different extensions would pass as known-good.
   The full fingerprint closes that. **Why WITHOUT a family comparison (caught in
   review by Gemini):** `classify_ua` separates `edge` from `chrome`, so a
   `family==family` check would produce a false mismatch for Edge on a Chrome
   fingerprint; the full fingerprint is family-agnostic, so the problem disappears.
   Family/version comparison is Phase 2 . It is **soft-only** (a challenge or a
   flag, never a hard block) — catalog lag costs at most one captcha for an early
   updater. **A mobile UA is excluded** by looking for the `mobi` substring in the
   lower-cased UA (the standard lightweight approach, per MDN; no regex) via a new
   `is_mobile_ua` helper, since `classify_ua` has no mobile flag; there is no farm for
   mobile fingerprints, so without this we would get false positives on real phones.
   *Decision 3: exact hashes make the `cipher_cnt` check redundant — the old branch
   collapses into the known-good check (cipher_cnt stays as a catalog field for
   observation and reporting, but the hash makes the decision).*
4. **Analytics — sharpen `is_genuine_browser`**
   ([analyze.py](../../infra/demo-stand/scripts/analyze.py)): today genuine means
   `cipher_cnt ∈ {15,16,20}` plus "not in the tool dictionary"; in Phase 1 genuine
   becomes `full_fp ∈ known-good`. That directly strengthens the purity gate from #1
   (fewer false positives and fewer misses).

### A pleasant property of the coverage

Chromium forks (Brave, Vivaldi, Opera, Edge) on the same Chromium build produce an
**identical full fingerprint** (ciphers plus curves/ALPN/version, all from BoringSSL)
→ **one entry covers them transitively**, and since the check is family-agnostic, a
`ua_family=edge` on a Chrome fingerprint is not flagged. If a fork touched the
extensions, it has a different full fingerprint and gets its own entry — which is
correct, because we want to see that. In practice very little farming is needed:
Chrome (which covers all of Chromium), Firefox, and Edge if it differs. Firefox forks
(LibreWolf) and Tor (with its deliberately uniform fingerprint) are a separate
concern — candidates for manual staging entries.

### Where to run the farm

*Decision 2: on a CI runner* (a job with Playwright — desktop browsers out of the box,
and emitting a draft PR from CI is natural). The alternative is a small VM; Phase 1
does not need one.

### The farm's access to `/__fp` on a hardened edge — DEFERRED, decide when building the farm

> This came up while hardening the edge (feature/edge-deny-nontenant): the edge moves
> to a posture where the public `:443` serves tenants only; no SNI / an IP literal / a
> non-tenant SNI is rejected (TLS) or answered with 444 (HTTP), and the operational
> knobs move to a private listener. In that posture `/__fp` is NO LONGER publicly
> reachable, and the naive "the farm drives a browser at `https://<stand>/__fp`" above
> stops working. The options are recorded below; the final choice comes when we build
> the farm.

Hard constraints (they drive the design):

- **We must capture the REAL browser JA4.** Any intermediary that TERMINATES TLS (an
  HTTPS proxy, a MITM) captures the intermediary's fingerprint rather than the
  browser's, which defeats the point of the farm. Any gateway on the path must be L4
  (TCP/NAT passthrough), with TLS end-to-end between browser and edge.
- **`/__fp` bypasses the cascade and always answers 200** (see
  [probe.lua](../../infra/demo-stand/lua/probe.lua)) — that stays. The probe is
  low-sensitivity (it returns the caller's own fingerprint), but it must not become a
  spoofable hole in the tenant-only posture.
- **Port and host are not access control.** A scan finds a dedicated `:8443` in
  seconds; obscurity protects nothing. Control is either a firewall by source IP (L4,
  before TCP) or crypto (a key or certificate).
- **A GitHub-hosted farm has NO fixed egress IP.** The GitHub Actions ranges are huge
  and shared, so a firewall allowlist over them is impossible. A second (floating) IP
  on the SAME VM as the edge cannot serve as a bastion (it creates no fixed source on
  the farm's path; the SNAT has to happen somewhere other than the edge). Such an IP is
  only useful for isolating the probe's surface (binding the probe to a separate
  IP:port with its own certificate and SNI), not as access control.

Options (both preserve the fingerprint — neither re-terminates TLS):

- *Option A — mTLS on the probe (no new infrastructure).* A dedicated probe server (a
  separate IP:port with its own `server_name`/cert) with `ssl_verify_client on` plus a
  private CA for the farm; the client certificate lives in GitHub Actions secrets and
  Playwright presents it (`clientCertificates`). Without the certificate the TLS
  handshake fails at verification, before `/__fp`. The JA4 is preserved (the client
  certificate is sent AFTER the ClientHello, and JA4 is computed from the ClientHello).
  **To verify when building:** that enabling a client certificate in the browser adds no
  extra extensions to the ClientHello (otherwise the captured JA4 diverges from
  production, where there is no mTLS) — a one-off "hello with mTLS == hello without
  mTLS" validation. Residual risk: flooding handshakes up to certificate verification is
  cheaper than a full handshake but not free at L4 → rate-limit it.
- *Option B — a WireGuard bastion (a separate static VM).* CI brings up a WG tunnel (key
  from secrets), the browser goes through the tunnel, and the bastion SNATs to its
  static IP; the edge firewall then DROPs the probe for everyone except the bastion IP.
  WireGuard is L3, so TLS stays end-to-end and the JA4 is perfectly accurate, with the
  port closed at the network layer. The cost is one small VM.

Dependencies for the choice: (1) whether the farm (Playwright/Puppeteer/Selenium) can
present a client certificate; (2) whether ClientHello fidelity under mTLS is confirmed;
(3) whether we are willing to run a small bastion VM. Default candidate: Option A (no
new infrastructure), with Option B as the fallback.

## Not in Phase 1 (→ Phase 2)

- **Versions plus full D3:** `classify_ua → (family, major)` and a mismatch by version —
  this needs new UA parsing (UA strings lie and vary wildly).
- **A self-healing trigger:** a spike of mismatches on a UA version absent from the
  catalog but with a high human_share → an automatic re-harvest. The detector itself
  signals that the catalog has gone stale (closing the loop with #1).
- **Mobile / Safari:** iOS Safari and Android Chrome have different fingerprints; that
  needs a macOS runner and mobile stacks a headless farm cannot provide. We do not apply
  the mismatch to mobile UAs.

## Risks

- **Catalog lag — TWO windows, do not conflate them** (caught in review):
  - *Window 1: browser release → the farm captures it → the draft PR is merged as
    `staging`.* Here the new fingerprint is not in the catalog at all, so the mismatch
    fires. It is contained only by being **soft-only** (one captcha), by the farm's
    cadence, and by the Phase 2 self-healing. Staging does not help here.
  - *Window 2: `staging` → `active` (calibration).* **The semantics of staging are
    INVERTED for a whitelist** relative to a blacklist: for a blocklist, `staging` means
    "match but do not block"; for an allowlist, `staging` means "already trusted, suppress
    the flag". So the membership check evaluates `full_fp ∈ (active ∪ staging)` → **a
    staging entry immediately suppresses the mismatch** for users on the new version.
    Promotion to `active` is a human blessing (a check that no bot hash leaked into the
    farm's output), not a gate real users are waiting behind.
- **An unknown legitimate desktop browser** missing from the catalog → a mismatch. The
  transitive Chromium coverage lowers the risk, and the soft mode keeps the cost at one
  captcha.
- **Poisoning** (if the catalog is ever auto-populated from traffic) — not in Phase 1:
  the catalog comes only from the farm plus manual PRs. Auto-population is a separate
  track (#5).

## Scope of work (Phase 1)

- The farm: a Playwright script, a CI job, and a draft-PR emitter targeting
  `catalogs/tls_fp_browser_known.yaml`.
- Backend Channel C: a new `tls_fp_browser_known` catalog (like `tls_fp_catalog`).
- The edge: load the known set into a shared_dict (modelled on `tls_fp_catalog`), amend
  `tls_fp_suspicious_ciphers` and add the mobile-UA exclusion.
- Analytics: `is_genuine_browser` via the known set.
- Tests: Lua (known-good hit/miss, mobile skip, soft-not-block) and Python
  (`is_genuine_browser`).
