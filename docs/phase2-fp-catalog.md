# Phase 2 fingerprint catalog — real handshake-derived fp

ClickUp task [86exmjzug](https://app.clickup.com/t/86exmjzug). Catalog of real fingerprints emitted by the PoC #2 stand after the Phase 2 wiring (synthetic md5 replaced with sha256 of `$ssl_ciphers` + handshake metadata; see [infra/nginx-lua-poc/lua/ja4_compute.lua](../infra/nginx-lua-poc/lua/ja4_compute.lua)).

Companion to Phase 1's strict-FoxIO-JA4 catalog at [antibot-lab/docs/ja3-poc-results.md §"Baseline fingerprint catalog"](../../antibot-lab/docs/ja3-poc-results.md).

## Format

```
L<ver><sni><cipher_cnt><alpn>_<sha256(sorted_ciphers):12>_<sha256(curves|alpn|ver):12>
```

Leading `L` distinguishes from FoxIO JA4 (`t` prefix). See [lua-poc-results.md §"Phase 2 — real fp"](lua-poc-results.md) for the full trade-off rationale.

## Captured 2026-05-16 on macOS arm64 (LibreSSL curl, OpenResty alpine native arm64)

| Client | Fingerprint | TLS ver | SNI | ALPN | Ciphers offered | Notes |
|---|---|---|---|---|---:|---|
| curl 8.7.1 (macOS LibreSSL) | `L13d49h2_de2bb2c70653_2d5fbeed7632` | 1.3 | antibot.local | h2 (negotiated) | 49 | LibreSSL ships a long compatibility cipher list including legacy GOST + RC4. The `d` (SNI present) discriminator + 49-cipher count is the cheap-to-eyeball signature. |
| python-requests 2.32.5 (Python 3.9 alpine) | `L13i30h1_bcf826a2cd28_60bdc24aefcc` | 1.3 | (empty) | http/1.1 | 30 | No SNI because connection target is `127.0.0.1` (IP literals don't get SNI from requests). ALPN `h1` is the actionable signal — a "Chrome" UA over `_h1` is suspicious by itself, matching Phase 1's observation. |
| Go-http-client/1.1 (Go 1.23 alpine) | `L13d1300_69e852b66fc7_1bb3b57910c1` | 1.3 | antibot.local | (none) | 13 | Go's default `crypto/tls` advertises NO ALPN (`00` suffix). 13-cipher list is the smallest of the three automation clients. |
| Chrome 148 macOS | `L13d15h2_1ed0482b9b4c_???` _(re-capture pending)_ | 1.3 | antibot.local | h2 | 15 (post-GREASE-strip) | Verified stable across 3 reloads. Raw `$ssl_ciphers` includes GREASE (`0x8a8a` on one capture, `0x6a6a` on another) which rotates per TLS connection — the filter strips it before sort+hash, so the fp stays the same. **Hash tail (`_???`) shifted by the ver-fix landed for [Gemini's PR #6 review](https://github.com/tabularasa31/abuse-controls/pull/6); needs operator re-capture in a real browser.** Prefix unchanged. |
| Firefox 150 macOS | `L13d16h2_902b16b03119_???` _(re-capture pending)_ | 1.3 | antibot.local | h2 | 16 | Firefox does NOT use GREASE — fp unaffected by the GREASE-strip filter. **Hash tail shifted by the ver-fix; needs operator re-capture.** Prefix and ja_b unchanged. |
| Safari 26.3.1 macOS | `L13d20h2_51b6cc891816_???` _(re-capture pending)_ | 1.3 | antibot.local | h2 | 20 (post-GREASE-strip) | Verified stable across 2 reloads pre-ver-fix. Raw `$ssl_ciphers` includes GREASE (`0x6a6a`) and curves include GREASE (`0x8a8a`) — both stripped. Cipher list contains legacy `DES-CBC3-SHA` (3 variants) which neither Chrome nor Firefox advertises in this version. **Hash tail shifted by the ver-fix; needs operator re-capture.** |

Catalog covers all 6 client classes targeted by the [86exmjzug](https://app.clickup.com/t/86exmjzug) acceptance gate — 3 automation clients have full fingerprints, 3 browser rows have prefix + ja_b captured but the ja_c tail is stale after the ver-fix landed (gemini code review on PR #6) and needs operator re-capture in real browsers. Each browser row notes its `_???` tail and the structural attributes (cipher count, ALPN, SNI presence) that are unaffected. The 6 client classes produce 6 distinct prefixes, so the "all distinct" property of the catalog holds even with the stale hash tails. Acceptance is satisfied modulo the operator step.

With the GREASE filter applied, **prefix `L<ver><sni><cipher_cnt><alpn>` now discriminates Chrome (15) vs Firefox (16) vs Safari (20) on cipher count alone** — the hash is still needed to discriminate clients with identical prefixes but no longer needed for browser-vs-browser separation in this set.

## GREASE finding (caught during browser capture, fixed in same PR)

Chrome and Safari implement [RFC 8701 GREASE](https://datatracker.ietf.org/doc/html/rfc8701) — they advertise random reserved cipher / curve values (`0x?A?A` where both nibbles match: `0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA` — 16 possible per slot) that rotate **per TLS connection**. Browsers ship GREASE to break server implementations that hardcode TLS values and to make fingerprinting harder.

The initial Spike 2 implementation did NOT strip GREASE before sort+hash, so:

- The same Chrome on the same machine produced a **different fp every new TLS connection** — GREASE value changed, landed in `$ssl_ciphers`, sort order shifted, sha256 output was different.
- A Chrome blocklist entry would have caught **only the one GREASE variant** the operator captured. ~16 possible variants per browser version means the blocklist becomes impractical for browsers.

Fix landed in [infra/nginx-lua-poc/lua/ja4_compute.lua](../infra/nginx-lua-poc/lua/ja4_compute.lua) (~15 LoC): the `is_grease()` helper pattern-matches `^0x([0-9a-f])a%1a$` against each cipher/curve token before adding to the canonical list. Fast-path skip for non-`0x` tokens keeps the per-request cost flat (named ciphers like `TLS_AES_128_GCM_SHA256` never invoke the regex).

Verified: Chrome and Safari fps reproduced across multiple reloads after the fix; Firefox unchanged (Mozilla does not enable GREASE in cipher_suites).

## Observations (full 6-client catalog)

- **Cipher counts span 13 → 49** (Go → curl) after GREASE strip. Automation clients sit at 13–30, browsers at 15–20. Coarse filter still useful.
- **Browser cipher counts are all distinct** (Chrome 15, Firefox 16, Safari 20) — prefix alone separates them in this catalog. The hash component remains the precise discriminator if/when two clients collide on prefix (none do in this 6-client set, but production traffic could surface collisions).
- **All 6 use TLS 1.3; all browsers negotiate `h2` ALPN** — discriminator is cipher list content, exactly as Phase 1 documented.
- **Phase 1 Safari structural observation reproduced**: Safari ships more ciphers than Firefox (20 vs 16) and includes legacy `DES-CBC3-SHA` variants, distinct prefix from Firefox.
- **Cross-browser hash collision check**: no two clients in this 6-client set produced the same fp (prefix OR hash). The closest pair on prefix was Chrome (`L13d15h2`) vs Firefox (`L13d16h2`) — 1-cipher difference.

## Cross-validation

Run [scripts/cross-validate-ja4.sh](../scripts/cross-validate-ja4.sh) to capture a pcap and validate against:

1. **FoxIO Python `ja4` library** (`pip install ja4`) — feeds the pcap through, extracts strict JA4. Our `L`-prefix fp is NOT byte-identical to FoxIO's `t`-prefix JA4 by design (see [lua-poc-results.md §"Phase 2 — real fp"](lua-poc-results.md) for why); validation is at the **component level**: cipher list, ALPN, TLS version, SNI presence must agree.
2. **Wireshark JA4 plugin** — third source, manual. Open the pcap, eyeball the same sessions, confirm components.

The script drives **automation clients only** (curl, python-requests, go-http-client) because real browsers can't be invoked headlessly with their production TLS stacks. Browser validation is the manual Wireshark step below.

Validation table for automation clients (filled in after running [scripts/cross-validate-ja4.sh](../scripts/cross-validate-ja4.sh)):

| Probe | Our `/__fp` cipher_count | ja4 lib cipher_count | Wireshark cipher_count | ALPN match | Result |
|---|---:|---:|---:|:---:|:---:|
| curl 8.7.1 | 49 | _TODO_ | _TODO_ | | |
| python-requests | 30 | _TODO_ | _TODO_ | | |
| go-http-client | 13 | _TODO_ | _TODO_ | | |

Browser-side validation (manual, no automation possible):

| Browser | Captured fp (above) | Wireshark ja4 plugin: ClientHello matches? | Cipher_count match? | ALPN match? |
|---|---|:---:|:---:|:---:|
| Chrome | _from row above_ | _TODO_ | _TODO_ | _TODO_ |
| Firefox | _from row above_ | _TODO_ | _TODO_ | _TODO_ |
| Safari | _from row above_ | _TODO_ | _TODO_ | _TODO_ |

For browsers: open `https://antibot.local:8443/__fp` while Wireshark captures on `lo0`, then in Wireshark filter `tls.handshake.type == 1`, click the browser's ClientHello, and compare the cipher count + ALPN against the catalog row above.

Pass = components match across all three sources (our stand, ja4 lib, Wireshark) for all 3 automation probes, AND Wireshark agrees with the captured browser fps on cipher count + ALPN.

## Why not strict FoxIO JA4 byte-compatibility

The PoC #2 stand uses Spike 2 from RFC §Е (see [docs/architecture/edge-lua-vs-sidecar.md](architecture/edge-lua-vs-sidecar.md) and [infra/nginx-lua-poc/spikes/lua-parser/RESULTS.md](../infra/nginx-lua-poc/spikes/lua-parser/RESULTS.md)). It trades:

- ✅ Zero build-chain maintenance (stays on stock `openresty/openresty:alpine`)
- ✅ Real, spoof-resistant, handshake-derived fingerprint
- ✅ ~32 K RPS allow path (median of 3 clean runs, post-GREASE-strip — see [PR #4](https://github.com/tabularasa31/abuse-controls/pull/4)); passes the ≥26 K acceptance bar by 23 % headroom. −8 % vs the synthetic md5 baseline, which is the cost of producing a real signal
- ✅ Distinguishes browser vs automation vs different TLS libraries

for:

- ❌ NOT byte-compatible with strict FoxIO JA4 — cannot drop in external JA4 feed blocklists
- ❌ Missing extension list component (nginx does not expose it to access_by_lua)

If we later need strict JA4 interop (e.g. for catalog imports from upstream JA4 feeds), revisit Spike 3 (FoxIO C module rebuilt with lua) — its scaffolding lives in [infra/nginx-lua-poc/spikes/foxio/](../infra/nginx-lua-poc/spikes/foxio/) and the Dockerfile is build-ready.
