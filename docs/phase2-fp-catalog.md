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
| curl 8.7.1 (macOS LibreSSL) | `L13d49h2_de2bb2c70653_d07b7f455339` | 1.3 | antibot.local | h2 (negotiated) | 49 | LibreSSL ships a long compatibility cipher list including legacy GOST + RC4. The `d` (SNI present) discriminator + 49-cipher count is the cheap-to-eyeball signature. |
| python-requests 2.32.5 (Python 3.9 alpine) | `L13i30h1_bcf826a2cd28_8c35449021c4` | 1.3 | (empty) | http/1.1 | 30 | No SNI because connection target is `127.0.0.1` (IP literals don't get SNI from requests). ALPN `h1` is the actionable signal — a "Chrome" UA over `_h1` is suspicious by itself, matching Phase 1's observation. |
| Go-http-client/1.1 (Go 1.23 alpine) | `L13d1300_69e852b66fc7_747a969b1fb5` | 1.3 | antibot.local | (none) | 13 | Go's default `crypto/tls` advertises NO ALPN (`00` suffix). 13-cipher list is the smallest of the three automation clients. |
| Chrome (macOS, latest) | _TODO — open https://antibot.local:8443/__fp in Chrome, paste `fp=` line_ | | | | | Manual capture per [scripts/lua-poc-probe.sh](../scripts/lua-poc-probe.sh) §"manual browser probes". |
| Firefox (macOS, latest) | _TODO — same_ | | | | | |
| Safari (macOS, latest) | _TODO — same_ | | | | | |

After the three browser fingerprints are captured, this catalog reaches 6 distinct entries (acceptance gate for [86exmjzug](https://app.clickup.com/t/86exmjzug)) and matches the Phase 1 catalog shape one-for-one.

## Observations (3-client subset)

- All 3 automation clients produce distinct fingerprints. Cipher-count alone (49 / 30 / 13) discriminates them.
- The component portion of the prefix (`L<ver><sni><cipher_cnt><alpn>`) is human-readable and the cheap fast-path filter; the SHA hash tails are the precise discriminator only when the prefix collides.
- All 3 produce TLS 1.3, but the cipher *list* differs by client TLS library — exactly the property that makes this signal robust to UA spoofing.

## Cross-validation

Run [scripts/cross-validate-ja4.sh](../scripts/cross-validate-ja4.sh) to capture a pcap and validate against:

1. **FoxIO Python `ja4` library** (`pip install ja4`) — feeds the pcap through, extracts strict JA4. Our `L`-prefix fp is NOT byte-identical to FoxIO's `t`-prefix JA4 by design (see [lua-poc-results.md §"Phase 2 — real fp"](lua-poc-results.md) for why); validation is at the **component level**: cipher list, ALPN, TLS version, SNI presence must agree.
2. **Wireshark JA4 plugin** — manual third source. Open the pcap, eyeball the same 3 sessions, confirm components.

Validation results (filled in after running):

| Probe | Our `/__fp` cipher_count | ja4 lib cipher_count | Wireshark cipher_count | ALPN match | Result |
|---|---:|---:|---:|:---:|:---:|
| curl 8.7.1 | 49 | _TODO_ | _TODO_ | | |
| python-requests | 30 | _TODO_ | _TODO_ | | |
| Chrome | _TODO_ | _TODO_ | _TODO_ | | |

Pass = components match across all three sources for all three probes.

## Why not strict FoxIO JA4 byte-compatibility

The PoC #2 stand uses Spike 2 from RFC §Е (see [docs/architecture/edge-lua-vs-sidecar.md](architecture/edge-lua-vs-sidecar.md) and [infra/nginx-lua-poc/spikes/lua-parser/RESULTS.md](../infra/nginx-lua-poc/spikes/lua-parser/RESULTS.md)). It trades:

- ✅ Zero build-chain maintenance (stays on stock `openresty/openresty:alpine`)
- ✅ Real, spoof-resistant, handshake-derived fingerprint
- ✅ +0.4 K RPS over the synthetic md5 baseline; passes the ≥26 K acceptance bar at 35.3 K
- ✅ Distinguishes browser vs automation vs different TLS libraries

for:

- ❌ NOT byte-compatible with strict FoxIO JA4 — cannot drop in external JA4 feed blocklists
- ❌ Missing extension list component (nginx does not expose it to access_by_lua)

If we later need strict JA4 interop (e.g. for catalog imports from upstream JA4 feeds), revisit Spike 3 (FoxIO C module rebuilt with lua) — its scaffolding lives in [infra/nginx-lua-poc/spikes/foxio/](../infra/nginx-lua-poc/spikes/foxio/) and the Dockerfile is build-ready.
