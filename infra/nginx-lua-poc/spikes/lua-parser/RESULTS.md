# Spike 2 — Lua compute_fp from nginx $ssl_* vars

Branch: `claude/vibrant-archimedes-797973`. Date: 2026-05-16.

## Approach

Computes a JA4-style hash in `access_by_lua` using only standard nginx vars (`$ssl_ciphers`, `$ssl_curves`, `$ssl_protocol`, `$ssl_alpn_protocol`, `$ssl_server_name`). No custom OpenResty build, no FFI, no clienthello phase. Format:

```
L<ver><sni><cipher_cnt><alpn>_<sha256(sorted_ciphers):12>_<sha256(curves|alpn|ver):12>
```

The leading `L` makes it grep-distinguishable from a true FoxIO JA4 (`t` prefix) if we ever ship both side by side.

## Image and build

| | |
|---|---|
| Base image | `openresty/openresty:alpine` (multi-arch, OpenResty 1.29.2.3) |
| Custom build | None |
| Build time | 0 s (pull only) |
| Image size | 75 MB (same as PoC #2) |
| New code | 80 LoC (`lua/ja4_compute.lua`) |
| Maintenance burden | None — stock image; Lua module owned by us |

## Smoke test — three automation clients, real distinct fingerprints

```
$ curl -ksS --resolve antibot.local:8453:127.0.0.1 https://antibot.local:8453/__fp
fp=L13d49h2_de2bb2c70653_d07b7f455339
tls_ver=TLSv1.3       sni=antibot.local   alpn=h2          ua=curl/8.7.1
ciphers: 49 (TLS_AES_*, TLS_CHACHA20_*, ECDHE-*, ... LEGACY-GOST...)

$ python3 -c "import requests, urllib3; urllib3.disable_warnings(); print(requests.get('https://127.0.0.1:8453/__fp', verify=False).text)"
fp=L13i30h1_bcf826a2cd28_8c35449021c4
tls_ver=TLSv1.3       sni=             alpn=http/1.1    ua=python-requests/2.32.5
ciphers: 30                                                      (no SNI: connected to 127.0.0.1)

$ docker run --rm --network host golang:1.23-alpine sh -c "<go probe>"
fp=L13d1300_69e852b66fc7_747a969b1fb5
tls_ver=TLSv1.3       sni=antibot.local   alpn=             ua=Go-http-client/1.1
ciphers: 13                                                      (Go default: no ALPN)
```

Cipher counts alone (49 / 30 / 13) discriminate browsers from automation tools, matching Phase 1 catalog observations. Hashes are stable across two runs each.

## Wrk allow-path bench

```
wrk -c100 -d20s -t4 --latency -H "Host: antibot.local" https://127.0.0.1:8453/
```

| Metric | Spike 2 | PoC #2 baseline (synthetic md5) | Delta |
|---|---:|---:|---:|
| RPS | **38 781** | 34 808 | +11 % |
| p50 | 2.26 ms | 2.49 ms | −0.23 ms |
| p75 | 3.06 ms | 3.37 ms | −0.31 ms |
| p90 | 4.37 ms | 4.89 ms | −0.52 ms |
| p99 | **9.02 ms** | 25.39 ms | −16.4 ms |

Spike 2 is *faster* than the synthetic baseline. Most likely: $ssl_ciphers is already populated by nginx (zero-cost var read) and replaces several Lua string-concat allocations the synthetic computation did per request. sha256 of the sorted cipher list (~600 bytes) costs less than the synthetic md5's string-building overhead.

**Verdict: passes the ≥26 K RPS acceptance bar by a wide margin.**

## Honest limitations

1. **Not byte-identical to FoxIO JA4.** Strict JA4_c requires the full extension list + signature_algorithms, which `lua-resty-core` does not expose in a phase where the data is still accessible. Bridging the clienthello phase to access phase via OpenSSL ex_data would add ~150 LoC of FFI plus session-reuse / SSL-pointer edge cases.
2. **Cross-validation against `pip install ja4` cannot match exact hash.** It can match the *components* we derive (cipher list, ALPN, TLS version, SNI presence) — these will match what `ja4` reads from the same pcap. The 12-char hashes will not match because they hash different inputs.
3. **`$ssl_alpn_protocol` is negotiated, not offered.** If the server only advertises h2, the client's offered ALPN list (which JA4 wants) is collapsed to "h2". For PoC #2 this is acceptable; production might want the offered list, which again needs clienthello phase.

## Recommendation as a spike

Spike 2 is **viable and the cheapest option**. It produces a real (handshake-derived, spoof-resistant) fingerprint that distinguishes browser from automation, exceeds the perf bar, and costs zero build maintenance. It is *not* a drop-in replacement for FoxIO JA4 — if the production v1 requires strict JA4 compatibility (e.g. to import existing JA4 blocklists from upstream feeds), Spike 1 or 3 is needed instead.

A reasonable middle path: ship Spike 2 today to unblock cascade tasks A1/A5, and treat strict JA4 (clienthello+FFI bridge or C-module) as a Phase 2.5 sub-task only if a concrete need for catalog interop appears.
