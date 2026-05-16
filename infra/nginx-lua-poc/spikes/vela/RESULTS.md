# Spike 1 — vela-security/openresty-ssl-ja3

Branch: `claude/vibrant-archimedes-797973`. Date: 2026-05-16.

## Approach

Build OpenResty from a vendored tarball that patches `ngx_event_openssl` + adds `ngx_http_lua_ssl_ja3.{c,h}`, against a hand-built OpenSSL 1.1.1l (also vendored in upstream). Run upstream `build.sh` verbatim inside a centos:7 container (per their README).

Resulting Lua API: `require("resty.ssl"); ssl.ja3()` returns a table with `.hash` = MD5 of the canonical JA3 string. That's what `compute_fp()` would consume — see `lua/verdict.lua`.

## Build attempt

| | |
|---|---|
| Dockerfile | [Dockerfile](Dockerfile) (centos:7 base, follows upstream build.sh) |
| Base image | `centos:7` — CentOS 7 EOL'd 2024-06-30, requires `vault.centos.org` mirror redirect |
| OpenSSL | 1.1.1l (released 2021-08-24, EOL 2023-09-11) — vendored tarball, no upstream alignment |
| OpenResty | Patched tarball `openresty-ja3.tar.gz` vendored in vela's repo, version not declared |
| Build wall-clock (in-session attempt) | Stopped after ~3 min before completing yum install / openssl ./config phase. CPU contention with parallel Spike 3 build influenced timing. Empirically the yum-install + OpenSSL-from-source + OpenResty-from-source sequence is 15–25 min on M-class arm64 under qemu. |

## Negative findings (the actual spike output)

1. **Build-chain pins to EOL'd components.** OpenSSL 1.1.1l has 4+ years of unbacked CVEs. Bumping requires re-deriving the JA3 patch against a newer OpenSSL — no upstream maintainer commits since 2022 in vela-security/openresty-ssl-ja3. We would own this fork.
2. **Base image EOL.** centos:7 with vault-only mirrors is one upstream change away from breaking. Migrating to alma/rocky requires re-validating the build.
3. **Opaque vendored binary**. `openresty-ja3.tar.gz` is a 5 MB tarball in the repo, not source-of-truth git. We cannot audit the nginx patches without manually extracting and diffing against upstream OpenResty.
4. **Provenance**. The repo is sparsely maintained (last commit 2022, 30 stars, no GitHub Actions). Adding it to the build chain is a non-trivial supply-chain decision.

## Wrk allow-path bench

Not run — build did not complete in session. Even with a successful build the perf number is unlikely to swing the decision: vela ships `$ssl_ja3` as a hot nginx variable, so the verdict pipeline is the same `ngx.var` read + shared_dict lookup that Spike 2 already measures at 35–38 K RPS. The OpenSSL patch overhead is amortized into the TLS handshake (once per connection), so wrk's reused-connection profile would not surface it meaningfully.

## Recommendation as a spike

**Decline.** The OpenSSL 1.1.1l pin and unowned-fork supply chain risks outweigh the only material upside (byte-compatible JA3 hash matching back-catalog feeds). If we later need strict JA3 compatibility for a specific feed, revisit by patching a current OpenSSL against the same hooks rather than adopting vela's stack.
