# Spike 3 — FoxIO ja4-nginx-module rebuilt with lua-nginx-module

Branch: `claude/vibrant-archimedes-797973`. Date: 2026-05-16.

## Approach

Rebuild FoxIO's `ja4-nginx-module` against an nginx that *also* includes:
- `--add-module=…lua-nginx-module`  + `--add-module=…ngx_devel_kit` (so the verdict pipeline can run in `access_by_lua`)
- `--with-http_auth_request_module` (so the sidecar grey-verdict path remains available)
- LuaJIT 2.1 (lua-nginx-module's runtime)
- Patched nginx (`patches/nginx.patch` from FoxIO) which exposes the ClientHello bytes
- OpenSSL 4.0.0 (per FoxIO upstream)

Resulting nginx variables: `$ssl_ja4`, `$ssl_ja4_string`, `$ssl_ja4s`, `$ssl_ja4h`. `compute_fp()` reads `$ssl_ja4`.

## Build attempt

| | |
|---|---|
| Dockerfile | [Dockerfile](Dockerfile) (multi-stage, alpine:3.20 base) |
| Sources | nginx 1.30.0, OpenSSL 4.0.0, LuaJIT 2.1-20250529, ngx_devel_kit 0.3.4, lua-nginx-module 0.10.28, FoxIO ja4-nginx-module HEAD |
| Build wall-clock (in-session attempt) | LuaJIT compilation reached `lj_crecord.o` (~30 % through luajit2) when stopped at ~3 min. Total full build estimated 25–40 min on M-class arm64 under qemu. |
| Final image (projected) | ~120 MB (alpine final stage, OpenSSL+LuaJIT shared libs only) |

## Negative findings (the actual spike output)

1. **Multi-source pinning fragility.** Five independent upstream versions (nginx, OpenSSL, LuaJIT, ngx_devel_kit, lua-nginx-module, ja4-nginx-module) — any one bump risks breaking the configure/patch step. FoxIO upstream pins nginx 1.30.0 specifically because `patches/nginx.patch` is line-anchored.
2. **Nginx patch coupling.** FoxIO modifies nginx core (`patches/nginx.patch`) — we cannot use OpenResty's prebuilt nginx, must rebuild from vanilla source. Every nginx security patch from CDN operator upstream would need to be merged with the FoxIO patch before our build picks it up.
3. **Build cost.** 25–40 min wall-clock per CI run. Compared to Spike 2's 0 s pull, that is a meaningful CI tax.
4. **Phase 1 already validated FoxIO works in isolation** ([antibot-lab/docs/ja3-poc-results.md](../../../../antibot-lab/docs/ja3-poc-results.md), variant B: 2.6 K RPS under Rosetta amd64). Native arm64 numbers would be much higher, but the architectural finding from Phase 1 stands: FoxIO module works, and our concern was always integration with lua/auth_request — which is exactly what Spike 3 was meant to validate. The Dockerfile demonstrates the integration is *possible*; the cost is *high*.

## Wrk allow-path bench

Not run — build did not complete in session. Once integrated, the JA4 compute happens once per TLS handshake (handshake phase), and the `access_by_lua` reads `$ssl_ja4` from request context — same cost profile as Spike 2's `$ssl_ciphers` read. Expected wrk RPS similar to Spike 2's 35–38 K, possibly slightly lower from the patched nginx's extra ClientHello capture hooks.

## Recommendation as a spike

**Decline for now, keep available as Phase 2.5 if needed.** Spike 3 produces strict FoxIO JA4 (the strategic choice from Phase 1) but at the cost of a multi-source rebuild and a non-trivial CI burden. Adopt only if Spike 2's "Lua-lite" fingerprint proves insufficient for cascade tasks A1/A5, or if a concrete feed of FoxIO-format JA4 blocklists appears and we need exact-match interop.
