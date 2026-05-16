# Phase 2 spikes — real JA3/JA4 in the Lua verdict pipeline

Three independent spikes from RFC §Е of [edge-lua-vs-sidecar.md](../../../docs/architecture/edge-lua-vs-sidecar.md). Each lives in its own directory with a Dockerfile, an nginx config that wires the fingerprint into `compute_fp()`, and a `RESULTS.md` capturing build time, image size, smoke-test fingerprints, and wrk allow-path throughput.

| Spike | Directory | Approach | Build burden |
|---|---|---|---|
| 1 | [vela/](vela/) | Custom OpenResty + JA3 OpenSSL patch (vela-security/openresty-ssl-ja3) | Pinned OpenSSL 1.1.1l, full OpenResty rebuild |
| 2 | [lua-parser/](lua-parser/) | `ssl_client_hello_by_lua_block` parses extensions, computes JA4 in pure Lua | Stock `openresty/openresty:alpine`, no rebuild |
| 3 | [foxio/](foxio/) | FoxIO `ja4-nginx-module` rebuilt against OpenResty with `--with-http_lua_module` + `--with-http_auth_request_module` | C-module recompile per OpenResty bump |

Run each spike's `./run-spike.sh` to bring up its stand (port 8453 / 8454 / 8455 to avoid clashing with the PoC at 8443), smoke-test, and bench. Results aggregated in [docs/lua-poc-results.md](../../../docs/lua-poc-results.md) §"Phase 2 — real fp".

Pass bar per spike: smoke produces real fp != md5(synthetic) for 3 automation clients; wrk allow-path ≥26 K RPS (75 % of the 34.8 K PoC #2 baseline).
