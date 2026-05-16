# PoC #2 — OpenResty Lua-only verdict path

ClickUp task [86exmhy8j](https://app.clickup.com/t/86exmhy8j). Measures whether running the Bot & Abuse Controls verdict pipeline (cache → blocklist → `ngx.exit`) entirely in `access_by_lua` on the edge is viable as an alternative to round-tripping every request to the Go sidecar via `auth_request`.

> **What this PoC does not prove.** The fingerprint computed in [verdict.lua](../infra/nginx-lua-poc/lua/verdict.lua) is **synthetic** — `md5(ssl_cipher .. ":" .. ssl_protocol .. ":" .. ua[:32])` — not real JA3/JA4. We picked synthetic because there is no off-the-shelf Lua library that computes JA3 from the raw ClientHello (`vela-security/openresty-ssl-ja3` is a custom-patched OpenResty image; `paragor/qrator-ja3-nginx` is only a Qrator-format reformatter), and rolling our own ClientHello parser is Phase 2 work. The architectural question this PoC answers — *is the Lua verdict pipeline fast enough on the edge?* — is orthogonal to where the fingerprint comes from. Phase 1 ([antibot-lab/docs/ja3-poc-results.md](../../antibot-lab/docs/ja3-poc-results.md)) already proved JA4 extraction via the FoxIO C module; Phase 2 will wire that into the Lua pipeline.

## Setup

- macOS arm64 M-class, OpenResty `1.29.2.3` on `openresty/openresty:alpine` (multi-arch, **native arm64** — unlike Phase 1's FoxIO image which was amd64-under-Rosetta).
- TLS 1.3 self-signed cert. `ssl_session_cache off` not strictly needed for this PoC (no raw ClientHello parsing) but kept consistent with Phase 1.
- `lua_shared_dict verdict_cache 10m` + `lua_shared_dict fp_blocklist 1m`, both populated at `init_by_lua`. 4 entries in blocklist (synthetic fps for curl, Go, python-requests, wrk).
- `access_by_lua_file verdict.lua` on `location /`, `content_by_lua_block ngx.print("ok\n")` for the allow path (no upstream — isolates the verdict-pipeline cost).
- `wrk 4.2.0`, `-c100 -d20s -t4 --latency`, host loopback (`https://127.0.0.1:8443/`).

## Bench: 2026-05-16, M-class MacBook Pro

| Variant | Path | RPS | p50 | p75 | p90 | p99 | Notes |
|---|---|---:|---:|---:|---:|---:|---|
| Baseline (no Lua, `/__health`) | TLS + nginx `return 200` | **39 746** | 2.25 ms | 2.93 ms | 3.89 ms | 8.90 ms | Same OpenResty image; no `access_by_lua`. |
| PoC #2 — allow path | TLS + `access_by_lua` (cache miss/hit) + `content_by_lua` 200 | **34 808** | 2.49 ms | 3.37 ms | 4.89 ms | 25.39 ms | 100 conns × 4 threads; cache warm after first req per fp. |
| PoC #2 — block path | TLS + `access_by_lua` → `ngx.exit(403)` | **36 523** | 2.44 ms | 3.22 ms | 4.33 ms | 10.21 ms | Verified all 730 935 responses non-2xx (`Non-2xx or 3xx responses: 730935` in wrk output). |

**Cost of the Lua verdict pipeline (allow path vs baseline):**
- RPS: −12% (39 746 → 34 808)
- p50: +0.24 ms
- p99: +16.5 ms (long tail likely from shared_dict contention under 4-thread cache misses; production would have a flatter distribution with longer steady-state and warmer caches)

**Block path is cheaper than allow** by a small margin (less work after `ngx.exit`, no content phase, no body) — but within the same order of magnitude, confirming the pipeline cost is dominated by the shared_dict lookup, not by the response handling.

## Comparison with Phase 1 numbers

Phase 1 ran on the **same M-class MacBook Pro** but with different stacks. Numbers from [antibot-lab/docs/ja3-poc-results.md](../../antibot-lab/docs/ja3-poc-results.md):

| Stand | Path | RPS | p50 | p99 | Confounder |
|---|---|---:|---:|---:|---|
| Baseline `nginx:alpine` (arm64) | `auth_request → antibot:9000 → origin` | 12 307 | 7.4 ms | 35.2 ms | Includes upstream + Go sidecar; antibot returned challenge for `wrk` UA → some block-issuance latency in RPS. |
| Variant B FoxIO (amd64 via Rosetta) | `/__ja4` nginx-only `return 200` | 2 638 | 22.7 ms | 828 ms | Rosetta overhead dominates; not comparable to native arm64. |
| **PoC #2 allow (this doc)** | `access_by_lua` → `ngx.print` | **34 808** | **2.49 ms** | **25.39 ms** | Native arm64, no upstream. |
| **PoC #2 block (this doc)** | `access_by_lua` → `ngx.exit(403)` | **36 523** | **2.44 ms** | **10.21 ms** | Native arm64. |

PoC #2 numbers are **higher** than Phase 1 baseline because Phase 1 baseline included a full HTTP round-trip to the Go sidecar plus a proxy to origin, whereas PoC #2 terminates the response in nginx. The two are not directly comparable as "edge Lua vs Go sidecar overhead" — they compare different total stacks. The right comparison is:

- **PoC #2 allow vs PoC #2 baseline** (same stack, same hardware, only difference is the Lua verdict pipeline) → **−12% RPS, +0.24 ms p50** is the cost of the verdict pipeline.
- **PoC #2 block vs Phase 1 baseline** → **PoC #2 block path is ~3× faster** (36.5K vs 12.3K RPS) at the conceptual cost of "drop a request" because no auth_request round-trip is needed.

## Conclusion

**The Lua verdict pipeline is viable on the edge.** A simple cache + shared_dict lookup in `access_by_lua` costs ~10–12% throughput on top of pure nginx+TLS, and adds sub-millisecond median latency. The p99 tail is wider than the baseline but still within an acceptable budget for a CDN edge.

Decisions for the [edge Lua vs Go sidecar RFC](architecture/edge-lua-vs-sidecar.md):
- Verdict cache + blocklist lookup → **edge Lua** (terminating, fast, no sidecar round-trip).
- Sidecar round-trip (`auth_request` or `ngx.location.capture`) reserved for the 5–10% "grey" verdicts that need heavy scoring or fresh state.

## Reproduce

```sh
cd abuse-controls
docker compose -f docker-compose.lua-poc.yml --profile lua-only up -d --build

# bench
wrk -c100 -d20s -t4 --latency -H "Host: antibot.local" \
    -H "User-Agent: Mozilla/5.0 ...Chrome/130.0" \
    https://127.0.0.1:8443/          # allow

wrk -c100 -d20s -t4 --latency -H "Host: antibot.local" \
    -H "User-Agent: curl/8.7.1" \
    https://127.0.0.1:8443/          # block (fp must be in blocklist.lua)

wrk -c100 -d20s -t4 --latency -H "Host: antibot.local" \
    https://127.0.0.1:8443/__health  # baseline (no Lua)
```

## Open follow-ups (Phase 2)

- Real JA3/JA4 from ClientHello — either custom OpenResty build (vela-security/openresty-ssl-ja3) or our own Lua parser using `ssl_client_hello_by_lua` from OpenResty ≥1.19.
- Sidecar catalog-pull benchmark — measure the `ngx.timer.every` + `http.request_uri` hot-reload cost at the worker level.
- p99 tail investigation — is the long tail from shared_dict spinlock contention? Try `lua-resty-lrucache` for per-worker cache layer to reduce shared_dict pressure.
