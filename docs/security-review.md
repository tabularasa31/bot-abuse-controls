# Security review — abuse-controls antibot

**Last reviewed:** 2026-05-16, ships in PR #3 + PR #4.
**Scope:** the edge Lua verdict pipeline shipping in `infra/nginx-lua-poc/lua/`. The Go sidecar has its own threat model (out of scope here).

This is a self-review intended for operators deciding whether the code is safe to put behind an HTTP request. It's specific, not a generic OWASP checklist.

## Trust boundaries

What the verdict pipeline **trusts**:

- nginx-populated `$ssl_*` variables, populated by stock nginx code during the TLS handshake. We don't parse the handshake ourselves — nginx + OpenSSL do.
- the `lua_shared_dict` contents written by `init_by_lua_file` (we control the loader) and, in production, by the catalog-pull worker (sidecar contract — see RFC §В1).
- the `openresty/openresty:alpine` image's published checksum (we pin no other base image).

What the verdict pipeline **does not trust**:

- `$http_user_agent`, `$remote_addr`, request body, request headers (other than the connection's TLS state). UA is read for the log line, never for any control-flow decision.
- the cipher list values themselves — only their order-after-sort and presence (GREASE filter strips reserved values, per [ADR-003](architecture-decisions/003-grease-strip.md)).
- the SNI string (we record `present|absent` only).

This boundary matters: the only way an attacker affects the pipeline's verdict is by negotiating a TLS handshake. They can't put anything in the request body, URL, or header that changes which blocklist entry they hit. The hash is a function of their TLS library — not their HTTP message.

## Failure modes and behaviour

| Failure | Pipeline behaviour | Why |
|---|---|---|
| `init_by_lua_file` errors at boot | nginx fails to start | Better to fail fast than serve with no blocklist. Catch in CI: [tests/ja4_helpers_test.lua](../tests/ja4_helpers_test.lua) covers the pure-Lua surface; `make ci` runs on every PR. |
| `compute_fp()` throws at request time | nginx logs `[error]`, the request **gets `allow`** verdict and is proxied | OpenResty's default `error_log` directive captures it; we never `ngx.exit(500)` from compute. Fail-open is correct: a crashed antibot should not also break the site. |
| `$ssl_ciphers` empty or truncated by nginx | fp is `L<ver><sni>00<alpn>_000000000000_<curves_hash>` | Falls through to `allow` (no blocklist match). Logged at INFO so we'd notice if it became frequent. |
| `lua_shared_dict fp_blocklist` fills up | `dict:set` returns `nil, "no memory"`, logged at ERR | The blocklist is sized for catalog cardinality (1 MB ≈ 10K entries); cascade 86exmk08u productionises sizing. New entries get rejected; existing entries keep working. |
| `lua_shared_dict verdict_cache` fills up | LRU eviction (built into `shared_dict`) | Worst case: cache hit ratio drops, more shared_dict lookups, slightly higher p99. Not a correctness issue. |
| OpenSSL CVE in the upstream image | Mitigated by `docker pull openresty/openresty:alpine && reload` | We carry no custom OpenSSL build (per [ADR-002](architecture-decisions/002-spike-2-lua-ssl-vars.md)) — no fork to patch, no rebuild to coordinate. |
| Catalog-pull worker pulls a poisoned catalog (sidecar compromised) | The blocklist gains entries from the bad catalog | Out of scope for this review — sidecar `/catalog` endpoint owns provenance; RFC §В1 specifies SemVer + ETag + atomicity. Mitigation: the verdict cache layer means a poisoned entry blocks only requests of that specific fp, not the whole site. |

## Fail-open philosophy

The verdict pipeline **never** does `ngx.exit(5xx)` itself. If our code crashes, the request is served. The reasoning: we are *additive* on top of nginx — if we go wrong, the worst we should do is "do nothing". Hard-fail (returning 500 from Lua) would mean the antibot is a single point of failure for site availability, which we explicitly do not want.

The only `ngx.exit(403)` in the pipeline is the deliberate "block this fp" decision. Even then, the production deployment pattern (see ADR-002 and the cascade) goes through **shadow mode first** (`would_verdict=block` logged but request still proxied) for any new blocklist entry, before flipping to enforcement.

Concrete artefacts:
- [infra/nginx-lua-poc/lua/verdict.lua](../infra/nginx-lua-poc/lua/verdict.lua) — read it; only exit is `ngx.exit(403)` on explicit block verdict. `compute()` is wrapped in `pcall` so a Lua error inside it (truncated `$ssl_*`, missing var, etc.) logs at ERR level and falls through to allow rather than propagating to a 500. Verified end-to-end by injecting `error()` into compute and confirming the request gets 200 not 500.
- [infra/nginx-shadow/lua/verdict.lua](../infra/nginx-shadow/lua/verdict.lua) — shadow-mode variant: logs the would-be verdict but never `ngx.exit`s. Used during the canary deployment phase before flipping to active blocking.

## DoS resistance

The verdict pipeline's cost is **bounded per request**:

- One `ngx.var.*` access × 5 (zero-allocation in nginx; vars already populated)
- One sort of an array ≤49 entries (worst observed in catalog) — Lua's `table.sort`, O(n log n) on small n
- Two SHA-256 invocations on ≤600 bytes each
- Two `lua_shared_dict:get` and one `:set` (lock-free hash lookups)
- One Lua `string.format` to assemble the fp

No loops over the blocklist, no regex over the request body, no syscalls. The cost is **CPU-bound and constant**, so a malicious client cannot construct a request that makes us do more work than a normal request would.

Measured under wrk on a 4-core MacBook: 32K RPS allow path, p99 ~10 ms (see [docs/lua-poc-results.md](lua-poc-results.md) §"Phase 2 — real fp"). The CPU headroom on a production edge is much larger, so the gap to "antibot becomes the bottleneck" is comfortable.

## Privilege and isolation

- Lua runs inside the nginx worker process — unprivileged, sandboxed by nginx's own process model.
- No FFI to native libraries (per [ADR-002](architecture-decisions/002-spike-2-lua-ssl-vars.md), pure Lua + `resty.sha256`/`resty.string`).
- No `os.execute`, no shell, no filesystem writes — the Lua code touches only `lua_shared_dict` (in-memory) and `ngx.log` (write-only to the nginx error log fd).
- No outbound network from the verdict pipeline; the catalog-pull worker (RFC §В1) is separate Lua code with its own review scope.

## Supply chain

| Component | Provenance | Why we trust it |
|---|---|---|
| `openresty/openresty:alpine` | Official Docker Hub image, maintained by OpenResty team | Multi-arch, signed, well-known. Our only base image. |
| `lua-resty-core` (bundled) | Ships in OpenResty | Same supply chain as nginx itself. |
| `resty.sha256`, `resty.string` | Bundled in OpenResty | Same. |
| Our Lua: `ja4_helpers`, `ja4_compute`, `verdict`, `probe`, `init`, `blocklist` | This repo, reviewed in PR #3 / #4 | Authored by us, unit-tested, lint-clean (`make ci`). |
| No other dependencies | — | Nothing else gets `require`'d. |

Compared to the rejected Spike 1 (vendored OpenSSL 1.1.1l + vendored OpenResty tarball + EOL CentOS 7 build base — see [Spike 1 RESULTS.md](../infra/nginx-lua-poc/spikes/vela/RESULTS.md)), our supply chain is intentionally small.

## Data exposure / logging

What gets logged for each request:

- In the production pipeline ([infra/nginx-lua-poc/lua/verdict.lua](../infra/nginx-lua-poc/lua/verdict.lua)): one line at INFO level per cache miss — `verdict=allow|block (cold) fp=L13d... ua=...`. UA is included so a "user complains about a 403" investigation can join on the UA without re-parsing the access log.
- The shadow-mode variant at [infra/nginx-shadow/lua/log_event.lua](../infra/nginx-shadow/lua/log_event.lua) emits one JSON line per request (fp + raw `$ssl_*` components truncated to 256 bytes + UA truncated to 200 chars + method/host/URI/status/request_time/remote_addr).

**Remote IP is logged** in shadow mode (via the JSON event line) and in production (via nginx's default access log if enabled; the antibot's own log line does NOT include remote_addr — it only has verdict + fp + UA). For GDPR / PDN-data compliance, the operator should configure nginx's `set_real_ip_from` + `real_ip_header` to either (a) anonymise (`X-Forwarded-For` from CDN with the last octet stripped) or (b) hash before logging. Not currently implemented — operator responsibility. Flagged for the production handoff (cascade 86exmk0e5).

**Request bodies are never logged.** We don't even read them; the verdict pipeline runs in `access_by_lua`, before the body is processed.

## Known limitations (full disclosure)

- **L-prefix fp is not byte-compatible with FoxIO JA4.** Documented in [ADR-004](architecture-decisions/004-l-prefix-not-foxio.md). Means external JA4 feeds cannot be imported directly.
- **TLS-impersonating bots can defeat us if they perfectly mimic a browser's cipher list.** Per ADR-002, mitigation is cascade A5 — UA↔JA consistency, not strict JA4.
- **GREASE strip is whitelist-based.** We strip the 16 documented GREASE values (RFC 8701). If a new GREASE-like rotation scheme is added to TLS, we won't strip it until we update the pattern. Probability: low (RFC 8701 has been stable since 2019).
- **Cross-validation is component-level, not byte-match.** Documented in [scripts/cross-validate-ja4.sh](../scripts/cross-validate-ja4.sh) and [docs/phase2-fp-catalog.md](phase2-fp-catalog.md).
- **No rate limit on the verdict pipeline itself.** A pathological client can hit us at line rate. The pipeline is bounded-cost per request (above), so this is degraded service not outage — but the cascade A3 rate-limit task addresses it explicitly.
- **shared_dict size sizing is hand-set** (10 MB cache, 1 MB blocklist). Sized for ~100 K cached fps and ~10 K blocklist entries. Production sizing depends on real fp cardinality from a shadow-mode trial — see [infra/nginx-shadow/README.md](../infra/nginx-shadow/README.md).

## What CI catches today

- `make test` — 61 assertions on the pure-Lua helpers (is_grease, split_strip_grease, alpn_two, sni_char, tls_ver_code). Includes all 16 GREASE values, mixed-case variants, near-miss non-GREASE.
- `make lint-lua` — luacheck across 20 Lua files, currently zero warnings.
- `make lint-sh` — shellcheck on probe + cross-validate scripts.
- `make ci` — all of the above; runs on every PR via GitHub Actions ([.github/workflows/ci.yml](../.github/workflows/ci.yml)).

What CI does **not** catch: the full `compute()` integration (depends on OpenResty runtime) and the proxy_pass + log_by_lua end-to-end. Those are covered by manual smoke-tests on the demo stand and the shadow-mode trial.
