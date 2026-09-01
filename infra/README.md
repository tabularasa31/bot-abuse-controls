# infra/ — what each directory is

## `demo-stand/` — the edge

A real OpenResty reverse proxy running the full verdict cascade. A host with a
non-empty `origin_ip` in its policy is proxied to that origin; everything else is
dropped with 444. Whether a verdict is enforced is per host: `mode=shadow`
computes and logs it, `mode=active` acts on it.

It carries its own observability — counters and deploy metadata pushed as
`EDGE_STATS` to Loki, the structured `BAC_LOG` stream, and a private read-only
management plane on `:9090` — plus the analytics in `scripts/analyze.py` and an
auto-update loop. See [`demo-stand/README.md`](demo-stand/README.md).

The fingerprint code ([`lua/ja4_compute.lua`](demo-stand/lua/ja4_compute.lua),
[`lua/ja4_helpers.lua`](demo-stand/lua/ja4_helpers.lua)) lives here, next to the
rest of the cascade.

## `demo-backend/` — the control plane's stack

Compose substrate for the Go service in
[`antibot-backend/`](../antibot-backend/): PostgreSQL plus a pair of backend
instances behind a TLS-terminating load balancer. See
[`demo-backend/README.md`](demo-backend/README.md) and
[config-distribution](../docs/architecture/config-distribution.md).

## `test-harness/` — the integration harness

Brings the edge and the backend up together under compose with accelerated pull
intervals and runs the catalog-contract cases from `tests/integration/`: delivery
latency, atomicity of a catalog swap, and fail-stale behaviour when the backend
is unreachable. See [`test-harness/README.md`](test-harness/README.md).
