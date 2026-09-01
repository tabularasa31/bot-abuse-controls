# infra/ — what each directory is

Three directories — two live stands and one historical marker. They are **not** competing "stands".

## `demo-stand/` — the live demo

The hosted demo (`bac.example.com`): a real OpenResty reverse proxy that
runs the full verdict cascade and proxies to an origin (`ORIGIN_URL`). Runs
in **shadow** (empty blocklist — computes and logs verdicts, blocks nothing).
This is the one thing we actually deploy and keep alive. Has its own
observability (counters + deploy metadata as `EDGE_STATS` → Loki
`{kind="edge_stats"}`, plus a private read-only mgmt plane on `:9090`),
structured `BAC_LOG`, analytics (`scripts/analyze.py`), and a cron
auto-update loop. See
[`demo-stand/README.md`](demo-stand/README.md).

The source of truth for the fingerprint code
([`lua/ja4_compute.lua`](demo-stand/lua/ja4_compute.lua),
[`lua/ja4_helpers.lua`](demo-stand/lua/ja4_helpers.lua)) lives here too, next
to the rest of the cascade.

## `demo-backend/` — the antibot-backend HA stack

Docker compose substrate (Postgres + an HA pair of antibot-backend behind a
TLS LB) for the centralized Go service in
[`antibot-backend/`](../antibot-backend/), per ADR-005 / config-distribution.
See [`demo-backend/README.md`](demo-backend/README.md).

## `nginx-lua-poc/` — removed

This was a separate spike, PoC #2 (an `access_by_lua` verdict path benchmark).
Once `ja4_compute.lua` / `ja4_helpers.lua` moved into `demo-stand/lua/`, the
directory was deleted outright, along with everything around it
(`docker-compose.lua-poc.yml`, `scripts/lua-poc-probe.sh`,
`docs/lua-poc-results.md`, `docs/phase2-fp-catalog.md`).

## Not here anymore

- **`nginx-shadow/`** — removed. It was a separate "shadow proxy in front of
  a real backend" package; that role is now exactly `demo-stand` (shadow +
  proxy to `ORIGIN_URL`), and keeping it meant a third drifting copy of the
  pipeline.

## Related (other repo)

The **vanilla** stack (FoxIO `ja4-nginx-module` + Go sidecar,
`bac-vanilla.example.com`) lives in a separate `antibot-lab` repo — a
parallel comparison track, not part of this repo.
