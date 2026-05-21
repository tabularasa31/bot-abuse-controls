# infra/ — what each directory is

Two directories, two distinct roles. They are **not** competing "stands".

## `demo-stand/` — the live demo

The hosted demo (`bac.example.com`): a real OpenResty reverse proxy that
runs the full verdict cascade and proxies to an origin (`ORIGIN_URL`). Runs
in **shadow** (empty blocklist — computes and logs verdicts, blocks nothing).
This is the one thing we actually deploy and keep alive. Has its own
observability (`/__admin`, `/metrics`), structured `BAC_LOG`, analytics
(`scripts/analyze.py`), and a cron auto-update loop. See
[`demo-stand/README.md`](demo-stand/README.md).

It does **not** vendor the fingerprint code — it bind-mounts
`nginx-lua-poc/lua` (see below) so the demo runs the exact production
compute, not a drifting copy.

## `nginx-lua-poc/` — canonical fp library + PoC benchmark

Home of the production fingerprint code: [`lua/ja4_compute.lua`](nginx-lua-poc/lua/ja4_compute.lua)
and [`lua/ja4_helpers.lua`](nginx-lua-poc/lua/ja4_helpers.lua). Also the
isolated rig that measured the cost of running the verdict path in
`access_by_lua` (PoC #2, task [86exmhy8j](https://app.clickup.com/t/86exmhy8j);
`../docker-compose.lua-poc.yml`). Treat it as a **shared library + benchmark**,
not a deployable stand — `demo-stand` depends on its `lua/`.

## Not here anymore

- **`nginx-shadow/`** — removed. It was a separate "shadow proxy in front of
  a real backend" package; that role is now exactly `demo-stand` (shadow +
  proxy to `ORIGIN_URL`), and keeping it meant a third drifting copy of the
  pipeline.

## Related (other repo)

The **vanilla** stack (FoxIO `ja4-nginx-module` + Go sidecar,
`bac-vanilla.example.com`) lives in the separate
[`antibot-lab`](https://github.com/tabularasa31/antibot-lab) repo — a parallel
comparison track, not part of this repo.
