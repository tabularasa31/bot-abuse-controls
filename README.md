# bot-abuse-controls

Bot & Abuse Controls v1 — an antibot cascade for a CDN edge (OpenResty/Lua) with a centralized control plane.

Implements the architectural decision from the [edge Lua vs Go sidecar RFC](docs/architecture/edge-lua-vs-sidecar.md) and [config-distribution.md](docs/architecture/config-distribution.md): filtering runs at the edge in OpenResty/Lua, while the control plane (catalogs, dashboard, rDNS, log sink) is a centralized Go service, [`antibot-backend/`](antibot-backend/). The per-edge sidecar was dropped — see config-distribution §"What was rejected".

## Layout

- `infra/demo-stand/` — long-running demo edge (the cascade itself)
- `infra/demo-backend/` — HA stack for antibot-backend (Postgres + LB)
- `antibot-backend/` — centralized Go service (catalog server + log receiver + rDNS)
- `docs/architecture/config-distribution.md` — the two-channel model (Channel A Puppet + Channel C HTTP pull)
- `docs/architecture/edge-lua-vs-sidecar.md` — the historical RFC (superseded by ADR-005)

## Running it

See [`infra/demo-stand/README.md`](infra/demo-stand/README.md) for the demo edge and
[`antibot-backend/README.md`](antibot-backend/README.md) for the backend.

## License

[AGPL-3.0](LICENSE). Network use counts as distribution: if you run a modified
version as a service, you have to publish the source of your modifications.

Two vendored Lua files stay under Apache-2.0 — see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
