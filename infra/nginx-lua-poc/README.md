# PoC #2 stand — OpenResty Lua-only verdict path

Isolated stand for ClickUp task [86exmhy8j](https://app.clickup.com/t/86exmhy8j). Measures the cost of running the verdict pipeline (cache check → blocklist lookup → `ngx.exit`) directly in `access_by_lua`, without round-tripping to a Go sidecar.

## What is — and isn't — being measured

| Layer | In this PoC (Phase 2) | In production |
|---|---|---|
| TLS terminate | OpenResty, TLS 1.3 | CDN operator edge nginx |
| Fingerprint compute | **Real** — sha256 of sorted `$ssl_ciphers` + handshake metadata; `L`-prefix (see [lua/ja4_compute.lua](lua/ja4_compute.lua)) | Same Lua, same fp |
| Verdict path | **Lua** (verdict.lua, shared_dict cache, ngx.exit) | Same Lua |
| Origin proxy | None (return 200 in nginx) | proxy_pass to upstream |

The fingerprint is real (TLS-handshake-derived from `$ssl_ciphers + $ssl_curves + $ssl_protocol + $ssl_alpn_protocol + $ssl_server_name`) and spoof-resistant — a client cannot lie about its TLS library's cipher list by changing UA. It is NOT byte-identical to strict FoxIO JA4 because nginx does not expose the full ClientHello extension list to `access_by_lua`; we hash what is available and gain the cipher-list discriminator without paying for a custom OpenSSL build. See [../../docs/lua-poc-results.md §"Phase 2 — real fp"](../../docs/lua-poc-results.md) for the three-spike comparison and decision.

Phase 1 proved fingerprint extraction works via the FoxIO C module — see [../../../antibot-lab/docs/ja3-poc-results.md](../../../antibot-lab/docs/ja3-poc-results.md). Phase 2 chose a pure-Lua path to avoid a custom build, with FoxIO scaffolding kept ready at [spikes/foxio/](spikes/foxio/) for if/when strict JA4 interop becomes a requirement.

## Layout

```
nginx-lua-poc/
├── certs/                 # self-signed cert (gitignored — generate locally)
├── lua-poc/Dockerfile     # FROM openresty/openresty:alpine
├── lua/
│   ├── blocklist.lua      # hardcoded fingerprint → verdict map
│   ├── init.lua           # init_by_lua: load blocklist into shared dict
│   ├── verdict.lua        # access_by_lua: cache + lookup + ngx.exit
│   └── probe.lua          # /__fp endpoint, dumps fingerprint for probe script
├── nginx.lua.conf         # server config
└── README.md
```

Compose file lives at repo root: `docker-compose.lua-poc.yml`.

## Quickstart

```sh
# 1. Cert (once)
cd infra/nginx-lua-poc/certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 30 \
  -subj "/CN=antibot.local"
cd ../../..

# 2. Stand
docker compose -f docker-compose.lua-poc.yml --profile lua-only up -d --build

# 3. Smoke
curl -k --resolve antibot.local:8443:127.0.0.1 https://antibot.local:8443/__health  # → ok
curl -k --resolve antibot.local:8443:127.0.0.1 https://antibot.local:8443/__fp      # → fp=... cipher=...

# 4. Probe — collect real fingerprints from curl / python / go (and
#    manually from Chrome / Firefox / Safari per the script's
#    "manual browser probes" section).
#    REQUIRED on a fresh clone: the real fp still depends on the
#    client's TLS stack (LibreSSL vs OpenSSL pick different cipher
#    lists), so the reference entries in blocklist.lua WILL NOT match
#    the fps your host produces. You must capture and paste your own.
./scripts/lua-poc-probe.sh

# 5. Edit infra/nginx-lua-poc/lua/blocklist.lua, paste fingerprints
#    you want to block under _M.entries with verdict "block",
#    then reload to re-run init_by_lua:
docker compose -f docker-compose.lua-poc.yml --profile lua-only restart

# 6. Verify
curl -k --resolve antibot.local:8443:127.0.0.1 https://antibot.local:8443/   # → 403 if curl fp in blocklist

# 7. Bench (allow path)
wrk -c100 -d20s -t4 --latency --resolve antibot.local:127.0.0.1 https://antibot.local:8443/

# 8. Tear down
docker compose -f docker-compose.lua-poc.yml --profile lua-only down
```

Results go to [../../docs/lua-poc-results.md](../../docs/lua-poc-results.md).
