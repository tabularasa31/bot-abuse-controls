# PoC #2 stand — OpenResty Lua-only verdict path

Isolated stand for ClickUp task [86exmhy8j](https://app.clickup.com/t/86exmhy8j). Measures the cost of running the verdict pipeline (cache check → blocklist lookup → `ngx.exit`) directly in `access_by_lua`, without round-tripping to a Go sidecar.

## What is — and isn't — being measured

| Layer | In this PoC | In production (Phase 2+) |
|---|---|---|
| TLS terminate | OpenResty, TLS 1.3 | CDN operator edge nginx |
| Fingerprint compute | **Synthetic** (md5 of cipher + protocol + UA prefix) | Real JA3/JA4 — Phase 2 |
| Verdict path | **Lua** (verdict.lua, shared_dict cache, ngx.exit) | Same Lua, real fingerprint |
| Origin proxy | None (return 200 in nginx) | proxy_pass to upstream |

The synthetic fingerprint exists only to make the verdict path deterministic per client class without depending on a JA3-aware build of OpenResty (none of the off-the-shelf Lua libraries actually compute JA3 from `ClientHello`; the question of *where the fingerprint comes from* is orthogonal to *can Lua handle the verdict pipeline*).

Phase 1 already proved fingerprint extraction works via the FoxIO C module — see [../../../antibot-lab/docs/ja3-poc-results.md](../../../antibot-lab/docs/ja3-poc-results.md). Phase 2 will wire that into the Lua pipeline.

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

# 4. Probe — collect fingerprints from curl / python / go
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
