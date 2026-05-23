# Demo-stand image: stock OpenResty + libmaxminddb + lua-resty-http.
#
# Additions over openresty/openresty:alpine:
#   1. libmaxminddb shared library — lua/resty/maxminddb.lua loads it via FFI
#      (ffi.load) for the A6 GeoLite2 lookup.
#   2. lua-resty-http (pinned tag) — Channel C client in catalog_pull.lua
#      (B5/B6) requires it for the conditional GET against antibot-backend.
#      The base openresty/alpine image does NOT ship it, so without this step
#      `require "resty.http"` fails at init_worker and Channel C is disabled
#      (the existing pcall logs an error and the edge falls back to the static
#      seed). Pinned via tag so the build is reproducible — bump deliberately.
#
# Lua sources and nginx.conf are bind-mounted at runtime (see
# docker-compose.demo.yml), so they are NOT copied in here — only native
# dependencies + third-party Lua libs are baked into the image.
#
# The GeoLite2 .mmdb databases are license-gated (MaxMind) and therefore NOT
# baked in either: fetch them with scripts/fetch-geoip.sh and mount the geoip/
# directory at runtime. Without them the stand still starts (geoip.lua is
# fail-open) — geo is simply undetermined.
FROM openresty/openresty:alpine

# libmaxminddb-libs ships libmaxminddb.so.0 (the runtime). lua/resty/maxminddb.lua
# loads it via ffi.load('libmaxminddb'), which dlopen()s the *unversioned*
# libmaxminddb.so — that symlink lives in -dev, so install it too or the load
# fails and geo silently disables. libmaxminddb (the tools pkg) is kept for the
# `mmdblookup` CLI, handy for debugging the .mmdb on the stand.
#
# ca-certificates is runtime: lua-resty-http needs trusted roots for HTTPS to
# antibot-backend on the production path.
RUN apk add --no-cache libmaxminddb libmaxminddb-dev ca-certificates

# lua-resty-http for Channel C (catalog_pull.lua). Pin to v0.17.2 (the latest
# stable as of 2026-05) — bump intentionally and rebuild. We pull the raw
# Lua sources from the github tag (no luarocks/opm dependency on the image)
# and drop them under /usr/local/openresty/site/lualib/resty/, which is on
# OpenResty's default lua_package_path. Three files ship in lib/resty/:
# http.lua, http_headers.lua, http_connect.lua.
#
# lua-resty-openssl is a hard requirement for the mTLS path: lua-resty-http
# v0.17.x calls `require "resty.openssl.x509.chain"` to validate the client
# cert before handing it to ssl handshake. Without it, http_connect.lua emits
# `mTLS isn't supported without lua-resty-openssl` and the fetch falls into
# fail-stale (verified on the <EDGE_VM_IP> stand: gauge stuck at -1, log
# fires on every tick). We unpack only the `resty/` subtree — keeping the
# image lean — and pin the same way.
#
# curl is install-only — pulled in as a virtual build-deps package and removed
# in the same RUN to keep it out of the final image (gemini review). curl also
# happens to be a transitive dep of libmaxminddb, so the final image keeps it
# regardless; the virtual marker still documents intent.
ARG LUA_RESTY_HTTP_VERSION=v0.17.2
ARG LUA_RESTY_OPENSSL_VERSION=1.7.1
RUN set -eux; \
    apk add --no-cache --virtual .build-deps curl; \
    mkdir -p /usr/local/openresty/site/lualib; \
    curl -fsSL "https://github.com/ledgetech/lua-resty-http/archive/refs/tags/${LUA_RESTY_HTTP_VERSION}.tar.gz" \
        | tar xzf - -C /usr/local/openresty/site/lualib \
            --strip-components=2 \
            "lua-resty-http-${LUA_RESTY_HTTP_VERSION#v}/lib/"; \
    ls -1 /usr/local/openresty/site/lualib/resty/http*.lua; \
    curl -fsSL "https://github.com/fffonion/lua-resty-openssl/archive/refs/tags/${LUA_RESTY_OPENSSL_VERSION}.tar.gz" \
        | tar xzf - -C /usr/local/openresty/site/lualib \
            --strip-components=2 \
            "lua-resty-openssl-${LUA_RESTY_OPENSSL_VERSION}/lib/"; \
    test -f /usr/local/openresty/site/lualib/resty/openssl/x509/chain.lua; \
    test -f /usr/local/openresty/site/lualib/resty/openssl.lua; \
    # Single chmod over the whole site/lualib/resty subtree — catches http*.lua,
    # openssl.lua (entry point), and resty/openssl/**/*.lua. site/lualib is
    # ours-only (base image's resty/ lives under lualib/, not site/lualib/),
    # so this is safe to broaden. Fixes gemini-review on PR #47: openssl.lua
    # was landing with 664 because the previous find rooted at resty/openssl/
    # missed it.
    find /usr/local/openresty/site/lualib/resty -type f -name '*.lua' -exec chmod 0644 {} +; \
    apk del .build-deps
