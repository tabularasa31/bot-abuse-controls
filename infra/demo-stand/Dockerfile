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
# curl + ca-certificates are pulled in for the lua-resty-http fetch step below.
RUN apk add --no-cache libmaxminddb libmaxminddb-dev curl ca-certificates

# lua-resty-http for Channel C (catalog_pull.lua). Pin to v0.17.2 (the latest
# stable as of 2026-05) — bump intentionally and rebuild. We pull the raw
# Lua sources from the github tag (no luarocks/opm dependency on the image)
# and drop them under /usr/local/openresty/site/lualib/resty/, which is on
# OpenResty's default lua_package_path. Three files ship in lib/resty/:
# http.lua, http_headers.lua, http_connect.lua.
ARG LUA_RESTY_HTTP_VERSION=v0.17.2
RUN set -eux; \
    tmpdir="$(mktemp -d)"; \
    curl -fsSL "https://github.com/ledgetech/lua-resty-http/archive/refs/tags/${LUA_RESTY_HTTP_VERSION}.tar.gz" \
        -o "${tmpdir}/src.tar.gz"; \
    tar xzf "${tmpdir}/src.tar.gz" -C "${tmpdir}"; \
    mkdir -p /usr/local/openresty/site/lualib/resty; \
    cp "${tmpdir}/lua-resty-http-${LUA_RESTY_HTTP_VERSION#v}"/lib/resty/*.lua \
        /usr/local/openresty/site/lualib/resty/; \
    chmod 0644 /usr/local/openresty/site/lualib/resty/http*.lua; \
    ls -1 /usr/local/openresty/site/lualib/resty/http*.lua; \
    rm -rf "${tmpdir}"
