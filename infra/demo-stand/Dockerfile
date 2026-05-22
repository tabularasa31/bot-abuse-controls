# Demo-stand image: stock OpenResty + libmaxminddb.
#
# The only addition over openresty/openresty:alpine is the libmaxminddb shared
# library, which lua/resty/maxminddb.lua loads via FFI (ffi.load) for the A6
# GeoLite2 lookup. The Lua sources and nginx.conf are bind-mounted at runtime
# (see docker-compose.demo.yml), so they are NOT copied in here — only the
# native dependency is baked into the image.
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
RUN apk add --no-cache libmaxminddb libmaxminddb-dev
