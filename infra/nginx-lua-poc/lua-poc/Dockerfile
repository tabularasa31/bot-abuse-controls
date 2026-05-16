FROM openresty/openresty:alpine

# Toolbelt for in-container probing and the openresty NOTICE/INFO log levels.
RUN apk add --no-cache curl bash

# Lua modules, config, and certs all come in via docker-compose bind mounts
# so we can iterate without rebuilds. See docker-compose.lua-poc.yml.
