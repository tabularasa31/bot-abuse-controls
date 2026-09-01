# Third-party notices

This project is licensed under AGPL-3.0 (see [LICENSE](LICENSE)). The files
listed below are third-party code, vendored unmodified, and remain under their
own license.

## Apache License 2.0

- `infra/demo-stand/lua/resty/ipmatcher.lua` — [lua-resty-ipmatcher](https://github.com/api7/lua-resty-ipmatcher)
  v0.6.1, Copyright API7.ai. Vendored because the stock
  `openresty/openresty:alpine` image does not bundle it.
- `infra/demo-stand/lua/resty/maxminddb.lua` — [lua-resty-maxminddb](https://github.com/anjia0532/lua-resty-maxminddb),
  Copyright 2017-now anjia (anjia0532@gmail.com). Same reason.

The full Apache-2.0 text is available at
<https://www.apache.org/licenses/LICENSE-2.0>. Both files keep their original
copyright and license headers in place.

Go dependencies are declared in `antibot-backend/go.mod` and are not vendored
into this repository.
