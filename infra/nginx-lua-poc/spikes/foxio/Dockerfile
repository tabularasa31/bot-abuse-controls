# Spike 3 — FoxIO ja4-nginx-module rebuilt with lua-nginx-module +
# auth_request, so the same image can host both the JA4 source-of-truth
# and the verdict pipeline.
#
# Mirrors FoxIO's upstream Dockerfile structure (nginx 1.30.0 source +
# OpenSSL 4.0.0 source + nginx.patch) but adds ngx_devel_kit +
# lua-nginx-module + LuaJIT, plus --with-http_auth_request_module.
#
# Build is expensive: OpenSSL 4.0.0 + nginx + lua + module ~ 25-40 min on
# M-class arm64 under qemu emulation. RESULTS.md documents wall-clock.

FROM alpine:3.20 AS base
RUN apk add --no-cache \
    gcc libc-dev make openssl-dev pcre-dev zlib-dev wget patch perl-dev \
    nghttp2-dev nghttp3-dev linux-headers git tar gzip

FROM base AS sources
WORKDIR /tmp
ARG NGINX_VERSION=1.30.0
ARG OPENSSL_VERSION=4.0.0
ARG LUAJIT_VERSION=2.1-20250529
ARG NDK_VERSION=0.3.4
ARG LUA_NGINX_VERSION=0.10.28

RUN wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz && \
    wget -q https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar -zxf openssl-${OPENSSL_VERSION}.tar.gz && \
    wget -q https://github.com/openresty/luajit2/archive/v${LUAJIT_VERSION}.tar.gz -O luajit2.tar.gz && \
    tar -zxf luajit2.tar.gz && \
    wget -q https://github.com/vision5/ngx_devel_kit/archive/v${NDK_VERSION}.tar.gz -O ndk.tar.gz && \
    tar -zxf ndk.tar.gz && \
    wget -q https://github.com/openresty/lua-nginx-module/archive/v${LUA_NGINX_VERSION}.tar.gz -O lua-nginx-module.tar.gz && \
    tar -zxf lua-nginx-module.tar.gz && \
    git clone --depth 1 https://github.com/FoxIO-LLC/ja4-nginx-module.git

FROM sources AS build
ARG LUAJIT_VERSION=2.1-20250529
RUN cd /tmp/luajit2-${LUAJIT_VERSION} && make -j$(nproc) && make install PREFIX=/usr/local/luajit
ENV LUAJIT_LIB=/usr/local/luajit/lib LUAJIT_INC=/usr/local/luajit/include/luajit-2.1

ARG NGINX_VERSION=1.30.0
ARG OPENSSL_VERSION=4.0.0
ARG NDK_VERSION=0.3.4
ARG LUA_NGINX_VERSION=0.10.28

WORKDIR /tmp/nginx-${NGINX_VERSION}
RUN patch -p1 < /tmp/ja4-nginx-module/patches/nginx.patch && \
    ./configure \
      --prefix=/etc/nginx \
      --with-openssl=/tmp/openssl-${OPENSSL_VERSION} \
      --with-http_ssl_module \
      --with-http_v2_module \
      --with-http_auth_request_module \
      --with-compat \
      --with-ld-opt="-Wl,-rpath,/usr/local/luajit/lib" \
      --add-module=/tmp/ngx_devel_kit-${NDK_VERSION} \
      --add-module=/tmp/lua-nginx-module-${LUA_NGINX_VERSION} \
      --add-module=/tmp/ja4-nginx-module/src && \
    make -j$(nproc) && make install

FROM alpine:3.20
RUN apk add --no-cache pcre zlib openssl libstdc++ && \
    addgroup -S nginx && adduser -S -G nginx nginx
COPY --from=build /etc/nginx /etc/nginx
COPY --from=build /usr/local/luajit /usr/local/luajit
RUN mkdir -p /etc/nginx/lua /etc/nginx/logs && \
    ln -sf /dev/stdout /etc/nginx/logs/access.log && \
    ln -sf /dev/stderr /etc/nginx/logs/error.log
EXPOSE 443
CMD ["/etc/nginx/sbin/nginx", "-g", "daemon off;"]
