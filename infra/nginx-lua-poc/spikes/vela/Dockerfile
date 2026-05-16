# Spike 1 — vela-security/openresty-ssl-ja3.
#
# Builds OpenSSL 1.1.1l (pinned, vendored as openssl-1.1.1l.tar.gz in upstream
# repo) + a patched OpenResty bundle (openresty-ja3.tar.gz) that adds:
#   * SSL_CLIENT_HELLO_CB → captures ClientHello bytes into ngx_event_openssl
#   * ngx_http_lua_ssl_ja3.[ch] → exposes resty.ssl.ja3() Lua API
#
# Build expects centos/yum (per upstream build.sh). We use centos:7 to stay
# close to the documented path; alpine has known fights with OpenSSL 1.1.1l
# on musl + modern gcc. Build time ~10-15 min on M-class arm64 under qemu.

FROM centos:7

# CentOS 7 reached EOL — point yum at the vault mirrors.
RUN sed -i 's/mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo && \
    yum install -y git gcc gcc-c++ make pcre-devel zlib-devel perl which curl tar gzip

WORKDIR /build
RUN git clone --depth 1 https://github.com/vela-security/openresty-ssl-ja3.git src

# Run their build verbatim — keeps blame on upstream for build success.
RUN cd src && bash build.sh

# Smoke marker so the layer is cached even when nginx.conf changes below.
RUN /usr/local/openresty/nginx/sbin/nginx -v 2>&1 | head -1 > /openresty-version.txt

# Bind-mount config + Lua at runtime.
EXPOSE 443
CMD ["/usr/local/openresty/nginx/sbin/nginx", "-g", "daemon off;"]
