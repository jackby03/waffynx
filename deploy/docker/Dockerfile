# Multi-stage build: nginx (stripped + waffynx module) + Go binaries + configs
# Build: docker build -t waffynx -f deploy/docker/Dockerfile .
#
# To build multi-arch:
# docker buildx create --use
# docker buildx build --platform linux/amd64,linux/arm64 -t waffynx:latest .

ARG BUILDPLATFORM
ARG TARGETPLATFORM

# ============================================================
# Stage 1: Build stripped nginx with waffynx module
# ============================================================
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS nginx-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make libpcre2-dev libssl-dev zlib1g-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/nginx
COPY third_party/nginx/ .

WORKDIR /build/modules
COPY modules/ modules/

WORKDIR /build/nginx
RUN bash auto/configure \
    --prefix=/opt/waffynx/nginx \
    --with-http_ssl_module --with-http_v2_module \
    --with-http_realip_module --with-http_stub_status_module \
    --without-http_charset_module --without-http_gzip_module \
    --without-http_ssi_module --without-http_userid_module \
    --without-http_access_module --without-http_auth_basic_module \
    --without-http_mirror_module --without-http_autoindex_module \
    --without-http_geo_module --without-http_map_module \
    --without-http_split_clients_module --without-http_referer_module \
    --without-http_fastcgi_module --without-http_uwsgi_module \
    --without-http_scgi_module --without-http_memcached_module \
    --without-http_grpc_module --without-http_limit_conn_module \
    --without-http_limit_req_module --without-http_empty_gif_module \
    --without-http_browser_module --without-http_upstream_hash_module \
    --without-http_upstream_ip_hash_module --without-http_upstream_least_conn_module \
    --without-http_upstream_random_module --without-http_upstream_zone_module \
    --without-http_upstream_keepalive_module \
    --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module \
    --add-module=/build/modules/ngx_waffynx

RUN make -j$(nproc) && strip objs/nginx

# ============================================================
# Stage 2: Build Go binaries
# ============================================================
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS go-builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /waffynx ./cmd/waffynx && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /appsec-bridge ./cmd/appsec-bridge && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /waf-api ./cmd/waf-api && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /waf-agent ./cmd/waf-agent

# ============================================================
# Stage 3: Runtime
# ============================================================
FROM --platform=$TARGETPLATFORM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl openssl python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/waffynx
RUN mkdir -p bin config logs nginx/sbin nginx/conf nginx/logs certs

COPY --from=nginx-builder /build/nginx/objs/nginx nginx/sbin/nginx
COPY --from=nginx-builder /build/nginx/conf/mime.types nginx/conf/mime.types

COPY --from=go-builder /waffynx bin/waffynx
COPY --from=go-builder /appsec-bridge bin/appsec-bridge
COPY --from=go-builder /waf-api bin/waf-api
COPY --from=go-builder /waf-agent bin/waf-agent

COPY configs/waffynx.yaml config/waffynx.yaml
COPY deploy/docker/nginx.conf nginx/conf/nginx.conf

COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh bin/*

EXPOSE 8080 8443 9090

ENTRYPOINT ["/entrypoint.sh"]
