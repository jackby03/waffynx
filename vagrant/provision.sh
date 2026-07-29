#!/bin/bash
set -euo pipefail

WAFFYNX_ROOT="${1:-/waffynx}"
WAFFYNX_HOME="/opt/waffynx"
GO_VERSION="1.22.4"
NGINX_BUILD_DIR="/tmp/nginx-build"

echo "============================================"
echo "  Waffynx VM Provisioning"
echo "============================================"
echo "  Project root: $WAFFYNX_ROOT"
echo "  Install dir:  $WAFFYNX_HOME"
echo "  Go version:   $GO_VERSION"
echo "============================================"

# ================================================================
# 1. System dependencies
# ================================================================
echo "==> Installing system packages..."
apt-get update -qq
apt-get install -y \
    build-essential \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev \
    libmaxminddb-dev \
    nftables \
    curl \
    wget \
    jq \
    git \
    ca-certificates \
    unzip \
    python3 \
    2>&1 | tail -3 || true

# Fallback: try PCRE2 if PCRE not available
if ! dpkg -l libpcre3-dev &>/dev/null; then
    echo "  Trying libpcre2-dev..."
    apt-get install -y libpcre2-dev 2>/dev/null || true
fi

# Verify GCC is available
if ! command -v cc &>/dev/null; then
    echo "CC not found, retrying package install..."
    apt-get install -y build-essential
fi
echo "==> C compiler: $(cc --version | head -1)"

# ================================================================
# 2. Install Go
# ================================================================
if ! command -v go &>/dev/null; then
    echo "==> Installing Go $GO_VERSION..."
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    rm /tmp/go.tar.gz
fi
echo "==> Go version: $(go version)"

# ================================================================
# 3. Build nginx with ngx_waffynx module
# ================================================================
echo "==> Building nginx with waffynx module..."

# VirtualBox shared folders (vboxsf) don't support the filesystem
# operations that nginx's auto/configure needs (temp files, symlinks).
# Copy source to a local directory first.
rm -rf "$NGINX_BUILD_DIR"
cp -r "$WAFFYNX_ROOT/third_party/nginx" "$NGINX_BUILD_DIR"
cp -r "$WAFFYNX_ROOT/modules" "$NGINX_BUILD_DIR/modules"

cd "$NGINX_BUILD_DIR"

# Strip CRLF from all files (Windows -> Linux)
find . -type f -exec sed -i 's/\r$//' {} \; 2>/dev/null || true

if ! bash auto/configure \
    --prefix="$WAFFYNX_HOME/nginx" \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_realip_module \
    --with-http_stub_status_module \
    --without-http_charset_module \
    --without-http_gzip_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_access_module \
    --without-http_auth_basic_module \
    --without-http_mirror_module \
    --without-http_autoindex_module \
    --without-http_geo_module \
    --without-http_map_module \
    --without-http_split_clients_module \
    --without-http_referer_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --without-http_memcached_module \
    --without-http_limit_conn_module \
    --without-http_limit_req_module \
    --without-http_empty_gif_module \
    --without-http_browser_module \
    --without-http_upstream_hash_module \
    --without-http_upstream_ip_hash_module \
    --without-http_upstream_least_conn_module \
    --without-http_upstream_random_module \
    --without-http_upstream_zone_module \
    --without-http_upstream_keepalive_module \
    --without-mail_pop3_module \
    --without-mail_imap_module \
    --without-mail_smtp_module \
    --add-module="$NGINX_BUILD_DIR/modules/ngx_waffynx" \
    > /tmp/nginx-configure.log 2>&1; then
    echo "ERROR: nginx configure failed:"
    cat /tmp/nginx-configure.log
    exit 1
fi

make -j$(nproc) > /tmp/nginx-make.log 2>&1

echo "==> Nginx build complete"

# ================================================================
# 3.5 Build C++ bridge library
# ================================================================
echo "==> Building open-appsec C++ bridge..."
cd "$WAFFYNX_ROOT"
make bridge-build || true

# ================================================================
# 4. Build Go binaries
# ================================================================
echo "==> Building Go binaries..."
cd "$WAFFYNX_ROOT"

for cmd in waffynx waf-agent waf-api appsec-bridge; do
    echo "     Building $cmd..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -ldflags="-s -w" -o "dist/$cmd" "./cmd/$cmd"
done

echo "==> Go build complete"

# ================================================================
# 5. Install everything to /opt/waffynx
# ================================================================
echo "==> Installing to $WAFFYNX_HOME..."

mkdir -p "$WAFFYNX_HOME/bin"
mkdir -p "$WAFFYNX_HOME/lib"
mkdir -p "$WAFFYNX_HOME/config"
mkdir -p "$WAFFYNX_HOME/logs"
mkdir -p "$WAFFYNX_HOME/nginx/sbin"
mkdir -p "$WAFFYNX_HOME/nginx/conf"
mkdir -p "$WAFFYNX_HOME/nginx/logs"
mkdir -p "$WAFFYNX_HOME/nginx/client_body_temp"
mkdir -p "$WAFFYNX_HOME/nginx/proxy_temp"
mkdir -p "$WAFFYNX_HOME/appsec"

# Copy nginx binary and config
cp "$NGINX_BUILD_DIR/objs/nginx" "$WAFFYNX_HOME/nginx/sbin/nginx"
cp "$NGINX_BUILD_DIR/conf/mime.types" "$WAFFYNX_HOME/nginx/conf/"

# Copy binaries and libraries
cp "$WAFFYNX_ROOT/dist/"* "$WAFFYNX_HOME/bin/" 2>/dev/null || cp "$WAFFYNX_ROOT/bin/"* "$WAFFYNX_HOME/bin/" 2>/dev/null || true
chmod +x "$WAFFYNX_HOME/bin/"*

# Copy and render nginx.conf
cp "$WAFFYNX_ROOT/configs/nginx.conf" "$WAFFYNX_HOME/nginx/conf/nginx.conf"
sed -i "s|/var/run/waffynx.sock|$WAFFYNX_HOME/waffynx.sock|g" \
    "$WAFFYNX_HOME/nginx/conf/nginx.conf"
sed -i "s|/opt/waffynx|$WAFFYNX_HOME|g" \
    "$WAFFYNX_HOME/nginx/conf/nginx.conf"

# Copy systemd units and fix to run as root in test VM
cp "$WAFFYNX_ROOT/deploy/systemd/waffynx.service" /etc/systemd/system/
cp "$WAFFYNX_ROOT/deploy/systemd/waf-agent.service" /etc/systemd/system/
cp "$WAFFYNX_ROOT/configs/agent.yaml" "$WAFFYNX_HOME/config/agent.yaml"

# Download GeoLite2 database (optional, requires license key)
if [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
    mkdir -p "$WAFFYNX_HOME/geoip"
    echo "==> Downloading GeoLite2-Country database..."
    if ! curl -sS --max-time 30 -o "$WAFFYNX_HOME/geoip/GeoLite2-Country.mmdb" \
        "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"; then
        echo "    NOTE: GeoLite2 download failed; geo-block will operate in passthrough mode"
    fi
fi
sed -i 's/User=waffynx/User=root/g' /etc/systemd/system/waffynx.service
sed -i 's/Group=waffynx/Group=root/g' /etc/systemd/system/waffynx.service
# Disable ProtectSystem for the test VM (it makes /opt read-only)
sed -i 's/ProtectSystem=strict/ProtectSystem=false/' /etc/systemd/system/waffynx.service
# Fix all paths
sed -i "s|/opt/waffynx|$WAFFYNX_HOME|g" /etc/systemd/system/waffynx.service
sed -i "s|/opt/waffynx|$WAFFYNX_HOME|g" /etc/systemd/system/waf-agent.service

# Create appsec-bridge service
cat > /etc/systemd/system/appsec-bridge.service << SERVICE
[Unit]
Description=Waffynx AppSec Bridge (open-appsec compatible ML daemon)
After=network.target

[Service]
Type=simple
ExecStart=$WAFFYNX_HOME/bin/appsec-bridge -s $WAFFYNX_HOME/open-appsec.sock
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload

echo "==> Installation complete"

# ================================================================
# 6. Start services
# ================================================================
echo "==> Starting services..."

systemctl enable appsec-bridge
systemctl enable waffynx

systemctl start appsec-bridge
sleep 1

# Update config: enable appsec with bridge mode
cat > "$WAFFYNX_HOME/config/waffynx.yaml" << YAML
name: "waffynx"
version: "1"
listen: ":8443"
logging:
  level: "debug"
  format: "console"
  output: "stdout"
sidecar:
  socket_path: "${WAFFYNX_HOME}/waffynx.sock"
  fail_open: true
  timeout_ms: 100
nginx:
  binary_path: "${WAFFYNX_HOME}/nginx/sbin/nginx"
  config_path: "${WAFFYNX_HOME}/nginx/conf"
  worker_processes: 1
  worker_connections: 1024
  enable_http2: false
appsec:
  enabled: true
  engine: "open-appsec"
  bridge_socket: "${WAFFYNX_HOME}/open-appsec.sock"
  timeout_ms: 200
gateway:
  max_connections: 1024
  read_timeout: 30
  write_timeout: 30
  idle_timeout: 60
firewall:
  enabled: false
api:
  enabled: false
  listen: ":9090"
  auth:
    jwt_secret: "change-me-in-production"
    token_ttl: 3600
routes: []
plugins:
  - name: "request-validation"
    enabled: true
    config:
      max_body_size: 10485760
  - name: "bot-protection"
    enabled: true
    config:
      mode: "block"
  - name: "geo-block"
    enabled: true
    config:
      mode: "block"
      db_path: "${WAFFYNX_HOME}/geoip/GeoLite2-Country.mmdb"
      blocked_countries: []
      allowed_countries:
        - "US"
        - "MX"
        - "CA"
  - name: "rate-limit"
    enabled: true
    config:
      requests_per_second: 100
      burst: 200
YAML

systemctl start waffynx
sleep 2

echo ""
echo "============================================"
echo "  Waffynx is ready!"
echo "============================================"
echo "  WAF:     http://localhost:8080"
echo "  Sidecar: $WAFFYNX_HOME/waffynx.sock"
echo "  Bridge:  $WAFFYNX_HOME/open-appsec.sock"
echo "  Logs:    journalctl -u waffynx -f"
echo "============================================"
