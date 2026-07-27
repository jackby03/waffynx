#!/bin/bash
set -euo pipefail

WAFFYNX_ROOT="${1:-/waffynx}"
WAFFYNX_HOME="/opt/waffynx"
GO_VERSION="1.22.4"

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
apt-get install -y -qq \
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
    > /dev/null

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

# Fix Windows CRLF -> LF in nginx source
find "$WAFFYNX_ROOT/third_party/nginx" -type f -not -path "*/.git/*" -exec sed -i 's/\r$//' {} \; 2>/dev/null || true
find "$WAFFYNX_ROOT/modules" -type f -exec sed -i 's/\r$//' {} \; 2>/dev/null || true

cd "$WAFFYNX_ROOT/third_party/nginx"

# Reconfigure with the VM's prefix
bash auto/configure \
    --prefix="$WAFFYNX_HOME/nginx" \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_realip_module \
    --with-http_stub_status_module \
    --with-stream \
    --with-stream_ssl_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --without-http_memcached_module \
    --without-mail_pop3_module \
    --without-mail_imap_module \
    --without-mail_smtp_module \
    --add-module="$WAFFYNX_ROOT/modules/ngx_waffynx" \
    > /tmp/nginx-configure.log 2>&1

make -j$(nproc) > /tmp/nginx-make.log 2>&1

echo "==> Nginx build complete"

# ================================================================
# 4. Build Go binaries
# ================================================================
echo "==> Building Go binaries..."
cd "$WAFFYNX_ROOT"

for cmd in waffynx waf-agent waf-api appsec-bridge; do
    echo "     Building $cmd..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -ldflags="-s -w" -o "bin/$cmd" "./cmd/$cmd" 2>/dev/null
done

echo "==> Go build complete"

# ================================================================
# 5. Install everything to /opt/waffynx
# ================================================================
echo "==> Installing to $WAFFYNX_HOME..."

mkdir -p "$WAFFYNX_HOME"/{bin,config,logs,nginx/{conf,logs,client_body_temp,proxy_temp},appsec}

# Copy nginx binary and config
cp "$WAFFYNX_ROOT/third_party/nginx/objs/nginx" "$WAFFYNX_HOME/nginx/sbin/nginx"
cp "$WAFFYNX_ROOT/third_party/nginx/conf/mime.types" "$WAFFYNX_HOME/nginx/conf/"

# Copy Go binaries
cp "$WAFFYNX_ROOT/bin/"* "$WAFFYNX_HOME/bin/"
chmod +x "$WAFFYNX_HOME/bin/"*

# Copy and patch waffynx config
sed -e "s|/var/run/waffynx.sock|$WAFFYNX_HOME/waffynx.sock|g" \
    -e "s|/var/run/open-appsec.sock|$WAFFYNX_HOME/open-appsec.sock|g" \
    -e "s|/opt/waffynx|$WAFFYNX_HOME|g" \
    "$WAFFYNX_ROOT/configs/waffynx.yaml" \
    > "$WAFFYNX_HOME/config/waffynx.yaml"

# Copy and render nginx.conf
cp "$WAFFYNX_ROOT/configs/nginx.conf" "$WAFFYNX_HOME/nginx/conf/nginx.conf"
sed -i "s|/var/run/waffynx.sock|$WAFFYNX_HOME/waffynx.sock|g" \
    "$WAFFYNX_HOME/nginx/conf/nginx.conf"
sed -i "s|/opt/waffynx|$WAFFYNX_HOME|g" \
    "$WAFFYNX_HOME/nginx/conf/nginx.conf"

# Copy systemd units
cp "$WAFFYNX_ROOT/deploy/systemd/waffynx.service" /etc/systemd/system/
cp "$WAFFYNX_ROOT/deploy/systemd/waf-agent.service" /etc/systemd/system/
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
cat > "$WAFFYNX_HOME/config/waffynx.yaml" << 'YAML'
name: "waffynx"
version: "1"
listen: ":8443"
logging:
  level: "debug"
  format: "console"
  output: "stdout"
sidecar:
  socket_path: "/opt/waffynx/waffynx.sock"
  fail_open: true
  timeout_ms: 100
nginx:
  binary_path: "/opt/waffynx/nginx/sbin/nginx"
  config_path: "/opt/waffynx/nginx/conf"
  worker_processes: 1
  worker_connections: 1024
  enable_http2: false
appsec:
  enabled: true
  engine: "open-appsec"
  bridge_socket: "/opt/waffynx/open-appsec.sock"
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
