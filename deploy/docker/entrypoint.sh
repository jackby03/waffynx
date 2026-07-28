#!/bin/bash
set -e

WAFFYNX_HOME=/opt/waffynx

# Generate self-signed cert if not present
if [ ! -f "$WAFFYNX_HOME/certs/server.crt" ]; then
    echo "==> Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$WAFFYNX_HOME/certs/server.key" \
        -out "$WAFFYNX_HOME/certs/server.crt" \
        -days 365 -subj "/CN=localhost/O=Waffynx/C=US" 2>/dev/null
fi

echo "==> Starting appsec-bridge..."
$WAFFYNX_HOME/bin/appsec-bridge -s $WAFFYNX_HOME/open-appsec.sock &
sleep 1

echo "==> Starting WAF API (dashboard on :9090)..."
$WAFFYNX_HOME/bin/waf-api --config $WAFFYNX_HOME/config/waffynx.yaml &

echo "==> Starting WAF engine (sidecar + nginx)..."
$WAFFYNX_HOME/bin/waffynx start --config $WAFFYNX_HOME/config/waffynx.yaml &

echo ""
echo "============================================"
echo "  Waffynx is running"
echo "  HTTP:   http://localhost:8080"
echo "  HTTPS:  https://localhost:8443"
echo "  API:    http://localhost:9090"
echo "============================================"

# Keep container alive
wait
