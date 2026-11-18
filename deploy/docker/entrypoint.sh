#!/bin/bash
set -e

WAFFYNX_HOME=/opt/waffynx
CONFIG_FILE="$WAFFYNX_HOME/config/waffynx.yaml"

# Resolve WAFFYNX_* before starting any daemon. Both waf-api and the engine must
# read the same topology and JWT secret; a failure here is fatal, not something to
# start with a half-applied configuration.
echo "==> Applying environment bootstrap..."
if ! "$WAFFYNX_HOME/bin/waffynx-bootstrap" --config "$CONFIG_FILE"; then
    echo "ERROR: environment bootstrap failed; refusing to start Waffynx" >&2
    exit 1
fi

# Generate self-signed cert if not present
if [ ! -f "$WAFFYNX_HOME/certs/server.crt" ]; then
    echo "==> Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$WAFFYNX_HOME/certs/server.key" \
        -out "$WAFFYNX_HOME/certs/server.crt" \
        -days 365 -subj "/CN=localhost/O=Waffynx/C=US" 2>/dev/null
fi

# open-appsec is not started. The engine scores in-process (appsec.engine defaults
# to basic-go); appsec-bridge only matters when appsec.engine is set to
# open-appsec, and then you point appsec.bridge_socket at an engine you run. The
# bundled stub was removed because it was never enabled — see third_party/README.md.

echo "==> Starting WAF API (dashboard on :9090)..."
$WAFFYNX_HOME/bin/waf-api --config "$CONFIG_FILE" &

echo "==> Starting WAF engine (sidecar + nginx)..."
$WAFFYNX_HOME/bin/waffynx start --config "$CONFIG_FILE" &

echo ""
echo "============================================"
echo "  Waffynx is running"
echo "  HTTP:   http://localhost:8080"
echo "  HTTPS:  https://localhost:8443"
echo "  API:    http://localhost:9090"
echo "============================================"

# Keep container alive
wait
