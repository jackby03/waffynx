#!/bin/sh
set -eu

WAFFYNX_HOME=/opt/waffynx
CONFIG_FILE="$WAFFYNX_HOME/config/waffynx.yaml"
DEFAULT_CONFIG="$WAFFYNX_HOME/defaults/waffynx.yaml"

if [ ! -f "$CONFIG_FILE" ] && [ -f "$DEFAULT_CONFIG" ]; then
    install -m 0600 "$DEFAULT_CONFIG" "$CONFIG_FILE"
fi

# Bootstrap resolves WAFFYNX_JWT_SECRET, WAFFYNX_ADMIN_USER/PASSWORD, and initial site.
"$WAFFYNX_HOME/bin/waffynx-bootstrap" --config "$CONFIG_FILE"

exec "$WAFFYNX_HOME/bin/waf-api" --config "$CONFIG_FILE"
