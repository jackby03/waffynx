#!/bin/bash
set -euo pipefail

# =============================================================================
# Waffynx Installation Script
# Supports: Ubuntu 22.04+, Debian 12+
# =============================================================================

WAFFYNX_HOME="/opt/waffynx"
WAFFYNX_USER="waffynx"
WAFFYNX_GROUP="waffynx"
LOG_FILE="/var/log/waffynx-install.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo ./install.sh)"
fi

mkdir -p "$(dirname "$LOG_FILE")"
> "$LOG_FILE"

log "============================================"
log "  Waffynx Installation"
log "============================================"

# -- Detect OS --
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    err "Cannot detect OS. Supported: Ubuntu 22.04+, Debian 12+"
fi

log "Detected: $OS $VER"

# -- Install dependencies --
log "Installing system dependencies..."

case $OS in
    ubuntu|debian)
        apt-get update -qq
        apt-get install -y -qq \
            build-essential \
            libpcre3-dev \
            libssl-dev \
            zlib1g-dev \
            libmaxminddb-dev \
            libgeoip-dev \
            nftables \
            curl \
            wget \
            unzip \
            jq \
            git \
            ca-certificates \
            >> "$LOG_FILE" 2>&1
        ;;
    *)
        err "Unsupported OS: $OS"
        ;;
esac

# -- Create user --
if ! id -u "$WAFFYNX_USER" >/dev/null 2>&1; then
    log "Creating $WAFFYNX_USER user..."
    useradd -r -s /sbin/nologin -d "$WAFFYNX_HOME" -M "$WAFFYNX_USER"
fi

# -- Create directories --
log "Creating directory structure..."
mkdir -p "$WAFFYNX_HOME"/{bin,config,logs,plugins,nginx/{conf,logs},appsec/{rules,models}}

# -- Copy binaries --
log "Installing waffynx binaries..."
cp bin/* "$WAFFYNX_HOME/bin/"

# -- Copy configuration --
log "Installing configuration..."
cp configs/waffynx.yaml "$WAFFYNX_HOME/config/"

# -- Set permissions --
log "Setting permissions..."
chown -R "$WAFFYNX_USER:$WAFFYNX_GROUP" "$WAFFYNX_HOME"
chmod 750 "$WAFFYNX_HOME"
chmod 640 "$WAFFYNX_HOME/config/waffynx.yaml"

# -- Install systemd services --
log "Installing systemd services..."
cp deploy/systemd/waffynx.service /etc/systemd/system/
cp deploy/systemd/waf-agent.service /etc/systemd/system/
systemctl daemon-reload

# -- Enable firewall --
if command -v nft &>/dev/null; then
    log "Configuring nftables..."
    nft add table ip waffynx 2>/dev/null || true
    nft add chain ip waffynx input { type filter hook input priority 0 \; } 2>/dev/null || true
fi

# -- Done --
log ""
log "============================================"
log "  Installation Complete!"
log "============================================"
log ""
log "  Binary:  $WAFFYNX_HOME/bin/waffynx"
log "  Config:  $WAFFYNX_HOME/config/waffynx.yaml"
log "  Logs:    $WAFFYNX_HOME/logs/"
log ""
log "  Start:   systemctl start waffynx waf-agent"
log "  Enable:  systemctl enable waffynx waf-agent"
log "  Status:  systemctl status waffynx"
log ""
echo "============================================"
