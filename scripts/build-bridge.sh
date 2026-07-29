#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
APPSEC_DIR="${PROJECT_ROOT}/third_party/open-appsec"
BIN_DIR="${PROJECT_ROOT}/dist"
BUILD_DIR="/tmp/waffynx-bridge-build"

echo "==> Building C++ bridge for Waffynx..."

mkdir -p "${BIN_DIR}"

# 1. Check dependencies
MISSING_TOOLS=()
for tool in cmake g++ bison flex; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo "WARNING: Missing build dependencies for full build: ${MISSING_TOOLS[*]}"
    echo "Attempting direct compilation of waffynx_bridge..."
    if command -v g++ &>/dev/null; then
        g++ -shared -fPIC -std=c++17 -O2 \
            -I "${APPSEC_DIR}/core/include/general" \
            -I "${APPSEC_DIR}/core/include/internal" \
            -I "${APPSEC_DIR}/core/include/services_sdk" \
            -I "${APPSEC_DIR}/components/include" \
            -I "${APPSEC_DIR}/components/security_apps/waap/waap_clib" \
            -I "${APPSEC_DIR}" \
            -o "${APPSEC_DIR}/libwaffynx_bridge.so" \
            "${APPSEC_DIR}/waffynx_bridge.cpp" || {
                echo "ERROR: Failed to compile libwaffynx_bridge.so with g++"
                exit 1
            }
        cp "${APPSEC_DIR}/libwaffynx_bridge.so" "${BIN_DIR}/"
        echo "==> Successfully compiled ${BIN_DIR}/libwaffynx_bridge.so"
        exit 0
    else
        echo "ERROR: g++ is required to build the bridge C++ library."
        exit 1
    fi
fi

# 2. Full build using cmake
mkdir -p "${BUILD_DIR}"

echo "==> Copying open-appsec sources to build directory ${BUILD_DIR}..."
rm -rf "${BUILD_DIR:?}"/*
cp -r "${APPSEC_DIR}"/* "${BUILD_DIR}/"

cd "${BUILD_DIR}"

# Strip CRLF (Windows -> Linux)
find . -type f -exec sed -i 's/\r$//' {} \; 2>/dev/null || true

echo "==> Running cmake..."
if cmake -B build -DCMAKE_BUILD_TYPE=Release .; then
    echo "==> Running make..."
    make -C build -j"$(nproc 2>/dev/null || echo 2)" || true
fi

echo "==> Compiling libwaffynx_bridge.so..."
g++ -shared -fPIC -std=c++17 -O2 \
    -I "${APPSEC_DIR}/core/include/general" \
    -I "${APPSEC_DIR}/core/include/internal" \
    -I "${APPSEC_DIR}/core/include/services_sdk" \
    -I "${APPSEC_DIR}/components/include" \
    -I "${APPSEC_DIR}/components/security_apps/waap/waap_clib" \
    -I "${APPSEC_DIR}" \
    -o "${APPSEC_DIR}/libwaffynx_bridge.so" \
    "${APPSEC_DIR}/waffynx_bridge.cpp"

cp "${APPSEC_DIR}/libwaffynx_bridge.so" "${BIN_DIR}/"
if [ -f "${BUILD_DIR}/build/libngen_core.so" ]; then
    cp "${BUILD_DIR}/build/libngen_core.so" "${BIN_DIR}/"
fi

echo "==> Bridge build completed successfully!"
