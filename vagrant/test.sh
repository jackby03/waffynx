#!/bin/bash
# waffynx-test.sh
# Automated test suite for the Waffynx WAF stack.
# Run inside the Vagrant VM after provisioning:
#   vagrant ssh -c "bash /waffynx/vagrant/test.sh"

set -euo pipefail

WAFFYNX_HOME="${WAFFYNX_HOME:-/opt/waffynx}"
BASE_URL="http://localhost:8080"
SIDECAR_SOCK="$WAFFYNX_HOME/waffynx.sock"
BRIDGE_SOCK="$WAFFYNX_HOME/open-appsec.sock"
PASSED=0
FAILED=0
TESTS=0

green() { echo -e "\033[32m$1\033[0m"; }
red()   { echo -e "\033[31m$1\033[0m"; }
bold()  { echo -e "\033[1m$1\033[0m"; }

assert_status() {
    local desc="$1" expected="$2" url="$3" extra_headers="${4:-}"
    TESTS=$((TESTS + 1))

    if [ -n "$extra_headers" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" $extra_headers --max-time 5 "$BASE_URL$url")
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE_URL$url")
    fi

    if [ "$status" = "$expected" ]; then
        PASSED=$((PASSED + 1))
        green "  [PASS] $desc (expected $expected, got $status)"
    else
        FAILED=$((FAILED + 1))
        red "  [FAIL] $desc (expected $expected, got $status)"
    fi
}

assert_status_unix() {
    local desc="$1" expected="$2" uri="$3"
    TESTS=$((TESTS + 1))

    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        --unix-socket "$SIDECAR_SOCK" \
        -H "X-WN-M: GET" \
        -H "X-WN-U: $uri" \
        -H "X-WN-H: example.com" \
        -H "X-WN-IP: 1.2.3.4" \
        -H "X-WN-UA: Mozilla/5.0" \
        http://localhost/evaluate)

    if [ "$status" = "$expected" ]; then
        PASSED=$((PASSED + 1))
        green "  [PASS] $desc (expected $expected, got $status)"
    else
        FAILED=$((FAILED + 1))
        red "  [FAIL] $desc (expected $expected, got $status)"
    fi
}

echo ""
bold "============================================"
bold "  Waffynx Automated Test Suite"
bold "============================================"
echo ""

# ---- 1. Service health ----
bold "--- Health Checks ---"

echo -n "  Sidecar socket... "
if [ -S "$SIDECAR_SOCK" ]; then green "found"; else red "NOT FOUND"; FAILED=$((FAILED+1)); fi

echo -n "  Bridge socket... "
if [ -S "$BRIDGE_SOCK" ]; then green "found"; else red "NOT FOUND"; FAILED=$((FAILED+1)); fi

echo -n "  Nginx running... "
if pgrep -x nginx >/dev/null; then green "yes"; else red "NO"; FAILED=$((FAILED+1)); fi

# ---- 2. Normal traffic (should pass) ----
echo ""
bold "--- Normal Traffic (should ALL pass) ---"

# Start a test backend
python3 -m http.server 3000 --bind 127.0.0.1 &>/dev/null &
BACKEND_PID=$!
sleep 1

assert_status "GET / (homepage)"    200 "/"
assert_status "GET /api/users"     200 "/api/users"
assert_status "POST /api/login"    200 "/api/login"
assert_status "GET /health"        200 "/health"

kill $BACKEND_PID 2>/dev/null || true

# ---- 3. Sidecar direct evaluation ----
echo ""
bold "--- Sidecar Direct (Unix Socket) ---"

assert_status_unix "Normal request"           204 "/api/health"
assert_status_unix "SQL injection blocked"    403 "/api/users?q=UNION+SELECT+1,2,3"
assert_status_unix "XSS blocked"             403 "/page?x=<script>alert(1)</script>"
assert_status_unix "Path traversal blocked"  403 "/?file=../../../etc/passwd"
assert_status_unix "Command injection blocked" 403 "/?cmd=;cat+/etc/passwd"

# ---- 4. Bridge connectivity ----
echo ""
bold "--- AppSec Bridge ---"

echo -n "  Bridge health check... "
bridge_health=$(curl -s --max-time 3 --unix-socket "$BRIDGE_SOCK" http://localhost/health 2>/dev/null || echo "")
if echo "$bridge_health" | grep -q '"status":"ok"'; then
    green "OK"
else
    red "FAILED"
    FAILED=$((FAILED+1))
fi

# ---- 5. Firewall (optional) ----
echo ""
bold "--- Firewall (nftables) ---"

echo -n "  nftables available... "
if command -v nft &>/dev/null; then
    green "yes"
else
    red "no"
fi

# ---- Summary ----
echo ""
bold "============================================"
TOTAL=$((PASSED + FAILED))
if [ "$FAILED" -eq 0 ]; then
    green "  ALL $TOTAL TESTS PASSED"
else
    red "  $FAILED/$TOTAL TESTS FAILED"
fi
bold "============================================"
echo ""

exit $FAILED
