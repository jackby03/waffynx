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

assert_status_unix_post() {
    local desc="$1" expected="$2" uri="$3" body="$4"
    TESTS=$((TESTS + 1))

    status=$(echo -n "$body" | curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        --unix-socket "$SIDECAR_SOCK" \
        -H "X-WN-M: POST" \
        -H "X-WN-U: $uri" \
        -H "X-WN-H: example.com" \
        -H "X-WN-IP: 1.2.3.4" \
        -H "X-WN-UA: Mozilla/5.0" \
        -H "Content-Type: application/json" \
        --data-binary @- \
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
TESTS=$((TESTS + 1))
if [ -S "$SIDECAR_SOCK" ]; then green "found"; PASSED=$((PASSED + 1)); else red "NOT FOUND"; FAILED=$((FAILED+1)); fi

echo -n "  Bridge socket... "
TESTS=$((TESTS + 1))
if [ -S "$BRIDGE_SOCK" ]; then green "found"; PASSED=$((PASSED + 1)); else red "NOT FOUND"; FAILED=$((FAILED+1)); fi

echo -n "  Nginx running... "
TESTS=$((TESTS + 1))
if pgrep -x nginx >/dev/null; then green "yes"; PASSED=$((PASSED + 1)); else red "NO"; FAILED=$((FAILED+1)); fi

# ---- 2. Normal traffic (should pass) ----
echo ""
bold "--- Normal Traffic (should ALL pass) ---"

cleanup_backend() {
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
}

cat << 'EOF' > /tmp/test-backend.py
import http.server
import socketserver

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 3000), Handler) as httpd:
    httpd.serve_forever()
EOF

python3 /tmp/test-backend.py &>/tmp/backend.log &
BACKEND_PID=$!
trap 'cleanup_backend' EXIT

echo -n "  Waiting for test backend... "
for i in $(seq 1 10); do
    if curl -s -o /dev/null --max-time 1 http://127.0.0.1:3000/ 2>/dev/null; then
        green "ready"
        break
    fi
    if [ "$i" -eq 10 ]; then
        red "FAILED TO START"
        TESTS=$((TESTS + 1))
        FAILED=$((FAILED + 1))
    fi
    sleep 0.5
done

assert_status "GET / (homepage)"    200 "/"
assert_status "GET /api/users"     200 "/api/users"
assert_status "POST /api/login"    200 "/api/login"
assert_status "GET /health"        200 "/health"

# ---- 3. Sidecar direct evaluation ----
echo ""
bold "--- Sidecar Direct (Unix Socket) ---"

assert_status_unix "Normal request"           204 "/api/health"
assert_status_unix "SQL injection blocked"    403 "/api/users?q=UNION+SELECT+1,2,3"
assert_status_unix "XSS blocked"             403 "/page?x=<script>alert(1)</script>"
assert_status_unix "Path traversal blocked"  403 "/?file=../../../etc/passwd"
assert_status_unix "Command injection blocked" 403 "/?cmd=;cat+/etc/passwd"

# ---- 3.5 Body inspection ----
echo ""
bold "--- Body Inspection (POST) ---"
assert_status_unix_post "Normal POST body"          204 "/api/login" '{"user":"admin","pass":"secret"}'
assert_status_unix_post "SQLi in POST body"         403 "/api/login" '{"user":"admin","pass":"'"'"' OR 1=1--"}'
assert_status_unix_post "XSS in POST body"          403 "/api/review" '{"comment":"<script>alert(1)</script>"}'

# ---- 4. Bridge connectivity ----
echo ""
bold "--- AppSec Bridge ---"

echo -n "  Bridge health check... "
TESTS=$((TESTS + 1))
bridge_health=$(curl -s --max-time 3 --unix-socket "$BRIDGE_SOCK" http://localhost/health 2>/dev/null || echo "")
if echo "$bridge_health" | grep -q '"status":"ok"'; then
    green "OK"
    PASSED=$((PASSED + 1))
else
    red "FAILED"
    FAILED=$((FAILED + 1))
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
