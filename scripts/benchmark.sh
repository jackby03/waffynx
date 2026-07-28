#!/bin/bash
# Waffynx benchmark suite
# Usage: bash scripts/benchmark.sh [host] [port]
# Requires: wrk or vegeta

HOST="${1:-localhost}"
PORT="${2:-8080}"
BASE="http://${HOST}:${PORT}"
PASSED=0
FAILED=0

GREEN='\033[32m'
RED='\033[31m'
NC='\033[0m'

bench() {
    local name="$1" url="$2" expected="$3"
    echo -n "  $name... "
    status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -H "User-Agent: Mozilla/5.0" "$url")
    if [ "$status" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC} ($status)"
        PASSED=$((PASSED+1))
    else
        echo -e "${RED}FAIL${NC} (expected $expected, got $status)"
        FAILED=$((FAILED+1))
    fi
}

echo "=== Waffynx Smoke Tests ==="
echo "Target: $BASE"
echo ""

bench "Health check"          "$BASE/health"               200
bench "Normal GET (allow)"    "$BASE/api/users"            200
bench "SQLi (block)"          "$BASE/?q=UNION+SELECT+1,2,3" 403
bench "XSS (block)"           "$BASE/?x=<script>alert(1)</script>" 403
bench "Path traversal (block)" "$BASE/?file=../../../etc/passwd" 403
bench "Cmd injection (block)" "$BASE/?cmd=;cat+/etc/passwd" 403

echo ""
echo "=== Throughput Test ==="

if command -v wrk &>/dev/null; then
    echo "Running wrk benchmark (10s, 4 threads, 100 connections)..."
    wrk -t4 -c100 -d10s -H "User-Agent: Mozilla/5.0" "$BASE/health" 2>&1 | grep -E "Requests/sec|Latency"
elif command -v vegeta &>/dev/null; then
    echo "Running vegeta benchmark (10s, rate=100/s)..."
    echo "GET $BASE/health" | vegeta attack -duration=10s -rate=100 -header "User-Agent: Mozilla/5.0" | vegeta report
elif command -v hey &>/dev/null; then
    echo "Running hey benchmark (1000 requests, 50 concurrent)..."
    hey -n 1000 -c 50 -H "User-Agent: Mozilla/5.0" "$BASE/health" 2>&1 | grep -E "Requests/sec|Average|Fastest|Slowest"
else
    echo "No benchmark tool found (wrk/vegeta/hey). Install one:"
    echo "  apt-get install wrk"
    echo "  go install github.com/tsenart/vegeta@latest"
fi

echo ""
echo "============================================"
TOTAL=$((PASSED + FAILED))
if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}ALL $TOTAL TESTS PASSED${NC}"
else
    echo -e "  ${RED}$FAILED/$TOTAL TESTS FAILED${NC}"
fi
echo "============================================"
