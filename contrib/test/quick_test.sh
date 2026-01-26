#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Quick Sanity Test
# Fast test to verify basic functionality
# Author: 0xcircuitbreaker - CircuitBreaker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_DIR="${SCRIPT_DIR}/../.."
INNOVAD="${INNOVA_DIR}/src/innovad"
TEST_DIR="/tmp/innova_quick_test"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

cleanup() {
    if [[ -f "${TEST_DIR}/innovad.pid" ]]; then
        local pid=$(cat "${TEST_DIR}/innovad.pid")
        kill $pid 2>/dev/null || true
        sleep 2
        kill -9 $pid 2>/dev/null || true
    fi
    rm -rf "${TEST_DIR}"
}

trap cleanup EXIT

rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}"

cat > "${TEST_DIR}/innova.conf" << EOF
testnet=1
server=1
daemon=0
rpcuser=test
rpcpassword=testpass
rpcport=19331
port=19339
rpcallowip=127.0.0.1
listen=0
dnsseed=0
staking=0
idns=0
EOF

rpc() {
    curl -s --user test:testpass \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"test\",\"method\":\"$1\",\"params\":$2}" \
        -H 'content-type:text/plain;' \
        http://127.0.0.1:19331/ 2>/dev/null | jq -r '.result // .error.message // "null"'
}

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name=$1
    local expected=$2
    local actual=$3

    if [[ "$actual" == "$expected" ]] || [[ "$expected" == "*" && -n "$actual" && "$actual" != "null" ]]; then
        log_pass "$name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "$name (expected: $expected, got: $actual)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo ""
echo "========================================"
echo "  Innova Quick Sanity Test"
echo "========================================"
echo ""

log_test "Binary exists"
if [[ -x "${INNOVAD}" ]]; then
    log_pass "Binary exists at ${INNOVAD}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Binary not found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
fi

log_test "Help command"
if "${INNOVAD}" --help 2>&1 | grep -q "Innova"; then
    log_pass "Help command works"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Help command failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "Version output"
VERSION=$("${INNOVAD}" --help 2>&1 | head -1)
if [[ "$VERSION" =~ "Innova version" ]]; then
    log_pass "Version: $VERSION"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Invalid version output"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "Node startup"
"${INNOVAD}" -datadir="${TEST_DIR}" -testnet > "${TEST_DIR}/debug.log" 2>&1 &
PID=$!
echo $PID > "${TEST_DIR}/innovad.pid"

WAIT=0
while ! curl -s --user test:testpass \
    --data-binary '{"jsonrpc":"1.0","id":"test","method":"getinfo","params":[]}' \
    -H 'content-type:text/plain;' \
    http://127.0.0.1:19331/ > /dev/null 2>&1; do
    sleep 1
    WAIT=$((WAIT + 1))
    if [[ $WAIT -ge 60 ]]; then
        log_fail "Node failed to start within 60s"
        cat "${TEST_DIR}/debug.log" | tail -20
        exit 1
    fi
done
log_pass "Node started (PID: $PID)"
TESTS_PASSED=$((TESTS_PASSED + 1))

log_test "RPC: getinfo"
INFO=$(rpc "getinfo" "[]")
if [[ "$INFO" != "null" ]]; then
    log_pass "getinfo returned data"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "getinfo failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "RPC: getblockcount"
HEIGHT=$(rpc "getblockcount" "[]")
if [[ "$HEIGHT" =~ ^[0-9]+$ ]]; then
    log_pass "Block height: $HEIGHT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Invalid block height: $HEIGHT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "RPC: getnewaddress"
ADDR=$(rpc "getnewaddress" "[]")
if [[ -n "$ADDR" && "$ADDR" != "null" && ${#ADDR} -gt 20 ]]; then
    log_pass "New address: ${ADDR:0:20}..."
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Invalid address: $ADDR"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "RPC: getmininginfo"
MINFO=$(rpc "getmininginfo" "[]")
if [[ "$MINFO" != "null" ]]; then
    log_pass "Mining info retrieved"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "getmininginfo failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "RPC: getstakinginfo"
SINFO=$(rpc "getstakinginfo" "[]")
if [[ "$SINFO" != "null" ]]; then
    log_pass "Staking info retrieved"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "getstakinginfo failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "RPC: validateaddress"
if [[ -n "$ADDR" && "$ADDR" != "null" ]]; then
    VALID=$(curl -s --user test:testpass \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"test\",\"method\":\"validateaddress\",\"params\":[\"$ADDR\"]}" \
        -H 'content-type:text/plain;' \
        http://127.0.0.1:19331/ 2>/dev/null | jq -r '.result.isvalid // "false"')
    if [[ "$VALID" == "true" ]]; then
        log_pass "Address validation works"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "Address validation failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    log_fail "Skipped - no address"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "RPC: getpeerinfo"
PEERS=$(rpc "getpeerinfo" "[]")
if [[ "$PEERS" != "null" ]]; then
    log_pass "Peer info retrieved"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "getpeerinfo failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

log_test "RPC: getrawmempool"
MEMPOOL=$(rpc "getrawmempool" "[]")
if [[ "$MEMPOOL" != "null" ]]; then
    log_pass "Mempool info retrieved"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "getrawmempool failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""
echo "========================================"
echo "  Test Results"
echo "========================================"
echo -e "  ${GREEN}Passed: ${TESTS_PASSED}${NC}"
echo -e "  ${RED}Failed: ${TESTS_FAILED}${NC}"
echo "========================================"
echo ""

if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
fi

exit 0
