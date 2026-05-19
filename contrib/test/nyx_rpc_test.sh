#!/bin/bash
# Nyx RPC Command Test Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Build first
cd "$INNOVA_ROOT/src"
make -f makefile.osx INNOVA_SPINNER=0 -j$(sysctl -n hw.ncpu) 2>&1 | tail -1
INNOVAD="$INNOVA_ROOT/src/innovad"

if [ ! -f "$INNOVAD" ]; then
    echo "FAIL: innovad not found after build"
    exit 1
fi

echo "Binary: $(ls -la $INNOVAD)"

# Setup
TEST_DIR="/tmp/nyx_rpc_test"
pkill -f "innovad.*nyx_rpc_test" 2>/dev/null || true
sleep 2
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

cat > "$TEST_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=nyxtest
rpcpassword=nyxpass
rpcport=28888
port=28889
listen=0
idns=0
listenonion=0
dnsseed=0
staking=0
smsg=1
nyx=1
EOF

RPC() {
    "$INNOVAD" -datadir="$TEST_DIR" -regtest -rpcuser=nyxtest -rpcpassword=nyxpass -rpcport=28888 "$@" 2>&1
}

cleanup() {
    pkill -f "innovad.*nyx_rpc_test" 2>/dev/null || true
    sleep 2
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Start node
echo ""
echo "=== Starting regtest node ==="
"$INNOVAD" -datadir="$TEST_DIR" -regtest -daemon
sleep 5

# Test 1: nyx status
echo ""
echo "=== TEST 1: nyx status ==="
RPC nyx status
echo "PASS: nyx status"

# Test 2: nyx peers
echo ""
echo "=== TEST 2: nyx peers ==="
RPC nyx peers
echo "PASS: nyx peers"

# Generate blocks for coins
echo ""
echo "=== Generating 110 blocks ==="
RPC setgenerate true 110 > /dev/null
sleep 2

ADDR=$(RPC getnewaddress)
echo "Got address: $ADDR"

# Test 3: nyx send
echo ""
echo "=== TEST 3: nyx send ==="
RPC nyx send "$ADDR" "$ADDR" "Hello from Nyx protocol!"
echo "PASS: nyx send"

sleep 3

# Test 4: nyx inbox
echo ""
echo "=== TEST 4: nyx inbox ==="
RPC nyx inbox all
echo "PASS: nyx inbox"

# Test 5: nyx sendanon
echo ""
echo "=== TEST 5: nyx sendanon ==="
RPC nyx sendanon "$ADDR" "Anonymous Nyx message!"
echo "PASS: nyx sendanon"

sleep 3

# Test 6: nyx inbox with anon message
echo ""
echo "=== TEST 6: nyx inbox (with anon) ==="
RPC nyx inbox all
echo "PASS: nyx inbox with anon"

# Test 7: nyx outbox
echo ""
echo "=== TEST 7: nyx outbox ==="
RPC nyx outbox
echo "PASS: nyx outbox"

echo ""
echo "========================================="
echo "  ALL NYX RPC TESTS PASSED"
echo "========================================="
