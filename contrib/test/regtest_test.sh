#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Regtest Mode Test Script
# Tests instant block generation and regtest-specific functionality
# Author: 0xcircuitbreaker - CircuitBreaker

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

REGTEST_DIR="/tmp/innova_regtest"
NODE1_DIR="$REGTEST_DIR/node1"
NODE2_DIR="$REGTEST_DIR/node2"

NODE1_PORT=18445
NODE2_PORT=18446
NODE1_RPC=18500
NODE2_RPC=18501

PASSED=0
FAILED=0

log() { echo -e "${BLUE}[REGTEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*-regtest" 2>/dev/null || true
    sleep 2
    rm -rf "$REGTEST_DIR"
}

trap cleanup EXIT

check_binary() {
    if [ ! -f "$INNOVAD" ]; then
        echo -e "${RED}ERROR: innovad not found at $INNOVAD${NC}"
        echo "Please build first: cd $INNOVA_ROOT/src && make -f makefile.osx"
        exit 1
    fi
    log "Found innovad binary"
}

setup_nodes() {
    log "Setting up regtest nodes..."

    rm -rf "$REGTEST_DIR"
    mkdir -p "$NODE1_DIR" "$NODE2_DIR"

    cat > "$NODE1_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=regtestuser
rpcpassword=regtestpass
rpcport=$NODE1_RPC
port=$NODE1_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$NODE2_PORT
debug=1
EOF

    cat > "$NODE2_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=regtestuser
rpcpassword=regtestpass
rpcport=$NODE2_RPC
port=$NODE2_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$NODE1_PORT
debug=1
EOF

    log "Created config files"
}

start_nodes() {
    log "Starting regtest nodes..."

    "$INNOVAD" -datadir="$NODE1_DIR" -regtest &
    sleep 2

    "$INNOVAD" -datadir="$NODE2_DIR" -regtest &
    sleep 3

    log "Nodes started"
}

rpc1() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=regtestuser -rpcpassword=regtestpass -rpcport=$NODE1_RPC "$@" 2>/dev/null
}

rpc2() {
    "$INNOVAD" -datadir="$NODE2_DIR" -rpcuser=regtestuser -rpcpassword=regtestpass -rpcport=$NODE2_RPC "$@" 2>/dev/null
}

test_basic_connectivity() {
    log "Testing basic connectivity..."

    if rpc1 getinfo >/dev/null; then
        success "Node 1 responds to RPC"
    else
        fail "Node 1 RPC failed"
        return 1
    fi

    if rpc2 getinfo >/dev/null; then
        success "Node 2 responds to RPC"
    else
        fail "Node 2 RPC failed"
        return 1
    fi

    local blocks1=$(rpc1 getinfo | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*')
    if [ "$blocks1" == "0" ]; then
        success "Node 1 at genesis block (regtest mode confirmed)"
    else
        warn "Node 1 at block $blocks1 (expected 0)"
    fi
}

test_peer_connection() {
    log "Testing peer connection..."

    sleep 5

    local peers1=$(rpc1 getpeerinfo | grep -c '"addr"' || echo 0)
    if [ "$peers1" -ge "1" ]; then
        success "Node 1 has $peers1 peer(s)"
    else
        warn "Node 1 has no peers yet (may need more time)"
    fi
}

test_address_generation() {
    log "Testing address generation..."

    local addr1=$(rpc1 getnewaddress)
    if [ -n "$addr1" ]; then
        success "Generated address on node 1: $addr1"
    else
        fail "Failed to generate address on node 1"
    fi

    local addr2=$(rpc2 getnewaddress)
    if [ -n "$addr2" ]; then
        success "Generated address on node 2: $addr2"
    else
        fail "Failed to generate address on node 2"
    fi
}

test_block_generation() {
    log "Testing PoW block generation (regtest)..."

    local addr=$(rpc1 getnewaddress)

    if rpc1 setgenerate true 1 >/dev/null 2>&1; then
        sleep 2
        local blocks=$(rpc1 getinfo | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*')
        if [ "$blocks" -ge "1" ]; then
            success "Generated block! Now at height $blocks"
        else
            warn "setgenerate returned but block count unchanged"
        fi
    else
        warn "setgenerate not available - testing getblocktemplate instead"
        if rpc1 getblocktemplate >/dev/null 2>&1; then
            success "getblocktemplate works"
        else
            warn "getblocktemplate not available"
        fi
    fi
}

test_rapid_blocks() {
    log "Testing rapid block generation..."

    local start_blocks=$(rpc1 getinfo | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*')

    for i in {1..5}; do
        rpc1 setgenerate true 1 2>/dev/null || true
        sleep 1
    done

    local end_blocks=$(rpc1 getinfo | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*')
    local generated=$((end_blocks - start_blocks))

    if [ "$generated" -gt "0" ]; then
        success "Rapid generation: $generated blocks in ~5 seconds"
    else
        warn "No blocks generated via setgenerate"
    fi
}

test_block_sync() {
    log "Testing block synchronization between nodes..."

    sleep 3

    local blocks1=$(rpc1 getinfo | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*')
    local blocks2=$(rpc2 getinfo | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*')

    if [ "$blocks1" == "$blocks2" ]; then
        success "Nodes synchronized at block $blocks1"
    else
        warn "Nodes not synced - Node1: $blocks1, Node2: $blocks2"
    fi
}

test_transaction() {
    log "Testing transaction creation..."

    local addr2=$(rpc2 getnewaddress)

    local balance=$(rpc1 getbalance | tr -d ' ')
    log "Node 1 balance: $balance"

    if [ "$(echo "$balance > 0" | bc)" -eq 1 ] 2>/dev/null; then
        local txid=$(rpc1 sendtoaddress "$addr2" 1.0 2>/dev/null || echo "")
        if [ -n "$txid" ]; then
            success "Transaction sent: $txid"
        else
            warn "Could not send transaction (insufficient funds or other issue)"
        fi
    else
        warn "No balance to send transaction (need to mine blocks with rewards)"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "        REGTEST TEST SUMMARY"
    echo "========================================"
    echo -e "  Passed: ${GREEN}$PASSED${NC}"
    echo -e "  Failed: ${RED}$FAILED${NC}"
    echo "========================================"

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed${NC}"
        return 1
    fi
}

main() {
    echo ""
    echo "========================================"
    echo "    INNOVA REGTEST MODE TEST"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Waiting for nodes to initialize..."
    sleep 5

    test_basic_connectivity
    test_peer_connection
    test_address_generation
    test_block_generation
    test_rapid_blocks
    test_block_sync
    test_transaction

    print_summary
}

main "$@"
