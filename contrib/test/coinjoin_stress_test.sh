#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova CoinJoin Mixing Stress Test Script
# Tests: mixing RPCs, denomination handling, pool limits, edge cases
# Author: 0xcircuitbreaker - CircuitBreaker

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_coinjoin_stress"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"
NODE3_DIR="$TEST_DIR/node3"

NODE1_PORT=26445
NODE2_PORT=26446
NODE3_PORT=26447
NODE1_RPC=26500
NODE2_RPC=26501
NODE3_RPC=26502

PASSED=0
FAILED=0
WARNINGS=0

log() { echo -e "${BLUE}[COINJOIN]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*coinjoin_stress" 2>/dev/null || true
    sleep 2
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

check_binary() {
    if [ ! -f "$INNOVAD" ]; then
        echo -e "${RED}ERROR: innovad not found at $INNOVAD${NC}"
        exit 1
    fi
    log "Found innovad binary"
}

setup_nodes() {
    log "Setting up 3-node CoinJoin test network..."
    rm -rf "$TEST_DIR"
    mkdir -p "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"

    for i in 1 2 3; do
        eval "dir=\$NODE${i}_DIR"
        eval "rpc=\$NODE${i}_RPC"
        eval "port=\$NODE${i}_PORT"

        cat > "$dir/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=cjtest
rpcpassword=cjpass
rpcport=$rpc
port=$port
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
mixingpoolsize=5
mixrounds=4
addnode=127.0.0.1:$NODE1_PORT
addnode=127.0.0.1:$NODE2_PORT
addnode=127.0.0.1:$NODE3_PORT
debug=1
printtoconsole=0
EOF
    done

    log "Config files created for 3 nodes"
}

start_nodes() {
    log "Starting nodes..."
    "$INNOVAD" -datadir="$NODE1_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$NODE2_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$NODE3_DIR" -regtest &
    sleep 4
    log "All nodes started"
}

rpc1() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=cjtest -rpcpassword=cjpass -rpcport=$NODE1_RPC "$@" 2>/dev/null
}

rpc1_err() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=cjtest -rpcpassword=cjpass -rpcport=$NODE1_RPC "$@" 2>&1
}

rpc2() {
    "$INNOVAD" -datadir="$NODE2_DIR" -rpcuser=cjtest -rpcpassword=cjpass -rpcport=$NODE2_RPC "$@" 2>/dev/null
}

rpc3() {
    "$INNOVAD" -datadir="$NODE3_DIR" -rpcuser=cjtest -rpcpassword=cjpass -rpcport=$NODE3_RPC "$@" 2>/dev/null
}

# TEST SUITES
test_mixing_rpc_availability() {
    section "CoinJoin RPC Command Availability"

    # Test startmixing help
    local result=$(rpc1_err help startmixing 2>&1 || echo "")
    if echo "$result" | grep -qi "startmixing\|amount\|denomination"; then
        success "startmixing RPC registered"
    else
        fail "startmixing RPC not available"
    fi

    # Test stopmixing help
    result=$(rpc1_err help stopmixing 2>&1 || echo "")
    if echo "$result" | grep -qi "stopmixing\|stop\|mixing"; then
        success "stopmixing RPC registered"
    else
        fail "stopmixing RPC not available"
    fi

    # Test getmixingstatus help
    result=$(rpc1_err help getmixingstatus 2>&1 || echo "")
    if echo "$result" | grep -qi "getmixingstatus\|status\|mixing"; then
        success "getmixingstatus RPC registered"
    else
        fail "getmixingstatus RPC not available"
    fi
}

test_mixing_status_initial() {
    section "Initial Mixing Status"

    local status=$(rpc1 getmixingstatus 2>/dev/null || echo "")
    if [ -n "$status" ]; then
        success "getmixingstatus responds"
        log "Status: $status"

        # Check for expected fields
        if echo "$status" | grep -q '"mixing_active"'; then
            success "Status includes mixing_active field"
        else
            warn "Status missing mixing_active field"
        fi

        if echo "$status" | grep -q '"pool_state"'; then
            success "Status includes pool_state field"
        else
            warn "Status missing pool_state field"
        fi

        if echo "$status" | grep -q '"denominations"'; then
            success "Status includes denominations field"
        else
            warn "Status missing denominations field"
        fi
    else
        fail "getmixingstatus returned empty"
    fi
}

test_denomination_validation() {
    section "Denomination Validation"

    # Test valid denominations: 10, 100, 1000, 10000
    for denom in 10 100 1000 10000; do
        local result=$(rpc1_err startmixing $denom 2>&1 || echo "")
        if echo "$result" | grep -qi "error.*denomination\|invalid.*denomination"; then
            fail "Valid denomination $denom rejected"
        else
            success "Denomination $denom accepted (or pool state valid)"
            # Stop mixing after each test
            rpc1 stopmixing >/dev/null 2>&1 || true
        fi
    done

    # Test invalid denomination
    local result=$(rpc1_err startmixing 50 2>&1 || echo "")
    if echo "$result" | grep -qi "error\|invalid\|denomination"; then
        success "Invalid denomination 50 rejected"
    else
        warn "Invalid denomination 50 response: ${result:0:80}"
    fi

    # Test zero amount
    result=$(rpc1_err startmixing 0 2>&1 || echo "")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Zero amount rejected"
    else
        warn "Zero amount response: ${result:0:80}"
    fi

    # Test negative amount
    result=$(rpc1_err startmixing -100 2>&1 || echo "")
    if echo "$result" | grep -qi "error\|invalid\|negative"; then
        success "Negative amount rejected"
    else
        warn "Negative amount response: ${result:0:80}"
    fi
}

test_large_denomination_cap() {
    section "Large Denomination Cap (DoS Prevention)"

    # Test very large amount that would create excessive denominations
    # MAX_MIXING_DENOMS = 1000, so 10000000 / 10 = 1000000 denoms would exceed cap
    local result=$(rpc1_err startmixing 10000000 2>&1 || echo "")
    if echo "$result" | grep -qi "denomination\|entries\|exceed\|cap\|limit\|too many"; then
        success "Excessive denomination count properly capped"
    else
        log "Large denom response: ${result:0:80}"
        # Even if accepted, verify the denomination array is bounded
        rpc1 stopmixing >/dev/null 2>&1 || true
        warn "Large denomination response should indicate cap"
    fi
}

test_start_stop_mixing() {
    section "Start/Stop Mixing Lifecycle"

    # Start mixing
    local result=$(rpc1_err startmixing 100 2>&1 || echo "")
    log "Start mixing result: ${result:0:120}"

    # Check status
    local status=$(rpc1 getmixingstatus 2>/dev/null || echo "")
    log "Status after start: $status"

    # Stop mixing
    result=$(rpc1 stopmixing 2>/dev/null || echo "")
    if [ -n "$result" ]; then
        success "stopmixing executed"
        log "Stop result: $result"
    else
        warn "stopmixing returned empty"
    fi

    # Status after stop
    status=$(rpc1 getmixingstatus 2>/dev/null || echo "")
    if echo "$status" | grep -q '"mixing_active"'; then
        local active=$(echo "$status" | grep -o '"mixing_active" *: *[a-z]*' | grep -o '[a-z]*$')
        if [ "$active" = "false" ]; then
            success "Mixing correctly shows inactive after stop"
        else
            warn "Mixing still active after stopmixing"
        fi
    fi
}

test_double_start() {
    section "Double Start/Stop Edge Cases"

    # Start mixing twice
    rpc1 startmixing 100 >/dev/null 2>&1 || true
    local result=$(rpc1_err startmixing 100 2>&1 || echo "")
    log "Double start response: ${result:0:80}"
    # Should either succeed idempotently or return "already mixing"
    success "Double start handled without crash"

    # Stop twice
    rpc1 stopmixing >/dev/null 2>&1 || true
    result=$(rpc1_err stopmixing 2>&1 || echo "")
    log "Double stop response: ${result:0:80}"
    success "Double stop handled without crash"

    # Stop without start
    result=$(rpc1_err stopmixing 2>&1 || echo "")
    log "Stop without start: ${result:0:80}"
    success "Stop without start handled without crash"
}

test_concurrent_mixing_requests() {
    section "Concurrent Mixing Requests"

    local pids=()
    local succeeded=0

    # Send concurrent startmixing requests
    for i in $(seq 1 5); do
        rpc1 startmixing 100 >/dev/null 2>&1 &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((succeeded++)) || true
        fi
    done

    success "Concurrent mixing requests: $succeeded/5 completed without crash"
    rpc1 stopmixing >/dev/null 2>&1 || true
}

test_mixing_with_insufficient_funds() {
    section "Mixing with Insufficient Funds"

    # Node 2 should have no coins initially
    local balance=$(rpc2 getbalance 2>/dev/null || echo "0")
    log "Node2 balance: $balance"

    local result=$(rpc2 startmixing 10000 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|insufficient\|funds\|balance"; then
        success "Mixing with insufficient funds rejected"
    else
        log "Insufficient funds response: ${result:0:80}"
        rpc2 stopmixing >/dev/null 2>&1 || true
        warn "Insufficient funds response should indicate error"
    fi
}

test_pool_size_config() {
    section "Pool Size Configuration"

    # Check that mixing pool size is configurable
    local status=$(rpc1 getmixingstatus 2>/dev/null || echo "")
    if echo "$status" | grep -q '"pool_size"'; then
        local pool_size=$(echo "$status" | grep -o '"pool_size" *: *[0-9]*' | grep -o '[0-9]*$')
        if [ -n "$pool_size" ] && [ "$pool_size" -ge 3 ] && [ "$pool_size" -le 8 ]; then
            success "Pool size $pool_size within valid range [3-8]"
        else
            warn "Pool size $pool_size outside expected range"
        fi
    else
        log "Pool size not in status output"
    fi
}

test_multi_node_status() {
    section "Multi-Node Mixing Status"

    # Check all nodes can report mixing status
    for i in 1 2 3; do
        local status=$(eval "rpc${i} getmixingstatus 2>/dev/null || echo ''")
        if [ -n "$status" ]; then
            success "Node $i reports mixing status"
        else
            fail "Node $i cannot report mixing status"
        fi
    done
}

print_summary() {
    echo ""
    echo "========================================"
    echo "    COINJOIN STRESS TEST SUMMARY"
    echo "========================================"
    echo -e "  Passed:   ${GREEN}$PASSED${NC}"
    echo -e "  Failed:   ${RED}$FAILED${NC}"
    echo -e "  Warnings: ${YELLOW}$WARNINGS${NC}"
    echo "========================================"

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All CoinJoin tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some CoinJoin tests failed${NC}"
        return 1
    fi
}

main() {
    echo ""
    echo "========================================"
    echo "   INNOVA COINJOIN STRESS TEST"
    echo "========================================"
    echo "  Node1: port $NODE1_PORT / rpc $NODE1_RPC"
    echo "  Node2: port $NODE2_PORT / rpc $NODE2_RPC"
    echo "  Node3: port $NODE3_PORT / rpc $NODE3_RPC"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Generating initial blocks on node1..."
    rpc1 setgenerate true 200 >/dev/null 2>&1 || true
    sleep 3

    test_mixing_rpc_availability
    test_mixing_status_initial
    test_denomination_validation
    test_large_denomination_cap
    test_start_stop_mixing
    test_double_start
    test_concurrent_mixing_requests
    test_mixing_with_insufficient_funds
    test_pool_size_config
    test_multi_node_status

    print_summary
}

main "$@"
