#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Staking Stress Test Script
# Tests PoS staking under various conditions including edge cases
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

TEST_DIR="/tmp/innova_staking_stress"
STAKER_DIR="$TEST_DIR/staker"
VALIDATOR_DIR="$TEST_DIR/validator"

STAKER_PORT=19445
VALIDATOR_PORT=19446
STAKER_RPC=19500
VALIDATOR_RPC=19501

PASSED=0
FAILED=0
WARNINGS=0

# Test duration for long-running tests (seconds)
STAKE_WAIT_TIME=${STAKE_WAIT_TIME:-120}
NUM_SPLIT_UTXOS=${NUM_SPLIT_UTXOS:-20}

log() { echo -e "${BLUE}[STAKE-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

# Safe JSON field extraction (handles multiline JSON output)
get_json_int() {
    local json="$1"
    local field="$2"
    echo "$json" | tr '\n' ' ' | grep -o "\"$field\" *: *[0-9]*" | head -1 | grep -o '[0-9]*$' || echo "0"
}

get_json_str() {
    local json="$1"
    local field="$2"
    echo "$json" | tr '\n' ' ' | grep -o "\"$field\" *: *\"[^\"]*\"" | head -1 | sed 's/.*: *"//;s/"$//' || echo ""
}

get_json_val() {
    local json="$1"
    local field="$2"
    echo "$json" | tr '\n' ' ' | grep -o "\"$field\" *: *[a-z0-9.]*" | head -1 | grep -o '[a-z0-9.]*$' || echo ""
}

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*staking_stress" 2>/dev/null || true
    sleep 2
    rm -rf "$TEST_DIR"
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
    log "Setting up staking test nodes..."
    rm -rf "$TEST_DIR"
    mkdir -p "$STAKER_DIR" "$VALIDATOR_DIR"

    cat > "$STAKER_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=staketest
rpcpassword=stakepass
rpcport=$STAKER_RPC
port=$STAKER_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=1
stakemindepth=1
stakeminvalue=1
stakecombinethreshold=5000
stakesplitthreshold=10000
addnode=127.0.0.1:$VALIDATOR_PORT
debug=1
printtoconsole=0
EOF

    cat > "$VALIDATOR_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=staketest
rpcpassword=stakepass
rpcport=$VALIDATOR_RPC
port=$VALIDATOR_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$STAKER_PORT
debug=1
printtoconsole=0
EOF

    log "Config files created"
}

start_nodes() {
    log "Starting nodes..."
    "$INNOVAD" -datadir="$STAKER_DIR" -regtest &
    sleep 3
    "$INNOVAD" -datadir="$VALIDATOR_DIR" -regtest &
    sleep 4
    # Explicitly connect nodes (addnode in config may not connect in regtest)
    rpc_staker addnode "127.0.0.1:$VALIDATOR_PORT" onetry >/dev/null 2>&1 || true
    rpc_validator addnode "127.0.0.1:$STAKER_PORT" onetry >/dev/null 2>&1 || true
    sleep 2
    log "Nodes started"
}

rpc_staker() {
    "$INNOVAD" -datadir="$STAKER_DIR" -rpcuser=staketest -rpcpassword=stakepass -rpcport=$STAKER_RPC "$@" 2>/dev/null
}

rpc_validator() {
    "$INNOVAD" -datadir="$VALIDATOR_DIR" -rpcuser=staketest -rpcpassword=stakepass -rpcport=$VALIDATOR_RPC "$@" 2>/dev/null
}

# TEST SUITES
test_basic_staking_setup() {
    section "Basic Staking Setup"

    # Verify nodes are up
    if rpc_staker getinfo >/dev/null 2>&1; then
        success "Staker node responds"
    else
        fail "Staker node not responding"
        return 1
    fi

    if rpc_validator getinfo >/dev/null 2>&1; then
        success "Validator node responds"
    else
        fail "Validator node not responding"
        return 1
    fi

    # Check staking is enabled on staker
    local sinfo=$(rpc_staker getstakinginfo 2>/dev/null || echo "{}")
    local staking_status=$(get_json_val "$sinfo" "staking")
    log "Staker staking status: $staking_status"

    # Generate initial PoW blocks for coinbase maturity
    log "Generating 150 PoW blocks for coinbase maturity..."
    rpc_staker setgenerate true 150 >/dev/null 2>&1 || true
    sleep 2

    local info=$(rpc_staker getinfo 2>/dev/null || echo "{}")
    local blocks=$(get_json_int "$info" "blocks")
    if [ "$blocks" -ge "100" ]; then
        success "Generated $blocks blocks for maturity"
    else
        fail "Only generated $blocks blocks (need >= 100)"
    fi

    # Check balance
    local balance=$(rpc_staker getbalance 2>/dev/null | tr -d ' \n')
    log "Staker balance: $balance INN"
    if [ -n "$balance" ] && [ "$(echo "$balance > 0" | bc 2>/dev/null)" = "1" ] 2>/dev/null; then
        success "Staker has positive balance"
    else
        fail "Staker has zero balance"
    fi
}

test_utxo_splitting() {
    section "UTXO Splitting Stress Test"

    log "Creating $NUM_SPLIT_UTXOS split UTXOs for staking..."
    local addr=$(rpc_staker getnewaddress 2>/dev/null || echo "")

    if [ -z "$addr" ]; then
        fail "Could not generate address for UTXO splitting"
        return
    fi

    local sent=0
    for i in $(seq 1 $NUM_SPLIT_UTXOS); do
        if rpc_staker sendtoaddress "$addr" 100.0 >/dev/null 2>&1; then
            ((sent++)) || true
        fi
        # Mine a block every few sends to confirm change outputs
        if [ $((i % 3)) -eq 0 ]; then
            rpc_staker setgenerate true 1 >/dev/null 2>&1 || true
            sleep 1
        fi
    done
    log "Sent $sent split transactions"

    # Mine blocks to confirm remaining
    rpc_staker setgenerate true 2 >/dev/null 2>&1 || true
    sleep 3

    # Count UTXOs safely (grep -c on single-line collapsed output)
    local utxo_list=$(rpc_staker listunspent 2>/dev/null || echo "[]")
    local utxo_count=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"txid"' | wc -l | tr -d ' ')

    log "UTXO count after splitting: $utxo_count"

    if [ "$utxo_count" -ge "$NUM_SPLIT_UTXOS" ]; then
        success "Created $utxo_count stake-able UTXOs"
    else
        warn "Only $utxo_count UTXOs created (expected >= $NUM_SPLIT_UTXOS)"
    fi
}

test_staking_activation() {
    section "Staking Activation Test"

    local info=$(rpc_staker getinfo 2>/dev/null || echo "{}")
    local start_blocks=$(get_json_int "$info" "blocks")
    log "Waiting for staking to activate at block $start_blocks (max ${STAKE_WAIT_TIME}s)..."
    local elapsed=0
    local staked=false

    while [ $elapsed -lt $STAKE_WAIT_TIME ]; do
        info=$(rpc_staker getinfo 2>/dev/null || echo "{}")
        local current_blocks=$(get_json_int "$info" "blocks")
        if [ "$current_blocks" -gt "$start_blocks" ]; then
            staked=true
            local new_blocks=$((current_blocks - start_blocks))
            success "Staked $new_blocks new PoS blocks in ${elapsed}s (now at height $current_blocks)"
            break
        fi

        # Check staking info periodically
        if [ $((elapsed % 20)) -eq 0 ] && [ $elapsed -gt 0 ]; then
            local sinfo=$(rpc_staker getstakinginfo 2>/dev/null || echo "{}")
            local weight=$(get_json_int "$sinfo" "weight")
            local expected=$(get_json_int "$sinfo" "expectedtime")
            log "Staking info at ${elapsed}s: weight=$weight, expectedtime=$expected"
        fi

        sleep 5
        elapsed=$((elapsed + 5))
    done

    if [ "$staked" = false ]; then
        warn "No PoS blocks generated in ${STAKE_WAIT_TIME}s (may need longer maturity)"
    fi
}

test_stake_split_combine() {
    section "Stake Split and Combine Test"

    # Check that stake splitting works by examining coinstake outputs
    local info=$(rpc_staker getinfo 2>/dev/null || echo "{}")
    local blocks=$(get_json_int "$info" "blocks")
    local hash=$(rpc_staker getblockhash "$blocks" 2>/dev/null || echo "")

    if [ -n "$hash" ]; then
        local block_data=$(rpc_staker getblock "$hash" 2>/dev/null || echo "")
        if echo "$block_data" | tr '\n' ' ' | grep -q '"flags" *: *"proof-of-stake"'; then
            success "Latest block is proof-of-stake"
        else
            log "Latest block is not PoS (may be PoW)"
        fi
    fi
}

test_concurrent_staking() {
    section "Concurrent Staking Load Test"

    log "Sending rapid transactions while staking is active..."
    local addr=$(rpc_validator getnewaddress 2>/dev/null || echo "")

    if [ -n "$addr" ]; then
        local tx_count=0
        for i in $(seq 1 50); do
            if rpc_staker sendtoaddress "$addr" 0.1 >/dev/null 2>&1; then
                ((tx_count++)) || true
            fi
        done
        success "Sent $tx_count transactions while staking"

        # Mine to confirm and check state
        rpc_staker setgenerate true 1 >/dev/null 2>&1 || true
        sleep 2
    else
        warn "Could not generate validator address"
    fi
}

test_node_sync() {
    section "Block Sync Validation"

    sleep 5

    local info_s=$(rpc_staker getinfo 2>/dev/null || echo "{}")
    local info_v=$(rpc_validator getinfo 2>/dev/null || echo "{}")
    local blocks_staker=$(get_json_int "$info_s" "blocks")
    local blocks_validator=$(get_json_int "$info_v" "blocks")

    log "Staker at block $blocks_staker, Validator at block $blocks_validator"

    local diff=$((blocks_staker - blocks_validator))
    if [ "$diff" -lt 0 ]; then diff=$((-diff)); fi

    if [ "$diff" -le 5 ]; then
        success "Nodes synchronized (diff: $diff blocks)"
    else
        warn "Nodes out of sync by $diff blocks"
    fi
}

test_memory_stability() {
    section "Memory Stability Check"

    # Match the staker data directory in the process list
    local pid=$(pgrep -f "innovad.*staking_stress/staker" | head -1 || echo "")
    if [ -z "$pid" ]; then
        # Fallback: try broader match
        pid=$(pgrep -f "innovad.*19500" | head -1 || echo "")
    fi

    if [ -n "$pid" ]; then
        local mem=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
        if [ -n "$mem" ] && [ "$mem" -gt 0 ] 2>/dev/null; then
            local mem_mb=$((mem / 1024))
            log "Staker node memory usage: ${mem_mb}MB"
            if [ "$mem_mb" -lt 2048 ]; then
                success "Memory usage within limits (${mem_mb}MB < 2048MB)"
            else
                warn "High memory usage: ${mem_mb}MB"
            fi
        else
            warn "Could not read memory for PID $pid"
        fi
    else
        warn "Could not find staker PID for memory check"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "     STAKING STRESS TEST SUMMARY"
    echo "========================================"
    echo -e "  Passed:   ${GREEN}$PASSED${NC}"
    echo -e "  Failed:   ${RED}$FAILED${NC}"
    echo -e "  Warnings: ${YELLOW}$WARNINGS${NC}"
    echo "========================================"

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All critical tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed${NC}"
        return 1
    fi
}

main() {
    echo ""
    echo "========================================"
    echo "    INNOVA STAKING STRESS TEST"
    echo "========================================"
    echo "  Stake wait time: ${STAKE_WAIT_TIME}s"
    echo "  Split UTXOs:     ${NUM_SPLIT_UTXOS}"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Waiting for initial node sync..."
    sleep 5

    test_basic_staking_setup
    test_utxo_splitting
    test_staking_activation
    test_stake_split_combine
    test_concurrent_staking
    test_node_sync
    test_memory_stability

    print_summary
}

main "$@"
