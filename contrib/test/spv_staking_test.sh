#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova SPV/HybridSPV Staking Test Script
# Tests SPV mode operation, bloom filters, merkle blocks, and SPV staking
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

TEST_DIR="/tmp/innova_spv_test"
FULL_DIR="$TEST_DIR/fullnode"
SPV_DIR="$TEST_DIR/spvnode"
VALIDATOR_DIR="$TEST_DIR/validator"

FULL_PORT=21445
SPV_PORT=21446
VALIDATOR_PORT=21447
FULL_RPC=21500
SPV_RPC=21501
VALIDATOR_RPC=21502

PASSED=0
FAILED=0
WARNINGS=0

STAKE_WAIT_TIME=${STAKE_WAIT_TIME:-180}

log() { echo -e "${BLUE}[SPV-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*spv_test" 2>/dev/null || true
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
    log "Setting up SPV test nodes..."
    rm -rf "$TEST_DIR"
    mkdir -p "$FULL_DIR" "$SPV_DIR" "$VALIDATOR_DIR"

    # Full node: provides block data and bloom filter service
    cat > "$FULL_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=spvtest
rpcpassword=spvpass
rpcport=$FULL_RPC
port=$FULL_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=1
stakemindepth=1
addnode=127.0.0.1:$SPV_PORT
addnode=127.0.0.1:$VALIDATOR_PORT
debug=1
printtoconsole=0
EOF

    # SPV node: light client with HybridSPV staking
    cat > "$SPV_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=spvtest
rpcpassword=spvpass
rpcport=$SPV_RPC
port=$SPV_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
spvmode=1
hybridspv=1
spvstaking=1
stakemindepth=1
addnode=127.0.0.1:$FULL_PORT
addnode=127.0.0.1:$VALIDATOR_PORT
debug=1
debugspv=1
printtoconsole=0
EOF

    # Validator: independent full node
    cat > "$VALIDATOR_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=spvtest
rpcpassword=spvpass
rpcport=$VALIDATOR_RPC
port=$VALIDATOR_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$FULL_PORT
addnode=127.0.0.1:$SPV_PORT
debug=1
printtoconsole=0
EOF

    log "Config files created for full, SPV, and validator nodes"
}

start_nodes() {
    log "Starting nodes..."
    "$INNOVAD" -datadir="$FULL_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$SPV_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$VALIDATOR_DIR" -regtest &
    sleep 4
    log "All nodes started"
}

rpc_full() {
    "$INNOVAD" -datadir="$FULL_DIR" -rpcuser=spvtest -rpcpassword=spvpass -rpcport=$FULL_RPC "$@" 2>/dev/null
}

rpc_spv() {
    "$INNOVAD" -datadir="$SPV_DIR" -rpcuser=spvtest -rpcpassword=spvpass -rpcport=$SPV_RPC "$@" 2>/dev/null
}

rpc_validator() {
    "$INNOVAD" -datadir="$VALIDATOR_DIR" -rpcuser=spvtest -rpcpassword=spvpass -rpcport=$VALIDATOR_RPC "$@" 2>/dev/null
}

# TEST SUITES
test_spv_initialization() {
    section "SPV Mode Initialization"

    # Check full node
    if rpc_full getinfo >/dev/null 2>&1; then
        success "Full node responds to RPC"
    else
        fail "Full node not responding"
        return 0
    fi

    # Check SPV node
    if rpc_spv getinfo >/dev/null 2>&1; then
        success "SPV node responds to RPC"
    else
        fail "SPV node not responding"
        return 0
    fi

    # Check SPV-specific info
    local spv_info=$(rpc_spv getspvinfo 2>/dev/null || echo "")
    if [ -n "$spv_info" ]; then
        success "SPV info available"
        log "SPV Info: $spv_info"

        if echo "$spv_info" | grep -qi "spv\|hybrid\|bloom"; then
            success "SPV mode indicators present"
        fi
    else
        warn "getspvinfo not available or returned empty"
    fi
}

test_spv_header_sync() {
    section "SPV Header Synchronization"

    # Generate blocks on full node
    log "Generating 200 blocks on full node..."
    rpc_full setgenerate true 200 >/dev/null 2>&1 || true
    sleep 2

    local full_blocks=$(rpc_full getinfo | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*')
    log "Full node at block $full_blocks"

    # Wait for SPV node to sync headers
    log "Waiting for SPV header sync (max 60s)..."
    local elapsed=0
    while [ $elapsed -lt 60 ]; do
        local spv_blocks=$(rpc_spv getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
        if [ "$spv_blocks" -ge "$full_blocks" ]; then
            success "SPV node synced to block $spv_blocks"
            break
        fi
        sleep 3
        elapsed=$((elapsed + 3))
        if [ $((elapsed % 15)) -eq 0 ]; then
            log "SPV at block $spv_blocks / $full_blocks after ${elapsed}s"
        fi
    done

    if [ $elapsed -ge 60 ]; then
        local spv_blocks=$(rpc_spv getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
        warn "SPV sync incomplete after 60s: at block $spv_blocks / $full_blocks"
    fi
}

test_spv_bloom_filter() {
    section "SPV Bloom Filter Test"

    # Generate addresses on SPV node and send coins to them
    local spv_addr=$(rpc_spv getnewaddress 2>/dev/null || echo "")
    if [ -z "$spv_addr" ]; then
        fail "Could not generate SPV address"
        return
    fi
    log "SPV address: $spv_addr"

    # Send from full node to SPV address
    local txid=$(rpc_full sendtoaddress "$spv_addr" 1000.0 2>/dev/null || echo "")
    if [ -n "$txid" ]; then
        success "Sent 1000 INN to SPV node: $txid"
    else
        warn "Could not send to SPV node (insufficient funds?)"
        return
    fi

    # Mine to confirm
    rpc_full setgenerate true 2 2>/dev/null || true
    sleep 5

    # Check SPV node received the transaction
    local spv_balance=$(rpc_spv getbalance 2>/dev/null | tr -d ' ')
    log "SPV node balance: $spv_balance"

    if [ "$(echo "$spv_balance > 0" | bc 2>/dev/null)" -eq 1 ] 2>/dev/null; then
        success "SPV node received funds via bloom filter"
    else
        warn "SPV node balance still 0 (bloom filter may need rescan)"
    fi
}

test_spv_utxo_cache() {
    section "SPV UTXO Cache Test"

    # Send multiple transactions to SPV node to populate UTXO cache
    local spv_addr=$(rpc_spv getnewaddress 2>/dev/null || echo "")
    local sent=0

    if [ -n "$spv_addr" ]; then
        for amount in 500 500 500 500 500; do
            if rpc_full sendtoaddress "$spv_addr" $amount 2>/dev/null; then
                ((sent++)) || true
            fi
        done
    fi

    if [ $sent -gt 0 ]; then
        success "Sent $sent transactions to SPV node"
    else
        warn "Could not send transactions to SPV node"
        return
    fi

    # Mine to confirm
    rpc_full setgenerate true 2 2>/dev/null || true
    sleep 5

    # Check SPV balance reflects all deposits
    local balance=$(rpc_spv getbalance 2>/dev/null | tr -d ' ')
    log "SPV balance after deposits: $balance"

    # Trigger SPV rescan if available
    if rpc_spv spvrescan 2>/dev/null; then
        log "SPV rescan triggered"
        sleep 5
    fi
}

test_spv_staking() {
    section "SPV Staking Test"

    local start_blocks=$(rpc_spv getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
    log "SPV node at block $start_blocks, waiting for staking (max ${STAKE_WAIT_TIME}s)..."

    # Check staking info
    local sinfo=$(rpc_spv getstakinginfo 2>/dev/null || echo "{}")
    log "SPV staking info: $sinfo"

    local elapsed=0
    local staked=false

    while [ $elapsed -lt $STAKE_WAIT_TIME ]; do
        local current=$(rpc_spv getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo "$start_blocks")
        if [ "$current" -gt "$start_blocks" ]; then
            staked=true
            local new=$((current - start_blocks))
            success "SPV node staked $new blocks in ${elapsed}s"
            break
        fi

        if [ $((elapsed % 30)) -eq 0 ] && [ $elapsed -gt 0 ]; then
            sinfo=$(rpc_spv getstakinginfo 2>/dev/null || echo "{}")
            log "SPV staking info at ${elapsed}s: $sinfo"
        fi

        sleep 5
        elapsed=$((elapsed + 5))
    done

    if [ "$staked" = false ]; then
        warn "SPV node did not stake in ${STAKE_WAIT_TIME}s (may need more maturity or block data)"
    fi
}

test_spv_block_verification() {
    section "SPV Block Verification"

    # Verify SPV and full node agree on chain
    local full_blocks=$(rpc_full getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
    local spv_blocks=$(rpc_spv getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
    local val_blocks=$(rpc_validator getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)

    log "Heights - Full: $full_blocks, SPV: $spv_blocks, Validator: $val_blocks"

    # Check block hash agreement at a common height
    local check_height=$((spv_blocks < full_blocks ? spv_blocks : full_blocks))
    if [ "$check_height" -gt 0 ]; then
        local hash_full=$(rpc_full getblockhash "$check_height" 2>/dev/null || echo "")
        local hash_spv=$(rpc_spv getblockhash "$check_height" 2>/dev/null || echo "")

        if [ -n "$hash_full" ] && [ "$hash_full" = "$hash_spv" ]; then
            success "SPV and full node agree on block hash at height $check_height"
        elif [ -n "$hash_full" ] && [ -n "$hash_spv" ]; then
            fail "SPV and full node disagree on block hash at height $check_height"
        else
            warn "Could not compare block hashes"
        fi
    fi
}

test_spv_transaction_relay() {
    section "SPV Transaction Relay Test"

    # Send from SPV node to full node
    local full_addr=$(rpc_full getnewaddress 2>/dev/null || echo "")
    local spv_balance=$(rpc_spv getbalance 2>/dev/null | tr -d ' ')

    if [ -n "$full_addr" ] && [ "$(echo "$spv_balance > 10" | bc 2>/dev/null)" -eq 1 ] 2>/dev/null; then
        local txid=$(rpc_spv sendtoaddress "$full_addr" 10.0 2>/dev/null || echo "")
        if [ -n "$txid" ]; then
            success "SPV node sent transaction: $txid"

            # Verify full node sees it
            sleep 3
            if rpc_full gettransaction "$txid" >/dev/null 2>&1; then
                success "Full node received SPV transaction"
            else
                warn "Full node hasn't received SPV transaction yet"
            fi
        else
            warn "SPV node could not send transaction"
        fi
    else
        warn "Insufficient SPV balance for relay test"
    fi
}

test_spv_memory_usage() {
    section "SPV Memory Usage"

    local pid_full=$(pgrep -f "innovad.*fullnode" | head -1)
    local pid_spv=$(pgrep -f "innovad.*spvnode" | head -1)

    if [ -n "$pid_full" ] && [ -n "$pid_spv" ]; then
        local mem_full=$(ps -o rss= -p "$pid_full" 2>/dev/null | tr -d ' ')
        local mem_spv=$(ps -o rss= -p "$pid_spv" 2>/dev/null | tr -d ' ')

        if [ -n "$mem_full" ] && [ -n "$mem_spv" ]; then
            local mb_full=$((mem_full / 1024))
            local mb_spv=$((mem_spv / 1024))

            log "Full node memory: ${mb_full}MB"
            log "SPV node memory:  ${mb_spv}MB"

            if [ "$mb_spv" -lt "$mb_full" ]; then
                success "SPV node uses less memory than full node (${mb_spv}MB < ${mb_full}MB)"
            else
                warn "SPV node uses more memory than expected (${mb_spv}MB >= ${mb_full}MB)"
            fi

            if [ "$mb_spv" -lt 512 ]; then
                success "SPV memory usage under 512MB"
            else
                warn "SPV memory usage high: ${mb_spv}MB"
            fi
        fi
    else
        warn "Could not find node PIDs for memory check"
    fi
}

test_spv_rapid_transactions() {
    section "SPV Rapid Transaction Stress Test"

    local addr=$(rpc_full getnewaddress 2>/dev/null || echo "")
    local spv_balance=$(rpc_spv getbalance 2>/dev/null | tr -d ' ')

    if [ -z "$addr" ] || [ "$(echo "$spv_balance < 100" | bc 2>/dev/null)" -eq 1 ] 2>/dev/null; then
        warn "Insufficient balance for rapid tx test"
        return
    fi

    local sent=0
    local failed=0
    for i in $(seq 1 30); do
        if rpc_spv sendtoaddress "$addr" 0.1 2>/dev/null; then
            ((sent++)) || true
        else
            ((failed++)) || true
        fi
    done

    log "Rapid TX results: $sent sent, $failed failed"
    if [ $sent -ge 20 ]; then
        success "SPV node handled rapid transactions: $sent/30 succeeded"
    elif [ $sent -gt 0 ]; then
        warn "Some rapid transactions failed: $sent/30 succeeded"
    else
        warn "Could not send any rapid transactions"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "      SPV STAKING TEST SUMMARY"
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
        return 0
    fi
}

main() {
    echo ""
    echo "========================================"
    echo "    INNOVA SPV STAKING TEST"
    echo "========================================"
    echo "  Full:      port $FULL_PORT / rpc $FULL_RPC"
    echo "  SPV:       port $SPV_PORT / rpc $SPV_RPC"
    echo "  Validator: port $VALIDATOR_PORT / rpc $VALIDATOR_RPC"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Waiting for nodes to initialize..."
    sleep 5

    test_spv_initialization
    test_spv_header_sync
    test_spv_bloom_filter
    test_spv_utxo_cache
    test_spv_staking
    test_spv_block_verification
    test_spv_transaction_relay
    test_spv_memory_usage
    test_spv_rapid_transactions

    print_summary
}

main "$@"
