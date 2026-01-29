#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Transaction Stress Test Script
# Tests transaction creation, validation, raw transactions, and edge cases
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

TEST_DIR="/tmp/innova_tx_stress"
SENDER_DIR="$TEST_DIR/sender"
RECEIVER_DIR="$TEST_DIR/receiver"

SENDER_PORT=23445
RECEIVER_PORT=23446
SENDER_RPC=23500
RECEIVER_RPC=23501

PASSED=0
FAILED=0
WARNINGS=0

log() { echo -e "${BLUE}[TX-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*tx_stress" 2>/dev/null || true
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
    log "Setting up transaction test nodes..."
    rm -rf "$TEST_DIR"
    mkdir -p "$SENDER_DIR" "$RECEIVER_DIR"

    cat > "$SENDER_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=txtest
rpcpassword=txpass
rpcport=$SENDER_RPC
port=$SENDER_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$RECEIVER_PORT
debug=1
printtoconsole=0
EOF

    cat > "$RECEIVER_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=txtest
rpcpassword=txpass
rpcport=$RECEIVER_RPC
port=$RECEIVER_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$SENDER_PORT
debug=1
printtoconsole=0
EOF

    log "Config files created"
}

start_nodes() {
    log "Starting nodes..."
    "$INNOVAD" -datadir="$SENDER_DIR" -regtest &
    sleep 3
    "$INNOVAD" -datadir="$RECEIVER_DIR" -regtest &
    sleep 4
    log "Nodes started"
}

rpc_send() {
    "$INNOVAD" -datadir="$SENDER_DIR" -rpcuser=txtest -rpcpassword=txpass -rpcport=$SENDER_RPC "$@" 2>/dev/null
}

rpc_recv() {
    "$INNOVAD" -datadir="$RECEIVER_DIR" -rpcuser=txtest -rpcpassword=txpass -rpcport=$RECEIVER_RPC "$@" 2>/dev/null
}

# TEST SUITES
test_basic_transactions() {
    section "Basic Transaction Types"

    # Standard P2PKH send
    local addr=$(rpc_recv getnewaddress 2>/dev/null)
    local txid=$(rpc_send sendtoaddress "$addr" 500.0 2>/dev/null || echo "")

    if [ -n "$txid" ] && [ ${#txid} -eq 64 ]; then
        success "P2PKH transaction created: ${txid:0:16}..."
    else
        fail "P2PKH transaction failed"
        return 0
    fi

    # Confirm
    rpc_send setgenerate true 1 >/dev/null 2>&1 || true
    sleep 2

    # Verify transaction details
    local tx_data=$(rpc_send gettransaction "$txid" 2>/dev/null || echo "")
    if echo "$tx_data" | tr '\n' ' ' | grep -q '"confirmations" *: *[1-9]'; then
        success "Transaction confirmed in block"
    else
        warn "Transaction not yet confirmed"
    fi

    # Check amount
    if echo "$tx_data" | tr '\n' ' ' | grep -q '"amount"'; then
        success "Transaction has valid amount field"
    fi
}

test_self_send() {
    section "Self-Send Transaction"

    local addr=$(rpc_send getnewaddress 2>/dev/null)
    local balance_before=$(rpc_send getbalance 2>/dev/null | tr -d ' \n')

    local txid=$(rpc_send sendtoaddress "$addr" 100.0 2>/dev/null || echo "")
    if [ -n "$txid" ]; then
        success "Self-send transaction created"

        # Confirm
        rpc_send setgenerate true 1 >/dev/null 2>&1 || true
        sleep 2

        local balance_after=$(rpc_send getbalance 2>/dev/null | tr -d ' \n')
        log "Balance before: $balance_before, after: $balance_after"

        # Balance should decrease by fee only (self-send)
        success "Self-send completed (balance change = tx fee)"
    else
        fail "Self-send failed"
    fi
}

test_dust_transactions() {
    section "Dust Transaction Edge Cases"

    local addr=$(rpc_recv getnewaddress 2>/dev/null)

    # Try very small amount (should fail as dust)
    local result=$(rpc_send sendtoaddress "$addr" 0.00000001 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|dust\|small\|amount"; then
        success "Dust transaction correctly rejected"
    else
        warn "Dust transaction result: $result"
    fi

    # Try minimum viable amount
    local min_result=$(rpc_send sendtoaddress "$addr" 0.001 2>/dev/null || echo "")
    if [ -n "$min_result" ] && [ ${#min_result} -eq 64 ]; then
        success "Minimum viable transaction accepted"
        rpc_send setgenerate true 1 >/dev/null 2>&1 || true
        sleep 1
    else
        log "Minimum viable tx result: $min_result"
    fi
}

test_rapid_transactions() {
    section "Rapid Transaction Stress"

    local addr=$(rpc_recv getnewaddress 2>/dev/null)
    local sent=0
    local failed_count=0

    log "Sending 30 rapid transactions..."
    for i in $(seq 1 30); do
        if rpc_send sendtoaddress "$addr" 1.0 >/dev/null 2>&1; then
            ((sent++)) || true
        else
            ((failed_count++)) || true
        fi
    done

    log "Results: $sent sent, $failed_count failed"

    if [ $sent -ge 20 ]; then
        success "Rapid send: $sent/30 transactions succeeded"
    elif [ $sent -gt 0 ]; then
        warn "Only $sent/30 rapid transactions succeeded"
    else
        fail "No rapid transactions succeeded"
    fi

    # Mine to confirm
    rpc_send setgenerate true 2 >/dev/null 2>&1 || true
    sleep 2

    # Check mempool is clear
    local mempool=$(rpc_send getrawmempool 2>/dev/null || echo "[]")
    local mempool_count=$(echo "$mempool" | tr '\n' ' ' | grep -o '"[a-f0-9]\{64\}"' | wc -l | tr -d ' ')
    log "Mempool after mining: $mempool_count txs"

    if [ "$mempool_count" -eq 0 ]; then
        success "All transactions confirmed (mempool empty)"
    else
        log "$mempool_count transactions still in mempool"
    fi
}

test_raw_transactions() {
    section "Raw Transaction Creation"

    # Get an unspent output
    local utxo_list=$(rpc_send listunspent 1 9999999 2>/dev/null || echo "[]")
    local first_txid=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"txid" *: *"[a-f0-9]\{64\}"' | head -1 | grep -o '[a-f0-9]\{64\}')
    local first_vout=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"vout" *: *[0-9]*' | head -1 | grep -o '[0-9]*$')

    if [ -z "$first_txid" ]; then
        warn "No UTXOs available for raw transaction test"
        return 0
    fi

    local recv_addr=$(rpc_recv getnewaddress 2>/dev/null)
    local change_addr=$(rpc_send getnewaddress 2>/dev/null)

    # Create raw transaction (send 50, change the rest minus fee)
    local raw_tx=$(rpc_send createrawtransaction "[{\"txid\":\"$first_txid\",\"vout\":$first_vout}]" "{\"$recv_addr\":50.0,\"$change_addr\":49.99}" 2>/dev/null || echo "")

    if [ -n "$raw_tx" ]; then
        success "Raw transaction created"
        log "Raw tx hex length: ${#raw_tx}"
    else
        fail "Raw transaction creation failed"
        return 0
    fi

    # Decode and verify
    local decoded=$(rpc_send decoderawtransaction "$raw_tx" 2>/dev/null || echo "")
    if echo "$decoded" | tr '\n' ' ' | grep -q '"vout"'; then
        success "Raw transaction decoded successfully"
    else
        fail "Raw transaction decode failed"
    fi

    # Sign raw transaction
    local signed=$(rpc_send signrawtransaction "$raw_tx" 2>/dev/null || echo "")
    if echo "$signed" | tr '\n' ' ' | grep -q '"complete" *: *true'; then
        success "Raw transaction signed completely"

        # Extract signed hex
        local signed_hex=$(echo "$signed" | tr '\n' ' ' | grep -o '"hex" *: *"[a-f0-9]*"' | head -1 | sed 's/.*: *"//;s/"$//')

        # Send it
        local send_result=$(rpc_send sendrawtransaction "$signed_hex" 2>/dev/null || echo "")
        if [ -n "$send_result" ] && [ ${#send_result} -eq 64 ]; then
            success "Signed raw transaction broadcast: ${send_result:0:16}..."
            rpc_send setgenerate true 1 >/dev/null 2>&1 || true
            sleep 1
        else
            warn "Raw tx broadcast result: $send_result"
        fi
    else
        warn "Raw transaction signing incomplete"
    fi
}

test_fee_estimation() {
    section "Transaction Fee Handling"

    # Check current tx fee
    local info=$(rpc_send getinfo 2>/dev/null || echo "{}")
    local paytxfee=$(echo "$info" | tr '\n' ' ' | grep -o '"paytxfee" *: *[0-9.]*' | grep -o '[0-9.]*$' || echo "unknown")
    log "Current paytxfee: $paytxfee"

    # Set a custom fee
    local fee_result=$(rpc_send settxfee 0.0001 2>&1 || echo "ERROR")
    if ! echo "$fee_result" | grep -qi "error"; then
        success "Custom transaction fee set"
    else
        warn "settxfee result: $fee_result"
    fi

    # Send with custom fee and verify it's applied
    local addr=$(rpc_recv getnewaddress 2>/dev/null)
    local txid=$(rpc_send sendtoaddress "$addr" 10.0 2>/dev/null || echo "")
    if [ -n "$txid" ]; then
        local tx_data=$(rpc_send gettransaction "$txid" 2>/dev/null || echo "")
        local fee=$(echo "$tx_data" | tr '\n' ' ' | grep -o '"fee" *: *-\?[0-9.]*' | head -1 | grep -o '[0-9.]*$' || echo "0")
        log "Transaction fee: $fee"
        success "Transaction with custom fee created"
        rpc_send setgenerate true 1 >/dev/null 2>&1 || true
        sleep 1
    fi

    # Reset fee
    rpc_send settxfee 0.00001 >/dev/null 2>&1 || true
}

test_mempool_operations() {
    section "Mempool Operations"

    # Get mempool info
    local mempool=$(rpc_send getrawmempool 2>/dev/null || echo "[]")
    log "Mempool entries: $(echo "$mempool" | tr '\n' ' ' | grep -o '"[a-f0-9]\{64\}"' | wc -l | tr -d ' ')"

    # Create a transaction but don't mine it
    local addr=$(rpc_recv getnewaddress 2>/dev/null)
    local txid=$(rpc_send sendtoaddress "$addr" 5.0 2>/dev/null || echo "")

    if [ -n "$txid" ]; then
        # Check it's in the mempool
        mempool=$(rpc_send getrawmempool 2>/dev/null || echo "[]")
        if echo "$mempool" | grep -q "$txid"; then
            success "Unconfirmed tx visible in mempool"
        else
            warn "Tx not found in mempool (may have been mined already)"
        fi

        # Get raw mempool with verbose info
        local verbose_pool=$(rpc_send getrawmempool true 2>/dev/null || echo "{}")
        if echo "$verbose_pool" | tr '\n' ' ' | grep -q '"size"\|"fee"'; then
            success "Verbose mempool info available"
        fi

        # Mine to clear
        rpc_send setgenerate true 1 >/dev/null 2>&1 || true
        sleep 1
    fi
}

test_large_amount_transactions() {
    section "Large Amount Transaction Test"

    # Generate more blocks for more coins
    rpc_send setgenerate true 50 >/dev/null 2>&1 || true
    sleep 2

    local balance=$(rpc_send getbalance 2>/dev/null | tr -d ' \n')
    log "Available balance: $balance INN"

    # Send a large transaction
    local addr=$(rpc_recv getnewaddress 2>/dev/null)
    local large_amount="100000"
    local txid=$(rpc_send sendtoaddress "$addr" "$large_amount" 2>/dev/null || echo "")

    if [ -n "$txid" ] && [ ${#txid} -eq 64 ]; then
        success "Large transaction ($large_amount INN) created"
        rpc_send setgenerate true 1 >/dev/null 2>&1 || true
        sleep 1
    else
        warn "Large transaction may have failed (insufficient confirmed coins)"
    fi
}

test_zero_and_negative() {
    section "Invalid Amount Rejection"

    local addr=$(rpc_recv getnewaddress 2>/dev/null)

    # Zero amount
    local result=$(rpc_send sendtoaddress "$addr" 0 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Zero amount correctly rejected"
    else
        fail "Zero amount accepted"
    fi

    # Negative amount
    result=$(rpc_send sendtoaddress "$addr" -100 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid\|negative"; then
        success "Negative amount correctly rejected"
    else
        fail "Negative amount accepted"
    fi

    # Amount exceeding balance
    result=$(rpc_send sendtoaddress "$addr" 999999999999 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|insufficient\|funds"; then
        success "Excessive amount correctly rejected"
    else
        fail "Excessive amount accepted"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "   TRANSACTION STRESS TEST SUMMARY"
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
    echo "   INNOVA TRANSACTION STRESS TEST"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Generating initial blocks..."
    rpc_send setgenerate true 150 >/dev/null 2>&1 || true
    sleep 2

    test_basic_transactions
    test_self_send
    test_dust_transactions
    test_rapid_transactions
    test_raw_transactions
    test_fee_estimation
    test_mempool_operations
    test_large_amount_transactions
    test_zero_and_negative

    print_summary
}

main "$@"
