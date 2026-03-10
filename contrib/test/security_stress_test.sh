#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Security Stress Test Script
# Tests: double-spend prevention, invalid transaction rejection,
#        malformed data handling, consensus rule enforcement
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

TEST_DIR="/tmp/innova_security_stress"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"

NODE1_PORT=25445
NODE2_PORT=25446
NODE1_RPC=25500
NODE2_RPC=25501

PASSED=0
FAILED=0
WARNINGS=0

log() { echo -e "${BLUE}[SEC-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*security_stress" 2>/dev/null || true
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
    log "Setting up security test nodes..."
    rm -rf "$TEST_DIR"
    mkdir -p "$NODE1_DIR" "$NODE2_DIR"

    cat > "$NODE1_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=sectest
rpcpassword=secpass
rpcport=$NODE1_RPC
port=$NODE1_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$NODE2_PORT
debug=1
printtoconsole=0
EOF

    cat > "$NODE2_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=sectest
rpcpassword=secpass
rpcport=$NODE2_RPC
port=$NODE2_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$NODE1_PORT
debug=1
printtoconsole=0
EOF

    log "Config files created"
}

start_nodes() {
    log "Starting nodes..."
    "$INNOVAD" -datadir="$NODE1_DIR" -regtest &
    sleep 3
    "$INNOVAD" -datadir="$NODE2_DIR" -regtest &
    sleep 4
    log "Nodes started"
}

rpc1() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=sectest -rpcpassword=secpass -rpcport=$NODE1_RPC "$@" 2>/dev/null
}

rpc1_err() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=sectest -rpcpassword=secpass -rpcport=$NODE1_RPC "$@" 2>&1
}

rpc2() {
    "$INNOVAD" -datadir="$NODE2_DIR" -rpcuser=sectest -rpcpassword=secpass -rpcport=$NODE2_RPC "$@" 2>/dev/null
}

# TEST SUITES
test_double_spend_prevention() {
    section "Double-Spend Prevention"

    local utxo_list=$(rpc1 listunspent 1 9999999 || echo "[]")
    local txid=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"txid" *: *"[a-f0-9]\{64\}"' | head -1 | grep -o '[a-f0-9]\{64\}')
    local vout=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"vout" *: *[0-9]*' | head -1 | grep -o '[0-9]*$')

    if [ -z "$txid" ]; then
        warn "No UTXOs available for double-spend test"
        return 0
    fi

    local addr1=$(rpc1 getnewaddress || echo "")
    local addr2=$(rpc1 getnewaddress || echo "")

    local raw1=$(rpc1 createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$addr1\":49.99}" 2>/dev/null || echo "")
    local raw2=$(rpc1 createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$addr2\":49.99}" 2>/dev/null || echo "")

    if [ -z "$raw1" ] || [ -z "$raw2" ]; then
        warn "Could not create raw transactions for double-spend test"
        return 0
    fi

    local signed1=$(rpc1 signrawtransaction "$raw1" || echo "")
    local hex1=$(echo "$signed1" | tr '\n' ' ' | grep -o '"hex" *: *"[a-f0-9]*"' | head -1 | sed 's/.*: *"//;s/"$//')

    local signed2=$(rpc1 signrawtransaction "$raw2" || echo "")
    local hex2=$(echo "$signed2" | tr '\n' ' ' | grep -o '"hex" *: *"[a-f0-9]*"' | head -1 | sed 's/.*: *"//;s/"$//')

    if [ -z "$hex1" ] || [ -z "$hex2" ]; then
        warn "Could not sign raw transactions for double-spend test"
        return 0
    fi

    local result1=$(rpc1 sendrawtransaction "$hex1" 2>/dev/null || echo "")
    if [ -n "$result1" ] && [ ${#result1} -eq 64 ]; then
        success "First transaction accepted: ${result1:0:16}..."
    else
        warn "First transaction not accepted"
        return 0
    fi

    local result2=$(rpc1_err sendrawtransaction "$hex2" 2>&1 || echo "ERROR")
    if echo "$result2" | grep -qi "error\|conflict\|already\|inputs.*spent\|missing\|double"; then
        success "Double-spend correctly REJECTED"
    else
        if [ -n "$result2" ] && [ ${#result2} -eq 64 ]; then
            fail "Double-spend was ACCEPTED (critical security issue!)"
        else
            warn "Double-spend response unclear: ${result2:0:80}"
        fi
    fi

    rpc1 setgenerate true 1 >/dev/null 2>&1 || true
    sleep 1

    local result3=$(rpc1_err sendrawtransaction "$hex2" 2>&1 || echo "ERROR")
    if echo "$result3" | grep -qi "error\|conflict\|already\|inputs.*spent\|missing\|double"; then
        success "Post-confirmation double-spend rejected"
    else
        fail "Post-confirmation double-spend not properly rejected"
    fi
}

test_invalid_transaction_rejection() {
    section "Invalid Transaction Rejection"

    local result=$(rpc1_err sendrawtransaction "deadbeef0123456789abcdef" 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|deserialization\|invalid\|decode"; then
        success "Malformed transaction hex rejected"
    else
        warn "Malformed tx response: ${result:0:80}"
    fi

    result=$(rpc1_err sendrawtransaction "" 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid\|parameter"; then
        success "Empty transaction rejected"
    else
        warn "Empty tx response: ${result:0:80}"
    fi

    result=$(rpc1_err decoderawtransaction "0000000000" 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|decode\|invalid"; then
        success "Malformed decode correctly rejected"
    else
        warn "Malformed decode response unclear"
    fi
}

test_invalid_address_handling() {
    section "Invalid Address Handling"

    local result=$(rpc1_err sendtoaddress "" 10.0 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Empty address rejected"
    else
        warn "Empty address response: ${result:0:80}"
    fi

    result=$(rpc1_err sendtoaddress "NOTAVALIDADDRESS12345" 10.0 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Random string address rejected"
    else
        warn "Random string address response: ${result:0:80}"
    fi

    result=$(rpc1_err importprivkey "NOTAVALIDPRIVATEKEY" "test" false 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Invalid private key import rejected"
    else
        warn "Invalid privkey response: ${result:0:80}"
    fi

    local invalid=$(rpc1 validateaddress "1111111111111111111111111" || echo "{}")
    if echo "$invalid" | tr '\n' ' ' | grep -q '"isvalid" *: *false'; then
        success "Numeric-only address correctly invalidated"
    fi
}

test_overflow_and_edge_values() {
    section "Overflow and Edge Value Testing"

    local addr=$(rpc1 getnewaddress || echo "")

    local result=$(rpc1_err sendtoaddress "$addr" 99999999999 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid\|amount\|insufficient"; then
        success "Excessive amount correctly rejected"
    else
        warn "Excessive amount response: ${result:0:80}"
    fi

    result=$(rpc1_err sendtoaddress "$addr" -1 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid\|negative"; then
        success "Negative amount rejected"
    else
        warn "Negative amount response: ${result:0:80}"
    fi

    result=$(rpc1_err sendtoaddress "$addr" 0 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Zero amount rejected"
    else
        warn "Zero amount response: ${result:0:80}"
    fi

    result=$(rpc1_err sendtoaddress "$addr" 0.123456789 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid\|precision"; then
        success "Over-precision amount rejected"
    else
        # May be accepted if truncated to 8 decimals
        log "Over-precision amount: ${result:0:80}"
    fi

    result=$(rpc1_err settxfee -0.001 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Negative fee rejected"
    else
        warn "Negative fee response: ${result:0:80}"
    fi
}

test_signature_validation() {
    section "Signature and Script Validation"

    local utxo_list=$(rpc1 listunspent 1 9999999 || echo "[]")
    local txid=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"txid" *: *"[a-f0-9]\{64\}"' | head -1 | grep -o '[a-f0-9]\{64\}')
    local vout=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"vout" *: *[0-9]*' | head -1 | grep -o '[0-9]*$')

    if [ -z "$txid" ]; then
        warn "No UTXOs for signature test"
        return 0
    fi

    local addr=$(rpc1 getnewaddress || echo "")
    local raw=$(rpc1 createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$addr\":49.99}" 2>/dev/null || echo "")
    local signed=$(rpc1 signrawtransaction "$raw" || echo "")
    local hex=$(echo "$signed" | tr '\n' ' ' | grep -o '"hex" *: *"[a-f0-9]*"' | head -1 | sed 's/.*: *"//;s/"$//')

    if [ -z "$hex" ]; then
        warn "Could not create signed transaction for modification test"
        return 0
    fi

    # Flip a byte in the middle to tamper with the signed transaction
    local mid=$((${#hex} / 2))
    local char="${hex:$mid:1}"
    local flipped
    if [ "$char" = "0" ]; then flipped="f"; else flipped="0"; fi
    local tampered="${hex:0:$mid}${flipped}${hex:$((mid+1))}"

    local result=$(rpc1_err sendrawtransaction "$tampered" 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|invalid\|signature\|script\|non-mandatory"; then
        success "Tampered transaction correctly rejected"
    else
        if [ -n "$result" ] && [ ${#result} -eq 64 ]; then
            fail "Tampered transaction was ACCEPTED (critical!)"
        else
            warn "Tampered tx response: ${result:0:80}"
        fi
    fi

    local unsigned_result=$(rpc1_err sendrawtransaction "$raw" 2>&1 || echo "ERROR")
    if echo "$unsigned_result" | grep -qi "error\|invalid\|script\|signature"; then
        success "Unsigned transaction correctly rejected"
    else
        warn "Unsigned tx response: ${unsigned_result:0:80}"
    fi
}

test_block_validation() {
    section "Block Validation Rules"

    local hash=$(rpc1 getblockhash 1 || echo "")
    if [ -z "$hash" ]; then
        warn "No blocks available for validation test"
        return 0
    fi

    local block=$(rpc1 getblock "$hash" || echo "")

    local has_hash=$(echo "$block" | tr '\n' ' ' | grep -c '"hash"')
    local has_merkle=$(echo "$block" | tr '\n' ' ' | grep -c '"merkleroot"')
    local has_time=$(echo "$block" | tr '\n' ' ' | grep -c '"time"')
    local has_nonce=$(echo "$block" | tr '\n' ' ' | grep -c '"nonce"')
    local has_bits=$(echo "$block" | tr '\n' ' ' | grep -c '"bits"')

    local fields=$((has_hash + has_merkle + has_time + has_nonce + has_bits))
    if [ $fields -ge 4 ]; then
        success "Block has required consensus fields ($fields/5)"
    else
        fail "Block missing consensus fields (only $fields/5)"
    fi

    local genesis=$(rpc1 getblockhash 0 || echo "")
    if [ -n "$genesis" ] && [ ${#genesis} -ge 60 ]; then
        success "Genesis block hash retrievable"
    fi

    local fake_hash="0000000000000000000000000000000000000000000000000000000000000001"
    local result=$(rpc1_err getblock "$fake_hash" 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|not found"; then
        success "Non-existent block correctly rejected"
    else
        warn "Non-existent block response: ${result:0:80}"
    fi
}

test_rpc_authentication() {
    section "RPC Authentication Security"

    local result=$("$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=wronguser -rpcpassword=wrongpass -rpcport=$NODE1_RPC getinfo 2>&1 || echo "AUTH_FAIL")
    if echo "$result" | grep -qi "error\|auth\|incorrect\|forbidden\|401\|couldn't connect\|fail"; then
        success "Wrong credentials correctly rejected"
    else
        if echo "$result" | tr '\n' ' ' | grep -q '"version"'; then
            fail "Wrong credentials were ACCEPTED (critical!)"
        else
            warn "Auth failure response unclear: ${result:0:80}"
        fi
    fi

    result=$("$INNOVAD" -datadir="$NODE1_DIR" -rpcport=$NODE1_RPC getinfo 2>&1 || echo "AUTH_FAIL")
    if echo "$result" | grep -qi "error\|auth\|incorrect\|fail\|couldn't"; then
        success "No credentials correctly rejected"
    else
        if echo "$result" | tr '\n' ' ' | grep -q '"version"'; then
            warn "No-credential request returned data (check cookie auth)"
        else
            success "No credentials rejected"
        fi
    fi
}

test_concurrent_operations() {
    section "Concurrent Operation Safety"

    local addr=$(rpc1 getnewaddress || echo "")
    local pids=()
    local succeeded=0

    for i in $(seq 1 10); do
        rpc1 sendtoaddress "$addr" 1.0 >/dev/null 2>&1 &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((succeeded++)) || true
        fi
    done

    if [ $succeeded -ge 5 ]; then
        success "Concurrent sends: $succeeded/10 succeeded safely"
    elif [ $succeeded -gt 0 ]; then
        warn "Concurrent sends: only $succeeded/10 succeeded"
    else
        warn "No concurrent sends succeeded (may be UTXO contention)"
    fi

    rpc1 setgenerate true 1 >/dev/null 2>&1 || true
    sleep 1

    local info_ok=0
    pids=()
    for i in $(seq 1 20); do
        rpc1 getinfo >/dev/null 2>&1 &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((info_ok++)) || true
        fi
    done

    if [ $info_ok -ge 15 ]; then
        success "Concurrent reads: $info_ok/20 succeeded"
    else
        warn "Concurrent reads: only $info_ok/20 succeeded"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "    SECURITY STRESS TEST SUMMARY"
    echo "========================================"
    echo -e "  Passed:   ${GREEN}$PASSED${NC}"
    echo -e "  Failed:   ${RED}$FAILED${NC}"
    echo -e "  Warnings: ${YELLOW}$WARNINGS${NC}"
    echo "========================================"

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All critical security tests passed!${NC}"
        return 0
    else
        echo -e "${RED}SECURITY ISSUES DETECTED - Review failures above${NC}"
        return 1
    fi
}

main() {
    echo ""
    echo "========================================"
    echo "   INNOVA SECURITY STRESS TEST"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Generating initial blocks..."
    rpc1 setgenerate true 150 >/dev/null 2>&1 || true
    sleep 2

    test_double_spend_prevention
    test_invalid_transaction_rejection
    test_invalid_address_handling
    test_overflow_and_edge_values
    test_signature_validation
    test_block_validation
    test_rpc_authentication
    test_concurrent_operations

    print_summary
}

main "$@"
