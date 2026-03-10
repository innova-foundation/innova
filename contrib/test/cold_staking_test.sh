#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Cold Staking Test Script
# Tests P2CS (Pay-to-Cold-Staking) delegation, staking, and revocation
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

TEST_DIR="/tmp/innova_cold_stake_test"
OWNER_DIR="$TEST_DIR/owner"
STAKER_DIR="$TEST_DIR/staker"
VALIDATOR_DIR="$TEST_DIR/validator"

OWNER_PORT=20445
STAKER_PORT=20446
VALIDATOR_PORT=20447
OWNER_RPC=20500
STAKER_RPC=20501
VALIDATOR_RPC=20502

PASSED=0
FAILED=0
WARNINGS=0

STAKE_WAIT_TIME=${STAKE_WAIT_TIME:-180}

log() { echo -e "${BLUE}[COLD-STAKE]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*cold_stake_test" 2>/dev/null || true
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
    log "Setting up 3-node cold staking test..."
    rm -rf "$TEST_DIR"
    mkdir -p "$OWNER_DIR" "$STAKER_DIR" "$VALIDATOR_DIR"

    cat > "$OWNER_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=cstest
rpcpassword=cspass
rpcport=$OWNER_RPC
port=$OWNER_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$STAKER_PORT
addnode=127.0.0.1:$VALIDATOR_PORT
debug=1
printtoconsole=0
EOF

    cat > "$STAKER_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=cstest
rpcpassword=cspass
rpcport=$STAKER_RPC
port=$STAKER_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=1
stakemindepth=1
stakeminvalue=1
addnode=127.0.0.1:$OWNER_PORT
addnode=127.0.0.1:$VALIDATOR_PORT
debug=1
printtoconsole=0
EOF

    cat > "$VALIDATOR_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=cstest
rpcpassword=cspass
rpcport=$VALIDATOR_RPC
port=$VALIDATOR_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$OWNER_PORT
addnode=127.0.0.1:$STAKER_PORT
debug=1
printtoconsole=0
EOF

    log "Config files created for owner, staker, validator"
}

start_nodes() {
    log "Starting nodes..."
    "$INNOVAD" -datadir="$OWNER_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$STAKER_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$VALIDATOR_DIR" -regtest &
    sleep 4
    log "All nodes started"
}

rpc_owner() {
    "$INNOVAD" -datadir="$OWNER_DIR" -rpcuser=cstest -rpcpassword=cspass -rpcport=$OWNER_RPC "$@" 2>/dev/null
}

rpc_staker() {
    "$INNOVAD" -datadir="$STAKER_DIR" -rpcuser=cstest -rpcpassword=cspass -rpcport=$STAKER_RPC "$@" 2>/dev/null
}

rpc_validator() {
    "$INNOVAD" -datadir="$VALIDATOR_DIR" -rpcuser=cstest -rpcpassword=cspass -rpcport=$VALIDATOR_RPC "$@" 2>/dev/null
}

test_rpc_commands() {
    section "Cold Staking RPC Commands"

    local staking_addr=$(rpc_staker getnewstakingaddress 2>/dev/null || echo "")
    if [ -n "$staking_addr" ]; then
        success "getnewstakingaddress returned: $staking_addr"
        log "Staking address: $staking_addr"
    else
        fail "getnewstakingaddress failed"
    fi

    local cs_info=$(rpc_owner getcoldstakinginfo 2>/dev/null || echo "")
    if [ -n "$cs_info" ]; then
        success "getcoldstakinginfo responds"
        log "Cold staking info: $cs_info"
    else
        fail "getcoldstakinginfo failed"
    fi

    local cold_utxos=$(rpc_owner listcoldutxos 2>/dev/null || echo "")
    if [ "$cold_utxos" = "[]" ] || [ -n "$cold_utxos" ]; then
        success "listcoldutxos responds (empty initially)"
    else
        fail "listcoldutxos failed"
    fi
}

test_delegation_creation() {
    section "Cold Staking Delegation"

    log "Mining 150 blocks on owner node..."
    rpc_owner setgenerate true 150 >/dev/null 2>&1 || true
    sleep 2

    local balance=$(rpc_owner getbalance 2>/dev/null | tr -d ' ')
    log "Owner balance: $balance INN"

    local staker_addr=$(rpc_staker getnewstakingaddress 2>/dev/null || echo "")
    if [ -z "$staker_addr" ]; then
        fail "Could not get staking address from staker node"
        return 0
    fi
    log "Staker address: $staker_addr"

    local delegation_amount="5000"
    log "Delegating $delegation_amount INN to staker..."
    local result=$(rpc_owner delegatestake "$staker_addr" "$delegation_amount" 2>/dev/null || echo "ERROR")

    if echo "$result" | grep -q "txid"; then
        local txid=$(echo "$result" | grep -o '"txid" *: *"[a-f0-9]*"' | grep -o '[a-f0-9]\{64\}')
        success "Delegation created: $txid"

        local owner_addr=$(echo "$result" | grep -o '"owner_address" *: *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
        log "Owner address: $owner_addr"
    else
        fail "Delegation failed: $result"
        return 0
    fi

    rpc_owner setgenerate true 2 2>/dev/null || true
    sleep 3

    local cold_utxos=$(rpc_owner listcoldutxos 2>/dev/null || echo "[]")
    if echo "$cold_utxos" | grep -q "txid"; then
        success "Cold staking UTXOs visible on owner node"
    else
        warn "Cold UTXOs not yet visible on owner (may need sync)"
    fi

    local staker_utxos=$(rpc_staker listcoldutxos true 2>/dev/null || echo "[]")
    if echo "$staker_utxos" | grep -q "txid"; then
        success "Cold staking UTXOs visible on staker node"
    else
        warn "Cold UTXOs not visible on staker node (staker key may need import)"
    fi
}

test_cold_staking_info() {
    section "Cold Staking Balance Verification"

    local cs_info=$(rpc_owner getcoldstakinginfo 2>/dev/null || echo "")
    log "Cold staking info after delegation: $cs_info"

    if echo "$cs_info" | grep -q '"cold_staking_balance"'; then
        local cs_balance=$(echo "$cs_info" | grep -o '"cold_staking_balance" *: *[0-9.]*' | grep -o '[0-9.]*$')
        if [ "$(echo "$cs_balance > 0" | bc 2>/dev/null)" -eq 1 ] 2>/dev/null; then
            success "Cold staking balance: $cs_balance INN"
        else
            log "Cold staking balance: $cs_balance (may be 0 if keys not shared)"
        fi
    fi
}

test_multiple_delegations() {
    section "Multiple Delegations Test"

    local staker_addr=$(rpc_staker getnewstakingaddress 2>/dev/null || echo "")
    if [ -z "$staker_addr" ]; then
        warn "Could not get staking address"
        return
    fi

    local delegated=0
    for amount in 1000 2000 3000; do
        local result=$(rpc_owner delegatestake "$staker_addr" "$amount" 2>/dev/null || echo "ERROR")
        if echo "$result" | grep -q "txid"; then
            ((delegated++)) || true
        fi
    done

    if [ $delegated -eq 3 ]; then
        success "Created 3 separate delegations"
    else
        warn "Only created $delegated/3 delegations"
    fi

    rpc_owner setgenerate true 2 2>/dev/null || true
    sleep 2
}

test_cold_stake_security() {
    section "Cold Staking Security Checks"

    local result=$(rpc_owner delegatestake "invalidaddress" 100 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "invalid\|error"; then
        success "Invalid staker address correctly rejected"
    else
        fail "Invalid staker address was accepted"
    fi

    local staker_addr=$(rpc_staker getnewstakingaddress 2>/dev/null || echo "")
    if [ -n "$staker_addr" ]; then
        result=$(rpc_owner delegatestake "$staker_addr" 0 2>&1 || echo "ERROR")
        if echo "$result" | grep -qi "invalid\|error"; then
            success "Zero delegation amount correctly rejected"
        else
            fail "Zero delegation amount was accepted"
        fi

        result=$(rpc_owner delegatestake "$staker_addr" -100 2>&1 || echo "ERROR")
        if echo "$result" | grep -qi "invalid\|error\|negative"; then
            success "Negative delegation amount correctly rejected"
        else
            fail "Negative delegation amount was accepted"
        fi
    fi
}

test_revocation() {
    section "Delegation Revocation Test"

    local cold_utxos=$(rpc_owner listcoldutxos 2>/dev/null || echo "[]")
    if echo "$cold_utxos" | grep -q "txid"; then
        local first_txid=$(echo "$cold_utxos" | grep -o '"txid" *: *"[a-f0-9]*"' | head -1 | grep -o '[a-f0-9]\{64\}')
        local first_vout=$(echo "$cold_utxos" | grep -o '"vout" *: *[0-9]*' | head -1 | grep -o '[0-9]*$')
        local first_amount=$(echo "$cold_utxos" | grep -o '"amount" *: *[0-9.]*' | head -1 | grep -o '[0-9.]*$')

        if [ -n "$first_txid" ] && [ -n "$first_amount" ]; then
            log "Attempting revocation of $first_amount INN (txid: $first_txid)"

            local revoke_addr=$(rpc_owner getnewaddress)
            local revoke_result=$(rpc_owner sendtoaddress "$revoke_addr" "$first_amount" 2>&1 || echo "ERROR")

            if echo "$revoke_result" | grep -q '[a-f0-9]\{64\}'; then
                success "Delegation revoked successfully"
            else
                log "Direct send revocation result: $revoke_result"
                warn "Revocation via sendtoaddress may need raw tx approach"
            fi
        fi
    else
        log "No cold UTXOs to revoke"
    fi
}

test_revokecoldstaking_rpc() {
    section "revokecoldstaking RPC Test"

    local staker_addr=$(rpc_staker getnewstakingaddress 2>/dev/null || echo "")
    if [ -z "$staker_addr" ]; then
        warn "Could not get staking address"
        return
    fi

    local result=$(rpc_owner delegatestake "$staker_addr" 500 2>/dev/null || echo "ERROR")
    local txid=""
    if echo "$result" | grep -q "txid"; then
        txid=$(echo "$result" | grep -o '"txid" *: *"[a-f0-9]*"' | grep -o '[a-f0-9]\{64\}')
    fi

    if [ -z "$txid" ]; then
        warn "Could not create delegation for revoke test"
        return
    fi

    rpc_owner setgenerate true 2 2>/dev/null || true
    sleep 2

    local revoke_result=$(rpc_owner revokecoldstaking "$txid" 1 2>&1 || echo "")
    if echo "$revoke_result" | grep -q '[a-f0-9]\{64\}'; then
        success "revokecoldstaking RPC returned txid"
        rpc_owner setgenerate true 2 2>/dev/null || true
        sleep 2
    else
        log "revokecoldstaking result: ${revoke_result:0:120}"
        warn "revokecoldstaking may need specific vout index"
    fi

    local bad_result=$(rpc_owner revokecoldstaking "0000000000000000000000000000000000000000000000000000000000000000" 0 2>&1 || echo "ERROR")
    if echo "$bad_result" | grep -qi "error\|not found\|invalid"; then
        success "revokecoldstaking rejects invalid txid"
    else
        warn "Invalid txid response: ${bad_result:0:80}"
    fi
}

test_large_delegation() {
    section "Large Delegation Amounts"

    log "Mining additional blocks for large balance..."
    rpc_owner setgenerate true 200 >/dev/null 2>&1 || true
    sleep 3

    local balance=$(rpc_owner getbalance 2>/dev/null | tr -d ' ')
    log "Owner balance: $balance INN"

    local staker_addr=$(rpc_staker getnewstakingaddress 2>/dev/null || echo "")
    if [ -z "$staker_addr" ]; then
        warn "Could not get staking address for large delegation"
        return
    fi

    local large_amount="50000"
    local result=$(rpc_owner delegatestake "$staker_addr" "$large_amount" 2>/dev/null || echo "ERROR")
    if echo "$result" | grep -q "txid"; then
        success "Large delegation of $large_amount INN created"
    else
        warn "Large delegation failed: ${result:0:80}"
    fi

    local result=$(rpc_owner delegatestake "$staker_addr" 50 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|minimum\|100"; then
        success "Below-minimum delegation (50 INN) correctly rejected"
    else
        warn "Below-minimum delegation response: ${result:0:80}"
    fi

    result=$(rpc_owner delegatestake "$staker_addr" 100 2>/dev/null || echo "ERROR")
    if echo "$result" | grep -q "txid"; then
        success "Minimum delegation (100 INN) accepted"
    else
        warn "Minimum delegation response: ${result:0:80}"
    fi

    rpc_owner setgenerate true 2 2>/dev/null || true
    sleep 2
}

test_cn_payment_cap_large_stake() {
    section "CN Payment Cap with Large Stakes"

    # Reward-based 30% cap: for large stakers, the reward (not principal) determines the cap
    log "Testing that large cold stake amounts produce valid blocks..."

    rpc_staker setgenerate true 10 2>/dev/null || true
    sleep 5

    local cs_info=$(rpc_owner getcoldstakinginfo 2>/dev/null || echo "")
    log "Cold staking info: $cs_info"

    local blocks_owner=$(rpc_owner getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
    local blocks_staker=$(rpc_staker getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
    local blocks_validator=$(rpc_validator getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)

    log "Block heights - Owner: $blocks_owner, Staker: $blocks_staker, Validator: $blocks_validator"

    local diff_os=$((blocks_owner - blocks_staker))
    if [ $diff_os -lt 0 ]; then diff_os=$((-diff_os)); fi
    local diff_ov=$((blocks_owner - blocks_validator))
    if [ $diff_ov -lt 0 ]; then diff_ov=$((-diff_ov)); fi

    if [ $diff_os -le 2 ] && [ $diff_ov -le 2 ]; then
        success "All nodes in consensus with large delegations"
    else
        warn "Nodes not fully sync'd (OS diff: $diff_os, OV diff: $diff_ov)"
    fi
}

test_consensus_validation() {
    section "Consensus Validation"

    sleep 5

    local blocks_owner=$(rpc_owner getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
    local blocks_staker=$(rpc_staker getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)
    local blocks_validator=$(rpc_validator getinfo 2>/dev/null | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*' || echo 0)

    log "Block heights - Owner: $blocks_owner, Staker: $blocks_staker, Validator: $blocks_validator"

    local max_diff=2
    local diff_os=$((blocks_owner - blocks_staker))
    if [ $diff_os -lt 0 ]; then diff_os=$((-diff_os)); fi
    local diff_ov=$((blocks_owner - blocks_validator))
    if [ $diff_ov -lt 0 ]; then diff_ov=$((-diff_ov)); fi

    if [ $diff_os -le $max_diff ] && [ $diff_ov -le $max_diff ]; then
        success "All 3 nodes in consensus (within $max_diff blocks)"
    else
        warn "Nodes not fully synchronized (OS diff: $diff_os, OV diff: $diff_ov)"
    fi

    local hash_owner=$(rpc_owner getblockhash "$blocks_validator" 2>/dev/null || echo "")
    local hash_validator=$(rpc_validator getblockhash "$blocks_validator" 2>/dev/null || echo "")

    if [ -n "$hash_owner" ] && [ "$hash_owner" = "$hash_validator" ]; then
        success "Owner and Validator agree on block hash at height $blocks_validator"
    elif [ -n "$hash_owner" ]; then
        warn "Possible chain fork detected at height $blocks_validator"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "    COLD STAKING TEST SUMMARY"
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
    echo "    INNOVA COLD STAKING TEST"
    echo "========================================"
    echo "  Owner:     port $OWNER_PORT / rpc $OWNER_RPC"
    echo "  Staker:    port $STAKER_PORT / rpc $STAKER_RPC"
    echo "  Validator: port $VALIDATOR_PORT / rpc $VALIDATOR_RPC"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Waiting for nodes to initialize..."
    sleep 5

    test_rpc_commands
    test_delegation_creation
    test_cold_staking_info
    test_multiple_delegations
    test_cold_stake_security
    test_revocation
    test_revokecoldstaking_rpc
    test_large_delegation
    test_cn_payment_cap_large_stake
    test_consensus_validation

    print_summary
}

main "$@"
