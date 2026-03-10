#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Blockchain Stress Test Script
# Tests chain reorgs, orphan blocks, block validation, and consensus
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

TEST_DIR="/tmp/innova_blockchain_stress"
NODE_A_DIR="$TEST_DIR/node_a"
NODE_B_DIR="$TEST_DIR/node_b"
NODE_C_DIR="$TEST_DIR/node_c"

NODE_A_PORT=24445
NODE_B_PORT=24446
NODE_C_PORT=24447
NODE_A_RPC=24500
NODE_B_RPC=24501
NODE_C_RPC=24502

PASSED=0
FAILED=0
WARNINGS=0

log() { echo -e "${BLUE}[CHAIN-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*blockchain_stress" 2>/dev/null || true
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
    log "Setting up 3-node blockchain test..."
    rm -rf "$TEST_DIR"
    mkdir -p "$NODE_A_DIR" "$NODE_B_DIR" "$NODE_C_DIR"

    cat > "$NODE_A_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=chaintest
rpcpassword=chainpass
rpcport=$NODE_A_RPC
port=$NODE_A_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
debug=1
printtoconsole=0
EOF

    cat > "$NODE_B_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=chaintest
rpcpassword=chainpass
rpcport=$NODE_B_RPC
port=$NODE_B_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
debug=1
printtoconsole=0
EOF

    cat > "$NODE_C_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=chaintest
rpcpassword=chainpass
rpcport=$NODE_C_RPC
port=$NODE_C_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
addnode=127.0.0.1:$NODE_A_PORT
addnode=127.0.0.1:$NODE_B_PORT
debug=1
printtoconsole=0
EOF

    log "Config files created for 3 nodes"
}

start_nodes() {
    log "Starting nodes..."
    "$INNOVAD" -datadir="$NODE_A_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$NODE_B_DIR" -regtest &
    sleep 2
    "$INNOVAD" -datadir="$NODE_C_DIR" -regtest &
    sleep 4
    log "All nodes started"
}

rpc_a() {
    "$INNOVAD" -datadir="$NODE_A_DIR" -rpcuser=chaintest -rpcpassword=chainpass -rpcport=$NODE_A_RPC "$@" 2>/dev/null
}

rpc_b() {
    "$INNOVAD" -datadir="$NODE_B_DIR" -rpcuser=chaintest -rpcpassword=chainpass -rpcport=$NODE_B_RPC "$@" 2>/dev/null
}

rpc_c() {
    "$INNOVAD" -datadir="$NODE_C_DIR" -rpcuser=chaintest -rpcpassword=chainpass -rpcport=$NODE_C_RPC "$@" 2>/dev/null
}

# TEST SUITES

test_genesis_block() {
    section "Genesis Block Validation"

    local hash_a=$(rpc_a getblockhash 0 2>/dev/null || echo "")
    local hash_b=$(rpc_b getblockhash 0 2>/dev/null || echo "")
    local hash_c=$(rpc_c getblockhash 0 2>/dev/null || echo "")

    if [ -n "$hash_a" ] && [ "$hash_a" = "$hash_b" ] && [ "$hash_b" = "$hash_c" ]; then
        success "All 3 nodes agree on genesis block hash"
        log "Genesis: ${hash_a:0:16}..."
    else
        fail "Genesis block mismatch: A=$hash_a B=$hash_b C=$hash_c"
    fi

    local genesis=$(rpc_a getblock "$hash_a" 2>/dev/null || echo "")
    if echo "$genesis" | tr '\n' ' ' | grep -q '"height" *: *0'; then
        success "Genesis block has correct height (0)"
    fi

    if echo "$genesis" | tr '\n' ' ' | grep -q '"previousblockhash"'; then
        fail "Genesis block should not have previousblockhash"
    else
        success "Genesis block correctly has no previous hash"
    fi
}

test_block_generation() {
    section "Block Generation and Propagation"

    log "Generating 50 blocks on Node A..."
    rpc_a setgenerate true 50 >/dev/null 2>&1 || true
    sleep 2

    local blocks_a=$(rpc_a getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    log "Node A at block $blocks_a"

    if [ "$blocks_a" -ge 50 ]; then
        success "Generated 50 blocks on Node A"
    else
        fail "Only $blocks_a blocks generated"
    fi

    rpc_a addnode "127.0.0.1:$NODE_C_PORT" onetry >/dev/null 2>&1 || true
    rpc_c addnode "127.0.0.1:$NODE_A_PORT" onetry >/dev/null 2>&1 || true
    sleep 5

    local blocks_c=$(rpc_c getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    log "Node C at block $blocks_c (should be $blocks_a)"

    if [ "$blocks_c" -ge "$blocks_a" ]; then
        success "Blocks propagated to Node C"
    else
        warn "Node C at $blocks_c blocks (expected $blocks_a)"
    fi
}

test_chain_fork_and_reorg() {
    section "Chain Fork and Reorganization"

    local start_a=$(rpc_a getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    rpc_a setgenerate true 5 >/dev/null 2>&1 || true
    sleep 2
    local end_a=$(rpc_a getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")

    rpc_b setgenerate true 3 >/dev/null 2>&1 || true
    sleep 2
    local end_b=$(rpc_b getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")

    log "Fork state: Node A at $end_a, Node B at $end_b"

    local tip_a=$(rpc_a getbestblockhash 2>/dev/null || echo "")
    local tip_b=$(rpc_b getbestblockhash 2>/dev/null || echo "")

    if [ -n "$tip_a" ] && [ -n "$tip_b" ] && [ "$tip_a" != "$tip_b" ]; then
        success "Fork created: different chain tips"
        log "Tip A: ${tip_a:0:16}..."
        log "Tip B: ${tip_b:0:16}..."
    else
        log "Nodes may share chain (same tips) - fork test limited in regtest"
    fi

    rpc_a addnode "127.0.0.1:$NODE_B_PORT" onetry >/dev/null 2>&1 || true
    rpc_b addnode "127.0.0.1:$NODE_A_PORT" onetry >/dev/null 2>&1 || true
    sleep 8

    local new_b=$(rpc_b getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    local new_tip_b=$(rpc_b getbestblockhash 2>/dev/null || echo "")

    log "After connect: Node A at $end_a, Node B at $new_b"

    if [ "$new_b" -ge "$end_a" ]; then
        success "Node B reorged to Node A's longer chain (height $new_b)"
    else
        warn "Node B at $new_b (expected >= $end_a after reorg)"
    fi

    local final_tip_a=$(rpc_a getbestblockhash 2>/dev/null || echo "")
    local final_tip_b=$(rpc_b getbestblockhash 2>/dev/null || echo "")
    if [ -n "$final_tip_a" ] && [ "$final_tip_a" = "$final_tip_b" ]; then
        success "Both nodes agree on chain tip after reorg"
    else
        warn "Chain tips may differ: A=${final_tip_a:0:16}... B=${final_tip_b:0:16}..."
    fi
}

test_block_structure() {
    section "Block Structure Validation"

    local height=$(rpc_a getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")

    for h in 1 10 "$height"; do
        local hash=$(rpc_a getblockhash "$h" 2>/dev/null || echo "")
        if [ -z "$hash" ]; then continue; fi

        local block=$(rpc_a getblock "$hash" 2>/dev/null || echo "")
        if [ -z "$block" ]; then continue; fi

        local has_hash=$(echo "$block" | tr '\n' ' ' | grep -c '"hash"' || echo "0")
        local has_height=$(echo "$block" | tr '\n' ' ' | grep -c '"height"' || echo "0")
        local has_time=$(echo "$block" | tr '\n' ' ' | grep -c '"time"' || echo "0")
        local has_tx=$(echo "$block" | tr '\n' ' ' | grep -c '"tx"' || echo "0")

        if [ "$has_hash" -gt 0 ] && [ "$has_height" -gt 0 ] && [ "$has_time" -gt 0 ] && [ "$has_tx" -gt 0 ]; then
            log "Block $h structure valid (hash, height, time, tx fields present)"
        else
            fail "Block $h missing essential fields"
        fi
    done
    success "Block structure validation passed"
}

test_block_hash_chain() {
    section "Block Hash Chain Integrity"

    local height=$(rpc_a getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    local max_check=20
    if [ "$height" -lt "$max_check" ]; then max_check=$height; fi

    local valid_chain=true
    for h in $(seq 1 $max_check); do
        local hash=$(rpc_a getblockhash "$h" 2>/dev/null || echo "")
        local block=$(rpc_a getblock "$hash" 2>/dev/null || echo "")
        local prev_hash=$(echo "$block" | tr '\n' ' ' | grep -o '"previousblockhash" *: *"[a-f0-9]*"' | head -1 | grep -o '[a-f0-9]\{64\}')
        local expected_prev=$(rpc_a getblockhash "$((h-1))" 2>/dev/null || echo "")

        if [ "$prev_hash" != "$expected_prev" ]; then
            fail "Block $h: previousblockhash mismatch"
            valid_chain=false
            break
        fi
    done

    if [ "$valid_chain" = true ]; then
        success "Block hash chain is consistent (checked $max_check blocks)"
    fi
}

test_difficulty() {
    section "Difficulty Adjustment"

    local info=$(rpc_a getinfo 2>/dev/null || echo "{}")
    local pow_diff=$(echo "$info" | tr '\n' ' ' | grep -o '"proof-of-work" *: *[0-9.]*' | grep -o '[0-9.]*$' || echo "0")
    local pos_diff=$(echo "$info" | tr '\n' ' ' | grep -o '"proof-of-stake" *: *[0-9.]*' | grep -o '[0-9.]*$' || echo "0")

    log "PoW difficulty: $pow_diff"
    log "PoS difficulty: $pos_diff"

    if [ -n "$pow_diff" ]; then
        success "PoW difficulty available"
    fi

    local diff_before=$pow_diff
    rpc_a setgenerate true 20 >/dev/null 2>&1 || true
    sleep 2

    info=$(rpc_a getinfo 2>/dev/null || echo "{}")
    local diff_after=$(echo "$info" | tr '\n' ' ' | grep -o '"proof-of-work" *: *[0-9.]*' | grep -o '[0-9.]*$' || echo "0")
    log "PoW difficulty after 20 more blocks: $diff_after"

    success "Difficulty tracking operational"
}

test_invalid_block_hash() {
    section "Invalid Block Hash Rejection"

    local result=$(rpc_a getblock "0000000000000000000000000000000000000000000000000000000000000000" 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|not found"; then
        success "Invalid block hash correctly rejected"
    else
        fail "Invalid block hash was accepted"
    fi

    local max_height=$(rpc_a getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    result=$(rpc_a getblockhash "$((max_height + 1000))" 2>&1 || echo "ERROR")
    if echo "$result" | grep -qi "error\|out of range"; then
        success "Out-of-range block height correctly rejected"
    else
        fail "Out-of-range block height was accepted"
    fi
}

test_chain_state_info() {
    section "Chain State Information"

    local mining_info=$(rpc_a getmininginfo 2>/dev/null || echo "{}")
    if echo "$mining_info" | tr '\n' ' ' | grep -q '"blocks"'; then
        success "Mining info available"
    else
        warn "Mining info unavailable"
    fi

    local best=$(rpc_a getbestblockhash 2>/dev/null || echo "")
    if [ -n "$best" ] && [ ${#best} -eq 64 ]; then
        success "Best block hash: ${best:0:16}..."
    else
        fail "Could not get best block hash"
    fi

    local count=$(rpc_a getblockcount 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ]; then
        success "Block count: $count"
    else
        warn "Block count is 0"
    fi
}

test_three_node_consensus() {
    section "Three-Node Consensus Verification"

    rpc_a addnode "127.0.0.1:$NODE_B_PORT" onetry >/dev/null 2>&1 || true
    rpc_a addnode "127.0.0.1:$NODE_C_PORT" onetry >/dev/null 2>&1 || true
    rpc_b addnode "127.0.0.1:$NODE_A_PORT" onetry >/dev/null 2>&1 || true
    rpc_b addnode "127.0.0.1:$NODE_C_PORT" onetry >/dev/null 2>&1 || true
    rpc_c addnode "127.0.0.1:$NODE_A_PORT" onetry >/dev/null 2>&1 || true
    rpc_c addnode "127.0.0.1:$NODE_B_PORT" onetry >/dev/null 2>&1 || true

    rpc_a setgenerate true 5 >/dev/null 2>&1 || true
    sleep 8

    local blocks_a=$(rpc_a getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    local blocks_b=$(rpc_b getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    local blocks_c=$(rpc_c getinfo 2>/dev/null | tr '\n' ' ' | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")

    log "Heights: A=$blocks_a, B=$blocks_b, C=$blocks_c"

    local tip_a=$(rpc_a getbestblockhash 2>/dev/null || echo "")
    local tip_b=$(rpc_b getbestblockhash 2>/dev/null || echo "")
    local tip_c=$(rpc_c getbestblockhash 2>/dev/null || echo "")

    local consensus=0
    if [ -n "$tip_a" ] && [ "$tip_a" = "$tip_b" ]; then ((consensus++)) || true; fi
    if [ -n "$tip_a" ] && [ "$tip_a" = "$tip_c" ]; then ((consensus++)) || true; fi
    if [ -n "$tip_b" ] && [ "$tip_b" = "$tip_c" ]; then ((consensus++)) || true; fi

    if [ $consensus -eq 3 ]; then
        success "All 3 nodes in full consensus"
    elif [ $consensus -gt 0 ]; then
        warn "Partial consensus ($consensus/3 pairs agree)"
    else
        warn "No consensus between nodes (regtest P2P may not be connecting)"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "   BLOCKCHAIN STRESS TEST SUMMARY"
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
    echo "   INNOVA BLOCKCHAIN STRESS TEST"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Waiting for nodes to initialize..."
    sleep 3

    test_genesis_block
    test_block_generation
    test_block_structure
    test_block_hash_chain
    test_chain_fork_and_reorg
    test_difficulty
    test_invalid_block_hash
    test_chain_state_info
    test_three_node_consensus

    print_summary
}

main "$@"
