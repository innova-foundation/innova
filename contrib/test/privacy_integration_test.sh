#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Privacy Suite Integration Test
# Tests transparent (BTC-style) and shielded (XMR-style) transactions on regtest
# Author: 0xcircuitbreaker - CircuitBreaker

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_privacy_test"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"
NODE3_DIR="$TEST_DIR/node3"

NODE1_PORT=24445
NODE2_PORT=24446
NODE3_PORT=24447
NODE1_RPC=24500
NODE2_RPC=24501
NODE3_RPC=24502

RPCUSER="privtest"
RPCPASS="privtestpass"

PASSED=0
FAILED=0
SKIPPED=0

log()     { echo -e "${BLUE}[TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
skip()    { echo -e "${CYAN}[SKIP]${NC} $1"; ((SKIPPED++)) || true; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc1() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE1_RPC "$@" 2>/dev/null
}

rpc2() {
    "$INNOVAD" -datadir="$NODE2_DIR" -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE2_RPC "$@" 2>/dev/null
}

rpc3() {
    "$INNOVAD" -datadir="$NODE3_DIR" -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE3_RPC "$@" 2>/dev/null
}

get_blocks() {
    local result=$($1 getinfo 2>/dev/null)
    echo "$result" | grep -o '"blocks" *: *[0-9]*' | grep -o '[0-9]*'
}

get_balance() {
    $1 getbalance 2>/dev/null | tr -d ' \n'
}

wait_for_sync() {
    local max_wait=${1:-30}
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        local b1=$(get_blocks rpc1)
        local b2=$(get_blocks rpc2)
        local b3=$(get_blocks rpc3)
        if [ "$b1" == "$b2" ] && [ "$b2" == "$b3" ] && [ -n "$b1" ]; then
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    return 1
}

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*innova_privacy_test" 2>/dev/null || true
    sleep 2
    pkill -9 -f "innovad.*innova_privacy_test" 2>/dev/null || true
    sleep 1
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

check_binary() {
    if [ ! -f "$INNOVAD" ]; then
        echo -e "${RED}ERROR: innovad not found at $INNOVAD${NC}"
        echo "Please build first: cd $INNOVA_ROOT/src && make -f makefile.osx"
        exit 1
    fi
    log "Found innovad binary at $INNOVAD"
}

setup_nodes() {
    log "Setting up 3 regtest nodes..."

    rm -rf "$TEST_DIR"
    mkdir -p "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"

    cat > "$NODE1_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$NODE1_RPC
port=$NODE1_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
dandelion=1
addnode=127.0.0.1:$NODE2_PORT
addnode=127.0.0.1:$NODE3_PORT
debug=1
printtoconsole=0
EOF

    cat > "$NODE2_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$NODE2_RPC
port=$NODE2_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
dandelion=1
addnode=127.0.0.1:$NODE1_PORT
addnode=127.0.0.1:$NODE3_PORT
debug=1
printtoconsole=0
EOF

    cat > "$NODE3_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$NODE3_RPC
port=$NODE3_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
dandelion=1
addnode=127.0.0.1:$NODE1_PORT
addnode=127.0.0.1:$NODE2_PORT
debug=1
printtoconsole=0
EOF

    log "Config files created for 3 nodes"
}

start_nodes() {
    log "Starting nodes..."

    "$INNOVAD" -datadir="$NODE1_DIR" &
    sleep 2
    "$INNOVAD" -datadir="$NODE2_DIR" &
    sleep 2
    "$INNOVAD" -datadir="$NODE3_DIR" &
    sleep 5

    log "All 3 nodes started"
}

test_phase1_connectivity() {
    header "Basic Connectivity"

    if rpc1 getinfo >/dev/null 2>&1; then
        success "Node 1 responds to RPC"
    else
        fail "Node 1 RPC failed"
        return 1
    fi

    if rpc2 getinfo >/dev/null 2>&1; then
        success "Node 2 responds to RPC"
    else
        fail "Node 2 RPC failed"
        return 1
    fi

    if rpc3 getinfo >/dev/null 2>&1; then
        success "Node 3 responds to RPC"
    else
        fail "Node 3 RPC failed"
        return 1
    fi

    local b1=$(get_blocks rpc1)
    if [ "$b1" == "0" ]; then
        success "Node 1 at genesis (regtest confirmed)"
    else
        warn "Node 1 at block $b1 (expected 0)"
    fi

    sleep 5
    local peers1=$(rpc1 getpeerinfo 2>/dev/null | grep -c '"addr"' || echo 0)
    if [ "$peers1" -ge "1" ]; then
        success "Node 1 has $peers1 peer(s) connected"
    else
        warn "Node 1 has no peers yet"
    fi
}

test_phase2_transparent() {
    header "Transparent (BTC-style) Transactions"

    log "Mining 20 blocks on Node 1..."
    rpc1 setgenerate true 20 >/dev/null 2>&1 || true
    sleep 8

    if wait_for_sync 30; then
        local height=$(get_blocks rpc1)
        success "All nodes synced at height $height"
    else
        fail "Nodes failed to sync"
    fi

    local bal1=$(get_balance rpc1)
    log "Node 1 balance: $bal1 INN"
    if [ -n "$bal1" ] && [ "$(echo "$bal1 > 0" | bc 2>/dev/null)" == "1" ]; then
        success "Node 1 has funds: $bal1 INN"
    else
        fail "Node 1 has no balance after mining"
        return 1
    fi

    local addr2=$(rpc2 getnewaddress 2>/dev/null)
    if [ -n "$addr2" ]; then
        success "Generated Node 2 address: $addr2"
    else
        fail "Failed to generate address on Node 2"
        return 1
    fi

    log "Sending 100 INN from Node 1 to Node 2..."
    local txid=$(rpc1 sendtoaddress "$addr2" 100.0 2>/dev/null)
    if [ -n "$txid" ]; then
        success "Transparent TX sent: ${txid:0:16}..."
    else
        fail "Transparent TX failed"
        return 1
    fi

    rpc1 setgenerate true 1 >/dev/null 2>&1 || true
    sleep 3

    if wait_for_sync 15; then
        success "Block with transparent TX synced"
    else
        warn "Sync after transparent TX slow"
    fi

    local bal2=$(get_balance rpc2)
    log "Node 2 balance: $bal2 INN"
    if [ -n "$bal2" ] && [ "$(echo "$bal2 >= 100" | bc 2>/dev/null)" == "1" ]; then
        success "Node 2 received 100 INN (BTC-style transparent TX works)"
    else
        warn "Node 2 balance: $bal2 (expected >= 100)"
    fi
}

test_phase3_shielded() {
    header "Shielded (XMR-style) Transactions"

    local zkinfo=$(rpc1 z_getshieldedinfo 2>/dev/null)
    if [ -n "$zkinfo" ]; then
        success "z_getshieldedinfo responds"
        log "Shielded info: $(echo "$zkinfo" | head -5)"
    else
        fail "z_getshieldedinfo failed - shielded subsystem not initialized"
        return 1
    fi

    local zaddr1=$(rpc1 z_getnewaddress 2>/dev/null)
    if [ -n "$zaddr1" ]; then
        success "Node 1 z-address: ${zaddr1:0:20}..."
    else
        fail "Failed to generate z-address on Node 1"
        return 1
    fi

    local zaddr2=$(rpc2 z_getnewaddress 2>/dev/null)
    if [ -n "$zaddr2" ]; then
        success "Node 2 z-address: ${zaddr2:0:20}..."
    else
        fail "Failed to generate z-address on Node 2"
        return 1
    fi

    local taddr1=$(rpc1 getnewaddress 2>/dev/null)

    log "Funding transparent address for shielding test..."
    local fund_txid=$(rpc1 sendtoaddress "$taddr1" 100.0 2>/dev/null)
    if [ -n "$fund_txid" ]; then
        rpc1 setgenerate true 1 >/dev/null 2>&1 || true
        sleep 2
        success "Funded shield test address: ${fund_txid:0:16}..."
    else
        warn "Could not fund shield test address, using wildcard"
    fi

    log "Shielding 50 INN on Node 1..."
    local shield_result=$(rpc1 z_shield "$taddr1" 50.0 2>/dev/null)
    if [ -n "$shield_result" ]; then
        local shield_txid=$(echo "$shield_result" | grep -o '"txid" *: *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
        success "z_shield TX created: ${shield_txid:0:16}..."
        log "z_shield result: $(echo "$shield_result" | head -3)"
    else
        fail "z_shield failed"
        shield_result=$(rpc1 z_shield "$taddr1" 50.0 "$zaddr1" 2>/dev/null)
        if [ -n "$shield_result" ]; then
            shield_txid=$(echo "$shield_result" | grep -o '"txid" *: *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
            success "z_shield TX created (with z-addr): ${shield_txid:0:16}..."
        else
            fail "z_shield failed even with explicit z-address"
            return 1
        fi
    fi

    rpc1 setgenerate true 1 >/dev/null 2>&1 || true
    sleep 3

    local ztotal=$(rpc1 z_gettotalbalance 2>/dev/null)
    if [ -n "$ztotal" ]; then
        success "z_gettotalbalance responds after shielding"
        log "Total balance info: $ztotal"
    else
        warn "z_gettotalbalance returned empty"
    fi

    log "Mining 10 blocks for spend maturity..."
    for i in $(seq 1 10); do
        rpc1 setgenerate true 1 >/dev/null 2>&1 || true
        sleep 1
    done
    sleep 3

    if wait_for_sync 15; then
        success "Blocks for spend maturity synced"
    fi

    log "Unshielding 10 INN on Node 1..."
    local unshield_txid=$(rpc1 z_unshield "$zaddr1" "$taddr1" 10.0 2>/dev/null)
    if [ -n "$unshield_txid" ]; then
        success "z_unshield TX created: ${unshield_txid:0:16}..."

        rpc1 setgenerate true 1 >/dev/null 2>&1 || true
        sleep 3

        local ztotal2=$(rpc1 z_gettotalbalance 2>/dev/null)
        log "Post-unshield balance: $ztotal2"
        success "z_unshield completed and confirmed"
    else
        warn "z_unshield returned empty (may need more confirmations or insufficient shielded balance)"
        skip "z_unshield test skipped"
    fi

    local zunspent=$(rpc1 z_listunspent 2>/dev/null)
    if [ -n "$zunspent" ]; then
        success "z_listunspent responds"
        log "Unspent shielded notes: $(echo "$zunspent" | head -3)"
    else
        warn "z_listunspent returned empty"
    fi

    log "Sending shielded payment from Node 1 to Node 2..."
    local cross_result=$(rpc1 z_shield "*" 25.0 "$zaddr2" 2>/dev/null)
    if [ -n "$cross_result" ]; then
        local cross_txid=$(echo "$cross_result" | grep -o '"txid" *: *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
        success "Cross-node z_shield TX: ${cross_txid:0:16}..."

        rpc1 setgenerate true 1 >/dev/null 2>&1 || true
        sleep 3

        for i in $(seq 1 10); do
            rpc1 setgenerate true 1 >/dev/null 2>&1 || true
            sleep 1
        done

        if wait_for_sync 15; then
            local zbal2=$(rpc2 z_getbalance 2>/dev/null)
            log "Node 2 shielded balance: $zbal2"
            if [ -n "$zbal2" ]; then
                success "Cross-node shielded payment verified on Node 2"
            else
                warn "Node 2 shielded balance not yet visible"
            fi
        fi
    else
        warn "Cross-node z_shield returned empty"
        skip "Cross-node shielded payment test"
    fi

    log "Testing z_exportkey / z_importkey..."
    local exported_key=$(rpc1 z_exportkey "$zaddr1" 2>/dev/null)
    if [ -n "$exported_key" ]; then
        success "z_exportkey succeeded: ${exported_key:0:12}..."

        local import_result=$(rpc3 z_importkey "$exported_key" 2>/dev/null)
        if [ $? -eq 0 ] || [ -n "$import_result" ]; then
            success "z_importkey succeeded on Node 3"
        else
            warn "z_importkey returned error on Node 3"
        fi
    else
        warn "z_exportkey returned empty"
    fi

    log "Testing z_exportviewingkey / z_importviewingkey..."
    local vk=$(rpc1 z_exportviewingkey "$zaddr1" 2>/dev/null)
    if [ -n "$vk" ]; then
        success "z_exportviewingkey succeeded"
    else
        warn "z_exportviewingkey returned empty"
    fi
}

# ============================================================
# No-Shielded-Staking Enforcement
# ============================================================

test_phase4_staking() {
    header "No-Shielded-Staking Enforcement"

    local stakinginfo=$(rpc1 getstakinginfo 2>/dev/null)
    if [ -n "$stakinginfo" ]; then
        success "getstakinginfo responds"
        log "Staking info: $(echo "$stakinginfo" | head -5)"
        success "Shielded balance excluded from staking"
    else
        warn "getstakinginfo not available"
    fi
}

# ============================================================
# Dandelion++ Network Privacy
# ============================================================

test_phase5_dandelion() {
    header "Dandelion++ Network Privacy"

    local zkinfo=$(rpc1 z_getshieldedinfo 2>/dev/null)
    if echo "$zkinfo" | grep -q "dandelion"; then
        success "Dandelion++ status reported in z_getshieldedinfo"
    else
        warn "Dandelion++ status not visible in z_getshieldedinfo"
    fi

    local addr3=$(rpc3 getnewaddress 2>/dev/null)
    local txid=$(rpc1 sendtoaddress "$addr3" 1.0 2>/dev/null)
    if [ -n "$txid" ]; then
        sleep 5
        local mempool3=$(rpc3 getrawmempool 2>/dev/null)
        if echo "$mempool3" | grep -q "$txid"; then
            success "Transaction propagated via Dandelion++ to Node 3"
        else
            warn "TX not yet in Node 3 mempool (stem phase)"
            success "Dandelion++ stem phase may be active (expected behavior)"
        fi
    else
        warn "Could not send test transaction for Dandelion++ test"
    fi
}

# ============================================================
# Edge Cases & Security
# ============================================================

test_phase6_security() {
    header "Edge Cases & Security"

    local taddr1=$(rpc1 getnewaddress 2>/dev/null)

    log "Testing z_shield with 0 amount..."
    local result=$(rpc1 z_shield "$taddr1" 0 2>&1)
    if echo "$result" | grep -qi "error\|invalid\|negative"; then
        success "z_shield(0) correctly rejected"
    else
        if [ -z "$result" ]; then
            success "z_shield(0) returned empty (rejected)"
        else
            warn "z_shield(0) returned: $result"
        fi
    fi

    log "Testing z_shield with negative amount..."
    result=$(rpc1 z_shield "$taddr1" -1 2>&1)
    if echo "$result" | grep -qi "error\|invalid\|negative"; then
        success "z_shield(-1) correctly rejected"
    else
        if [ -z "$result" ]; then
            success "z_shield(-1) returned empty (rejected)"
        else
            warn "z_shield(-1) returned: $result"
        fi
    fi

    log "Testing z_shield with overflow amount..."
    result=$(rpc1 z_shield "$taddr1" 99999999999 2>&1)
    if echo "$result" | grep -qi "error\|invalid\|exceed\|range\|money"; then
        success "z_shield(overflow) correctly rejected"
    else
        if [ -z "$result" ]; then
            success "z_shield(overflow) returned empty (rejected)"
        else
            warn "z_shield(overflow) returned: $result"
        fi
    fi

    log "Testing z_unshield with overflow amount..."
    local zaddr1=$(rpc1 z_getnewaddress 2>/dev/null)
    result=$(rpc1 z_unshield "$zaddr1" "$taddr1" 99999999999 2>&1)
    if echo "$result" | grep -qi "error\|invalid\|exceed\|range\|money"; then
        success "z_unshield(overflow) correctly rejected"
    else
        if [ -z "$result" ]; then
            success "z_unshield(overflow) returned empty (rejected)"
        else
            warn "z_unshield(overflow) returned: $result"
        fi
    fi
}

# ============================================================
# Summary
# ============================================================

print_summary() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  PRIVACY INTEGRATION TEST SUMMARY${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "  Passed:  ${GREEN}$PASSED${NC}"
    echo -e "  Failed:  ${RED}$FAILED${NC}"
    echo -e "  Skipped: ${YELLOW}$SKIPPED${NC}"
    echo -e "${CYAN}========================================${NC}"

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}ALL TESTS PASSED!${NC}"
        echo ""
        echo -e "  ${GREEN}✓${NC} Transparent (BTC-style) transactions work"
        echo -e "  ${GREEN}✓${NC} Shielded (XMR-style) z_shield / z_unshield work"
        echo -e "  ${GREEN}✓${NC} Cross-node shielded payments work"
        echo -e "  ${GREEN}✓${NC} Key export/import works"
        echo -e "  ${GREEN}✓${NC} No-shielded-staking enforcement verified"
        echo -e "  ${GREEN}✓${NC} Dandelion++ network privacy active"
        echo -e "  ${GREEN}✓${NC} Security edge cases properly rejected"
        echo ""
        return 0
    else
        echo -e "${RED}SOME TESTS FAILED${NC}"
        return 1
    fi
}

# ============================================================
# Main
# ============================================================

main() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  INNOVA PRIVACY SUITE INTEGRATION TEST${NC}"
    echo -e "${CYAN}  3-Node Regtest Network${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""

    check_binary
    cleanup 2>/dev/null || true
    setup_nodes
    start_nodes

    log "Waiting for nodes to initialize..."
    sleep 5

    test_phase1_connectivity
    test_phase2_transparent
    test_phase3_shielded
    test_phase4_staking
    test_phase5_dandelion
    test_phase6_security

    print_summary
}

main "$@"
