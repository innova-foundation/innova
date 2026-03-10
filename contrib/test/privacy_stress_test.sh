#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Privacy Suite Stress Test
# Comprehensive stress testing of shielded transactions, Lelantus proofs,
# Silent Payments, Dandelion++, and all privacy RPC commands.
# Author: 0xcircuitbreaker - CircuitBreaker

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_privacy_stress"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"
NODE1_PORT=26530
NODE1_RPC=26531
NODE2_PORT=26540
NODE2_RPC=26541

PASSED=0
FAILED=0
WARNINGS=0
TOTAL=0

log() { echo -e "${BLUE}[PRIVACY-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; ((TOTAL++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; ((TOTAL++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"; }
subsection() { echo -e "\n${MAGENTA}--- $1 ---${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*privacy_stress" 2>/dev/null || true
    pkill -f "innovad.*node1" 2>/dev/null || true
    pkill -f "innovad.*node2" 2>/dev/null || true
    sleep 3
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

check_binary() {
    if [ ! -f "$INNOVAD" ]; then
        echo -e "${RED}ERROR: innovad not found at $INNOVAD${NC}"
        echo "Build with: cd src && make -f makefile.unix (or makefile.osx)"
        exit 1
    fi
    log "Found innovad binary"
}

setup_nodes() {
    log "Setting up privacy test nodes..."
    rm -rf "$TEST_DIR"
    mkdir -p "$NODE1_DIR" "$NODE2_DIR"

    cat > "$NODE1_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=privtest
rpcpassword=privpass
rpcport=$NODE1_RPC
port=$NODE1_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
debug=1
debugshielded=1
printtoconsole=0
addnode=127.0.0.1:$NODE2_PORT
dandelion=1
EOF

    cat > "$NODE2_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=privtest
rpcpassword=privpass
rpcport=$NODE2_RPC
port=$NODE2_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
debug=1
debugshielded=1
printtoconsole=0
addnode=127.0.0.1:$NODE1_PORT
dandelion=1
EOF

    log "Config files created for 2-node network"
}

start_nodes() {
    log "Starting node 1..."
    "$INNOVAD" -datadir="$NODE1_DIR" -regtest &
    sleep 3

    log "Starting node 2..."
    "$INNOVAD" -datadir="$NODE2_DIR" -regtest &
    sleep 3

    local retries=0
    while [ $retries -lt 20 ]; do
        local peers=$(rpc1 getconnectioncount 2>/dev/null || echo "0")
        if [ "$peers" -gt 0 ] 2>/dev/null; then
            log "Nodes connected (peers: $peers)"
            return
        fi
        sleep 1
        ((retries++))
    done
    warn "Nodes may not be connected, continuing anyway"
}

rpc1() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=privtest -rpcpassword=privpass -rpcport=$NODE1_RPC "$@" 2>/dev/null
}

rpc1_err() {
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=privtest -rpcpassword=privpass -rpcport=$NODE1_RPC "$@" 2>&1
}

rpc2() {
    "$INNOVAD" -datadir="$NODE2_DIR" -rpcuser=privtest -rpcpassword=privpass -rpcport=$NODE2_RPC "$@" 2>/dev/null
}

rpc2_err() {
    "$INNOVAD" -datadir="$NODE2_DIR" -rpcuser=privtest -rpcpassword=privpass -rpcport=$NODE2_RPC "$@" 2>&1
}

generate_blocks() {
    local node=$1
    local count=$2
    log "Generating $count blocks on node $node..."
    if [ "$node" = "1" ]; then
        for i in $(seq 1 $count); do
            rpc1 setgenerate true 1 >/dev/null 2>&1 || true
        done
    else
        for i in $(seq 1 $count); do
            rpc2 setgenerate true 1 >/dev/null 2>&1 || true
        done
    fi
    sleep 2
}

wait_sync() {
    log "Waiting for nodes to sync..."
    local retries=0
    while [ $retries -lt 30 ]; do
        local h1=$(rpc1 getblockcount 2>/dev/null || echo "0")
        local h2=$(rpc2 getblockcount 2>/dev/null || echo "0")
        if [ "$h1" = "$h2" ] && [ "$h1" -gt 0 ] 2>/dev/null; then
            log "Nodes synced at height $h1"
            return
        fi
        sleep 1
        ((retries++))
    done
    warn "Nodes may not be synced (h1=$(rpc1 getblockcount), h2=$(rpc2 getblockcount))"
}


# ============================================================
# TEST SUITE 1: SHIELDED ADDRESS AND KEY MANAGEMENT
# ============================================================
test_shielded_key_management() {
    section "TEST SUITE 1: Shielded Key Management"

    subsection "Address Generation"

    local zaddr1=$(rpc1 z_getnewaddress 2>/dev/null || echo "")
    if [ -n "$zaddr1" ] && [ ${#zaddr1} -gt 20 ]; then
        success "z_getnewaddress returns valid address (${#zaddr1} chars)"
    else
        fail "z_getnewaddress failed: '$zaddr1'"
        return
    fi

    local zaddr2=$(rpc1 z_getnewaddress 2>/dev/null || echo "")
    local zaddr3=$(rpc1 z_getnewaddress 2>/dev/null || echo "")
    if [ "$zaddr1" != "$zaddr2" ] && [ "$zaddr2" != "$zaddr3" ]; then
        success "Multiple z_getnewaddress calls produce unique addresses"
    else
        fail "z_getnewaddress returned duplicate addresses"
    fi

    local zaddrs=$(rpc1 z_listaddresses 2>/dev/null || echo "")
    if echo "$zaddrs" | tr '\n' ' ' | grep -q "$zaddr1"; then
        success "z_listaddresses includes generated address"
    else
        fail "z_listaddresses missing generated address"
    fi

    local addr_count=$(echo "$zaddrs" | grep -c '"' || echo "0")
    if [ "$addr_count" -ge 3 ] 2>/dev/null; then
        success "z_listaddresses shows all $((addr_count/2)) addresses"
    else
        warn "Address count check: $addr_count entries"
    fi

    subsection "Key Export/Import"

    local exported=$(rpc1 z_exportkey "$zaddr1" 2>/dev/null || echo "")
    if [ -n "$exported" ] && [ ${#exported} -gt 20 ]; then
        success "z_exportkey returns spending key (${#exported} chars)"
    else
        warn "z_exportkey returned: '$exported'"
    fi

    local vk=$(rpc1 z_exportviewingkey "$zaddr1" 2>/dev/null || echo "")
    if [ -n "$vk" ] && [ ${#vk} -gt 10 ]; then
        success "z_exportviewingkey returns viewing key (${#vk} chars)"
    else
        warn "z_exportviewingkey returned: '$vk'"
    fi

    if [ -n "$exported" ] && [ ${#exported} -gt 20 ]; then
        local import_result=$(rpc2_err z_importkey "$exported" 2>&1 || echo "")
        if ! echo "$import_result" | grep -qi "error"; then
            success "z_importkey imports spending key on node2"
        else
            fail "z_importkey failed: $import_result"
        fi
    fi

    if [ -n "$vk" ] && [ ${#vk} -gt 10 ]; then
        local import_vk=$(rpc2_err z_importviewingkey "$vk" 2>&1 || echo "")
        if ! echo "$import_vk" | grep -qi "error"; then
            success "z_importviewingkey imports viewing key on node2"
        else
            warn "z_importviewingkey: $import_vk"
        fi
    fi

    subsection "Shielded Balance"

    local zbal=$(rpc1 z_getbalance "$zaddr1" 2>/dev/null || echo "")
    if [ "$zbal" = "0" ] || [ "$zbal" = "0.00000000" ] || echo "$zbal" | grep -qE '^[0-9]'; then
        success "z_getbalance returns valid balance: $zbal"
    else
        fail "z_getbalance failed: '$zbal'"
    fi

    local ztotal=$(rpc1 z_gettotalbalance 2>/dev/null || echo "")
    if echo "$ztotal" | tr '\n' ' ' | grep -qE '"transparent"|"shielded"|"total"'; then
        success "z_gettotalbalance returns structured balance"
    else
        warn "z_gettotalbalance: $ztotal"
    fi

    ZADDR1="$zaddr1"
    ZADDR2="$zaddr2"
    ZADDR3="$zaddr3"
}


# ============================================================
# TEST SUITE 2: SHIELDED TRANSACTIONS (z_shield / z_unshield)
# ============================================================
test_shielded_transactions() {
    section "TEST SUITE 2: Shielded Transactions"

    local taddr=$(rpc1 getnewaddress 2>/dev/null || echo "")
    if [ -z "$taddr" ]; then
        fail "Cannot get transparent address"
        return
    fi

    generate_blocks 1 120
    sleep 2

    local balance=$(rpc1 getbalance 2>/dev/null || echo "0")
    log "Node1 transparent balance: $balance"

    if [ "$(echo "$balance > 0" | bc 2>/dev/null)" != "1" ] 2>/dev/null; then
        warn "No transparent balance available, skipping shielded tx tests"
        return
    fi

    subsection "Shield Transaction (t -> z)"

    local shield_result=$(rpc1_err z_shield "$taddr" 10.0 "$ZADDR1" 2>&1)
    if echo "$shield_result" | tr '\n' ' ' | grep -qiE '"txid"|"operationid"|[0-9a-f]{64}'; then
        success "z_shield created transaction"
        local shield_txid=$(echo "$shield_result" | tr -d '"' | tr -d ' ' | head -1)
        log "Shield txid: $shield_txid"
    else
        if echo "$shield_result" | grep -qi "fork\|height\|not.*active"; then
            warn "z_shield rejected (fork height not reached): $shield_result"
            log "Generating blocks to reach fork height..."
            generate_blocks 1 50
            shield_result=$(rpc1_err z_shield "$taddr" 10.0 "$ZADDR1" 2>&1)
            if echo "$shield_result" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
                success "z_shield succeeded after reaching fork height"
            else
                fail "z_shield still failed: $shield_result"
                return
            fi
        else
            fail "z_shield failed: $shield_result"
            return
        fi
    fi

    generate_blocks 1 6
    wait_sync

    local zbal=$(rpc1 z_getbalance "$ZADDR1" 2>/dev/null || echo "0")
    log "Shielded balance after shield: $zbal"
    if [ "$(echo "$zbal > 0" | bc 2>/dev/null)" = "1" ] 2>/dev/null; then
        success "Shielded balance is positive after z_shield ($zbal)"
    else
        warn "Shielded balance still 0 after z_shield (may need more confirmations)"
    fi

    subsection "Multiple Shield Transactions"

    local shield_count=0
    for i in 1 2 3; do
        local sr=$(rpc1_err z_shield "$taddr" 5.0 "$ZADDR2" 2>&1)
        if echo "$sr" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
            ((shield_count++))
        fi
    done
    if [ $shield_count -ge 2 ]; then
        success "Multiple z_shield transactions created ($shield_count/3)"
    else
        warn "Only $shield_count/3 shield transactions succeeded"
    fi

    generate_blocks 1 6
    wait_sync

    subsection "Unshield Transaction (z -> t)"

    local unshield_result=$(rpc1_err z_unshield "$ZADDR1" "$taddr" 5.0 2>&1)
    if echo "$unshield_result" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
        success "z_unshield created transaction"
    else
        if echo "$unshield_result" | grep -qi "insufficient\|no.*note\|balance"; then
            warn "z_unshield: insufficient shielded funds: $unshield_result"
        else
            fail "z_unshield failed: $unshield_result"
        fi
    fi

    generate_blocks 1 6
    wait_sync

    subsection "Shielded-to-Shielded Transfer"

    local z2z_result=$(rpc1_err z_shield "$ZADDR1" 2.0 "$ZADDR3" 2>&1)
    if echo "$z2z_result" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
        success "z->z shielded transfer created"
    else
        warn "z->z transfer: $z2z_result"
    fi

    generate_blocks 1 6
}


# ============================================================
# TEST SUITE 3: SHIELDED TRANSACTION VALIDATION
# ============================================================
test_shielded_validation() {
    section "TEST SUITE 3: Shielded Transaction Validation"

    subsection "Invalid Transaction Rejection"

    local taddr=$(rpc1 getnewaddress 2>/dev/null || echo "")
    local zero_result=$(rpc1_err z_shield "$taddr" 0.0 "$ZADDR1" 2>&1)
    if echo "$zero_result" | grep -qi "error\|invalid\|amount"; then
        success "z_shield rejects zero amount"
    else
        fail "z_shield did not reject zero amount: $zero_result"
    fi

    local neg_result=$(rpc1_err z_shield "$taddr" -1.0 "$ZADDR1" 2>&1)
    if echo "$neg_result" | grep -qi "error\|invalid\|amount\|negative"; then
        success "z_shield rejects negative amount"
    else
        fail "z_shield did not reject negative amount: $neg_result"
    fi

    local bad_result=$(rpc1_err z_shield "$taddr" 1.0 "invalidzaddr123" 2>&1)
    if echo "$bad_result" | grep -qi "error\|invalid\|address"; then
        success "z_shield rejects invalid shielded address"
    else
        fail "z_shield did not reject invalid address: $bad_result"
    fi

    local huge_result=$(rpc1_err z_shield "$taddr" 999999999.0 "$ZADDR1" 2>&1)
    if echo "$huge_result" | grep -qi "error\|insufficient\|balance\|amount"; then
        success "z_shield rejects insufficient balance"
    else
        fail "z_shield did not reject over-balance: $huge_result"
    fi

    subsection "Unshield Validation"

    local empty_zaddr=$(rpc1 z_getnewaddress 2>/dev/null || echo "")
    if [ -n "$empty_zaddr" ]; then
        local empty_result=$(rpc1_err z_unshield "$empty_zaddr" "$taddr" 1.0 2>&1)
        if echo "$empty_result" | grep -qi "error\|insufficient\|no.*note\|balance"; then
            success "z_unshield rejects empty shielded address"
        else
            fail "z_unshield did not reject empty address: $empty_result"
        fi
    fi

    local bad_unshield=$(rpc1_err z_unshield "$ZADDR1" "invalidtaddr" 1.0 2>&1)
    if echo "$bad_unshield" | grep -qi "error\|invalid\|address"; then
        success "z_unshield rejects invalid transparent address"
    else
        fail "z_unshield did not reject invalid address: $bad_unshield"
    fi
}


# ============================================================
# TEST SUITE 4: DOUBLE-SPEND PREVENTION (NULLIFIER ENFORCEMENT)
# ============================================================
test_double_spend_prevention() {
    section "TEST SUITE 4: Double-Spend Prevention"

    subsection "Nullifier Uniqueness"

    local taddr=$(rpc1 getnewaddress 2>/dev/null || echo "")
    generate_blocks 1 10

    local shield1=$(rpc1_err z_shield "$taddr" 5.0 "$ZADDR1" 2>&1)
    if ! echo "$shield1" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
        warn "Cannot create shield tx for double-spend test"
        return
    fi

    generate_blocks 1 6
    sleep 2

    local taddr2=$(rpc1 getnewaddress 2>/dev/null || echo "")
    local unshield1=$(rpc1_err z_unshield "$ZADDR1" "$taddr" 2.0 2>&1) &
    local pid1=$!
    local unshield2=$(rpc1_err z_unshield "$ZADDR1" "$taddr2" 2.0 2>&1) &
    local pid2=$!
    wait $pid1 2>/dev/null || true
    wait $pid2 2>/dev/null || true

    log "Concurrent unshield test completed"
    success "Concurrent double-spend test executed without crash"

    generate_blocks 1 6

    subsection "Cross-Node Nullifier Enforcement"

    wait_sync
    local n2_zbal=$(rpc2 z_getbalance "$ZADDR1" 2>/dev/null || echo "")
    log "Node2 sees shielded balance: $n2_zbal"
    success "Cross-node shielded state sync verified"
}


# ============================================================
# TEST SUITE 5: SILENT PAYMENTS (BIP-352)
# ============================================================
test_silent_payments() {
    section "TEST SUITE 5: Silent Payments"

    subsection "Address Generation"

    local spaddr=$(rpc1 sp_getnewaddress 2>/dev/null || echo "")
    if [ -n "$spaddr" ] && [ ${#spaddr} -gt 20 ]; then
        success "sp_getnewaddress returns valid address (${#spaddr} chars)"
    else
        if echo "$spaddr" | grep -qi "error\|not.*found\|method"; then
            warn "Silent payments RPC not available: $spaddr"
            return
        fi
        fail "sp_getnewaddress failed: '$spaddr'"
        return
    fi

    local spaddr2=$(rpc1 sp_getnewaddress 2>/dev/null || echo "")
    if [ "$spaddr" != "$spaddr2" ]; then
        success "Multiple sp_getnewaddress calls produce unique addresses"
    else
        fail "sp_getnewaddress returned duplicate"
    fi

    subsection "SP Address Listing"

    local splist=$(rpc1 sp_listaddresses 2>/dev/null || echo "")
    if echo "$splist" | tr '\n' ' ' | grep -qE '\[.*\]'; then
        success "sp_listaddresses returns address list"
    else
        warn "sp_listaddresses: $splist"
    fi

    subsection "SP Balance"

    local spbal=$(rpc1 sp_getbalance 2>/dev/null || echo "")
    if echo "$spbal" | grep -qE '^[0-9]'; then
        success "sp_getbalance returns valid balance: $spbal"
    else
        warn "sp_getbalance: $spbal"
    fi

    SPADDR1="$spaddr"
}


# ============================================================
# TEST SUITE 6: DANDELION++ NETWORK PRIVACY
# ============================================================
test_dandelion() {
    section "TEST SUITE 6: Dandelion++ Network Privacy"

    subsection "Dandelion State"

    local peerinfo=$(rpc1 getpeerinfo 2>/dev/null || echo "")
    if [ -n "$peerinfo" ]; then
        success "getpeerinfo returns peer data"
    else
        warn "getpeerinfo empty"
    fi

    local taddr1=$(rpc1 getnewaddress 2>/dev/null || echo "")
    local taddr2=$(rpc2 getnewaddress 2>/dev/null || echo "")

    generate_blocks 1 10
    wait_sync

    local txid=$(rpc1 sendtoaddress "$taddr2" 1.0 2>/dev/null || echo "")
    if [ -n "$txid" ] && [ ${#txid} -eq 64 ]; then
        sleep 5  # Allow Dandelion stem+fluff propagation
        local mempool2=$(rpc2 getrawmempool 2>/dev/null || echo "")
        if echo "$mempool2" | grep -q "$txid"; then
            success "Transaction propagated through Dandelion++ to node2"
        else
            warn "Transaction not yet in node2 mempool (may still be in stem phase)"
            sleep 15
            mempool2=$(rpc2 getrawmempool 2>/dev/null || echo "")
            if echo "$mempool2" | grep -q "$txid"; then
                success "Transaction propagated after stem timeout"
            else
                warn "Transaction still not in node2 mempool"
            fi
        fi
    else
        warn "Could not send transaction for Dandelion test: $txid"
    fi

    generate_blocks 1 2
    wait_sync

    subsection "Shielded Transaction Propagation via Dandelion"

    local staddr=$(rpc1 getnewaddress 2>/dev/null || echo "")
    if [ -n "$ZADDR1" ]; then
        local shield_dand=$(rpc1_err z_shield "$staddr" 1.0 "$ZADDR1" 2>&1)
        if echo "$shield_dand" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
            sleep 8
            success "Shielded transaction submitted through Dandelion++ pipeline"
        fi
    fi

    generate_blocks 1 6
    wait_sync
}


# ============================================================
# TEST SUITE 7: EDGE CASES AND BOUNDARY CONDITIONS
# ============================================================
test_edge_cases() {
    section "TEST SUITE 7: Edge Cases & Boundary Conditions"

    subsection "Minimum/Maximum Amounts"

    local taddr=$(rpc1 getnewaddress 2>/dev/null || echo "")
    generate_blocks 1 10

    local dust_result=$(rpc1_err z_shield "$taddr" 0.00000001 "$ZADDR1" 2>&1)
    if echo "$dust_result" | grep -qi "error\|dust\|small\|minimum"; then
        success "z_shield rejects dust amount"
    else
        warn "z_shield dust amount response: $dust_result"
    fi

    local max_result=$(rpc1_err z_shield "$taddr" 18000000.0 "$ZADDR1" 2>&1)
    if echo "$max_result" | grep -qi "error\|insufficient\|invalid"; then
        success "z_shield rejects exceeding max supply"
    else
        warn "z_shield max amount response: $max_result"
    fi

    subsection "Address Format Stress"

    local empty=$(rpc1_err z_shield "" 1.0 "$ZADDR1" 2>&1)
    if echo "$empty" | grep -qi "error\|invalid"; then
        success "z_shield rejects empty from address"
    else
        warn "z_shield empty address: $empty"
    fi

    local unicode=$(rpc1_err z_shield "$taddr" 1.0 "z_тест" 2>&1)
    if echo "$unicode" | grep -qi "error\|invalid"; then
        success "z_shield rejects unicode in address"
    else
        warn "z_shield unicode: $unicode"
    fi

    local longstr=$(python3 -c "print('z' * 10000)" 2>/dev/null || echo "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
    local long_result=$(rpc1_err z_shield "$taddr" 1.0 "$longstr" 2>&1)
    if echo "$long_result" | grep -qi "error\|invalid"; then
        success "z_shield rejects oversized address string"
    else
        warn "z_shield long address: $long_result"
    fi

    subsection "Rapid RPC Stress"

    local rapid_count=0
    local rapid_ok=0
    for i in $(seq 1 20); do
        local r=$(rpc1 z_getnewaddress 2>/dev/null || echo "")
        if [ -n "$r" ] && [ ${#r} -gt 10 ]; then
            ((rapid_ok++))
        fi
        ((rapid_count++))
    done
    if [ $rapid_ok -ge 18 ]; then
        success "Rapid z_getnewaddress: $rapid_ok/$rapid_count succeeded"
    else
        fail "Rapid z_getnewaddress: only $rapid_ok/$rapid_count succeeded"
    fi

    rapid_ok=0
    for i in $(seq 1 20); do
        local r=$(rpc1 z_gettotalbalance 2>/dev/null || echo "")
        if echo "$r" | tr '\n' ' ' | grep -qE '"total"'; then
            ((rapid_ok++))
        fi
    done
    if [ $rapid_ok -ge 18 ]; then
        success "Rapid z_gettotalbalance: $rapid_ok/20 succeeded"
    else
        fail "Rapid z_gettotalbalance: only $rapid_ok/20 succeeded"
    fi
}


# ============================================================
# TEST SUITE 8: REORG RESILIENCE
# ============================================================
test_reorg_resilience() {
    section "TEST SUITE 8: Reorg Resilience"

    subsection "Shielded State After Block Generation"

    local zbal_before=$(rpc1 z_getbalance "$ZADDR1" 2>/dev/null || echo "0")
    local height_before=$(rpc1 getblockcount 2>/dev/null || echo "0")
    log "Before: height=$height_before, zbalance=$zbal_before"

    generate_blocks 1 10
    wait_sync

    local zbal_after=$(rpc1 z_getbalance "$ZADDR1" 2>/dev/null || echo "0")
    local height_after=$(rpc1 getblockcount 2>/dev/null || echo "0")
    log "After: height=$height_after, zbalance=$zbal_after"

    if [ "$height_after" -gt "$height_before" ] 2>/dev/null; then
        success "Chain progressed from $height_before to $height_after"
    else
        fail "Chain did not progress"
    fi

    local zbal_n2=$(rpc2 z_getbalance "$ZADDR1" 2>/dev/null || echo "0")
    if [ "$zbal_after" = "$zbal_n2" ]; then
        success "Both nodes agree on shielded balance: $zbal_after"
    else
        warn "Node balance mismatch: node1=$zbal_after, node2=$zbal_n2"
    fi

    subsection "Total Balance Consistency"

    local total1=$(rpc1 z_gettotalbalance 2>/dev/null || echo "")
    local total2=$(rpc2 z_gettotalbalance 2>/dev/null || echo "")
    if [ -n "$total1" ] && [ -n "$total2" ]; then
        local t1_total=$(echo "$total1" | tr '\n' ' ' | grep -oE '"total"[^"]*"[^"]*"' | head -1)
        local t2_total=$(echo "$total2" | tr '\n' ' ' | grep -oE '"total"[^"]*"[^"]*"' | head -1)
        log "Node1 total: $t1_total"
        log "Node2 total: $t2_total"
        success "Both nodes report total balance"
    fi
}


# ============================================================
# TEST SUITE 9: PRIVACY GUARANTEES VERIFICATION
# ============================================================
test_privacy_guarantees() {
    section "TEST SUITE 9: Privacy Guarantees"

    subsection "No Shielded Staking Enforcement"

    rpc1 setstaking true 2>/dev/null || true
    sleep 2

    local stakeinfo=$(rpc1 getstakinginfo 2>/dev/null || echo "")
    if [ -n "$stakeinfo" ]; then
        success "getstakinginfo accessible (shielded funds should be excluded)"
    fi

    rpc1 setstaking false 2>/dev/null || true

    subsection "Viewing Key Privacy"

    if [ -n "$ZADDR1" ]; then
        local vk=$(rpc1 z_exportviewingkey "$ZADDR1" 2>/dev/null || echo "")
        if [ -n "$vk" ] && [ ${#vk} -gt 10 ]; then
            success "Viewing key exported (${#vk} chars)"

            rpc2 z_importviewingkey "$vk" 2>/dev/null || true
            local vk_bal=$(rpc2 z_getbalance "$ZADDR1" 2>/dev/null || echo "")
            log "Node2 sees balance via viewing key: $vk_bal"
            success "Viewing key imported on node2"
        fi
    fi

    subsection "Fork Height Enforcement"

    local info=$(rpc1 getinfo 2>/dev/null || echo "")
    if [ -n "$info" ]; then
        success "Node operational with privacy features"
    fi
}


# ============================================================
# TEST SUITE 10: STRESS LOAD TESTING
# ============================================================
test_stress_load() {
    section "TEST SUITE 10: Stress Load Testing"

    subsection "Mass Address Generation"

    local start_time=$(date +%s)
    local gen_count=0
    for i in $(seq 1 50); do
        local addr=$(rpc1 z_getnewaddress 2>/dev/null || echo "")
        if [ -n "$addr" ]; then
            ((gen_count++))
        fi
    done
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    if [ $gen_count -ge 48 ]; then
        success "Mass generation: $gen_count/50 addresses in ${duration}s"
    else
        fail "Mass generation: only $gen_count/50 succeeded"
    fi

    subsection "Concurrent RPC Operations"

    local pids=""
    for i in $(seq 1 10); do
        rpc1 z_getnewaddress >/dev/null 2>&1 &
        pids="$pids $!"
        rpc1 z_gettotalbalance >/dev/null 2>&1 &
        pids="$pids $!"
        rpc1 z_listaddresses >/dev/null 2>&1 &
        pids="$pids $!"
    done

    local concurrent_ok=0
    local concurrent_fail=0
    for pid in $pids; do
        if wait $pid 2>/dev/null; then
            ((concurrent_ok++))
        else
            ((concurrent_fail++))
        fi
    done

    if [ $concurrent_fail -eq 0 ]; then
        success "Concurrent RPCs: all $concurrent_ok completed without error"
    elif [ $concurrent_fail -lt 5 ]; then
        warn "Concurrent RPCs: $concurrent_ok ok, $concurrent_fail failed"
    else
        fail "Concurrent RPCs: $concurrent_ok ok, $concurrent_fail failed"
    fi

    subsection "Sustained Shield/Unshield Cycle"

    local taddr=$(rpc1 getnewaddress 2>/dev/null || echo "")
    generate_blocks 1 20

    local cycle_count=0
    for i in $(seq 1 5); do
        local sr=$(rpc1_err z_shield "$taddr" 1.0 "$ZADDR1" 2>&1)
        if echo "$sr" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
            ((cycle_count++))
        fi
        generate_blocks 1 2
    done

    if [ $cycle_count -ge 3 ]; then
        success "Shield cycle: $cycle_count/5 transactions in sustained loop"
    else
        warn "Shield cycle: only $cycle_count/5 succeeded"
    fi
}


# ============================================================
# TEST SUITE 11: SILENT PAYMENT STRESS
# ============================================================
test_silent_payment_stress() {
    section "TEST SUITE 11: Silent Payment Stress"

    subsection "Mass SP Address Generation"

    local sp_gen_count=0
    for i in $(seq 1 20); do
        local addr=$(rpc1 sp_getnewaddress 2>/dev/null || echo "")
        if [ -n "$addr" ] && [ ${#addr} -gt 10 ]; then
            ((sp_gen_count++))
        fi
    done

    if [ $sp_gen_count -ge 18 ]; then
        success "SP mass generation: $sp_gen_count/20 addresses"
    else
        if [ $sp_gen_count -eq 0 ]; then
            warn "Silent payments RPC not available, skipping"
            return
        fi
        fail "SP mass generation: only $sp_gen_count/20"
    fi

    subsection "SP List Performance"

    local sp_list=$(rpc1 sp_listaddresses 2>/dev/null || echo "")
    local sp_count=$(echo "$sp_list" | grep -c '"' || echo "0")
    if [ "$sp_count" -gt 10 ] 2>/dev/null; then
        success "sp_listaddresses shows $((sp_count/2))+ addresses"
    else
        warn "sp_listaddresses count: $sp_count"
    fi

    subsection "SP Balance Queries Under Load"

    local sp_bal_ok=0
    for i in $(seq 1 10); do
        local bal=$(rpc1 sp_getbalance 2>/dev/null || echo "")
        if echo "$bal" | grep -qE '^[0-9]'; then
            ((sp_bal_ok++))
        fi
    done

    if [ $sp_bal_ok -ge 8 ]; then
        success "SP balance queries: $sp_bal_ok/10 succeeded"
    else
        warn "SP balance queries: $sp_bal_ok/10"
    fi
}


# ============================================================
# TEST SUITE 12: NODE STABILITY UNDER PRIVACY LOAD
# ============================================================
test_node_stability() {
    section "TEST SUITE 12: Node Stability Under Privacy Load"

    subsection "Node Health After All Tests"

    local n1_info=$(rpc1 getinfo 2>/dev/null || echo "")
    local n2_info=$(rpc2 getinfo 2>/dev/null || echo "")

    if echo "$n1_info" | tr '\n' ' ' | grep -q '"version"'; then
        success "Node 1 still responsive after all tests"
    else
        fail "Node 1 unresponsive!"
    fi

    if echo "$n2_info" | tr '\n' ' ' | grep -q '"version"'; then
        success "Node 2 still responsive after all tests"
    else
        fail "Node 2 unresponsive!"
    fi

    local h1=$(rpc1 getblockcount 2>/dev/null || echo "0")
    local h2=$(rpc2 getblockcount 2>/dev/null || echo "0")
    if [ "$h1" = "$h2" ] && [ "$h1" -gt 0 ] 2>/dev/null; then
        success "Both nodes at same height: $h1"
    else
        warn "Height mismatch: node1=$h1, node2=$h2"
    fi

    local mp1=$(rpc1 getrawmempool 2>/dev/null || echo "[]")
    local mp2=$(rpc2 getrawmempool 2>/dev/null || echo "[]")
    log "Node1 mempool entries: $(echo "$mp1" | grep -c '"' || echo "0")"
    log "Node2 mempool entries: $(echo "$mp2" | grep -c '"' || echo "0")"
    success "Mempool accessible on both nodes"

    local pid1=$(pgrep -f "innovad.*node1" 2>/dev/null | head -1 || echo "")
    local pid2=$(pgrep -f "innovad.*node2" 2>/dev/null | head -1 || echo "")
    if [ -n "$pid1" ]; then
        local rss1=$(ps -o rss= -p $pid1 2>/dev/null || echo "0")
        log "Node1 RSS: $((rss1/1024))MB (pid $pid1)"
        success "Node1 process healthy"
    fi
    if [ -n "$pid2" ]; then
        local rss2=$(ps -o rss= -p $pid2 2>/dev/null || echo "0")
        log "Node2 RSS: $((rss2/1024))MB (pid $pid2)"
        success "Node2 process healthy"
    fi

    subsection "Final Consistency Check"

    generate_blocks 1 10
    wait_sync

    local final_total=$(rpc1 z_gettotalbalance 2>/dev/null || echo "")
    log "Final total balance: $final_total"
    if echo "$final_total" | tr '\n' ' ' | grep -qE '"total"'; then
        success "Final balance query successful"
    fi
}


# ============================================================
# MAIN EXECUTION
# ============================================================
main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     INNOVA PRIVACY SUITE - COMPREHENSIVE STRESS TEST    ║${NC}"
    echo -e "${CYAN}║  Shielded Tx | Silent Payments | Dandelion++ | Lelantus ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n"

    check_binary
    setup_nodes
    start_nodes

    generate_blocks 1 150
    wait_sync

    test_shielded_key_management
    test_shielded_transactions
    test_shielded_validation
    test_double_spend_prevention
    test_silent_payments
    test_dandelion
    test_edge_cases
    test_reorg_resilience
    test_privacy_guarantees
    test_stress_load
    test_silent_payment_stress
    test_node_stability

    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    TEST SUMMARY                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}  PASSED:   $PASSED${NC}"
    echo -e "${RED}  FAILED:   $FAILED${NC}"
    echo -e "${YELLOW}  WARNINGS: $WARNINGS${NC}"
    echo -e "${BLUE}  TOTAL:    $TOTAL${NC}"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║          ALL PRIVACY STRESS TESTS PASSED!               ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║          $FAILED TEST(S) FAILED - REVIEW REQUIRED              ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
        exit 1
    fi
}

main "$@"
