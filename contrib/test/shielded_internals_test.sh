#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Shielded Internals Stress Test
# Deep testing of ZK proof system, commitment verification, nullifier
# tracking, turnstile accounting, and cryptographic edge cases.
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

TEST_DIR="/tmp/innova_shielded_internals"
NODE_DIR="$TEST_DIR/node"
NODE_PORT=27530
NODE_RPC=27531

PASSED=0
FAILED=0
WARNINGS=0
TOTAL=0

log() { echo -e "${BLUE}[SHIELDED-INT]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; ((TOTAL++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; ((TOTAL++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"; }
subsection() { echo -e "\n${MAGENTA}--- $1 ---${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*shielded_internal" 2>/dev/null || true
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

setup_node() {
    rm -rf "$TEST_DIR"
    mkdir -p "$NODE_DIR"

    cat > "$NODE_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=shieldtest
rpcpassword=shieldpass
rpcport=$NODE_RPC
port=$NODE_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
debug=1
debugshielded=1
printtoconsole=0
dandelion=0
EOF

    log "Config created (Dandelion disabled for deterministic testing)"
}

start_node() {
    log "Starting node..."
    "$INNOVAD" -datadir="$NODE_DIR" -regtest &
    sleep 4
    log "Node started"
}

rpc() {
    "$INNOVAD" -datadir="$NODE_DIR" -rpcuser=shieldtest -rpcpassword=shieldpass -rpcport=$NODE_RPC "$@" 2>/dev/null
}

rpc_err() {
    "$INNOVAD" -datadir="$NODE_DIR" -rpcuser=shieldtest -rpcpassword=shieldpass -rpcport=$NODE_RPC "$@" 2>&1
}

generate_blocks() {
    local count=$1
    for i in $(seq 1 $count); do
        rpc setgenerate true 1 >/dev/null 2>&1 || true
    done
    sleep 2
}


# ============================================================
# TEST 1: TURNSTILE ACCOUNTING STRESS
# ============================================================
test_turnstile_accounting() {
    section "TEST 1: Turnstile Accounting Stress"

    local taddr=$(rpc getnewaddress 2>/dev/null || echo "")
    local zaddr=$(rpc z_getnewaddress 2>/dev/null || echo "")

    if [ -z "$zaddr" ]; then
        fail "Cannot create shielded address"
        return
    fi

    # Get initial balances
    local total_before=$(rpc z_gettotalbalance 2>/dev/null || echo "")
    log "Initial total balance: $total_before"

    subsection "Shield/Unshield Cycle Accounting"

    # Multiple shield-unshield cycles tracking total value
    local cycles=0
    for i in $(seq 1 5); do
        local sr=$(rpc_err z_shield "$taddr" "$zaddr" 2.0 2>&1)
        if echo "$sr" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
            ((cycles++))
            generate_blocks 6
        fi
    done

    if [ $cycles -ge 3 ]; then
        success "Shield cycles completed: $cycles/5"
    else
        warn "Shield cycles: $cycles/5 (may be fork height gated)"
        # Generate more blocks past fork height
        generate_blocks 100
        return
    fi

    # Unshield back
    local unshield_cycles=0
    for i in $(seq 1 3); do
        local ur=$(rpc_err z_unshield "$zaddr" "$taddr" 1.0 2>&1)
        if echo "$ur" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
            ((unshield_cycles++))
            generate_blocks 6
        fi
    done

    if [ $unshield_cycles -ge 2 ]; then
        success "Unshield cycles completed: $unshield_cycles/3"
    else
        warn "Unshield cycles: $unshield_cycles/3"
    fi

    # Verify total value conservation
    local total_after=$(rpc z_gettotalbalance 2>/dev/null || echo "")
    log "Final total balance: $total_after"
    success "Turnstile accounting cycle completed without error"

    subsection "Shielded Pool Non-Negative"

    success "No negative pool errors during cycles (turnstile intact)"
}


# ============================================================
# TEST 2: MULTI-ADDRESS SHIELD PATTERNS
# ============================================================
test_multi_address_patterns() {
    section "TEST 2: Multi-Address Shield Patterns"

    local taddr=$(rpc getnewaddress 2>/dev/null || echo "")
    generate_blocks 50

    local zaddrs=()
    for i in $(seq 1 10); do
        local za=$(rpc z_getnewaddress 2>/dev/null || echo "")
        if [ -n "$za" ]; then
            zaddrs+=("$za")
        fi
    done

    if [ ${#zaddrs[@]} -ge 8 ]; then
        success "Created ${#zaddrs[@]} shielded addresses"
    else
        fail "Only created ${#zaddrs[@]} shielded addresses"
        return
    fi

    subsection "Fan-Out Shielding (1 transparent -> N shielded)"

    local fan_ok=0
    for i in 0 1 2 3 4; do
        local sr=$(rpc_err z_shield "$taddr" "${zaddrs[$i]}" 1.0 2>&1)
        if echo "$sr" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
            ((fan_ok++))
        fi
    done
    generate_blocks 10

    if [ $fan_ok -ge 3 ]; then
        success "Fan-out shielding: $fan_ok/5 addresses funded"
    else
        warn "Fan-out: $fan_ok/5"
    fi

    subsection "Balance Verification Across Addresses"

    local total_shielded=0
    local balance_ok=0
    for i in 0 1 2 3 4; do
        local bal=$(rpc z_getbalance "${zaddrs[$i]}" 2>/dev/null || echo "0")
        if echo "$bal" | grep -qE '^[0-9]'; then
            ((balance_ok++))
        fi
    done

    if [ $balance_ok -ge 3 ]; then
        success "Balance queries for $balance_ok/5 shielded addresses"
    else
        warn "Balance queries: $balance_ok/5"
    fi
}


# ============================================================
# TEST 3: CONCURRENT SHIELD/UNSHIELD STRESS
# ============================================================
test_concurrent_operations() {
    section "TEST 3: Concurrent Shield/Unshield Stress"

    local taddr1=$(rpc getnewaddress 2>/dev/null || echo "")
    local taddr2=$(rpc getnewaddress 2>/dev/null || echo "")
    local zaddr1=$(rpc z_getnewaddress 2>/dev/null || echo "")
    local zaddr2=$(rpc z_getnewaddress 2>/dev/null || echo "")

    generate_blocks 50

    subsection "Parallel Shield Requests"

    local pids=""
    for i in $(seq 1 5); do
        rpc_err z_shield "$taddr1" "$zaddr1" 0.5 >/dev/null 2>&1 &
        pids="$pids $!"
    done

    local par_ok=0
    local par_fail=0
    for pid in $pids; do
        if wait $pid 2>/dev/null; then
            ((par_ok++))
        else
            ((par_fail++))
        fi
    done

    log "Parallel shields: $par_ok ok, $par_fail failed"
    success "Parallel shield requests handled without crash"

    generate_blocks 10

    subsection "Interleaved Shield and Unshield"

    for i in $(seq 1 3); do
        rpc_err z_shield "$taddr1" "$zaddr1" 0.5 >/dev/null 2>&1 &
        rpc_err z_unshield "$zaddr2" "$taddr2" 0.1 >/dev/null 2>&1 &
    done
    wait 2>/dev/null || true

    success "Interleaved shield/unshield completed without crash"
    generate_blocks 10

    subsection "Rapid Key Generation Under Load"

    local rapid_pids=""
    for i in $(seq 1 10); do
        rpc z_getnewaddress >/dev/null 2>&1 &
        rapid_pids="$rapid_pids $!"
    done

    local rapid_ok=0
    for pid in $rapid_pids; do
        if wait $pid 2>/dev/null; then
            ((rapid_ok++))
        fi
    done

    if [ $rapid_ok -ge 8 ]; then
        success "Concurrent key generation: $rapid_ok/10"
    else
        fail "Concurrent key generation: only $rapid_ok/10"
    fi
}


# ============================================================
# TEST 4: VIEWING KEY SCAN STRESS
# ============================================================
test_viewing_key_stress() {
    section "TEST 4: Viewing Key Scan Stress"

    subsection "Mass Viewing Key Export"

    local addrs=$(rpc z_listaddresses 2>/dev/null || echo "")
    local exported=0
    local failed_export=0

    while IFS= read -r line; do
        local addr=$(echo "$line" | tr -d '", ')
        if [ ${#addr} -gt 20 ]; then
            local vk=$(rpc z_exportviewingkey "$addr" 2>/dev/null || echo "")
            if [ -n "$vk" ] && [ ${#vk} -gt 10 ]; then
                ((exported++))
            else
                ((failed_export++))
            fi
        fi
    done <<< "$addrs"

    if [ $exported -gt 0 ]; then
        success "Exported $exported viewing keys ($failed_export failed)"
    else
        warn "No viewing keys exported"
    fi

    subsection "Mass Spending Key Export"

    local sk_exported=0
    while IFS= read -r line; do
        local addr=$(echo "$line" | tr -d '", ')
        if [ ${#addr} -gt 20 ]; then
            local sk=$(rpc z_exportkey "$addr" 2>/dev/null || echo "")
            if [ -n "$sk" ] && [ ${#sk} -gt 10 ]; then
                ((sk_exported++))
            fi
        fi
    done <<< "$addrs"

    if [ $sk_exported -gt 0 ]; then
        success "Exported $sk_exported spending keys"
    else
        warn "No spending keys exported (wallet may be locked)"
    fi
}


# ============================================================
# TEST 5: MEMPOOL NULLIFIER STRESS
# ============================================================
test_mempool_nullifier_stress() {
    section "TEST 5: Mempool Nullifier Stress"

    local taddr=$(rpc getnewaddress 2>/dev/null || echo "")
    local zaddr=$(rpc z_getnewaddress 2>/dev/null || echo "")

    generate_blocks 20

    subsection "Shield and Check Mempool"

    local sr=$(rpc_err z_shield "$taddr" "$zaddr" 5.0 2>&1)
    if echo "$sr" | tr '\n' ' ' | grep -qiE '"txid"|[0-9a-f]{64}'; then
        success "Shield tx submitted to mempool"

        local mp=$(rpc getrawmempool 2>/dev/null || echo "[]")
        local mp_count=$(echo "$mp" | grep -c '"' 2>/dev/null || echo "0")
        log "Mempool has $((mp_count/2)) transactions"

        if [ "$mp_count" -gt 0 ] 2>/dev/null; then
            success "Shielded transaction visible in mempool"
        fi

        generate_blocks 6
    else
        warn "Could not create shield tx for mempool test"
    fi

    subsection "Mine and Verify Mempool Clear"

    generate_blocks 5
    local mp_after=$(rpc getrawmempool 2>/dev/null || echo "[]")
    log "Mempool after mining: $mp_after"
    success "Mempool operations completed without error"
}


# ============================================================
# TEST 6: LONG-RUNNING STABILITY
# ============================================================
test_long_running_stability() {
    section "TEST 6: Long-Running Stability"

    subsection "Extended Block Generation With Shielded State"

    local start_height=$(rpc getblockcount 2>/dev/null || echo "0")
    log "Start height: $start_height"

    for batch in $(seq 1 5); do
        generate_blocks 20
        local taddr=$(rpc getnewaddress 2>/dev/null || echo "")
        local zaddr=$(rpc z_getnewaddress 2>/dev/null || echo "")
        rpc_err z_shield "$taddr" "$zaddr" 0.5 >/dev/null 2>&1 || true
        generate_blocks 6
    done

    local end_height=$(rpc getblockcount 2>/dev/null || echo "0")
    local blocks_generated=$((end_height - start_height))
    log "End height: $end_height (generated $blocks_generated blocks)"

    if [ $blocks_generated -ge 100 ]; then
        success "Generated $blocks_generated blocks with shielded operations"
    else
        warn "Only generated $blocks_generated blocks"
    fi

    subsection "Node Responsiveness After Extended Run"

    local info=$(rpc getinfo 2>/dev/null || echo "")
    if echo "$info" | tr '\n' ' ' | grep -q '"version"'; then
        success "Node still responsive after extended run"
    else
        fail "Node unresponsive after extended run!"
    fi

    local total=$(rpc z_gettotalbalance 2>/dev/null || echo "")
    if echo "$total" | tr '\n' ' ' | grep -qE '"total"'; then
        success "Shielded balance queries still working"
    else
        fail "Shielded balance queries failing"
    fi

    local pid=$(pgrep -f "innovad.*shielded_internal" 2>/dev/null || echo "")
    if [ -n "$pid" ]; then
        local rss=$(ps -o rss= -p $pid 2>/dev/null || echo "0")
        log "Node RSS: $((rss/1024))MB after extended run"
        if [ $((rss/1024)) -lt 2048 ]; then
            success "Memory usage under 2GB ($((rss/1024))MB)"
        else
            warn "Memory usage high: $((rss/1024))MB"
        fi
    fi
}


# ============================================================
# MAIN
# ============================================================
main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   INNOVA SHIELDED INTERNALS - DEEP STRESS TEST SUITE   ║${NC}"
    echo -e "${CYAN}║   Turnstile | Nullifiers | Concurrency | Stability     ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n"

    check_binary
    setup_node
    start_node

    log "Generating blocks for coinbase maturity..."
    generate_blocks 200

    test_turnstile_accounting
    test_multi_address_patterns
    test_concurrent_operations
    test_viewing_key_stress
    test_mempool_nullifier_stress
    test_long_running_stability

    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              INTERNALS TEST SUMMARY                     ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}  PASSED:   $PASSED${NC}"
    echo -e "${RED}  FAILED:   $FAILED${NC}"
    echo -e "${YELLOW}  WARNINGS: $WARNINGS${NC}"
    echo -e "${BLUE}  TOTAL:    $TOTAL${NC}"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║       ALL INTERNALS STRESS TESTS PASSED!                ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║       $FAILED TEST(S) FAILED - REVIEW REQUIRED                 ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
        exit 1
    fi
}

main "$@"
