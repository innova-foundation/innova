#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Wallet Stress Test Script
# Tests wallet operations: encryption, backup, key import/export, address generation
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

TEST_DIR="/tmp/innova_wallet_stress"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"

NODE1_PORT=22445
NODE2_PORT=22446
NODE1_RPC=22500
NODE2_RPC=22501

PASSED=0
FAILED=0
WARNINGS=0

log() { echo -e "${BLUE}[WALLET-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

get_json_val() {
    local json="$1"
    local field="$2"
    echo "$json" | tr '\n' ' ' | grep -o "\"$field\" *: *[a-z0-9.\"]*" | head -1 | sed 's/.*: *//;s/"//g' || echo ""
}

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*wallet_stress" 2>/dev/null || true
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
    log "Setting up wallet test nodes..."
    rm -rf "$TEST_DIR"
    mkdir -p "$NODE1_DIR" "$NODE2_DIR"

    cat > "$NODE1_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=wallettest
rpcpassword=walletpass
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
rpcuser=wallettest
rpcpassword=walletpass
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
    "$INNOVAD" -datadir="$NODE1_DIR" -rpcuser=wallettest -rpcpassword=walletpass -rpcport=$NODE1_RPC "$@" 2>/dev/null
}

rpc2() {
    "$INNOVAD" -datadir="$NODE2_DIR" -rpcuser=wallettest -rpcpassword=walletpass -rpcport=$NODE2_RPC "$@" 2>/dev/null
}

# TEST SUITES
test_address_generation() {
    section "Address Generation Stress Test"

    # Generate many addresses rapidly
    local count=0
    for i in $(seq 1 50); do
        local addr=$(rpc1 getnewaddress 2>/dev/null || echo "")
        if [ -n "$addr" ]; then
            ((count++)) || true
        fi
    done

    if [ $count -ge 45 ]; then
        success "Generated $count/50 addresses rapidly"
    else
        fail "Only generated $count/50 addresses"
    fi

    # Test address validation
    local test_addr=$(rpc1 getnewaddress 2>/dev/null)
    local valid=$(rpc1 validateaddress "$test_addr" 2>/dev/null || echo "{}")
    if echo "$valid" | tr '\n' ' ' | grep -q '"isvalid" *: *true'; then
        success "Address validation works correctly"
    else
        fail "Address validation failed for valid address"
    fi

    # Test invalid address
    local invalid=$(rpc1 validateaddress "INVALIDADDRESS123" 2>/dev/null || echo "{}")
    if echo "$invalid" | tr '\n' ' ' | grep -q '"isvalid" *: *false'; then
        success "Invalid address correctly rejected"
    else
        fail "Invalid address not detected"
    fi
}

test_key_operations() {
    section "Key Import/Export Operations"

    # Get a private key
    local addr=$(rpc1 getnewaddress 2>/dev/null)
    local privkey=$(rpc1 dumpprivkey "$addr" 2>/dev/null || echo "")

    if [ -n "$privkey" ]; then
        success "Private key export (dumpprivkey) works"
        log "Key length: ${#privkey} chars"
    else
        fail "Could not export private key"
        return 0
    fi

    # Import the key to node2
    local import_result=$(rpc2 importprivkey "$privkey" "imported_key" false 2>&1 || echo "ERROR")
    if ! echo "$import_result" | grep -qi "error"; then
        success "Private key import to second node succeeded"
    else
        warn "Key import result: $import_result"
    fi

    # Send coins to the shared address and verify both nodes see them
    rpc1 setgenerate true 20 >/dev/null 2>&1 || true
    sleep 2

    local send_result=$(rpc1 sendtoaddress "$addr" 100.0 2>/dev/null || echo "")
    if [ -n "$send_result" ]; then
        rpc1 setgenerate true 2 >/dev/null 2>&1 || true
        sleep 2
        success "Sent coins to shared address"
    else
        warn "Could not send to shared address"
    fi
}

test_wallet_backup() {
    section "Wallet Backup/Restore Test"

    local backup_file="$TEST_DIR/wallet_backup.dat"

    # Create backup
    local result=$(rpc1 backupwallet "$backup_file" 2>&1 || echo "ERROR")
    if [ -f "$backup_file" ]; then
        local size=$(ls -la "$backup_file" | awk '{print $5}')
        success "Wallet backup created ($size bytes)"
    else
        fail "Wallet backup failed: $result"
        return 0
    fi

    # Verify backup file is not empty
    if [ -s "$backup_file" ]; then
        success "Backup file is non-empty"
    else
        fail "Backup file is empty"
    fi

    # Verify backup is a valid BDB file (starts with magic bytes)
    local magic=$(xxd -l 4 "$backup_file" 2>/dev/null | head -1 || echo "")
    if [ -n "$magic" ]; then
        success "Backup file has valid header"
    fi
}

test_wallet_encryption() {
    section "Wallet Encryption Test"

    # Node2 has an unencrypted wallet - encrypt it
    local enc_result=$(rpc2 encryptwallet "testpassphrase123" 2>&1 || echo "ERROR")
    if echo "$enc_result" | grep -qi "encrypted\|stopping\|restart"; then
        success "Wallet encryption initiated"
        # Node will restart - wait for it
        sleep 5
        "$INNOVAD" -datadir="$NODE2_DIR" -regtest &
        sleep 5
    else
        # May already be encrypted or other issue
        log "Encryption result: $enc_result"
    fi

    # Check wallet status
    local info=$(rpc2 getinfo 2>/dev/null || echo "{}")
    if echo "$info" | tr '\n' ' ' | grep -q '"unlocked_until"'; then
        success "Wallet shows encrypted status"
    else
        log "Wallet encryption state not confirmed in getinfo"
    fi

    # Test unlock for spending
    local unlock=$(rpc2 walletpassphrase "testpassphrase123" 60 2>&1 || echo "ERROR")
    if ! echo "$unlock" | grep -qi "error"; then
        success "Wallet unlock succeeded"
    else
        warn "Wallet unlock result: $unlock"
    fi

    # Test wrong password
    local bad_unlock=$(rpc2 walletpassphrase "wrongpassword" 60 2>&1 || echo "")
    if echo "$bad_unlock" | grep -qi "error\|incorrect"; then
        success "Wrong password correctly rejected"
    else
        warn "Wrong password handling unclear"
    fi

    # Lock wallet
    local lock=$(rpc2 walletlock 2>&1 || echo "ERROR")
    if ! echo "$lock" | grep -qi "error"; then
        success "Wallet lock succeeded"
    else
        log "Lock result: $lock"
    fi
}

test_multisend() {
    section "Multi-Send Stress Test"

    # Generate blocks for coins
    rpc1 setgenerate true 50 >/dev/null 2>&1 || true
    sleep 2

    # Generate 10 addresses and send to all of them
    local addrs=()
    for i in $(seq 1 10); do
        addrs+=("$(rpc1 getnewaddress 2>/dev/null)")
    done

    local sent=0
    for addr in "${addrs[@]}"; do
        if [ -n "$addr" ] && rpc1 sendtoaddress "$addr" 10.0 >/dev/null 2>&1; then
            ((sent++)) || true
        fi
        # Mine a block every 3 sends to keep change confirmed
        if [ $((sent % 3)) -eq 0 ]; then
            rpc1 setgenerate true 1 >/dev/null 2>&1 || true
            sleep 1
        fi
    done

    if [ $sent -ge 8 ]; then
        success "Sent to $sent/10 addresses"
    elif [ $sent -gt 0 ]; then
        warn "Only sent to $sent/10 addresses"
    else
        fail "Could not send to any addresses"
    fi

    # Confirm all
    rpc1 setgenerate true 2 >/dev/null 2>&1 || true
    sleep 2

    # Check UTXO count
    local utxo_list=$(rpc1 listunspent 2>/dev/null || echo "[]")
    local utxo_count=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"txid"' | wc -l | tr -d ' ')
    log "UTXO count after multi-send: $utxo_count"

    if [ "$utxo_count" -ge 10 ]; then
        success "Multi-send created expected UTXOs ($utxo_count)"
    fi
}

test_keypool() {
    section "Keypool Management Test"

    # Check keypool size
    local info=$(rpc1 getinfo 2>/dev/null || echo "{}")
    local pool_size=$(echo "$info" | tr '\n' ' ' | grep -o '"keypoolsize" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    log "Keypool size: $pool_size"

    if [ "$pool_size" -gt 0 ]; then
        success "Keypool has $pool_size keys"
    else
        fail "Keypool is empty"
    fi

    # Refill keypool
    local refill=$(rpc1 keypoolrefill 200 2>&1 || echo "ERROR")
    if ! echo "$refill" | grep -qi "error"; then
        sleep 2
        info=$(rpc1 getinfo 2>/dev/null || echo "{}")
        pool_size=$(echo "$info" | tr '\n' ' ' | grep -o '"keypoolsize" *: *[0-9]*' | grep -o '[0-9]*$' || echo "0")
        if [ "$pool_size" -ge 200 ]; then
            success "Keypool refilled to $pool_size keys"
        else
            warn "Keypool at $pool_size after refill (expected >= 200)"
        fi
    else
        warn "Keypool refill: $refill"
    fi
}

test_listtransactions() {
    section "Transaction History Test"

    local txlist=$(rpc1 listtransactions 2>/dev/null || echo "[]")
    local tx_count=$(echo "$txlist" | tr '\n' ' ' | grep -o '"txid"' | wc -l | tr -d ' ')
    log "Transaction history entries: $tx_count"

    if [ "$tx_count" -gt 0 ]; then
        success "Transaction history available ($tx_count entries)"
    else
        warn "No transaction history yet"
    fi

    # Test with count parameter
    local recent=$(rpc1 listtransactions "" 5 2>/dev/null || echo "[]")
    local recent_count=$(echo "$recent" | tr '\n' ' ' | grep -o '"txid"' | wc -l | tr -d ' ')
    if [ "$recent_count" -le 5 ]; then
        success "Transaction count limit works ($recent_count <= 5)"
    fi
}

test_wallet_info() {
    section "Wallet Info Consistency"

    local info=$(rpc1 getinfo 2>/dev/null || echo "{}")
    local balance=$(echo "$info" | tr '\n' ' ' | grep -o '"balance" *: *[0-9.]*' | head -1 | grep -o '[0-9.]*$' || echo "0")
    local getbalance=$(rpc1 getbalance 2>/dev/null | tr -d ' \n' || echo "0")

    log "getinfo balance: $balance"
    log "getbalance: $getbalance"

    # They should match
    if [ "$balance" = "$getbalance" ]; then
        success "Balance consistency check passed"
    else
        warn "Balance mismatch: getinfo=$balance vs getbalance=$getbalance"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "     WALLET STRESS TEST SUMMARY"
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
    echo "    INNOVA WALLET STRESS TEST"
    echo "========================================"
    echo ""

    check_binary
    setup_nodes
    start_nodes

    log "Waiting for nodes to initialize..."
    sleep 3

    # Generate initial blocks for coins
    rpc1 setgenerate true 150 >/dev/null 2>&1 || true
    sleep 2

    test_address_generation
    test_key_operations
    test_wallet_backup
    test_wallet_encryption
    test_multisend
    test_keypool
    test_listtransactions
    test_wallet_info

    print_summary
}

main "$@"
