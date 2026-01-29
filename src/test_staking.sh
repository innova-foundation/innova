#!/bin/bash
#
# Innova Staking Test Script
# Tests staking functionality in both normal and SPV modes
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATADIR="${DATADIR:-$HOME/.innova-test}"
DAEMON="${SCRIPT_DIR}/innovad"
CLI="${SCRIPT_DIR}/innova-cli"
RPC_PORT=15531
TESTNET=1

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    $CLI -datadir="$DATADIR" -testnet stop 2>/dev/null || true
    sleep 2
    pkill -f "innovad.*$DATADIR" 2>/dev/null || true
}

trap cleanup EXIT

check_requirements() {
    log_info "Checking requirements..."

    if [ ! -x "$DAEMON" ]; then
        log_error "innovad not found or not executable at $DAEMON"
        exit 1
    fi

    if [ ! -x "$CLI" ]; then
        log_error "innova-cli not found or not executable at $CLI"
        exit 1
    fi

    log_ok "Requirements met"
}

setup_datadir() {
    log_info "Setting up test data directory: $DATADIR"

    mkdir -p "$DATADIR"

    cat > "$DATADIR/innova.conf" << EOF
testnet=1
server=1
rpcuser=innovatest
rpcpassword=testpass123
rpcport=$RPC_PORT
rpcallowip=127.0.0.1
listen=1
staking=1
debug=1
printstakemodifier=0
EOF

    log_ok "Data directory configured"
}

start_daemon() {
    local extra_args="$1"
    log_info "Starting innovad with args: $extra_args"

    $DAEMON -datadir="$DATADIR" -testnet $extra_args &

    local attempts=0
    while [ $attempts -lt 30 ]; do
        if $CLI -datadir="$DATADIR" -testnet getinfo &>/dev/null; then
            log_ok "Daemon started successfully"
            return 0
        fi
        sleep 1
        ((attempts++)) || true
    done

    log_error "Daemon failed to start"
    return 1
}

stop_daemon() {
    log_info "Stopping daemon..."
    $CLI -datadir="$DATADIR" -testnet stop 2>/dev/null || true
    sleep 3
}

run_cli() {
    $CLI -datadir="$DATADIR" -testnet "$@"
}

test_basic_info() {
    log_info "=== Testing Basic Node Info ==="

    local info=$(run_cli getinfo)
    echo "$info" | head -20

    local blocks=$(echo "$info" | grep '"blocks"' | grep -o '[0-9]*')
    local connections=$(echo "$info" | grep '"connections"' | grep -o '[0-9]*')

    log_ok "Current blocks: $blocks"
    log_ok "Connections: $connections"
}

test_staking_info() {
    log_info "=== Testing Staking Info ==="

    local staking_info=$(run_cli getstakinginfo 2>/dev/null || echo "{}")
    echo "$staking_info"

    local staking=$(echo "$staking_info" | grep '"staking"' | grep -o 'true\|false')
    local enabled=$(echo "$staking_info" | grep '"enabled"' | grep -o 'true\|false')

    if [ "$enabled" == "true" ]; then
        log_ok "Staking is enabled"
    else
        log_warn "Staking is not enabled (may need mature coins)"
    fi

    if [ "$staking" == "true" ]; then
        log_ok "Currently staking"
    else
        log_warn "Not currently staking (may need unlocked wallet with mature coins)"
    fi
}

test_wallet_status() {
    log_info "=== Testing Wallet Status ==="

    local balance=$(run_cli getbalance 2>/dev/null || echo "0")
    log_info "Balance: $balance INN"

    local unconfirmed=$(run_cli getunconfirmedbalance 2>/dev/null || echo "0")
    log_info "Unconfirmed: $unconfirmed INN"

    local stakeable=$(run_cli liststakeinputs 2>/dev/null | grep -c "txid" || echo "0")
    log_info "Stakeable UTXOs: $stakeable"
}

test_spv_staking() {
    log_info "=== Testing SPV Staking Mode ==="

    stop_daemon
    sleep 2

    start_daemon "-hybridspv"
    sleep 5

    local info=$(run_cli getinfo)
    local spv_mode=$(echo "$info" | grep -i "spv" || echo "not found")

    log_info "SPV Info: $spv_mode"

    local staking_info=$(run_cli getstakinginfo 2>/dev/null || echo "{}")
    echo "$staking_info"

    log_info "Checking SPV UTXO cache..."
    if [ -f "$DATADIR/testnet/spvutxos.dat" ]; then
        local cache_size=$(ls -lh "$DATADIR/testnet/spvutxos.dat" | awk '{print $5}')
        log_ok "SPV UTXO cache exists: $cache_size"
    else
        log_warn "SPV UTXO cache not found (normal if no stakeable UTXOs)"
    fi
}

test_stake_generation() {
    log_info "=== Testing Stake Generation (requires mature coins) ==="

    local stakeable=$(run_cli liststakeinputs 2>/dev/null | grep -c "txid" || echo "0")

    if [ "$stakeable" -eq 0 ]; then
        log_warn "No stakeable inputs available"
        log_info "To test stake generation, you need:"
        log_info "  1. Testnet coins in your wallet"
        log_info "  2. Coins must be mature (10+ confirmations)"
        log_info "  3. Wallet must be unlocked for staking"
        return 0
    fi

    log_info "Found $stakeable stakeable inputs"

    local encrypted=$(run_cli getinfo | grep '"unlocked_until"' || echo "")
    if [ -n "$encrypted" ]; then
        log_info "Wallet is encrypted, checking unlock status..."
        local unlock_time=$(echo "$encrypted" | grep -o '[0-9]*')
        if [ "$unlock_time" -eq 0 ]; then
            log_warn "Wallet is locked. Use: innova-cli walletpassphrase <pass> <timeout> true"
        else
            log_ok "Wallet is unlocked for staking"
        fi
    fi

    log_info "Monitoring stake attempts for 30 seconds..."
    for i in {1..6}; do
        local staking_info=$(run_cli getstakinginfo 2>/dev/null)
        local expected_time=$(echo "$staking_info" | grep '"expectedtime"' | grep -o '[0-9]*')
        if [ -n "$expected_time" ] && [ "$expected_time" -gt 0 ]; then
            log_info "Expected time to stake: ${expected_time}s"
        fi
        sleep 5
    done
}

generate_report() {
    log_info "=== Staking Test Report ==="

    echo ""
    echo "======================================"
    echo "       INNOVA STAKING TEST REPORT"
    echo "======================================"
    echo ""
    echo "Test Date: $(date)"
    echo "Data Directory: $DATADIR"
    echo ""

    local info=$(run_cli getinfo 2>/dev/null || echo "{}")
    local blocks=$(echo "$info" | grep '"blocks"' | grep -o '[0-9]*' || echo "N/A")
    local version=$(echo "$info" | grep '"version"' | grep -o '[0-9]*' || echo "N/A")

    echo "Node Version: $version"
    echo "Block Height: $blocks"
    echo ""

    local staking=$(run_cli getstakinginfo 2>/dev/null || echo "{}")
    echo "Staking Status:"
    echo "$staking" | grep -E '"staking"|"enabled"|"difficulty"|"weight"' | sed 's/^/  /'
    echo ""

    echo "======================================"
}

main() {
    echo ""
    echo "============================================"
    echo "     INNOVA STAKING TEST SUITE"
    echo "============================================"
    echo ""

    check_requirements
    setup_datadir

    log_info "Starting normal mode tests..."
    start_daemon ""
    sleep 5

    test_basic_info
    test_wallet_status
    test_staking_info
    test_stake_generation

    test_spv_staking

    generate_report

    log_ok "All tests completed!"
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
