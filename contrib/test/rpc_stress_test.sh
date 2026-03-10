#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova RPC Stress Test Script
# Tests comprehensive RPC interface: info, network, mining, wallet, raw RPCs
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

TEST_DIR="/tmp/innova_rpc_stress"
NODE_DIR="$TEST_DIR/node"
NODE_PORT=24445
NODE_RPC=24500

PASSED=0
FAILED=0
WARNINGS=0

log() { echo -e "${BLUE}[RPC-TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*rpc_stress" 2>/dev/null || true
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
    log "Setting up RPC test node..."
    rm -rf "$TEST_DIR"
    mkdir -p "$NODE_DIR"

    cat > "$NODE_DIR/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=rpctest
rpcpassword=rpcpass
rpcport=$NODE_RPC
port=$NODE_PORT
listen=1
idns=0
listenonion=0
dnsseed=0
staking=0
debug=1
printtoconsole=0
EOF

    log "Config file created"
}

start_node() {
    log "Starting node..."
    "$INNOVAD" -datadir="$NODE_DIR" -regtest &
    sleep 4
    log "Node started"
}

rpc() {
    "$INNOVAD" -datadir="$NODE_DIR" -rpcuser=rpctest -rpcpassword=rpcpass -rpcport=$NODE_RPC "$@" 2>/dev/null
}

rpc_err() {
    "$INNOVAD" -datadir="$NODE_DIR" -rpcuser=rpctest -rpcpassword=rpcpass -rpcport=$NODE_RPC "$@" 2>&1
}

# TEST SUITES
test_info_rpcs() {
    section "Information RPCs"

    local info=$(rpc getinfo || echo "")
    if echo "$info" | tr '\n' ' ' | grep -q '"version"'; then
        success "getinfo returns valid data"
    else
        fail "getinfo failed"
    fi

    local bci=$(rpc getblockchaininfo 2>/dev/null || echo "")
    if [ -n "$bci" ] && echo "$bci" | tr '\n' ' ' | grep -q '"chain"\|"blocks"'; then
        success "getblockchaininfo available"
    else
        log "getblockchaininfo not available (older codebase)"
    fi

    local mining=$(rpc getmininginfo || echo "")
    if echo "$mining" | tr '\n' ' ' | grep -q '"blocks"\|"difficulty"'; then
        success "getmininginfo returns valid data"
    else
        fail "getmininginfo failed"
    fi

    local diff=$(rpc getdifficulty || echo "")
    if [ -n "$diff" ] && echo "$diff" | tr '\n' ' ' | grep -q '"proof-of-work"\|[0-9]'; then
        success "getdifficulty returns value"
    else
        warn "getdifficulty result: $diff"
    fi

    local best=$(rpc getbestblockhash || echo "")
    if [ -n "$best" ] && [ ${#best} -ge 60 ]; then
        success "getbestblockhash returns hash (${best:0:16}...)"
    else
        fail "getbestblockhash failed"
    fi

    local count=$(rpc getblockcount || echo "")
    if [ -n "$count" ] && echo "$count" | grep -q '^[0-9]'; then
        success "getblockcount returns: $count"
    else
        fail "getblockcount failed"
    fi
}

test_network_rpcs() {
    section "Network RPCs"

    local conns=$(rpc getconnectioncount || echo "")
    if echo "$conns" | grep -q '^[0-9]'; then
        success "getconnectioncount: $conns"
    else
        fail "getconnectioncount failed"
    fi

    local peers=$(rpc getpeerinfo || echo "")
    if echo "$peers" | tr '\n' ' ' | grep -q '^\['; then
        success "getpeerinfo returns array"
    else
        fail "getpeerinfo failed"
    fi

    local totals=$(rpc getnettotals || echo "")
    if echo "$totals" | tr '\n' ' ' | grep -q '"totalbytesrecv"\|"totalbytesSent"'; then
        success "getnettotals returns data"
    else
        log "getnettotals response: $(echo "$totals" | head -3)"
        warn "getnettotals format unclear"
    fi

    local netinfo=$(rpc getnetworkinfo 2>/dev/null || echo "")
    if [ -n "$netinfo" ] && echo "$netinfo" | tr '\n' ' ' | grep -q '"version"\|"subversion"'; then
        success "getnetworkinfo available"
    else
        log "getnetworkinfo not available"
    fi
}

test_wallet_rpcs() {
    section "Wallet RPCs"

    local balance=$(rpc getbalance || echo "")
    if echo "$balance" | grep -q '^[0-9]'; then
        success "getbalance: $balance"
    else
        fail "getbalance failed"
    fi

    local addr=$(rpc getnewaddress || echo "")
    if [ -n "$addr" ] && [ ${#addr} -ge 20 ]; then
        success "getnewaddress: ${addr:0:16}..."
    else
        fail "getnewaddress failed"
    fi

    local valid=$(rpc validateaddress "$addr" || echo "{}")
    if echo "$valid" | tr '\n' ' ' | grep -q '"isvalid" *: *true'; then
        success "validateaddress confirms valid"
    else
        fail "validateaddress failed for generated address"
    fi

    local account=$(rpc getaccount "$addr" 2>/dev/null || echo "ERROR")
    if ! echo "$account" | grep -qi "error"; then
        success "getaccount works"
    else
        log "getaccount not available (may be deprecated)"
    fi

    local utxos=$(rpc listunspent || echo "[]")
    if echo "$utxos" | tr '\n' ' ' | grep -q '^\['; then
        success "listunspent returns array"
    else
        fail "listunspent failed"
    fi

    local txs=$(rpc listtransactions || echo "[]")
    if echo "$txs" | tr '\n' ' ' | grep -q '^\['; then
        success "listtransactions returns array"
    else
        fail "listtransactions failed"
    fi

    local winfo=$(rpc getwalletinfo 2>/dev/null || echo "")
    if [ -n "$winfo" ] && echo "$winfo" | tr '\n' ' ' | grep -q '"walletname"\|"balance"'; then
        success "getwalletinfo available"
    else
        log "getwalletinfo not available"
    fi

    local privkey=$(rpc dumpprivkey "$addr" || echo "")
    if [ -n "$privkey" ] && [ ${#privkey} -ge 40 ]; then
        success "dumpprivkey works (${#privkey} chars)"
    else
        fail "dumpprivkey failed"
    fi
}

test_block_rpcs() {
    section "Block RPCs"

    rpc setgenerate true 100 >/dev/null 2>&1 || true
    sleep 2

    local hash=$(rpc getblockhash 1 || echo "")
    if [ -n "$hash" ] && [ ${#hash} -ge 60 ]; then
        success "getblockhash(1): ${hash:0:16}..."
    else
        fail "getblockhash failed"
        return 0
    fi

    local block=$(rpc getblock "$hash" || echo "")
    if echo "$block" | tr '\n' ' ' | grep -q '"hash".*"height"'; then
        success "getblock returns verbose data"
    else
        fail "getblock verbose failed"
    fi

    local rawhex=$(rpc getblock "$hash" false || echo "")
    if [ -n "$rawhex" ] && echo "$rawhex" | grep -q '^[0-9a-f]'; then
        success "getblock raw hex: ${#rawhex} chars"
    else
        warn "getblock raw hex format unclear"
    fi

    local header=$(rpc getblockheader "$hash" 2>/dev/null || echo "")
    if [ -n "$header" ] && echo "$header" | tr '\n' ' ' | grep -q '"hash"'; then
        success "getblockheader available"
    else
        log "getblockheader not available"
    fi

    local block1_tx=$(echo "$block" | tr '\n' ' ' | grep -o '"tx" *: *\[.*\]' | grep -o '"[a-f0-9]\{64\}"' | head -1 | tr -d '"')
    if [ -n "$block1_tx" ]; then
        local txout=$(rpc gettxout "$block1_tx" 0 2>/dev/null || echo "")
        if [ -n "$txout" ]; then
            success "gettxout returns data"
        else
            log "gettxout returned empty (spent output)"
        fi
    fi
}

test_mining_rpcs() {
    section "Mining RPCs"

    local before=$(rpc getblockcount || echo "0")
    rpc setgenerate true 5 >/dev/null 2>&1 || true
    sleep 2
    local after=$(rpc getblockcount || echo "0")

    if [ "$after" -gt "$before" ]; then
        success "setgenerate mined $((after - before)) blocks"
    else
        fail "setgenerate did not produce blocks"
    fi

    local minfo=$(rpc getmininginfo || echo "")
    if echo "$minfo" | tr '\n' ' ' | grep -q '"blocks"'; then
        success "getmininginfo shows block count"
    fi

    local sinfo=$(rpc getstakinginfo 2>/dev/null || echo "")
    if echo "$sinfo" | tr '\n' ' ' | grep -q '"staking"\|"enabled"'; then
        success "getstakinginfo available"
    else
        log "getstakinginfo not available"
    fi
}

test_raw_tx_rpcs() {
    section "Raw Transaction RPCs"

    rpc setgenerate true 20 >/dev/null 2>&1 || true
    sleep 1

    local utxo_list=$(rpc listunspent 1 9999999 || echo "[]")
    local txid=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"txid" *: *"[a-f0-9]\{64\}"' | head -1 | grep -o '[a-f0-9]\{64\}')
    local vout=$(echo "$utxo_list" | tr '\n' ' ' | grep -o '"vout" *: *[0-9]*' | head -1 | grep -o '[0-9]*$')

    if [ -z "$txid" ]; then
        warn "No UTXOs available for raw tx tests"
        return 0
    fi

    local addr=$(rpc getnewaddress || echo "")

    local rawtx=$(rpc createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$addr\":49.99}" 2>/dev/null || echo "")
    if [ -n "$rawtx" ] && echo "$rawtx" | grep -q '^[0-9a-f]'; then
        success "createrawtransaction: ${#rawtx} hex chars"
    else
        fail "createrawtransaction failed"
        return 0
    fi

    local decoded=$(rpc decoderawtransaction "$rawtx" || echo "")
    if echo "$decoded" | tr '\n' ' ' | grep -q '"txid".*"vout"'; then
        success "decoderawtransaction works"
    else
        fail "decoderawtransaction failed"
    fi

    local signed=$(rpc signrawtransaction "$rawtx" || echo "")
    if echo "$signed" | tr '\n' ' ' | grep -q '"complete" *: *true'; then
        success "signrawtransaction completed"
    else
        warn "signrawtransaction incomplete"
    fi

    local known_hash=$(rpc getblockhash 1 || echo "")
    local known_block=$(rpc getblock "$known_hash" || echo "{}")
    local known_txid=$(echo "$known_block" | tr '\n' ' ' | grep -o '"tx" *: *\[.*\]' | grep -o '"[a-f0-9]\{64\}"' | head -1 | tr -d '"')

    if [ -n "$known_txid" ]; then
        local rawtxdata=$(rpc getrawtransaction "$known_txid" 2>/dev/null || echo "")
        if [ -n "$rawtxdata" ]; then
            success "getrawtransaction returns data"
        else
            log "getrawtransaction requires -txindex"
        fi

        local rawtxverbose=$(rpc getrawtransaction "$known_txid" 1 2>/dev/null || echo "")
        if echo "$rawtxverbose" | tr '\n' ' ' | grep -q '"txid"'; then
            success "getrawtransaction verbose works"
        else
            log "getrawtransaction verbose not available"
        fi
    fi
}

test_mempool_rpcs() {
    section "Mempool RPCs"

    local mempool=$(rpc getrawmempool || echo "[]")
    if echo "$mempool" | tr '\n' ' ' | grep -q '^\['; then
        success "getrawmempool returns array"
    else
        fail "getrawmempool failed"
    fi

    local addr=$(rpc getnewaddress || echo "")
    local txid=$(rpc sendtoaddress "$addr" 10.0 2>/dev/null || echo "")

    if [ -n "$txid" ] && [ ${#txid} -eq 64 ]; then
        local verbose_pool=$(rpc getrawmempool true 2>/dev/null || echo "{}")
        if echo "$verbose_pool" | tr '\n' ' ' | grep -q '"size"\|"fee"\|"time"'; then
            success "getrawmempool verbose returns details"
        else
            log "Verbose mempool data format unclear"
        fi

        rpc setgenerate true 1 >/dev/null 2>&1 || true
        sleep 1
    fi
}

test_rapid_rpc_calls() {
    section "Rapid RPC Call Stress"

    local count=0
    local start_time=$(date +%s)

    for i in $(seq 1 50); do
        if rpc getblockcount >/dev/null 2>&1; then
            ((count++)) || true
        fi
    done

    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    if [ $count -ge 45 ]; then
        success "Rapid RPC: $count/50 calls succeeded (${elapsed}s)"
    elif [ $count -gt 0 ]; then
        warn "Rapid RPC: only $count/50 succeeded"
    else
        fail "Rapid RPC: all calls failed"
    fi

    local mixed=0
    for i in $(seq 1 20); do
        rpc getblockcount >/dev/null 2>&1 && ((mixed++)) || true
        rpc getbestblockhash >/dev/null 2>&1 && ((mixed++)) || true
        rpc getbalance >/dev/null 2>&1 && ((mixed++)) || true
    done

    if [ $mixed -ge 50 ]; then
        success "Mixed rapid RPC: $mixed/60 calls succeeded"
    elif [ $mixed -gt 0 ]; then
        warn "Mixed rapid RPC: only $mixed/60 succeeded"
    else
        fail "Mixed rapid RPC: all calls failed"
    fi
}

test_error_handling() {
    section "RPC Error Handling"

    local result=$(rpc_err nonexistentmethod 2>&1 || echo "")
    if echo "$result" | grep -qi "error\|not found\|unknown"; then
        success "Invalid method correctly rejected"
    else
        warn "Invalid method response unclear: $result"
    fi

    result=$(rpc_err getblockhash -1 2>&1 || echo "")
    if echo "$result" | grep -qi "error\|out of range\|invalid"; then
        success "Invalid block height correctly rejected"
    else
        warn "Invalid block height response: $result"
    fi

    result=$(rpc validateaddress "NOTANADDRESS" || echo "{}")
    if echo "$result" | tr '\n' ' ' | grep -q '"isvalid" *: *false'; then
        success "Invalid address correctly identified"
    else
        warn "Invalid address validation unclear"
    fi

    result=$(rpc_err sendtoaddress "BADADDR" 1.0 2>&1 || echo "")
    if echo "$result" | grep -qi "error\|invalid"; then
        success "Send to invalid address rejected"
    else
        warn "Send to invalid address response unclear"
    fi
}

test_cold_staking_rpcs() {
    section "Cold Staking RPCs"

    local csinfo=$(rpc getcoldstakinginfo 2>/dev/null || echo "")
    if echo "$csinfo" | tr '\n' ' ' | grep -q '"enabled"\|"cold_staking"'; then
        success "getcoldstakinginfo available"
    else
        log "getcoldstakinginfo not available or different format"
    fi

    local saddr=$(rpc getnewstakingaddress 2>/dev/null || echo "")
    if [ -n "$saddr" ] && [ ${#saddr} -ge 20 ]; then
        success "getnewstakingaddress: ${saddr:0:16}..."
    else
        log "getnewstakingaddress not available"
    fi

    local cutxos=$(rpc listcoldutxos 2>/dev/null || echo "")
    if echo "$cutxos" | tr '\n' ' ' | grep -q '^\['; then
        success "listcoldutxos returns array"
    else
        log "listcoldutxos not available"
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo "      RPC STRESS TEST SUMMARY"
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
    echo "     INNOVA RPC STRESS TEST"
    echo "========================================"
    echo ""

    check_binary
    setup_node
    start_node

    test_info_rpcs
    test_network_rpcs
    test_wallet_rpcs
    test_block_rpcs
    test_mining_rpcs
    test_raw_tx_rpcs
    test_mempool_rpcs
    test_rapid_rpc_calls
    test_error_handling
    test_cold_staking_rpcs

    print_summary
}

main "$@"
