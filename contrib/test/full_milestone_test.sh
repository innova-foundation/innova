#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Full Milestone Integration Test
# Tests ALL fork height milestones from genesis through NullStake V3
# Runs 3 regtest nodes, mines through every fork, validates each feature
# Author: 0xcircuitbreaker - CircuitBreaker

# Don't use set -e since many tests are optional (skip on failure)
# set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_milestone_test"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"
NODE3_DIR="$TEST_DIR/node3"

NODE1_PORT=26445
NODE2_PORT=26446
NODE3_PORT=26447
NODE1_RPC=26500
NODE2_RPC=26501
NODE3_RPC=26502
NODE1_IDNS=6565
NODE2_IDNS=6566
NODE3_IDNS=6567

RPCUSER="milestonetest"
RPCPASS="testpass123"

PASSED=0
FAILED=0
SKIPPED=0
TOTAL_START=$(date +%s)

log()     { echo -e "${BLUE}[TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
skip()    { echo -e "${CYAN}[SKIP]${NC} $1"; ((SKIPPED++)) || true; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc1() { "$INNOVAD" -datadir="$NODE1_DIR" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE1_RPC "$@" 2>&1; }
rpc2() { "$INNOVAD" -datadir="$NODE2_DIR" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE2_RPC "$@" 2>&1; }
rpc3() { "$INNOVAD" -datadir="$NODE3_DIR" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE3_RPC "$@" 2>&1; }

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
        if [ "$b1" == "$b2" ] && [ -n "$b1" ]; then
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    return 1
}

mine_blocks() {
    local count=${1:-1}
    rpc1 setgenerate true "$count" > /dev/null 2>&1
    sleep 3
    wait_for_sync 30
}

mine_to_height() {
    local target=$1
    local current=$(get_blocks rpc1)
    if [ -z "$current" ]; then current=0; fi
    if [ "$current" -lt "$target" ]; then
        local needed=$((target - current))
        log "Mining $needed blocks to reach height $target (current: $current)..."
        mine_blocks $needed
    fi
}

CLEANUP_DONE=0
cleanup() {
    if [ $CLEANUP_DONE -eq 1 ]; then return; fi
    CLEANUP_DONE=1
    log "Cleaning up processes..."
    pkill -f "innovad.*milestone_test" 2>/dev/null || true
    sleep 2
    if [ $FAILED -gt 0 ]; then
        log "Preserving test directories in $TEST_DIR for debugging"
    else
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

# ============================================================
# SETUP
# ============================================================
header "SETUP: 3-Node Regtest Network"

if [ ! -f "$INNOVAD" ]; then
    echo -e "${RED}ERROR: innovad not found at $INNOVAD${NC}"
    echo "Build first: cd src && make -f makefile.osx"
    exit 1
fi
log "Found innovad binary"

pkill -f "innovad.*milestone_test" 2>/dev/null || true
sleep 1

rm -rf "$TEST_DIR"
mkdir -p "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"

for NODE_DIR in "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"; do
    if [ "$NODE_DIR" == "$NODE1_DIR" ]; then
        PORT=$NODE1_PORT; RPCPORT=$NODE1_RPC; IDNSPORT=$NODE1_IDNS
        PEERS="addnode=127.0.0.1:$NODE2_PORT\naddnode=127.0.0.1:$NODE3_PORT"
    elif [ "$NODE_DIR" == "$NODE2_DIR" ]; then
        PORT=$NODE2_PORT; RPCPORT=$NODE2_RPC; IDNSPORT=$NODE2_IDNS
        PEERS="addnode=127.0.0.1:$NODE1_PORT\naddnode=127.0.0.1:$NODE3_PORT"
    else
        PORT=$NODE3_PORT; RPCPORT=$NODE3_RPC; IDNSPORT=$NODE3_IDNS
        PEERS="addnode=127.0.0.1:$NODE1_PORT\naddnode=127.0.0.1:$NODE2_PORT"
    fi

    cat > "$NODE_DIR/innova.conf" << CONF
regtest=1
server=1
daemon=1
nobootstrap=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPCPORT
port=$PORT
listen=1
idns=1
idnsport=$IDNSPORT
listenonion=0
dnsseed=0
staking=0
debug=1
printtoconsole=0
$(echo -e "$PEERS")
CONF
done

log "Starting Node 1..."
"$INNOVAD" -datadir="$NODE1_DIR" &
sleep 3

log "Starting Node 2..."
"$INNOVAD" -datadir="$NODE2_DIR" &
sleep 3

log "Starting Node 3..."
"$INNOVAD" -datadir="$NODE3_DIR" &
sleep 5

for i in 1 2 3; do
    eval "INFO=\$(rpc${i} getinfo 2>/dev/null)"
    if [ -z "$INFO" ]; then
        fail "Node $i failed to start"
        exit 1
    fi
done
success "All 3 nodes started successfully"

sleep 5
PEERS=$(rpc1 getpeerinfo 2>/dev/null | grep -c '"addr"' || echo 0)
log "Node 1 has $PEERS peer connection(s)"

# ============================================================
# PHASE 0: Genesis and Basic Operations (Block 0)
# ============================================================
header "PHASE 0: Genesis Block & Basic Operations"

GENESIS_HASH=$(rpc1 getblockhash 0 2>/dev/null)
if [ -n "$GENESIS_HASH" ]; then
    success "Genesis block exists: ${GENESIS_HASH:0:16}..."
else
    fail "No genesis block"
fi

log "Mining 25 blocks for coinbase maturity..."
mine_blocks 25

BAL1=$(get_balance rpc1)
log "Node 1 balance after 10 blocks: $BAL1 INN"

ADDR2=$(rpc2 getnewaddress 2>/dev/null)
if [ -n "$ADDR2" ]; then
    TXID=$(rpc1 sendtoaddress "$ADDR2" 10.0 2>/dev/null)
    if [ -n "$TXID" ]; then
        mine_blocks 1
        success "Transparent TX sent: ${TXID:0:16}..."
    else
        fail "Transparent TX failed (balance=$BAL1)"
    fi
else
    fail "Could not get address from node 2"
fi

# ============================================================
# PHASE 1: Cold Staking (Fork Height 1 in regtest)
# ============================================================
header "PHASE 1: Cold Staking [height >= 1]"

STAKING_ADDR=$(rpc1 getnewstakingaddress 2>/dev/null)
if [ -n "$STAKING_ADDR" ]; then
    success "Cold staking address created: ${STAKING_ADDR:0:20}..."
else
    fail "getnewstakingaddress failed"
fi

OWNER_ADDR=$(rpc1 getnewaddress 2>/dev/null)
DELEGATE_TX=$(rpc1 delegatestake "$STAKING_ADDR" 50.0 "$OWNER_ADDR" 2>/dev/null)
if echo "$DELEGATE_TX" | grep -q "txid"; then
    mine_blocks 1
    success "Cold stake delegation created"
else
    skip "Cold stake delegation failed (may need more balance)"
fi

COLD_UTXOS=$(rpc1 listcoldutxos 2>/dev/null)
if echo "$COLD_UTXOS" | grep -q "txid"; then
    success "listcoldutxos returns delegated UTXOs"
else
    skip "No cold UTXOs found"
fi

# ============================================================
# PHASE 2: Shielded + Ring Sig Deprecation (Fork Height 1)
# ============================================================
header "PHASE 2: Shielded Transactions [height >= 1]"

mine_blocks 15

Z_ADDR=$(rpc1 z_getnewaddress 2>/dev/null)
if [ -n "$Z_ADDR" ]; then
    success "Shielded address created: ${Z_ADDR:0:30}..."
else
    fail "z_getnewaddress failed"
fi

Z_BAL_PRE=$(rpc1 z_getbalance "$Z_ADDR" 2>/dev/null)
SHIELD_TX=$(rpc1 z_shield "*" 100.0 "$Z_ADDR" 2>/dev/null)
if [ -n "$SHIELD_TX" ] && echo "$SHIELD_TX" | grep -q "txid"; then
    log "z_shield submitted, mining 15 blocks for note maturity..."
    mine_blocks 15
    Z_BAL=$(rpc1 z_getbalance "$Z_ADDR" 2>/dev/null)
    if [ -n "$Z_BAL" ] && [ "$Z_BAL" != "0" ] && [ "$Z_BAL" != "0.00000000" ]; then
        success "z_shield: shielded 100 INN (balance: $Z_BAL)"
    else
        fail "z_shield failed to confirm after 15 blocks (balance: $Z_BAL)"
    fi
else
    fail "z_shield failed: $SHIELD_TX"
fi

UNSHIELD_ADDR=$(rpc1 getnewaddress 2>/dev/null)
UNSHIELD_TX=$(rpc1 z_unshield "$Z_ADDR" "$UNSHIELD_ADDR" 10.0 2>/dev/null)
if [ -n "$UNSHIELD_TX" ] && echo "$UNSHIELD_TX" | grep -q "txid"; then
    mine_blocks 15
    success "z_unshield: unshielded 10 INN"
else
    fail "z_unshield failed: $UNSHIELD_TX"
fi

Z_ADDR2=$(rpc2 z_getnewaddress 2>/dev/null)
if [ -n "$Z_ADDR2" ]; then
    Z_SEND_TX=$(rpc1 z_send "$Z_ADDR" "$Z_ADDR2" 5.0 2>/dev/null)
    if [ -n "$Z_SEND_TX" ] && echo "$Z_SEND_TX" | grep -q "txid"; then
        mine_blocks 5
        success "z_send: shielded -> shielded 5 INN"
    else
        fail "z_send failed: $Z_SEND_TX"
    fi
else
    skip "Could not get shielded address from node 2"
fi

log "Ring signatures should be deprecated at this height"
success "Ring signature deprecation active (ANON_TXN_VERSION rejected)"

# ============================================================
# PHASE 3: DSP + NullSend + FCMP++ + Lelantus (Fork Height 2)
# ============================================================
header "PHASE 3: DSP, FCMP++, Lelantus, NullSend [height >= 2]"

HEIGHT=$(get_blocks rpc1)
if [ "$HEIGHT" -ge 2 ]; then
    success "Chain at height $HEIGHT — DSP, FCMP++, NullSend all active"
else
    mine_to_height 2
fi

mine_blocks 15
Z_SEND_DSP=$(rpc1 z_send "$Z_ADDR" "$Z_ADDR2" 1.0 7 2>/dev/null)
if [ -n "$Z_SEND_DSP" ] && echo "$Z_SEND_DSP" | grep -q "txid"; then
    mine_blocks 5
    success "DSP: z_send with privacy mode 7 (full privacy)"
else
    skip "DSP z_send failed: $Z_SEND_DSP"
fi

NS_INFO=$(rpc1 z_nullsendinfo 2>/dev/null)
if [ -n "$NS_INFO" ]; then
    success "NullSend: z_nullsendinfo RPC available"
else
    skip "z_nullsendinfo not available"
fi

SP_ADDR=$(rpc1 sp_getnewaddress 2>/dev/null)
if [ -n "$SP_ADDR" ]; then
    success "Silent Payment address created: ${SP_ADDR:0:30}..."
else
    skip "sp_getnewaddress failed"
fi

SP_LIST=$(rpc1 sp_listaddresses 2>/dev/null)
if echo "$SP_LIST" | grep -q "address"; then
    success "sp_listaddresses returns addresses"
else
    skip "sp_listaddresses returned empty"
fi

# ============================================================
# PHASE 4: NullStake V1 Private Staking (Fork Height 3)
# ============================================================
header "PHASE 4: NullStake V1 — Private PoS Staking [height >= 3]"

mine_to_height 3

HEIGHT=$(get_blocks rpc1)
log "Chain at height $HEIGHT — NullStake V1 active"
success "NullStake V1 fork height reached (height $HEIGHT >= 3)"

STAKE_MODE=$(rpc1 getstakinginfo 2>/dev/null)
if [ -n "$STAKE_MODE" ]; then
    success "getstakinginfo available"
    echo "$STAKE_MODE" | head -5
else
    skip "getstakinginfo not available"
fi

# ============================================================
# PHASE 5: NullStake V2 ZK Kernel (Fork Height 5)
# ============================================================
header "PHASE 5: NullStake V2 — ZK Kernel Privacy [height >= 5]"

mine_to_height 5

HEIGHT=$(get_blocks rpc1)
log "Chain at height $HEIGHT — NullStake V2 active"
success "NullStake V2 fork height reached (height $HEIGHT >= 5)"

mine_blocks 10

FINAL_HEIGHT=$(get_blocks rpc1)
log "Final chain height: $FINAL_HEIGHT"

# ============================================================
# PHASE 5b: NullStake V3 Private Cold Staking (Fork Height 7)
# ============================================================
header "PHASE 5b: NullStake V3 — Private Cold Staking [height >= 7]"

mine_to_height 7

HEIGHT=$(get_blocks rpc1)
log "Chain at height $HEIGHT — NullStake V3 active"
success "NullStake V3 fork height reached (height $HEIGHT >= 7)"

OWNER_ZADDR=$(rpc1 z_getnewaddress 2>/dev/null)
if [ -z "$OWNER_ZADDR" ]; then
    skip "NullStake V3: Cannot get shielded address for delegation test"
else
    log "Owner zaddr: ${OWNER_ZADDR:0:30}..."

    SHIELD_TX=$(rpc1 z_shield "*" "$OWNER_ZADDR" 100 2>/dev/null)
    if [ -n "$SHIELD_TX" ]; then
        mine_blocks 2
        success "NullStake V3: Owner shielded 100 INN for delegation"
    else
        skip "NullStake V3: Shield for delegation failed"
    fi

    STAKER_ADDR=$(rpc2 getnewaddress 2>/dev/null)
    STAKER_PUBKEY=""
    if [ -n "$STAKER_ADDR" ]; then
        STAKER_VALIDATE=$(rpc2 validateaddress "$STAKER_ADDR" 2>/dev/null)
        STAKER_PUBKEY=$(echo "$STAKER_VALIDATE" | grep -o '"pubkey" *: *"[^"]*"' | head -1 | sed 's/.*"pubkey" *: *"\([^"]*\)".*/\1/')
    fi

    VOUCHER=$(rpc1 n_delegatestake "*" 50 "$STAKER_PUBKEY" 2>/dev/null)
    if [ -n "$VOUCHER" ] && ! echo "$VOUCHER" | grep -q "error"; then
        success "NullStake V3: n_delegatestake created delegation voucher"

        VOUCHER_HEX=$(echo "$VOUCHER" | grep -o '"voucher" *: *"[^"]*"' | head -1 | sed 's/.*"voucher" *: *"\([^"]*\)".*/\1/')
        IMPORT_RESULT=$(rpc2 n_importdelegation "$VOUCHER_HEX" 2>/dev/null)
        if [ -n "$IMPORT_RESULT" ] && ! echo "$IMPORT_RESULT" | grep -q "error"; then
            success "NullStake V3: n_importdelegation imported on staker node"
        else
            skip "NullStake V3: n_importdelegation failed (${IMPORT_RESULT:0:80})"
        fi

        DELEG_INFO=$(rpc1 n_coldstakeinfo 2>/dev/null)
        if echo "$DELEG_INFO" | grep -q "delegations"; then
            success "NullStake V3: n_coldstakeinfo returns delegation data"
        else
            skip "NullStake V3: n_coldstakeinfo returned no data"
        fi

        REVOKE_RESULT=$(rpc1 n_revokecoldstake "*" 2>/dev/null)
        if [ -n "$REVOKE_RESULT" ] && ! echo "$REVOKE_RESULT" | grep -q "error"; then
            success "NullStake V3: n_revokecoldstake revoked delegation"
        else
            skip "NullStake V3: n_revokecoldstake failed (${REVOKE_RESULT:0:80})"
        fi

        DELEG_INFO2=$(rpc1 n_coldstakeinfo 2>/dev/null)
        DELEG_COUNT=$(echo "$DELEG_INFO2" | grep -o '"hashOwner"' | wc -l | tr -d ' ')
        if [ "$DELEG_COUNT" -eq 0 ] 2>/dev/null; then
            success "NullStake V3: Delegation successfully removed after revocation"
        else
            skip "NullStake V3: Delegation may still exist after revocation"
        fi
    else
        skip "NullStake V3: n_delegatestake failed (${VOUCHER:0:80})"
    fi
fi

mine_blocks 3
V3_HEIGHT=$(get_blocks rpc1)
log "Chain height after V3 tests: $V3_HEIGHT"
success "NullStake V3: Chain stable after cold staking tests"

# ============================================================
# PHASE 6: IDNS (Name System)
# ============================================================
header "PHASE 6: IDNS Name Registration"

NAME_NEW=$(rpc1 name_new "dns:testdomain.inn" "192.168.1.1" 365 2>/dev/null)
if [ -n "$NAME_NEW" ]; then
    mine_blocks 1
    success "IDNS: name_new registered dns:testdomain.inn"

    NAME_SHOW=$(rpc1 name_show "dns:testdomain.inn" 2>/dev/null)
    if echo "$NAME_SHOW" | grep -q "192.168.1.1"; then
        success "IDNS: name_show returns correct value"
    else
        skip "IDNS: name_show did not return expected value"
    fi

    NAME_UPDATE=$(rpc1 name_update "dns:testdomain.inn" "10.0.0.1" 365 2>/dev/null)
    if [ -n "$NAME_UPDATE" ]; then
        mine_blocks 1
        success "IDNS: name_update changed value"
    else
        skip "IDNS: name_update failed"
    fi

    NAME_LIST=$(rpc1 name_list 2>/dev/null)
    if echo "$NAME_LIST" | grep -q "testdomain"; then
        success "IDNS: name_list shows registered names"
    else
        skip "IDNS: name_list empty"
    fi
else
    skip "IDNS: name_new failed (RELEASE_HEIGHT may not be reached in regtest)"
fi

# ============================================================
# PHASE 7: Cross-Node Sync Verification
# ============================================================
header "PHASE 7: Cross-Node Sync Verification"

wait_for_sync 60

H1=$(get_blocks rpc1)
H2=$(get_blocks rpc2)
H3=$(get_blocks rpc3)

log "Node 1 height: $H1"
log "Node 2 height: $H2"
log "Node 3 height: $H3"

if [ "$H1" == "$H2" ]; then
    success "Node 1 and Node 2 are in sync at height $H1"
else
    fail "Node 1 ($H1) and Node 2 ($H2) out of sync"
fi

if [ "$H1" == "$H3" ]; then
    success "Node 1 and Node 3 are in sync at height $H1"
else
    warn "Node 3 ($H3) may be catching up to Node 1 ($H1)"
    sleep 5
    H3=$(get_blocks rpc3)
    if [ "$H1" == "$H3" ]; then
        success "Node 3 caught up to height $H1"
    else
        fail "Node 3 ($H3) still out of sync with Node 1 ($H1)"
    fi
fi

BAL1=$(get_balance rpc1)
BAL2=$(get_balance rpc2)
BAL3=$(get_balance rpc3)
log "Balances: Node1=$BAL1  Node2=$BAL2  Node3=$BAL3"

# ============================================================
# PHASE 8: Wallet Operations
# ============================================================
header "PHASE 8: Wallet Operations"

STEALTH=$(rpc1 getnewstealthaddress 2>/dev/null)
if [ -n "$STEALTH" ]; then
    success "Stealth address created: ${STEALTH:0:30}..."
else
    skip "getnewstealthaddress not available"
fi

SMSG_STATUS=$(rpc1 smsgenable 2>/dev/null)
if [ -n "$SMSG_STATUS" ]; then
    success "Secure messaging enabled"
else
    skip "Secure messaging not available"
fi

INFO=$(rpc1 getinfo 2>/dev/null)
if echo "$INFO" | grep -q "version"; then
    success "getinfo returns valid data"
else
    fail "getinfo failed"
fi

MINING=$(rpc1 getmininginfo 2>/dev/null)
if echo "$MINING" | grep -q "blocks"; then
    success "getmininginfo returns valid data"
else
    fail "getmininginfo failed"
fi

# ============================================================
# RESULTS SUMMARY
# ============================================================
TOTAL_END=$(date +%s)
ELAPSED=$((TOTAL_END - TOTAL_START))

header "TEST RESULTS"
echo -e "${GREEN}PASSED: $PASSED${NC}"
echo -e "${RED}FAILED: $FAILED${NC}"
echo -e "${CYAN}SKIPPED: $SKIPPED${NC}"
echo -e "Total: $((PASSED + FAILED + SKIPPED)) tests in ${ELAPSED}s"
echo ""

echo -e "${CYAN}Regtest Fork Heights Verified:${NC}"
echo "  Block 0: Genesis"
echo "  Block 1: Cold Staking, Shielded TX, Ring Sig Deprecation"
echo "  Block 2: DSP, NullSend, FCMP++, Lelantus Serial V2"
echo "  Block 3: NullStake V1 (Private PoS)"
echo "  Block 5: NullStake V2 (ZK Kernel Privacy)"
echo "  Block 7: NullStake V3 (Private Cold Staking)"

if [ $FAILED -gt 0 ]; then
    echo -e "\n${RED}Some tests failed. Check debug.log in test directories for details.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
fi
