#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 adversarial regtest: shield real value, then replay, reorg under the pool and
# restart mid-flight. The value-balance rejection is in privacy_vnext_builder_tests.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_ADV_TEST_DIR:-/tmp/innova_iv5_adversarial_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT=27845
RPC=27900
IDNS=7865
RPCUSER="iv5adv"
RPCPASS="iv5advpass"

# Boundary B activates early; the first post-DAG epoch ends at 310, and the pool
# balance only reaches the epoch state once an epoch completes.
BOUNDARY_B=20
FUND_HEIGHT=140
EPOCH_HEIGHT=330

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() { "$INNOVAD" -datadir="$NODE_DIR" -regtest -rpcuser=$RPCUSER \
        -rpcpassword=$RPCPASS -rpcport=$RPC "$@" 2>&1; }

height()   { rpc getblockcount 2>/dev/null | tr -d '"[:space:]'; }
jnum()     { echo "$1" | grep -oE "\"$2\" *: *-?[0-9.]+" | grep -oE '\-?[0-9.]+$' | head -1; }
jstr()     { echo "$1" | sed -n "s/.*\"$2\" *: *\"\([^\"]*\)\".*/\1/p" | head -1; }
is_int()   { echo "$1" | grep -qE '^[0-9]+$'; }

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
        pgrep -f "datadir=$NODE_DIR" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

start_node() {
    "$INNOVAD" -datadir="$NODE_DIR" -regtest -daemon >/dev/null 2>&1
    for _ in $(seq 1 90); do
        rpc getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

mine_to() {
    local target="$1" h
    for _ in $(seq 1 90); do
        h="$(height)"
        is_int "$h" && [ "$h" -ge "$target" ] && return 0
        rpc setgenerate true $(( target - ${h:-0} )) >/dev/null 2>&1
        sleep 4
    done
    return 1
}

cleanup() {
    stop_node || pkill -f "datadir=$NODE_DIR" 2>/dev/null || true
    [ "${IV5_ADV_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 adversarial regtest"

rm -rf "$TEST_DIR"; mkdir -p "$NODE_DIR"
cat > "$NODE_DIR/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPC
port=$PORT
listen=1
idnsport=$IDNS
dnsseed=0
stakingmode=0
nofinalityvoting=1
maxconnections=125
regtestboundaryb=$BOUNDARY_B
regtestiv5rehearsal=1
EOF

start_node || { fail "node did not start"; exit 1; }
success "node started with Boundary B at $BOUNDARY_B and IV5 rehearsal enabled"

# ============================================================
header "1. IV5 activates and reports itself ready"
# ============================================================

mine_to "$FUND_HEIGHT" || { fail "could not mine to $FUND_HEIGHT"; exit 1; }
INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
# Check whether consensus accepts an IV5 payload; the ABI's consensus-active flag
# stays zero until separately reviewed.
ACCEPTED="$(echo "$INFO" | grep -o '"privacy_vnext_transactions_accepted" *: *[a-z]*' | grep -o '[a-z]*$')"
ACTIVE="$(echo "$INFO" | grep -o '"boundary_b_active" *: *[a-z]*' | grep -o '[a-z]*$')"
if [ "$ACCEPTED" = "true" ] && [ "$ACTIVE" = "true" ]; then
    success "Boundary B active and consensus accepts IV5 transactions"
else
    fail "IV5 not accepting (boundary_b_active=$ACTIVE transactions_accepted=$ACCEPTED)"
    exit 1
fi

# ============================================================
header "2. A shield puts real value into the pool"
# ============================================================

SEED="$(rpc z_createiv5seed 2>&1)"
if echo "$SEED" | grep -q '"created"'; then
    success "IV5 seed created"
else
    fail "z_createiv5seed failed: $(echo "$SEED" | head -2)"
    exit 1
fi

BAL_BEFORE="$(jnum "$(rpc z_getshieldedinfo 2>/dev/null)" privacy_vnext_balance)"
TREE_BEFORE="$(jnum "$(rpc z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_size)"

SHIELD="$(rpc z_shieldall 2>&1)"
TXID="$(jstr "$SHIELD" txid)"
SHIELDED="$(jnum "$SHIELD" shielded)"
INPUTS="$(jnum "$SHIELD" inputs)"
if [ -n "$TXID" ] && [ ${#TXID} -eq 64 ]; then
    success "shield built and accepted: $INPUTS input(s), $SHIELDED INN, txid ${TXID:0:16}"
else
    fail "z_shieldall failed: $(echo "$SHIELD" | head -3)"
    exit 1
fi

# It must reach a block, not merely the mempool.
mine_to $(( $(height) + 3 )) || true
CONF="$(rpc gettransaction "$TXID" 2>&1)"
if echo "$CONF" | grep -q '"confirmations"'; then
    success "shield confirmed in a block"
else
    fail "shield did not confirm: $(echo "$CONF" | head -2)"
fi

# ============================================================
header "3. Replaying the shield is refused"
# ============================================================

RAW="$(rpc getrawtransaction "$TXID" 2>/dev/null | tr -d '"[:space:]')"
if [ -n "$RAW" ] && [ ${#RAW} -gt 100 ]; then
    REPLAY="$(rpc sendrawtransaction "$RAW" 2>&1)"
    if echo "$REPLAY" | grep -qiE "already|error|denied|exists"; then
        success "resubmitting the confirmed shield is refused"
    else
        fail "the chain accepted a replay of an already-confirmed shield: $REPLAY"
    fi
else
    warn "could not fetch the raw shield; replay case skipped"
fi

# ============================================================
header "4. The tree and the store move together"
# ============================================================

mine_to "$EPOCH_HEIGHT" || { fail "could not mine to $EPOCH_HEIGHT"; exit 1; }
INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
TREE_AFTER="$(jnum "$INFO" privacy_vnext_tree_size)"
STORE_AFTER="$(jnum "$INFO" privacy_vnext_tree_store_size)"
BAL_AFTER="$(jnum "$INFO" privacy_vnext_balance)"

if is_int "$TREE_AFTER" && [ "$TREE_AFTER" -gt "${TREE_BEFORE:-0}" ]; then
    success "tree grew from ${TREE_BEFORE:-0} to $TREE_AFTER leaves"
else
    fail "tree did not grow (before=${TREE_BEFORE:-?} after=${TREE_AFTER:-?})"
fi

if [ "$TREE_AFTER" = "$STORE_AFTER" ]; then
    success "node-local store is level with the epoch tree at $STORE_AFTER"
else
    fail "store ($STORE_AFTER) disagrees with the epoch tree ($TREE_AFTER)"
fi

# The wallet must be able to see what it shielded.
if [ "$(echo "$BAL_AFTER > ${BAL_BEFORE:-0}" | bc -l 2>/dev/null)" = "1" ]; then
    success "wallet reports the shielded balance: $BAL_AFTER INN"
else
    warn "wallet shielded balance did not increase (before=${BAL_BEFORE:-?} after=${BAL_AFTER:-?})"
fi

# ============================================================
header "5. A reorg takes the pool back with it"
# ============================================================

REORG_FROM=$(( $(height) - 8 ))
ROLLBACK_HASH="$(rpc getblockhash "$REORG_FROM" 2>/dev/null | tr -d '"[:space:]')"
if [ -z "$ROLLBACK_HASH" ]; then
    fail "could not read a block hash to invalidate"
else
    rpc invalidateblock "$ROLLBACK_HASH" >/dev/null 2>&1
    sleep 5
    REORG_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
    REORG_TREE="$(jnum "$REORG_INFO" privacy_vnext_tree_size)"
    REORG_STORE="$(jnum "$REORG_INFO" privacy_vnext_tree_store_size)"
    if [ "$REORG_TREE" = "$REORG_STORE" ]; then
        success "store stayed level with the tree across the rollback ($REORG_STORE)"
    else
        fail "after rollback the store ($REORG_STORE) and tree ($REORG_TREE) disagree"
    fi

    rpc reconsiderblock "$ROLLBACK_HASH" >/dev/null 2>&1
    sleep 5
    mine_to $(( REORG_FROM + 12 )) || true
    BACK_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
    BACK_TREE="$(jnum "$BACK_INFO" privacy_vnext_tree_size)"
    BACK_STORE="$(jnum "$BACK_INFO" privacy_vnext_tree_store_size)"
    if [ "$BACK_TREE" = "$BACK_STORE" ] && is_int "$BACK_TREE" && [ "$BACK_TREE" -ge "$TREE_AFTER" ]; then
        success "chain recovered and the pool returned to $BACK_TREE leaves"
    else
        fail "after recovery tree=$BACK_TREE store=$BACK_STORE (expected >= $TREE_AFTER, equal)"
    fi
fi

# ============================================================
header "6. The pool survives a restart"
# ============================================================

PRE_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
PRE_TREE="$(jnum "$PRE_INFO" privacy_vnext_tree_size)"
PRE_STORE="$(jnum "$PRE_INFO" privacy_vnext_tree_store_size)"
PRE_ROOT="$(jstr "$PRE_INFO" privacy_vnext_tree_root)"

if stop_node && start_node; then
    POST_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
    POST_TREE="$(jnum "$POST_INFO" privacy_vnext_tree_size)"
    POST_STORE="$(jnum "$POST_INFO" privacy_vnext_tree_store_size)"
    POST_ROOT="$(jstr "$POST_INFO" privacy_vnext_tree_root)"
    if [ "$PRE_TREE" = "$POST_TREE" ] && [ "$PRE_STORE" = "$POST_STORE" ] && \
       [ "$PRE_ROOT" = "$POST_ROOT" ]; then
        success "tree, store and root all survived the restart unchanged"
    else
        fail "restart changed the pool: tree $PRE_TREE->$POST_TREE store $PRE_STORE->$POST_STORE root ${PRE_ROOT:0:12}->${POST_ROOT:0:12}"
    fi
    if rpc gettransaction "$TXID" 2>/dev/null | grep -q '"confirmations"'; then
        success "the shield is still known to the wallet after restart"
    else
        fail "the wallet lost the shield across a restart"
    fi
else
    fail "node did not come back after restart"
fi

# ============================================================
header "7. The node reports no errors"
# ============================================================

ERRORS="$(jstr "$(rpc getinfo 2>/dev/null)" errors)"
if [ -z "$ERRORS" ]; then
    success "getinfo reports no errors"
else
    fail "node reports errors: $ERRORS"
fi

if grep -qiE "IV5 pool balance|takes more from the pool|does not validate" \
        "$NODE_DIR/regtest/debug.log" 2>/dev/null; then
    fail "the log carries an IV5 pool or validation complaint"
    grep -iE "IV5 pool balance|takes more from the pool|does not validate" \
        "$NODE_DIR/regtest/debug.log" | tail -3
else
    success "no IV5 pool or validation complaints in the log"
fi

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
