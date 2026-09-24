#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 tree store catch-up hook: the chain crosses epoch boundaries and a reorg, and the
# store position stays consistent with the epoch state. No shielded outputs are created.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_tree_store_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="$(iv5_test_dir /tmp/innova_iv5_store_test)"
NODE_DIR="$TEST_DIR/node1"

NODE_PORT="$(iv5_port 0 27645)"
NODE_RPC="$(iv5_port 1 27700)"
NODE_IDNS="$(iv5_port 2 7665)"

RPCUSER="iv5storetest"
RPCPASS="testpass123"

# Regtest epochs run 300 blocks from the DAG fork at 11, and Boundary B cannot sit
# below epoch-state V3 (311), so the first epoch with tree state is 311..610.
BOUNDARY_B_HEIGHT=311
TARGET_HEIGHT=640

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() {
    "$INNOVAD" -datadir="$NODE_DIR" -regtest -rpcuser=$RPCUSER \
        -rpcpassword=$RPCPASS -rpcport=$NODE_RPC "$@" 2>&1
}

get_blocks() {
    rpc getinfo 2>/dev/null | grep -oE '"blocks" *: *[0-9]+' | grep -oE '[0-9]+'
}

json_number_field() {
    echo "$1" | grep -oE "\"$2\" *: *-?[0-9]+" | grep -oE '\-?[0-9]+$' | head -1
}

cleanup() {
    iv5_kill_daemons "innova_iv5_store_test" TERM 2>/dev/null || true
    sleep 2
    rm -rf "$TEST_DIR"
}

start_node() {
    mkdir -p "$NODE_DIR"
    cat > "$NODE_DIR/innova.conf" << EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$NODE_RPC
port=$NODE_PORT
listen=1
idnsport=$NODE_IDNS
stakingmode=0
nofinalityvoting=1
dnsseed=0
maxconnections=125
regtestboundaryb=$BOUNDARY_B_HEIGHT
EOF
    "$INNOVAD" -datadir="$NODE_DIR" -regtest -daemon > /dev/null 2>&1
    for i in $(seq 1 60); do
        if rpc getinfo > /dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

trap cleanup EXIT

header "IV5 tree store: SetBestChain catch-up hook"

cleanup
if ! start_node; then
    fail "node did not come up"
    exit 1
fi
success "node started with Boundary B at height $BOUNDARY_B_HEIGHT"

# ============================================================
header "Test 1: the chain advances past Boundary B and a completed epoch"
# ============================================================

log "Mining to height $TARGET_HEIGHT (this completes the first post-DAG epoch)..."
STALLED=0
LAST_HEIGHT=0
# Post-DAG blocks are paced by the spacing floor, about 1.7 a second here, so the
# budget scales with the target. The stall counter is what catches a real stall.
MINE_ROUNDS=$(( TARGET_HEIGHT / 5 + 20 ))
for i in $(seq 1 "$MINE_ROUNDS"); do
    HEIGHT=$(get_blocks)
    [ -n "$HEIGHT" ] && [ "$HEIGHT" -ge "$TARGET_HEIGHT" ] && break
    if [ -n "$HEIGHT" ] && [ "$HEIGHT" -le "$LAST_HEIGHT" ]; then
        STALLED=$((STALLED + 1))
        [ "$STALLED" -ge 5 ] && break
    else
        STALLED=0
        LAST_HEIGHT=${HEIGHT:-0}
    fi
    REMAINING=$((TARGET_HEIGHT - ${HEIGHT:-0}))
    [ "$REMAINING" -gt 0 ] && rpc setgenerate true "$REMAINING" > /dev/null 2>&1
    sleep 5
done

HEIGHT=$(get_blocks)
if [ -n "$HEIGHT" ] && [ "$HEIGHT" -ge "$TARGET_HEIGHT" ]; then
    success "chain reached height $HEIGHT with the store hook active"
elif [ "$STALLED" -ge 5 ]; then
    fail "chain stalled at height ${HEIGHT:-unknown}: no block for 25s, expected $TARGET_HEIGHT"
else
    fail "mining budget of $MINE_ROUNDS rounds ran out at height ${HEIGHT:-unknown} before $TARGET_HEIGHT"
fi

# ============================================================
header "Test 2: the store never reports a sync failure"
# ============================================================

if grep -q "IV5 tree store did not reach epoch" "$NODE_DIR/regtest/debug.log" 2>/dev/null || \
   grep -q "IV5 tree store did not reach epoch" "$NODE_DIR/debug.log" 2>/dev/null; then
    fail "the store reported a sync failure"
    grep -h "IV5 tree store" "$NODE_DIR/regtest/debug.log" "$NODE_DIR/debug.log" 2>/dev/null | tail -5
else
    success "no store sync failure was reported"
fi

# ============================================================
header "Test 3: the store position agrees with the epoch state"
# ============================================================

INFO=$(rpc z_getshieldedinfo 2>/dev/null)
TREE_SIZE=$(json_number_field "$INFO" "privacy_vnext_tree_size")
STORE_SIZE=$(json_number_field "$INFO" "privacy_vnext_tree_store_size")

if [ -z "$TREE_SIZE" ] || [ -z "$STORE_SIZE" ]; then
    fail "z_getshieldedinfo did not report the tree and store sizes"
elif [ "$TREE_SIZE" = "$STORE_SIZE" ]; then
    success "store is level with the epoch tree at $STORE_SIZE leaves"
else
    fail "store holds $STORE_SIZE leaves but the epoch tree records $TREE_SIZE"
fi

# ============================================================
header "Test 4: a reorg leaves the store consistent"
# ============================================================

TIP=$(rpc getbestblockhash 2>/dev/null | tr -d '"' | tr -d '[:space:]')
DEPTH_HASH=$(rpc getblockhash $((HEIGHT - 5)) 2>/dev/null | tr -d '"' | tr -d '[:space:]')

if [ -z "$DEPTH_HASH" ]; then
    fail "could not read a block hash to invalidate"
else
    log "Invalidating back 5 blocks from height $HEIGHT..."
    rpc invalidateblock "$DEPTH_HASH" > /dev/null 2>&1
    sleep 3
    REORG_HEIGHT=$(get_blocks)

    rpc reconsiderblock "$DEPTH_HASH" > /dev/null 2>&1
    sleep 3
    rpc setgenerate true 6 > /dev/null 2>&1
    sleep 5

    FINAL_HEIGHT=$(get_blocks)
    if [ -n "$FINAL_HEIGHT" ] && [ "$FINAL_HEIGHT" -ge "$REORG_HEIGHT" ]; then
        success "chain recovered to height $FINAL_HEIGHT after the reorg"
    else
        fail "chain did not recover after the reorg (at ${FINAL_HEIGHT:-unknown})"
    fi

    INFO=$(rpc z_getshieldedinfo 2>/dev/null)
    TREE_SIZE=$(json_number_field "$INFO" "privacy_vnext_tree_size")
    STORE_SIZE=$(json_number_field "$INFO" "privacy_vnext_tree_store_size")
    if [ -n "$TREE_SIZE" ] && [ "$TREE_SIZE" = "$STORE_SIZE" ]; then
        success "store is still level with the epoch tree after the reorg"
    else
        fail "after the reorg the store holds ${STORE_SIZE:-?} and the tree records ${TREE_SIZE:-?}"
    fi

    if grep -q "IV5 tree store did not reach epoch" "$NODE_DIR/regtest/debug.log" 2>/dev/null || \
       grep -q "IV5 tree store did not reach epoch" "$NODE_DIR/debug.log" 2>/dev/null; then
        fail "the store reported a sync failure after the reorg"
    else
        success "no store sync failure was reported after the reorg"
    fi
fi

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
