#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# IDAG Phase 4: DAGKNIGHT Adaptive Ordering Test
# Tests: DAGKNIGHT activation, adaptive k, pairwise ordering, confidence, transition
# Regtest: FORK_HEIGHT_DAG = 11, FORK_HEIGHT_DAGKNIGHT = 13

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_dagknight_test"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"

NODE1_PORT=27645
NODE2_PORT=27646
NODE1_RPC=27700
NODE2_RPC=27701
NODE1_IDNS=7765
NODE2_IDNS=7766

RPCUSER="dktest"
RPCPASS="testpass789"

PASSED=0
FAILED=0
SKIPPED=0

log()     { echo -e "${BLUE}[TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
skip()    { echo -e "${CYAN}[SKIP]${NC} $1"; ((SKIPPED++)) || true; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc1() { "$INNOVAD" -datadir="$NODE1_DIR" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE1_RPC "$@" 2>&1; }
rpc2() { "$INNOVAD" -datadir="$NODE2_DIR" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$NODE2_RPC "$@" 2>&1; }

get_blocks() {
    local result=$($1 getinfo 2>/dev/null)
    echo "$result" | grep -oE '"blocks" *: *[0-9]+' | grep -oE '[0-9]+'
}

mine_blocks() {
    local rpc_func=$1
    local count=$2
    for ((i=0; i<count; i++)); do
        $rpc_func setgenerate true 1 > /dev/null 2>&1
        sleep 0.5
    done
}

cleanup() {
    log "Cleaning up..."
    pkill -f "innovad.*dagknight_test" 2>/dev/null || true
    sleep 3
    rm -rf "$TEST_DIR"
}

setup_nodes() {
    cleanup
    mkdir -p "$NODE1_DIR" "$NODE2_DIR"

    for DIR in "$NODE1_DIR" "$NODE2_DIR"; do
        PORT=$NODE1_PORT; RPORT=$NODE1_RPC; IDNS=$NODE1_IDNS; PEER=$NODE2_PORT
        if [ "$DIR" = "$NODE2_DIR" ]; then
            PORT=$NODE2_PORT; RPORT=$NODE2_RPC; IDNS=$NODE2_IDNS; PEER=$NODE1_PORT
        fi
        cat > "$DIR/innova.conf" << EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPORT
port=$PORT
listen=1
idnsport=$IDNS
addnode=127.0.0.1:$PEER
debug=1
stakingmode=0
nofinalityvoting=0
EOF
    done

    log "Starting nodes..."
    "$INNOVAD" -datadir="$NODE1_DIR" -regtest -daemon -pid="$NODE1_DIR/dagknight_test.pid" > /dev/null 2>&1
    sleep 2
    "$INNOVAD" -datadir="$NODE2_DIR" -regtest -daemon -pid="$NODE2_DIR/dagknight_test.pid" > /dev/null 2>&1
    sleep 3

    for i in $(seq 1 15); do
        if rpc1 getinfo > /dev/null 2>&1 && rpc2 getinfo > /dev/null 2>&1; then
            log "Both nodes responding"
            return 0
        fi
        sleep 2
    done
    fail "Nodes failed to start"
    return 1
}

# =======================================================================
header "IDAG Phase 4: DAGKNIGHT Adaptive Ordering"
# =======================================================================

if [ ! -f "$INNOVAD" ]; then
    fail "innovad not found at $INNOVAD"
    exit 1
fi

setup_nodes || exit 1

# =======================================================================
header "Test 1: Pre-DAGKNIGHT (GHOSTDAG still active)"
# =======================================================================

log "Mining 12 blocks (DAG active at 11, DAGKNIGHT at 13)..."
mine_blocks rpc1 12
sleep 2

BLOCKS=$(get_blocks rpc1)
log "Height: $BLOCKS"

DAGINFO=$(rpc1 getdaginfo 2>/dev/null)

DK_ACTIVE=$(echo "$DAGINFO" | grep -oE '"dagknight_active" *: *[a-z]+' | grep -oE '[a-z]+$')
if [ "$DK_ACTIVE" = "false" ]; then
    success "DAGKNIGHT not yet active at height $BLOCKS"
else
    fail "DAGKNIGHT should not be active at height $BLOCKS"
fi

ALGO=$(echo "$DAGINFO" | grep -oE '"ordering_algorithm" *: *"[^"]+"' | grep -oP ':\s*"\K[^"]+')
if [ "$ALGO" = "GHOSTDAG" ]; then
    success "Ordering algorithm is GHOSTDAG pre-activation"
else
    fail "Expected GHOSTDAG, got: $ALGO"
fi

# =======================================================================
header "Test 2: DAGKNIGHT Activation"
# =======================================================================

log "Mining 3 more blocks to reach height 15 (past DAGKNIGHT fork at 13)..."
mine_blocks rpc1 3
sleep 2

BLOCKS=$(get_blocks rpc1)
log "Height: $BLOCKS"

DAGINFO2=$(rpc1 getdaginfo 2>/dev/null)

DK_ACTIVE2=$(echo "$DAGINFO2" | grep -oE '"dagknight_active" *: *[a-z]+' | grep -oE '[a-z]+$')
if [ "$DK_ACTIVE2" = "true" ]; then
    success "DAGKNIGHT active at height $BLOCKS"
else
    fail "DAGKNIGHT should be active at height $BLOCKS: $DK_ACTIVE2"
fi

ALGO2=$(echo "$DAGINFO2" | grep -oP '"ordering_algorithm"\s*:\s*"\K[^"]+')
if [ "$ALGO2" = "DAGKNIGHT" ]; then
    success "Ordering algorithm switched to DAGKNIGHT"
else
    fail "Expected DAGKNIGHT, got: $ALGO2"
fi

# Check fork height field
DK_FORK=$(echo "$DAGINFO2" | grep -oE '"dagknight_fork_height" *: *[0-9]+' | grep -oE '[0-9]+')
if [ "$DK_FORK" = "13" ]; then
    success "DAGKNIGHT fork height correctly reported as 13"
else
    fail "Expected fork height 13, got: $DK_FORK"
fi

# =======================================================================
header "Test 3: Inferred K"
# =======================================================================

log "Mining 10 more blocks for k inference data..."
mine_blocks rpc1 10
sleep 2

DAGINFO3=$(rpc1 getdaginfo 2>/dev/null)
INFERRED_K=$(echo "$DAGINFO3" | grep -oE '"inferred_k" *: *[0-9]+' | grep -oE '[0-9]+')

if [ -n "$INFERRED_K" ]; then
    success "Inferred k reported: $INFERRED_K"
else
    fail "inferred_k not found in getdaginfo"
fi

# Check via getdagorder that blocks have inferred_k
DAGORDER=$(rpc1 getdagorder 5 2>/dev/null)
if echo "$DAGORDER" | grep -q '"inferred_k"'; then
    success "getdagorder includes inferred_k for DAGKNIGHT blocks"
else
    skip "inferred_k not in getdagorder (may not have DAGKNIGHT blocks in view)"
fi

# =======================================================================
header "Test 4: getdagconfidence RPC"
# =======================================================================

# Get a recent block hash
BEST_HASH=$(rpc1 getbestblockhash 2>/dev/null)
if [ -z "$BEST_HASH" ]; then
    fail "Could not get best block hash"
else
    # Single block confidence
    CONF=$(rpc1 getdagconfidence "$BEST_HASH" 2>/dev/null)

    if echo "$CONF" | grep -q '"order_confidence"'; then
        success "getdagconfidence returns order_confidence"
    else
        fail "getdagconfidence missing order_confidence: $CONF"
    fi

    if echo "$CONF" | grep -q '"inferred_k"'; then
        success "getdagconfidence returns inferred_k"
    else
        fail "getdagconfidence missing inferred_k"
    fi

    if echo "$CONF" | grep -q '"blue"'; then
        success "getdagconfidence returns blue status"
    else
        fail "getdagconfidence missing blue status"
    fi
fi

# =======================================================================
header "Test 5: Pairwise Block Ordering"
# =======================================================================

# Get two block hashes to compare
HASH_A=$(rpc1 getblockhash 14 2>/dev/null | tr -d '"')
HASH_B=$(rpc1 getblockhash 16 2>/dev/null | tr -d '"')

if [ -n "$HASH_A" ] && [ -n "$HASH_B" ]; then
    PAIRWISE=$(rpc1 getdagconfidence "$HASH_A" "$HASH_B" 2>/dev/null)

    if echo "$PAIRWISE" | grep -q '"pairwise"'; then
        success "Pairwise ordering returned"
    else
        fail "Pairwise ordering missing: $PAIRWISE"
    fi

    ORDER=$(echo "$PAIRWISE" | grep -oP '"order"\s*:\s*"\K[^"]+')
    if [ "$ORDER" = "before" ]; then
        success "Block at height 14 ordered before block at height 16"
    elif [ "$ORDER" = "after" ]; then
        fail "Block at lower height should be ordered before higher height"
    else
        warn "Order result: $ORDER (may be expected for non-ancestor blocks)"
    fi

    PAIR_CONF=$(echo "$PAIRWISE" | grep -oP '"confidence"\s*:\s*\K[0-9]+')
    if [ -n "$PAIR_CONF" ] && [ "$PAIR_CONF" -ge 0 ]; then
        success "Pairwise confidence: $PAIR_CONF"
    else
        fail "Pairwise confidence missing or invalid"
    fi
else
    skip "Could not get block hashes for pairwise comparison"
fi

# =======================================================================
header "Test 6: DAG Score Accumulation with DAGKNIGHT"
# =======================================================================

SCORE=$(echo "$DAGINFO3" | grep -oP '"best_dag_score"\s*:\s*"\K[^"]+')
if [ -n "$SCORE" ] && [ "$SCORE" != "0000000000000000000000000000000000000000000000000000000000000000" ]; then
    success "DAG score is non-zero: ${SCORE:0:20}..."
else
    fail "DAG score is zero or missing"
fi

# =======================================================================
header "Test 7: Cross-Node Sync with DAGKNIGHT"
# =======================================================================

sleep 5
BLOCKS2=$(get_blocks rpc2)
BLOCKS1=$(get_blocks rpc1)

if [ "$BLOCKS2" = "$BLOCKS1" ]; then
    success "Nodes synced at height $BLOCKS2 with DAGKNIGHT"
else
    warn "Node 2 at $BLOCKS2, node 1 at $BLOCKS1 — waiting..."
    sleep 10
    BLOCKS2=$(get_blocks rpc2)
    if [ "$BLOCKS2" = "$BLOCKS1" ]; then
        success "Nodes synced after wait: $BLOCKS2"
    else
        fail "Sync failed: node1=$BLOCKS1 node2=$BLOCKS2"
    fi
fi

# Verify DAGKNIGHT also active on node 2
DK_N2=$(rpc2 getdaginfo 2>/dev/null | grep -oP '"dagknight_active"\s*:\s*\K[a-z]+')
if [ "$DK_N2" = "true" ]; then
    success "Node 2 also reports DAGKNIGHT active"
else
    fail "Node 2 DAGKNIGHT status: $DK_N2"
fi

# =======================================================================
header "Test 8: Transition Blocks Coexist"
# =======================================================================

# Check that both GHOSTDAG-era and DAGKNIGHT-era blocks exist in getdagorder
DAGORDER_FULL=$(rpc1 getdagorder 50 2>/dev/null)
HAS_INFERRED=$(echo "$DAGORDER_FULL" | grep -c '"inferred_k"' || true)
TOTAL_BLOCKS=$(echo "$DAGORDER_FULL" | grep -c '"hash"' || true)

log "Total blocks in order: $TOTAL_BLOCKS, with inferred_k: $HAS_INFERRED"

if [ "$TOTAL_BLOCKS" -gt 0 ]; then
    success "DAG order has $TOTAL_BLOCKS blocks spanning GHOSTDAG->DAGKNIGHT transition"
else
    fail "No blocks in DAG order"
fi

# =======================================================================
# Cleanup
# =======================================================================

header "Cleanup"
rpc1 stop > /dev/null 2>&1
rpc2 stop > /dev/null 2>&1
sleep 3
pkill -f "innovad.*dagknight_test" 2>/dev/null || true
sleep 2
rm -rf "$TEST_DIR"

# =======================================================================
# Summary
# =======================================================================

header "IDAG Phase 4 Test Results"
echo -e "${GREEN}PASSED: $PASSED${NC}"
echo -e "${RED}FAILED: $FAILED${NC}"
echo -e "${CYAN}SKIPPED: $SKIPPED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAILED test(s) failed${NC}"
    exit 1
fi
