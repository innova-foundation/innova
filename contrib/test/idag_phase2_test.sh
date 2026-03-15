#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# IDAG Phase 2: DAG Consensus Integration Test
# Tests: DAG activation, multi-parent blocks, GHOSTDAG ordering, conflict resolution
# Regtest: FORK_HEIGHT_DAG = 11

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_dag_test"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"

NODE1_PORT=27445
NODE2_PORT=27446
NODE1_RPC=27500
NODE2_RPC=27501
NODE1_IDNS=7565
NODE2_IDNS=7566

RPCUSER="dagtest"
RPCPASS="testpass123"

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
    pkill -f "innovad.*dag_test" 2>/dev/null || true
    pkill -f "innovad.*dag_debug" 2>/dev/null || true
    sleep 3
    rm -rf "$TEST_DIR"
}

setup_nodes() {
    cleanup
    mkdir -p "$NODE1_DIR" "$NODE2_DIR"

    cat > "$NODE1_DIR/innova.conf" << EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$NODE1_RPC
port=$NODE1_PORT
listen=1
idnsport=$NODE1_IDNS
addnode=127.0.0.1:$NODE2_PORT
stakingmode=0
nofinalityvoting=1
debug=1
EOF

    cat > "$NODE2_DIR/innova.conf" << EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$NODE2_RPC
port=$NODE2_PORT
listen=1
idnsport=$NODE2_IDNS
addnode=127.0.0.1:$NODE1_PORT
stakingmode=0
nofinalityvoting=1
debug=1
EOF

    log "Starting node 1..."
    "$INNOVAD" -datadir="$NODE1_DIR" -regtest -daemon > /dev/null 2>&1
    sleep 3

    log "Starting node 2..."
    "$INNOVAD" -datadir="$NODE2_DIR" -regtest -daemon > /dev/null 2>&1
    sleep 3

    # Wait for RPC
    for i in $(seq 1 30); do
        if rpc1 getinfo > /dev/null 2>&1; then break; fi
        sleep 1
    done
    for i in $(seq 1 30); do
        if rpc2 getinfo > /dev/null 2>&1; then break; fi
        sleep 1
    done
}

# ============================================================
header "IDAG Phase 2: DAG Consensus Tests"
# ============================================================

setup_nodes

# ============================================================
header "Test 1: Pre-DAG blocks (height < 11)"
# ============================================================

log "Mining 10 blocks on node 1 (pre-DAG)..."
mine_blocks "rpc1" 10
sleep 3

HEIGHT=$(get_blocks "rpc1")
if [ "$HEIGHT" = "10" ]; then
    success "Pre-DAG: mined to height 10"
else
    fail "Pre-DAG: expected height 10, got $HEIGHT"
fi

# Check DAG info shows inactive
DAG_INFO=$(rpc1 getdaginfo 2>/dev/null)
DAG_ACTIVE=$(echo "$DAG_INFO" | grep -o '"dag_active" *: *[a-z]*' | grep -o '[a-z]*$')
if [ "$DAG_ACTIVE" = "false" ]; then
    success "Pre-DAG: getdaginfo shows dag_active=false"
else
    fail "Pre-DAG: expected dag_active=false, got $DAG_ACTIVE"
fi

# ============================================================
header "Test 2: DAG activation at height 11"
# ============================================================

log "Mining block 11 (DAG activates)..."
mine_blocks "rpc1" 1
sleep 3

HEIGHT=$(get_blocks "rpc1")
if [ "$HEIGHT" = "11" ]; then
    success "DAG activation: mined to height 11"
else
    fail "DAG activation: expected height 11, got $HEIGHT"
fi

DAG_INFO=$(rpc1 getdaginfo 2>/dev/null)
DAG_ACTIVE=$(echo "$DAG_INFO" | grep -o '"dag_active" *: *[a-z]*' | grep -o '[a-z]*$')
if [ "$DAG_ACTIVE" = "true" ]; then
    success "DAG activation: getdaginfo shows dag_active=true"
else
    fail "DAG activation: expected dag_active=true, got $DAG_ACTIVE"
fi

# ============================================================
header "Test 3: DAG tips tracking"
# ============================================================

TIPS=$(rpc1 getdagtips 2>/dev/null)
TIP_COUNT=$(echo "$TIPS" | grep -c '"hash"' || echo "0")
if [ "$TIP_COUNT" -ge "1" ]; then
    success "DAG tips: getdagtips returns $TIP_COUNT tip(s)"
else
    fail "DAG tips: expected at least 1 tip, got $TIP_COUNT"
fi

# ============================================================
header "Test 4: Mining more DAG blocks"
# ============================================================

log "Mining 5 more blocks..."
mine_blocks "rpc1" 5
sleep 3

HEIGHT=$(get_blocks "rpc1")
if [ "$HEIGHT" = "16" ]; then
    success "DAG mining: mined to height 16"
else
    fail "DAG mining: expected height 16, got $HEIGHT"
fi

# ============================================================
header "Test 5: GHOSTDAG ordering"
# ============================================================

ORDER=$(rpc1 getdagorder 10 2>/dev/null)
ORDER_COUNT=$(echo "$ORDER" | grep -c '"order"' || echo "0")
if [ "$ORDER_COUNT" -ge "1" ]; then
    success "GHOSTDAG order: getdagorder returns $ORDER_COUNT entries"
else
    fail "GHOSTDAG order: expected entries, got $ORDER_COUNT"
fi

# Check that ordering has blue blocks
BLUE_COUNT=$(echo "$ORDER" | grep -c '"blue" *: *true' || echo "0")
if [ "$BLUE_COUNT" -ge "1" ]; then
    success "GHOSTDAG order: found $BLUE_COUNT blue blocks"
else
    fail "GHOSTDAG order: expected blue blocks, got $BLUE_COUNT"
fi

# ============================================================
header "Test 6: Block DAG metadata in getblock"
# ============================================================

BEST_HASH=$(rpc1 getbestblockhash 2>/dev/null)
if [ -n "$BEST_HASH" ]; then
    BLOCK=$(rpc1 getblock "$BEST_HASH" 2>/dev/null)
    HAS_DAGPARENTS=$(echo "$BLOCK" | grep -c '"dagparents"' || echo "0")
    if [ "$HAS_DAGPARENTS" -ge "1" ]; then
        success "Block metadata: getblock includes dagparents field"
    else
        fail "Block metadata: missing dagparents in getblock"
    fi

    HAS_DAGSCORE=$(echo "$BLOCK" | grep -c '"dagscore"' || echo "0")
    if [ "$HAS_DAGSCORE" -ge "1" ]; then
        success "Block metadata: getblock includes dagscore field"
    else
        fail "Block metadata: missing dagscore in getblock"
    fi
else
    skip "Block metadata: couldn't get best block hash"
fi

# ============================================================
header "Test 7: Node sync with DAG"
# ============================================================

sleep 5
HEIGHT2=$(get_blocks "rpc2")
if [ "$HEIGHT2" = "$HEIGHT" ]; then
    success "Node sync: node2 synced to height $HEIGHT2"
else
    warn "Node sync: node2 at height $HEIGHT2, node1 at $HEIGHT (may need more time)"
    sleep 10
    HEIGHT2=$(get_blocks "rpc2")
    if [ "$HEIGHT2" = "$HEIGHT" ]; then
        success "Node sync: node2 synced to height $HEIGHT2 (after wait)"
    else
        fail "Node sync: node2 at $HEIGHT2, expected $HEIGHT"
    fi
fi

# ============================================================
header "Test 8: DAG score accumulation"
# ============================================================

DAG_INFO=$(rpc1 getdaginfo 2>/dev/null)
HAS_SCORE=$(echo "$DAG_INFO" | grep -c '"best_dag_score"' || echo "0")
if [ "$HAS_SCORE" -ge "1" ]; then
    success "DAG score: best_dag_score field present in getdaginfo"
else
    fail "DAG score: missing best_dag_score in getdaginfo"
fi

# ============================================================
header "Test 9: Finality still works with DAG"
# ============================================================

# Finality activates at height 10, DAG at 11. Check finality info
FIN_INFO=$(rpc1 getfinalityinfo 2>/dev/null)
FIN_ACTIVE=$(echo "$FIN_INFO" | grep -o '"fork_active" *: *[a-z]*' | grep -o '[a-z]*$')
if [ "$FIN_ACTIVE" = "true" ]; then
    success "Finality: fork_active=true alongside DAG"
else
    fail "Finality: expected fork_active=true"
fi

# ============================================================
header "Test 10: DAG constants check"
# ============================================================

GHOSTDAG_K=$(echo "$DAG_INFO" | grep -o '"ghostdag_k" *: *[0-9]*' | grep -o '[0-9]*$')
MAX_PARENTS=$(echo "$DAG_INFO" | grep -o '"max_parents" *: *[0-9]*' | grep -o '[0-9]*$')
MERGE_DEPTH=$(echo "$DAG_INFO" | grep -o '"merge_depth" *: *[0-9]*' | grep -o '[0-9]*$')

if [ "$GHOSTDAG_K" = "18" ]; then
    success "DAG constants: GHOSTDAG_K=18"
else
    fail "DAG constants: expected GHOSTDAG_K=18, got $GHOSTDAG_K"
fi

if [ "$MAX_PARENTS" = "32" ]; then
    success "DAG constants: MAX_DAG_PARENTS=32"
else
    fail "DAG constants: expected MAX_DAG_PARENTS=32, got $MAX_PARENTS"
fi

if [ "$MERGE_DEPTH" = "64" ]; then
    success "DAG constants: DAG_MERGE_DEPTH=64"
else
    fail "DAG constants: expected DAG_MERGE_DEPTH=64, got $MERGE_DEPTH"
fi


# ============================================================
header "Summary"
# ============================================================

cleanup

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  IDAG Phase 2 Test Results${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "${GREEN}  PASSED:  $PASSED${NC}"
echo -e "${RED}  FAILED:  $FAILED${NC}"
echo -e "${YELLOW}  SKIPPED: $SKIPPED${NC}"
echo -e "${CYAN}============================================${NC}"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
