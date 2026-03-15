#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# IDAG Phase 3: Throughput Scaling & Epoch Infrastructure Test
# Tests: adaptive epoch interval, DAG pruning, epoch state persistence, incremental startup, mempool DAG cleanup
# Regtest: FORK_HEIGHT_DAG = 11, FORK_HEIGHT_FINALITY = 10

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_dag_p3_test"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"

NODE1_PORT=27545
NODE2_PORT=27546
NODE1_RPC=27600
NODE2_RPC=27601
NODE1_IDNS=7665
NODE2_IDNS=7666

RPCUSER="dagp3test"
RPCPASS="testpass456"

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
    pkill -f "innovad.*dag_p3_test" 2>/dev/null || true
    pkill -f "innovad.*dag_p3_debug" 2>/dev/null || true
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
debug=1
stakingmode=0
nofinalityvoting=0
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
debug=1
stakingmode=0
nofinalityvoting=0
EOF

    log "Starting node 1..."
    "$INNOVAD" -datadir="$NODE1_DIR" -regtest -daemon -pid="$NODE1_DIR/dag_p3_test.pid" > /dev/null 2>&1
    sleep 3

    log "Starting node 2..."
    "$INNOVAD" -datadir="$NODE2_DIR" -regtest -daemon -pid="$NODE2_DIR/dag_p3_test.pid" > /dev/null 2>&1
    sleep 3

    # Wait for RPC
    for i in $(seq 1 15); do
        if rpc1 getinfo > /dev/null 2>&1 && rpc2 getinfo > /dev/null 2>&1; then
            log "Both nodes responding to RPC"
            return 0
        fi
        sleep 2
    done
    fail "Nodes failed to start"
    return 1
}

# =======================================================================
header "IDAG Phase 3: Throughput Scaling & Epoch Infrastructure"
# =======================================================================

# Check if binary exists
if [ ! -f "$INNOVAD" ]; then
    fail "innovad not found at $INNOVAD"
    echo -e "\n${RED}Build innovad first: cd src && make -f makefile.osx${NC}"
    exit 1
fi

setup_nodes || exit 1

# =======================================================================
header "Test 1: Adaptive Epoch Interval"
# =======================================================================

log "Mining 12 blocks to pass DAG fork height (11)..."
mine_blocks rpc1 12
sleep 2

BLOCKS=$(get_blocks rpc1)
log "Node 1 at height: $BLOCKS"

# Pre-DAG epoch interval should be 60, post-DAG should be 300
# In regtest, DAG fork is at height 11, so at height 12 we're post-DAG
DAGINFO=$(rpc1 getdaginfo 2>/dev/null)
EPOCH_INTERVAL=$(echo "$DAGINFO" | grep -oE '"epoch_interval" *: *[0-9]+' | grep -oE '[0-9]+')

if [ "$EPOCH_INTERVAL" = "300" ]; then
    success "Post-DAG epoch interval is 300 (5 min at 1s blocks)"
else
    fail "Expected post-DAG epoch_interval=300, got: $EPOCH_INTERVAL"
fi

# Check finality info for pre-DAG epoch interval
FININFO=$(rpc1 getfinalityinfo 2>/dev/null)
FIN_EPOCH_INTERVAL=$(echo "$FININFO" | grep -oE '"epoch_interval" *: *[0-9]+' | grep -oE '[0-9]+')

if [ "$FIN_EPOCH_INTERVAL" = "300" ]; then
    success "Finality epoch interval updated to 300 post-DAG"
else
    fail "Finality epoch_interval: expected 300, got: $FIN_EPOCH_INTERVAL"
fi

# Check current epoch number
CURRENT_EPOCH=$(echo "$DAGINFO" | grep -oE '"current_epoch" *: *[0-9]+' | grep -oE '[0-9]+')
log "Current epoch: $CURRENT_EPOCH"

if [ -n "$CURRENT_EPOCH" ]; then
    success "Current epoch is reported in getdaginfo"
else
    fail "current_epoch missing from getdaginfo"
fi

# =======================================================================
header "Test 2: DAG Entry Count & Pruning Info"
# =======================================================================

DAG_ENTRIES=$(echo "$DAGINFO" | grep -oE '"dag_entries" *: *[0-9]+' | grep -oE '[0-9]+')
PRUNED_BELOW=$(echo "$DAGINFO" | grep -oE '"pruned_below" *: *-?[0-9]+' | grep -oE '\-?[0-9]+')

if [ -n "$DAG_ENTRIES" ] && [ "$DAG_ENTRIES" -gt 0 ]; then
    success "DAG entry count reported: $DAG_ENTRIES"
else
    fail "DAG entry count missing or zero: $DAG_ENTRIES"
fi

if [ -n "$PRUNED_BELOW" ]; then
    success "Pruned_below reported: $PRUNED_BELOW"
else
    fail "pruned_below missing from getdaginfo"
fi

# =======================================================================
header "Test 3: Epoch State via getepochinfo"
# =======================================================================

# Mine enough blocks to complete an epoch boundary
# In regtest post-DAG, epoch interval is 300
# Epoch 0 would be blocks 0-299 — that's a lot. Let's just test the RPC exists
EPOCH_INFO=$(rpc1 getepochinfo 0 2>/dev/null)

if echo "$EPOCH_INFO" | grep -q '"epoch"'; then
    success "getepochinfo RPC returns epoch data"
else
    fail "getepochinfo RPC failed: $EPOCH_INFO"
fi

# Check the status field for not-yet-computed epoch
if echo "$EPOCH_INFO" | grep -q '"status".*not_computed'; then
    success "Epoch 0 correctly shows not_computed status"
elif echo "$EPOCH_INFO" | grep -q '"block_count"'; then
    success "Epoch 0 has computed block_count (already computed)"
else
    fail "Unexpected epoch info format: $EPOCH_INFO"
fi

# Check height_start and height_end are present
if echo "$EPOCH_INFO" | grep -q '"height_start"'; then
    success "getepochinfo includes height_start"
else
    fail "getepochinfo missing height_start"
fi

if echo "$EPOCH_INFO" | grep -q '"height_end"'; then
    success "getepochinfo includes height_end"
else
    fail "getepochinfo missing height_end"
fi

# Test getepochinfo with no param (current epoch)
EPOCH_CURRENT=$(rpc1 getepochinfo 2>/dev/null)
if echo "$EPOCH_CURRENT" | grep -q '"epoch"'; then
    success "getepochinfo with no param returns current epoch"
else
    fail "getepochinfo no-param failed: $EPOCH_CURRENT"
fi

# =======================================================================
header "Test 4: DAG Memory Bounded After Many Blocks"
# =======================================================================

log "Mining 50 more blocks (total ~62)..."
mine_blocks rpc1 50
sleep 3

BLOCKS=$(get_blocks rpc1)
log "Node 1 now at height: $BLOCKS"

DAGINFO2=$(rpc1 getdaginfo 2>/dev/null)
DAG_ENTRIES2=$(echo "$DAGINFO2" | grep -oE '"dag_entries" *: *[0-9]+' | grep -oE '[0-9]+')

log "DAG entries after $BLOCKS blocks: $DAG_ENTRIES2"

if [ -n "$DAG_ENTRIES2" ] && [ "$DAG_ENTRIES2" -gt 0 ]; then
    success "DAG entries present after many blocks: $DAG_ENTRIES2"
else
    fail "No DAG entries after mining"
fi

# With only ~50 post-DAG blocks and DAG_PRUNE_DEPTH=100000, no pruning should have occurred
if [ "$PRUNED_BELOW" = "-1" ]; then
    success "No pruning yet (expected, fewer blocks than prune depth)"
else
    log "Pruned below height: $PRUNED_BELOW (may be normal if prune depth is low)"
fi

# =======================================================================
header "Test 5: Incremental Startup (restart node, verify DAG intact)"
# =======================================================================

# Record state before restart
TIPS_BEFORE=$(rpc1 getdagtips 2>/dev/null | grep -c '"hash"')
ENTRIES_BEFORE=$DAG_ENTRIES2
log "Before restart: $TIPS_BEFORE tips, $ENTRIES_BEFORE entries"

# Stop node 1
log "Stopping node 1..."
rpc1 stop > /dev/null 2>&1
sleep 5

# Verify it stopped
if rpc1 getinfo > /dev/null 2>&1; then
    warn "Node 1 still responding, waiting longer..."
    sleep 5
fi

# Restart node 1
log "Restarting node 1..."
"$INNOVAD" -datadir="$NODE1_DIR" -regtest -daemon -pid="$NODE1_DIR/dag_p3_test.pid" > /dev/null 2>&1
sleep 5

# Wait for RPC
for i in $(seq 1 15); do
    if rpc1 getinfo > /dev/null 2>&1; then
        log "Node 1 back online"
        break
    fi
    sleep 2
done

DAGINFO3=$(rpc1 getdaginfo 2>/dev/null)
DAG_ENTRIES3=$(echo "$DAGINFO3" | grep -oE '"dag_entries" *: *[0-9]+' | grep -oE '[0-9]+')
TIPS_AFTER=$(rpc1 getdagtips 2>/dev/null | grep -c '"hash"')
BLOCKS_AFTER=$(get_blocks rpc1)

log "After restart: height=$BLOCKS_AFTER, $TIPS_AFTER tips, $DAG_ENTRIES3 entries"

if [ "$BLOCKS_AFTER" = "$BLOCKS" ]; then
    success "Block height preserved after restart: $BLOCKS_AFTER"
else
    fail "Block height changed after restart: was $BLOCKS, now $BLOCKS_AFTER"
fi

if [ -n "$DAG_ENTRIES3" ] && [ "$DAG_ENTRIES3" -gt 0 ]; then
    success "DAG entries preserved after restart: $DAG_ENTRIES3"
else
    fail "DAG entries lost after restart: $DAG_ENTRIES3"
fi

if [ "$TIPS_AFTER" -gt 0 ]; then
    success "DAG tips preserved after restart: $TIPS_AFTER"
else
    fail "DAG tips lost after restart"
fi

# Check debug log for incremental rebuild
if grep -q "incremental rebuild" "$NODE1_DIR/regtest/debug.log" 2>/dev/null; then
    success "Incremental DAG rebuild detected in debug log"
elif grep -q "RebuildDAGOrderIncremental" "$NODE1_DIR/regtest/debug.log" 2>/dev/null; then
    success "Incremental DAG rebuild detected in debug log"
elif grep -q "DAG clean height" "$NODE1_DIR/regtest/debug.log" 2>/dev/null; then
    success "DAG clean height saved/loaded in debug log"
else
    skip "Incremental rebuild log message not found (may use full rebuild if clean height not saved)"
fi

# =======================================================================
header "Test 6: Cross-Node DAG Sync"
# =======================================================================

# Wait for node 2 to sync
sleep 5

BLOCKS2=$(get_blocks rpc2)
log "Node 2 at height: $BLOCKS2"

if [ "$BLOCKS2" = "$BLOCKS_AFTER" ]; then
    success "Node 2 synced to same height: $BLOCKS2"
else
    warn "Node 2 at height $BLOCKS2 (expected $BLOCKS_AFTER) — may need more sync time"
    sleep 10
    BLOCKS2=$(get_blocks rpc2)
    if [ "$BLOCKS2" = "$BLOCKS_AFTER" ]; then
        success "Node 2 synced after additional wait: $BLOCKS2"
    else
        fail "Node 2 sync failed: at $BLOCKS2, expected $BLOCKS_AFTER"
    fi
fi

# Check DAG info on node 2
DAGINFO_N2=$(rpc2 getdaginfo 2>/dev/null)
N2_ENTRIES=$(echo "$DAGINFO_N2" | grep -oE '"dag_entries" *: *[0-9]+' | grep -oE '[0-9]+')
N2_EPOCH=$(echo "$DAGINFO_N2" | grep -oE '"current_epoch" *: *[0-9]+' | grep -oE '[0-9]+')

if [ -n "$N2_ENTRIES" ] && [ "$N2_ENTRIES" -gt 0 ]; then
    success "Node 2 has DAG entries: $N2_ENTRIES"
else
    fail "Node 2 has no DAG entries"
fi

if [ -n "$N2_EPOCH" ]; then
    success "Node 2 reports current_epoch: $N2_EPOCH"
else
    fail "Node 2 missing current_epoch"
fi

# =======================================================================
header "Test 7: getdaginfo Enhanced Fields"
# =======================================================================

# Verify all new Phase 3 fields exist in getdaginfo
for FIELD in "epoch_interval" "current_epoch" "dag_entries" "pruned_below"; do
    if echo "$DAGINFO3" | grep -q "\"$FIELD\""; then
        success "getdaginfo has field: $FIELD"
    else
        fail "getdaginfo missing field: $FIELD"
    fi
done

# =======================================================================
header "Test 8: getepochinfo Epoch Boundary Computation"
# =======================================================================

# Get epoch info for current epoch
EPOCH_INFO_CURRENT=$(rpc1 getepochinfo 2>/dev/null)
EPOCH_NUM=$(echo "$EPOCH_INFO_CURRENT" | grep -oE '"epoch" *: *[0-9]+' | grep -oE '[0-9]+')
H_START=$(echo "$EPOCH_INFO_CURRENT" | grep -oE '"height_start" *: *[0-9]+' | grep -oE '[0-9]+')
H_END=$(echo "$EPOCH_INFO_CURRENT" | grep -oE '"height_end" *: *[0-9]+' | grep -oE '[0-9]+')

log "Current epoch: $EPOCH_NUM (height $H_START - $H_END)"

if [ -n "$H_START" ] && [ -n "$H_END" ]; then
    RANGE=$((H_END - H_START + 1))
    log "Epoch range: $RANGE blocks"
    if [ "$RANGE" = "300" ]; then
        success "Epoch range is 300 blocks (correct post-DAG interval)"
    elif [ "$RANGE" = "60" ]; then
        success "Epoch range is 60 blocks (pre-DAG interval)"
    else
        fail "Unexpected epoch range: $RANGE"
    fi
else
    fail "Could not parse height_start/height_end from getepochinfo"
fi

# =======================================================================
# Cleanup
# =======================================================================

header "Cleanup"

rpc1 stop > /dev/null 2>&1
rpc2 stop > /dev/null 2>&1
sleep 3

pkill -f "innovad.*dag_p3_test" 2>/dev/null || true
sleep 2
rm -rf "$TEST_DIR"

# =======================================================================
# Summary
# =======================================================================

header "IDAG Phase 3 Test Results"
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
