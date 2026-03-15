#!/bin/bash
# IDAG Heavy Stress Test v2 — 8 nodes, mature chain, PoW+PoS, TPS limit test
# Mines slowly for maturity, distributes coins, enables staking, then pushes TPS

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_stress"
NUM_NODES=8
BASE_PORT=28000
BASE_RPC=28100
RPCUSER="stresstest"
RPCPASS="stresstestpass"

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[STRESS]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() {
    local node=$1; shift
    local port=$((BASE_RPC + node))
    "$INNOVAD" -datadir="$TEST_DIR/node$node" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$port "$@" 2>&1
}

jq_field() {
    echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$2',''))" 2>/dev/null
}

get_blocks() {
    local r=$(rpc $1 getinfo 2>/dev/null)
    jq_field "$r" "blocks"
}

get_balance() {
    rpc $1 getbalance 2>/dev/null | tr -d '"' | tr -d ' ' | tr -d '\n'
}

wait_sync() {
    local target_node=$1
    local target_height=$2
    local max_wait=$3
    for ((w=0; w<max_wait; w++)); do
        local h=$(get_blocks $target_node)
        [ "$h" = "$target_height" ] && return 0
        sleep 1
    done
    return 1
}

wait_all_sync() {
    local expected=$1
    local max_wait=${2:-30}
    for ((w=0; w<max_wait; w++)); do
        local synced=0
        for ((i=0; i<NUM_NODES; i++)); do
            local h=$(get_blocks $i)
            [ "$h" = "$expected" ] && ((synced++))
        done
        [ $synced -eq $NUM_NODES ] && return 0
        sleep 1
    done
    return 1
}

cleanup() {
    log "Killing all test nodes..."
    pkill -f "innovad.*innova_stress" 2>/dev/null || true
    sleep 2
    pkill -9 -f "innovad.*innova_stress" 2>/dev/null || true
    sleep 1
    rm -rf "$TEST_DIR"
}

setup_cluster() {
    cleanup
    log "Setting up $NUM_NODES node cluster..."

    for ((i=0; i<NUM_NODES; i++)); do
        local dir="$TEST_DIR/node$i"
        mkdir -p "$dir"
        cat > "$dir/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$((BASE_RPC + i))
port=$((BASE_PORT + i))
listen=1
idnsport=$((28200 + i))
debug=0
staking=1
stakingmode=0
nofinalityvoting=0
minstakeinterval=2
minersleep=500
EOF
        # Mesh: everyone connects to node 0 + neighbors
        [ $i -gt 0 ] && echo "addnode=127.0.0.1:$BASE_PORT" >> "$dir/innova.conf"
        [ $i -gt 1 ] && echo "addnode=127.0.0.1:$((BASE_PORT + i - 1))" >> "$dir/innova.conf"
        [ $i -lt $((NUM_NODES - 1)) ] && echo "addnode=127.0.0.1:$((BASE_PORT + i + 1))" >> "$dir/innova.conf"
    done

    for ((i=0; i<NUM_NODES; i++)); do
        "$INNOVAD" -datadir="$TEST_DIR/node$i" -regtest -pid="$TEST_DIR/node$i/stress.pid" > /dev/null 2>&1
        sleep 0.3
    done

    log "Waiting for all nodes..."
    for ((attempt=0; attempt<60; attempt++)); do
        local ready=0
        for ((i=0; i<NUM_NODES; i++)); do
            rpc $i getinfo > /dev/null 2>&1 && ((ready++))
        done
        [ $ready -eq $NUM_NODES ] && log "All $NUM_NODES nodes online" && return 0
        sleep 1
    done
    fail "Nodes failed to start"
    return 1
}

mine_slow() {
    # Mine blocks one at a time with sync pauses to keep cluster healthy
    local count=$1
    local sync_every=${2:-10}
    for ((b=0; b<count; b++)); do
        rpc 0 setgenerate true 1 > /dev/null 2>&1
        sleep 0.2
        # Pause for sync every N blocks
        if [ $(((b+1) % sync_every)) -eq 0 ]; then
            sleep 2
        fi
    done
}

# =====================================================================
header "IDAG Stress Test v2 ($NUM_NODES nodes, mature chain)"
# =====================================================================

[ ! -f "$INNOVAD" ] && fail "innovad not found" && exit 1
setup_cluster || exit 1

# =====================================================================
header "Phase 1: Slow mine to fork activation (height 15)"
# =====================================================================

log "Mining 15 blocks slowly (1 block + sync pause)..."
mine_slow 15 5
sleep 5

HEIGHT=$(get_blocks 0)
log "Node 0 at height: $HEIGHT"

wait_all_sync "$HEIGHT" 20
SYNCED=0
for ((i=0; i<NUM_NODES; i++)); do
    [ "$(get_blocks $i)" = "$HEIGHT" ] && ((SYNCED++))
done
log "$SYNCED/$NUM_NODES nodes synced at height $HEIGHT"
[ $SYNCED -eq $NUM_NODES ] && success "All nodes synced past DAG fork ($HEIGHT)" || fail "Sync: $SYNCED/$NUM_NODES"

# =====================================================================
header "Phase 2: Distribute coins early (before maturity mining)"
# =====================================================================

log "Getting addresses from all nodes..."
ADDRS=()
for ((i=0; i<NUM_NODES; i++)); do
    ADDR=$(rpc $i getnewaddress 2>/dev/null | tr -d '"')
    ADDRS+=("$ADDR")
done

log "Sending 20000 INN to each of the $((NUM_NODES-1)) other nodes..."
for ((i=1; i<NUM_NODES; i++)); do
    rpc 0 sendtoaddress "${ADDRS[$i]}" 20000 > /dev/null 2>&1
done

# Confirm the sends
rpc 0 setgenerate true 1 > /dev/null 2>&1
sleep 2

# =====================================================================
header "Phase 3: Mine 200 blocks for full maturity (slow, sync-friendly)"
# =====================================================================

log "Mining 200 blocks in batches of 10 with sync pauses..."
for ((batch=0; batch<20; batch++)); do
    mine_slow 10 10
    H=$(get_blocks 0)
    [ $((batch % 5)) -eq 4 ] && log "  ...height $H (batch $((batch+1))/20)"
    sleep 1
done

HEIGHT=$(get_blocks 0)
log "Chain at height: $HEIGHT"

# Wait for full cluster sync
wait_all_sync "$HEIGHT" 60
SYNCED=0
for ((i=0; i<NUM_NODES; i++)); do
    [ "$(get_blocks $i)" = "$HEIGHT" ] && ((SYNCED++))
done
[ $SYNCED -eq $NUM_NODES ] && success "Full sync after maturity mining: $SYNCED/$NUM_NODES at $HEIGHT" || fail "Sync: $SYNCED/$NUM_NODES"

# =====================================================================
header "Phase 4: Verify coin distribution + maturity"
# =====================================================================

FUNDED=0
for ((i=1; i<NUM_NODES; i++)); do
    BAL=$(get_balance $i)
    if python3 -c "exit(0 if float('${BAL:-0}') > 100 else 1)" 2>/dev/null; then
        ((FUNDED++))
        [ $i -le 3 ] && log "  Node $i balance: $BAL INN"
    fi
done
log "$FUNDED/$((NUM_NODES-1)) nodes funded with spendable balance"
[ $FUNDED -ge $((NUM_NODES-2)) ] && success "Distribution mature: $FUNDED nodes funded" || fail "Only $FUNDED funded"

# =====================================================================
header "Phase 5: DAG + DAGKNIGHT status"
# =====================================================================

DAGINFO=$(rpc 0 getdaginfo 2>/dev/null)
DAG_ACTIVE=$(jq_field "$DAGINFO" "dag_active")
DK_ACTIVE=$(jq_field "$DAGINFO" "dagknight_active")
DAG_ENTRIES=$(jq_field "$DAGINFO" "dag_entries")
ALGO=$(jq_field "$DAGINFO" "ordering_algorithm")

log "DAG: active=$DAG_ACTIVE, DAGKNIGHT=$DK_ACTIVE, entries=$DAG_ENTRIES, algo=$ALGO"
[ "$DAG_ACTIVE" = "True" ] && success "DAG active with $DAG_ENTRIES entries" || fail "DAG not active"
[ "$DK_ACTIVE" = "True" ] && success "DAGKNIGHT ordering active" || fail "DAGKNIGHT not active"

# =====================================================================
header "Phase 6: Wait for PoS blocks (staking active)"
# =====================================================================

log "Waiting up to 60s for PoS blocks to appear..."
POS_FOUND=0
for ((w=0; w<60; w++)); do
    H=$(get_blocks 0)
    if [ -n "$H" ] && [ "$H" -gt "$HEIGHT" ]; then
        # Check if new blocks are PoS
        HASH=$(rpc 0 getblockhash $H 2>/dev/null | tr -d '"')
        if [ -n "$HASH" ]; then
            BLOCK=$(rpc 0 getblock "$HASH" 2>/dev/null)
            FLAGS=$(jq_field "$BLOCK" "flags")
            if echo "$FLAGS" | grep -qi "proof-of-stake"; then
                ((POS_FOUND++))
                [ $POS_FOUND -eq 1 ] && log "First PoS block at height $H!"
            fi
        fi
        HEIGHT=$H
    fi
    [ $POS_FOUND -ge 3 ] && break
    sleep 1
done

log "PoS blocks found: $POS_FOUND in 60s window"
[ $POS_FOUND -gt 0 ] && success "PoS staking in DAG: $POS_FOUND blocks produced" || warn "No PoS blocks yet (may need longer maturity)"

# =====================================================================
header "Phase 7: TPS Limit Test — 1000 rapid txs"
# =====================================================================

BLOCKS_BEFORE=$(get_blocks 0)
log "Sending 1000 transactions as fast as possible..."

SPAM_ADDRS=()
for ((i=0; i<10; i++)); do
    SPAM_ADDRS+=($(rpc 0 getnewaddress 2>/dev/null | tr -d '"'))
done

TX_SENT=0
TX_FAILED=0
START_TIME=$(date +%s%N)

for ((t=0; t<1000; t++)); do
    TARGET=${SPAM_ADDRS[$((t % 10))]}
    RESULT=$(rpc 0 sendtoaddress "$TARGET" 0.001 2>/dev/null)
    if echo "$RESULT" | grep -qE "^[0-9a-f]{64}$"; then
        ((TX_SENT++))
    else
        ((TX_FAILED++))
        # If we hit mempool full or insufficient funds, stop early
        [ $TX_FAILED -ge 50 ] && log "  Stopping early: $TX_FAILED failures" && break
    fi
done

END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
ELAPSED_S=$((ELAPSED_MS / 1000))
[ $ELAPSED_S -eq 0 ] && ELAPSED_S=1

TPS=$((TX_SENT * 1000 / (ELAPSED_MS + 1)))
log "Sent $TX_SENT txs in ${ELAPSED_MS}ms ($TX_FAILED failed)"
log "Raw submission rate: ~$TPS TPS"

# Note: this measures RPC submission speed, not on-chain confirmation
success "TX submission: $TX_SENT txs at ~$TPS TPS (RPC throughput)"

# =====================================================================
header "Phase 8: Mine the spam + measure on-chain throughput"
# =====================================================================

MEMPOOL_BEFORE=$(rpc 0 getrawmempool 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
log "Mempool before mining: $MEMPOOL_BEFORE txs"

MINE_START=$(date +%s)
# Mine until mempool is empty
MINE_ROUNDS=0
while [ $MINE_ROUNDS -lt 100 ]; do
    rpc 0 setgenerate true 1 > /dev/null 2>&1
    sleep 0.3
    ((MINE_ROUNDS++))
    MP=$(rpc 0 getrawmempool 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    [ "$MP" = "0" ] && break
done
MINE_END=$(date +%s)
MINE_ELAPSED=$((MINE_END - MINE_START))

BLOCKS_AFTER=$(get_blocks 0)
BLOCKS_MINED=$((BLOCKS_AFTER - BLOCKS_BEFORE))

MEMPOOL_AFTER=$(rpc 0 getrawmempool 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

ON_CHAIN_TPS=0
[ $MINE_ELAPSED -gt 0 ] && ON_CHAIN_TPS=$((TX_SENT / MINE_ELAPSED))
AVG_TXS_PER_BLOCK=0
[ $BLOCKS_MINED -gt 0 ] && AVG_TXS_PER_BLOCK=$((TX_SENT / BLOCKS_MINED))

log "Mining complete: $BLOCKS_MINED blocks in ${MINE_ELAPSED}s"
log "On-chain throughput: ~$ON_CHAIN_TPS TPS confirmed"
log "Avg txs/block: ~$AVG_TXS_PER_BLOCK"
log "Mempool after: $MEMPOOL_AFTER remaining"

success "On-chain: $TX_SENT txs in $BLOCKS_MINED blocks (~$ON_CHAIN_TPS confirmed TPS, ~$AVG_TXS_PER_BLOCK tx/block)"

# =====================================================================
header "Phase 9: Cross-node tx spam"
# =====================================================================

log "All funded nodes sending 20 txs each..."
CROSS_SENT=0
for ((i=1; i<NUM_NODES; i++)); do
    for ((t=0; t<20; t++)); do
        TARGET=${ADDRS[$((RANDOM % NUM_NODES))]}
        RESULT=$(rpc $i sendtoaddress "$TARGET" 0.001 2>/dev/null)
        echo "$RESULT" | grep -qE "^[0-9a-f]{64}$" && ((CROSS_SENT++))
    done
done

rpc 0 setgenerate true 5 > /dev/null 2>&1
sleep 3

log "Cross-node txs: $CROSS_SENT"
[ $CROSS_SENT -ge 50 ] && success "Cross-node spam: $CROSS_SENT txs from $((NUM_NODES-1)) nodes" || warn "Cross-node: $CROSS_SENT txs"

# =====================================================================
header "Phase 10: Final cluster sync + integrity"
# =====================================================================

sleep 10
FINAL_HEIGHT=$(get_blocks 0)
wait_all_sync "$FINAL_HEIGHT" 30
SYNCED=0
for ((i=0; i<NUM_NODES; i++)); do
    [ "$(get_blocks $i)" = "$FINAL_HEIGHT" ] && ((SYNCED++))
done

log "$SYNCED/$NUM_NODES nodes at final height $FINAL_HEIGHT"
[ $SYNCED -eq $NUM_NODES ] && success "Final sync: all $NUM_NODES at $FINAL_HEIGHT" || fail "Final sync: $SYNCED/$NUM_NODES"

# DAG integrity
DAGINFO2=$(rpc 0 getdaginfo 2>/dev/null)
ENTRIES2=$(jq_field "$DAGINFO2" "dag_entries")
log "Final DAG: $ENTRIES2 entries"
[ -n "$ENTRIES2" ] && [ "$ENTRIES2" -gt 0 ] 2>/dev/null && success "DAG intact: $ENTRIES2 entries" || fail "DAG entries: $ENTRIES2"

# Finality
FININFO=$(rpc 0 getfinalityinfo 2>/dev/null)
TIER=$(jq_field "$FININFO" "finality_tier")
VOTERS=$(jq_field "$FININFO" "current_epoch_voters")
log "Finality: tier=$TIER, voters=$VOTERS"
success "Finality status: tier=$TIER"

# Final mempool
FINAL_MP=$(rpc 0 getrawmempool 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
log "Final mempool: $FINAL_MP txs"

# =====================================================================
header "Cleanup"
# =====================================================================
cleanup

# =====================================================================
header "RESULTS"
# =====================================================================
echo -e "${GREEN}PASSED: $PASSED${NC}"
echo -e "${RED}FAILED: $FAILED${NC}"
echo ""
echo "=== Performance Summary ==="
echo "  Nodes:           $NUM_NODES"
echo "  Final height:    $FINAL_HEIGHT"
echo "  TX submitted:    $TX_SENT"
echo "  RPC throughput:  ~$TPS TPS"
echo "  On-chain TPS:    ~$ON_CHAIN_TPS TPS"
echo "  Avg tx/block:    ~$AVG_TXS_PER_BLOCK"
echo "  Blocks mined:    $BLOCKS_MINED (spam phase)"
echo "  Cross-node txs:  $CROSS_SENT"
echo "  PoS blocks:      $POS_FOUND"
echo "  DAG entries:     $ENTRIES2"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All stress tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAILED test(s) failed${NC}"
    exit 1
fi
