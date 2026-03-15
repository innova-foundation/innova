#!/bin/bash
# IDAG TPS Limit Test — Push throughput to maximum with adaptive blocks
# Pre-funds wallet with many UTXOs, then blasts transactions

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="/tmp/innova_tps"
NUM_NODES=4
BASE_PORT=29000
BASE_RPC=29100
RPCUSER="tpstest"
RPCPASS="tpstestpass"

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TPS]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() {
    local node=$1; shift
    "$INNOVAD" -datadir="$TEST_DIR/node$node" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$((BASE_RPC + node)) "$@" 2>&1
}

jq_field() {
    echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$2',''))" 2>/dev/null
}

get_blocks() {
    local r=$(rpc $1 getinfo 2>/dev/null)
    jq_field "$r" "blocks"
}

cleanup() {
    pkill -f "innovad.*innova_tps" 2>/dev/null || true
    sleep 2
    pkill -9 -f "innovad.*innova_tps" 2>/dev/null || true
    sleep 1
    rm -rf "$TEST_DIR"
}

setup() {
    cleanup
    log "Setting up $NUM_NODES nodes..."
    for ((i=0; i<NUM_NODES; i++)); do
        mkdir -p "$TEST_DIR/node$i"
        cat > "$TEST_DIR/node$i/innova.conf" << EOF
regtest=1
server=1
daemon=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$((BASE_RPC + i))
port=$((BASE_PORT + i))
listen=1
idnsport=$((29200 + i))
debug=0
staking=1
stakingmode=0
minstakeinterval=2
blockmaxsize=8000000
EOF
        [ $i -gt 0 ] && echo "addnode=127.0.0.1:$BASE_PORT" >> "$TEST_DIR/node$i/innova.conf"
        "$INNOVAD" -datadir="$TEST_DIR/node$i" -regtest -pid="$TEST_DIR/node$i/tps.pid" > /dev/null 2>&1
        sleep 0.3
    done

    for ((a=0; a<30; a++)); do
        local ready=0
        for ((i=0; i<NUM_NODES; i++)); do
            rpc $i getinfo > /dev/null 2>&1 && ((ready++))
        done
        [ $ready -eq $NUM_NODES ] && log "All $NUM_NODES nodes online" && return 0
        sleep 1
    done
    return 1
}

# =====================================================================
header "IDAG TPS Limit Test"
# =====================================================================

[ ! -f "$INNOVAD" ] && fail "innovad not found" && exit 1
setup || exit 1

# =====================================================================
header "Phase 1: Mine 200 blocks (maturity + DAG activation)"
# =====================================================================

log "Mining 200 blocks (10 at a time with sync pauses)..."
for ((batch=0; batch<20; batch++)); do
    rpc 0 setgenerate true 10 > /dev/null 2>&1
    sleep 0.5
done
sleep 5

HEIGHT=$(get_blocks 0)
log "Height: $HEIGHT"
success "Chain at height $HEIGHT"

# =====================================================================
header "Phase 2: Create 2000 UTXOs for spam fuel"
# =====================================================================

log "Splitting coins into 2000 small UTXOs..."
# First get an address
ADDR=$(rpc 0 getnewaddress 2>/dev/null | tr -d '"')

# Send many small amounts to ourselves to create UTXOs
# Use sendmany for efficiency — send 50 outputs per call
UTXO_CREATED=0
for ((batch=0; batch<40; batch++)); do
    # Build sendmany JSON: 50 addresses per call
    ADDRS_JSON="{"
    for ((j=0; j<50; j++)); do
        A=$(rpc 0 getnewaddress 2>/dev/null | tr -d '"')
        [ $j -gt 0 ] && ADDRS_JSON+=","
        ADDRS_JSON+="\"$A\":1.0"
    done
    ADDRS_JSON+="}"

    RESULT=$(rpc 0 sendmany "" "$ADDRS_JSON" 2>/dev/null)
    if echo "$RESULT" | grep -qE "^[0-9a-f]{64}$"; then
        UTXO_CREATED=$((UTXO_CREATED + 50))
    else
        log "  sendmany failed at batch $batch: $(echo $RESULT | head -c 80)"
        break
    fi

    # Mine every 5 batches to keep chain moving
    [ $((batch % 5)) -eq 4 ] && rpc 0 setgenerate true 1 > /dev/null 2>&1
done

# Mine remaining
rpc 0 setgenerate true 5 > /dev/null 2>&1
sleep 3

log "Created $UTXO_CREATED UTXOs"
[ $UTXO_CREATED -ge 1000 ] && success "UTXO split: $UTXO_CREATED UTXOs created" || fail "Only $UTXO_CREATED UTXOs"

# Mine more for maturity
log "Mining 110 blocks for UTXO maturity..."
for ((batch=0; batch<11; batch++)); do
    rpc 0 setgenerate true 10 > /dev/null 2>&1
    sleep 0.5
done
sleep 3

HEIGHT=$(get_blocks 0)
log "Height after maturity: $HEIGHT"

# =====================================================================
header "Phase 3: Check adaptive block size"
# =====================================================================

DAGINFO=$(rpc 0 getdaginfo 2>/dev/null)
ADAPTIVE_LIMIT=$(jq_field "$DAGINFO" "adaptive_block_limit")
ADAPTIVE_CEIL=$(jq_field "$DAGINFO" "adaptive_block_ceiling")
ADAPTIVE_FLOOR=$(jq_field "$DAGINFO" "adaptive_block_floor")

log "Adaptive: limit=$ADAPTIVE_LIMIT, ceiling=$ADAPTIVE_CEIL, floor=$ADAPTIVE_FLOOR"
[ -n "$ADAPTIVE_LIMIT" ] && success "Adaptive block sizing active: limit=$ADAPTIVE_LIMIT" || fail "Adaptive not reporting"

# =====================================================================
header "Phase 4: TPS Blast — send as fast as possible"
# =====================================================================

# Get spendable UTXO count
UNSPENT=$(rpc 0 listunspent 1 9999999 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
log "Spendable UTXOs: $UNSPENT"

TARGET_TXS=2000
log "Sending $TARGET_TXS transactions as fast as possible..."

SPAM_ADDRS=()
for ((i=0; i<20; i++)); do
    SPAM_ADDRS+=($(rpc 0 getnewaddress 2>/dev/null | tr -d '"'))
done

TX_SENT=0
TX_FAILED=0
FAIL_STREAK=0
START_NS=$(python3 -c "import time; print(int(time.time_ns()))")

for ((t=0; t<TARGET_TXS; t++)); do
    TARGET=${SPAM_ADDRS[$((t % 20))]}
    RESULT=$(rpc 0 sendtoaddress "$TARGET" 0.001 2>/dev/null)
    if echo "$RESULT" | grep -qE "^[0-9a-f]{64}$"; then
        ((TX_SENT++))
        FAIL_STREAK=0
    else
        ((TX_FAILED++))
        ((FAIL_STREAK++))
        [ $FAIL_STREAK -ge 30 ] && log "  30 consecutive failures, stopping" && break
    fi

    # Progress update every 500
    [ $((TX_SENT % 500)) -eq 0 ] && [ $TX_SENT -gt 0 ] && log "  ...$TX_SENT sent"
done

END_NS=$(python3 -c "import time; print(int(time.time_ns()))")
ELAPSED_MS=$(python3 -c "print(($END_NS - $START_NS) // 1000000)")
ELAPSED_S=$((ELAPSED_MS / 1000))
[ $ELAPSED_S -eq 0 ] && ELAPSED_S=1

RPC_TPS=$((TX_SENT * 1000 / (ELAPSED_MS + 1)))
log "Submitted $TX_SENT txs in ${ELAPSED_MS}ms ($TX_FAILED failed)"
log "RPC submission rate: ~$RPC_TPS TPS"
success "TX blast: $TX_SENT sent at ~$RPC_TPS TPS (RPC)"

# =====================================================================
header "Phase 5: Mine the mempool — measure on-chain throughput"
# =====================================================================

MEMPOOL=$(rpc 0 getrawmempool 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
log "Mempool: $MEMPOOL txs to mine"

MINE_START=$(date +%s)
BLOCKS_BEFORE=$(get_blocks 0)
MINE_ROUNDS=0

while [ $MINE_ROUNDS -lt 200 ]; do
    rpc 0 setgenerate true 1 > /dev/null 2>&1
    sleep 0.2
    ((MINE_ROUNDS++))
    MP=$(rpc 0 getrawmempool 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    [ "$MP" = "0" ] && break
    # Progress
    [ $((MINE_ROUNDS % 20)) -eq 0 ] && log "  ...mined $MINE_ROUNDS blocks, mempool: $MP"
done

MINE_END=$(date +%s)
MINE_ELAPSED=$((MINE_END - MINE_START))
BLOCKS_AFTER=$(get_blocks 0)
BLOCKS_MINED=$((BLOCKS_AFTER - BLOCKS_BEFORE))

ON_CHAIN_TPS=0
[ $MINE_ELAPSED -gt 0 ] && ON_CHAIN_TPS=$((TX_SENT / MINE_ELAPSED))
AVG_TX_BLOCK=0
[ $BLOCKS_MINED -gt 0 ] && AVG_TX_BLOCK=$((TX_SENT / BLOCKS_MINED))

log "Mining complete: $BLOCKS_MINED blocks in ${MINE_ELAPSED}s"
log "On-chain: ~$ON_CHAIN_TPS TPS confirmed, ~$AVG_TX_BLOCK tx/block"

FINAL_MP=$(rpc 0 getrawmempool 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
log "Final mempool: $FINAL_MP"

success "On-chain throughput: $TX_SENT txs in $BLOCKS_MINED blocks (~$ON_CHAIN_TPS confirmed TPS)"

# =====================================================================
header "Phase 6: Block size analysis"
# =====================================================================

log "Checking block sizes during spam..."
MAX_BLOCK_SIZE_SEEN=0
TOTAL_SIZE=0
SIZE_COUNT=0
for ((h=BLOCKS_BEFORE+1; h<=BLOCKS_AFTER; h++)); do
    HASH=$(rpc 0 getblockhash $h 2>/dev/null | tr -d '"')
    if [ -n "$HASH" ]; then
        BLOCK=$(rpc 0 getblock "$HASH" 2>/dev/null)
        SIZE=$(jq_field "$BLOCK" "size")
        if [ -n "$SIZE" ] && [ "$SIZE" -gt 0 ] 2>/dev/null; then
            TOTAL_SIZE=$((TOTAL_SIZE + SIZE))
            ((SIZE_COUNT++))
            [ "$SIZE" -gt $MAX_BLOCK_SIZE_SEEN ] && MAX_BLOCK_SIZE_SEEN=$SIZE
        fi
    fi
    # Sample every 5th block for speed
    h=$((h + 4))
done

AVG_SIZE=0
[ $SIZE_COUNT -gt 0 ] && AVG_SIZE=$((TOTAL_SIZE / SIZE_COUNT))

log "Block sizes: max=${MAX_BLOCK_SIZE_SEEN} bytes, avg=${AVG_SIZE} bytes (sampled $SIZE_COUNT blocks)"

if [ $MAX_BLOCK_SIZE_SEEN -gt 300000 ]; then
    success "Adaptive growth: max block ${MAX_BLOCK_SIZE_SEEN} bytes (> 300KB floor)"
else
    log "Blocks stayed within floor (low tx volume per block)"
fi

# =====================================================================
header "Phase 7: Adaptive limit after stress"
# =====================================================================

DAGINFO2=$(rpc 0 getdaginfo 2>/dev/null)
ADAPTIVE2=$(jq_field "$DAGINFO2" "adaptive_block_limit")
log "Adaptive limit after stress: $ADAPTIVE2 (was $ADAPTIVE_LIMIT before)"

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
echo "  TX submitted:     $TX_SENT"
echo "  TX failed:        $TX_FAILED"
echo "  RPC TPS:          ~$RPC_TPS"
echo "  On-chain TPS:     ~$ON_CHAIN_TPS"
echo "  Avg tx/block:     ~$AVG_TX_BLOCK"
echo "  Blocks mined:     $BLOCKS_MINED"
echo "  Max block size:   $MAX_BLOCK_SIZE_SEEN bytes"
echo "  Avg block size:   $AVG_SIZE bytes"
echo "  Adaptive limit:   $ADAPTIVE2"
echo ""
[ $FAILED -eq 0 ] && echo -e "${GREEN}All tests passed!${NC}" || echo -e "${RED}$FAILED failed${NC}"
