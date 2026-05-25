#!/bin/bash
# IDAG TPS Measurement Test - deterministic regtest submission and block metrics

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="${TEST_DIR:-/tmp/innova_tps}"
NUM_NODES="${NUM_NODES:-4}"
BASE_PORT="${BASE_PORT:-29000}"
BASE_RPC="${BASE_RPC:-29100}"
RPCUSER="${RPCUSER:-tpstest}"
RPCPASS="${RPCPASS:-tpstestpass}"

INITIAL_HEIGHT="${INITIAL_HEIGHT:-120}"
TARGET_UTXOS="${TARGET_UTXOS:-2000}"
UTXO_BATCH_SIZE="${UTXO_BATCH_SIZE:-50}"
UTXO_AMOUNT="${UTXO_AMOUNT:-1.0}"
TARGET_TXS="${TARGET_TXS:-1000}"
MIN_SPENDABLE_UTXOS="${MIN_SPENDABLE_UTXOS:-$TARGET_TXS}"
RPC_CALL_TIMEOUT="${RPC_CALL_TIMEOUT:-30}"
POLL_RPC_TIMEOUT="${POLL_RPC_TIMEOUT:-5}"
MINE_TIMEOUT_PER_BLOCK="${MINE_TIMEOUT_PER_BLOCK:-30}"

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TPS]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() {
    local node=$1; shift
    "$INNOVAD" -datadir="$TEST_DIR/node$node" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$((BASE_RPC + node)) "$@" 2>&1
}

rpc_timed() {
    local node=$1
    local timeout=$2
    shift 2

    python3 - "$timeout" "$INNOVAD" "$TEST_DIR/node$node" "$RPCUSER" "$RPCPASS" "$((BASE_RPC + node))" "$@" <<'PY'
import subprocess
import sys

timeout = float(sys.argv[1])
innovad = sys.argv[2]
datadir = sys.argv[3]
rpcuser = sys.argv[4]
rpcpass = sys.argv[5]
rpcport = sys.argv[6]
args = sys.argv[7:]

cmd = [
    innovad,
    f"-datadir={datadir}",
    "-regtest",
    f"-rpcuser={rpcuser}",
    f"-rpcpassword={rpcpass}",
    f"-rpcport={rpcport}",
] + args

try:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    sys.stdout.write(proc.stdout)
    sys.exit(proc.returncode)
except subprocess.TimeoutExpired as exc:
    if exc.stdout:
        sys.stdout.write(exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode())
    print(f"RPC timeout after {timeout:g}s: {' '.join(args)}")
    sys.exit(124)
PY
}

json_field() {
    local json="$1"
    local field="$2"
    FIELD="$field" python3 -c '
import json
import os
import sys
try:
    value = json.load(sys.stdin).get(os.environ["FIELD"], "")
    if isinstance(value, bool):
        print(str(value).lower())
    elif value is None:
        print("")
    else:
        print(value)
except Exception:
    pass
' <<< "$json" 2>/dev/null
}

json_array_len() {
    local json="$1"
    local field="$2"
    FIELD="$field" python3 -c '
import json
import os
import sys
try:
    value = json.load(sys.stdin).get(os.environ["FIELD"], [])
    print(len(value) if isinstance(value, list) else 0)
except Exception:
    print(0)
' <<< "$json" 2>/dev/null
}

compact() {
    echo "$1" | tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g' | cut -c 1-180
}

is_int() {
    echo "$1" | grep -qE '^[0-9]+$'
}

normalize_txid() {
    echo "$1" | tr -d '"[:space:]' | grep -Eio '^[0-9a-f]{64}$' | head -1
}

amount_ge() {
    python3 - "$1" "$2" <<'PY'
from decimal import Decimal, InvalidOperation
import sys
try:
    sys.exit(0 if Decimal(sys.argv[1] or "0") >= Decimal(sys.argv[2] or "0") else 1)
except (InvalidOperation, IndexError):
    sys.exit(1)
PY
}

now_ms() {
    python3 -c 'import time; print(int(time.time() * 1000))'
}

get_blocks() {
    local r
    r=$(rpc_timed "$1" "$POLL_RPC_TIMEOUT" getblockcount 2>/dev/null | tr -d '"[:space:]')
    if is_int "$r"; then
        echo "$r"
    fi
}

get_balance() {
    rpc_timed "$1" "$POLL_RPC_TIMEOUT" getbalance 2>/dev/null | tr -d '"' | tr -d ' ' | tr -d '\n'
}

get_mempool_count() {
    rpc_timed "$1" "$POLL_RPC_TIMEOUT" getrawmempool 2>/dev/null | python3 -c '
import json
import sys
try:
    print(len(json.load(sys.stdin)))
except Exception:
    print(-1)
' 2>/dev/null
}

get_listunspent_count() {
    local minconf=${2:-1}
    rpc_timed "$1" "$RPC_CALL_TIMEOUT" listunspent "$minconf" 9999999 2>/dev/null | python3 -c '
import json
import sys
try:
    print(len(json.load(sys.stdin)))
except Exception:
    print(0)
' 2>/dev/null
}

get_block_json() {
    local node=$1
    local height=$2
    local hash
    hash=$(rpc_timed "$node" "$POLL_RPC_TIMEOUT" getblockhash "$height" 2>/dev/null | tr -d '"[:space:]')
    [ -z "$hash" ] && return 1
    rpc_timed "$node" "$RPC_CALL_TIMEOUT" getblock "$hash" 2>/dev/null
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
staking=0
stakingmode=0
minstakeinterval=2
blockmaxsize=8000000
EOF
        [ $i -gt 0 ] && echo "addnode=127.0.0.1:$BASE_PORT" >> "$TEST_DIR/node$i/innova.conf"
    done

    for ((i=0; i<NUM_NODES; i++)); do
        "$INNOVAD" -datadir="$TEST_DIR/node$i" -regtest -pid="$TEST_DIR/node$i/tps.pid" > /dev/null 2>&1
        sleep 0.3
    done

    for ((a=0; a<60; a++)); do
        local ready=0
        for ((i=0; i<NUM_NODES; i++)); do
            rpc "$i" getinfo > /dev/null 2>&1 && ((ready++))
        done
        [ "$ready" -eq "$NUM_NODES" ] && log "All $NUM_NODES nodes online" && return 0
        sleep 1
    done
    fail "Nodes failed to start"
    return 1
}

wait_all_sync_at_or_above() {
    local target_height=$1
    local max_wait=${2:-30}

    for ((w=0; w<max_wait; w++)); do
        local synced=0
        for ((i=0; i<NUM_NODES; i++)); do
            local h
            h=$(get_blocks "$i")
            if is_int "$h" && [ "$h" -ge "$target_height" ]; then
                ((synced++))
            fi
        done
        [ "$synced" -eq "$NUM_NODES" ] && return 0
        sleep 1
    done
    return 1
}

cluster_lag() {
    local min=""
    local max=""
    for ((i=0; i<NUM_NODES; i++)); do
        local h
        h=$(get_blocks "$i")
        if is_int "$h"; then
            [ -z "$min" ] || [ "$h" -lt "$min" ] && min=$h
            [ -z "$max" ] || [ "$h" -gt "$max" ] && max=$h
        fi
    done
    if [ -z "$min" ] || [ -z "$max" ]; then
        echo "unknown"
    else
        echo "$((max - min))"
    fi
}

mine_until_height() {
    local node=$1
    local target_height=$2
    local max_per_block=${3:-$MINE_TIMEOUT_PER_BLOCK}
    local current
    current=$(get_blocks "$node")

    if ! is_int "$current"; then
        fail "Cannot read current height from node $node"
        return 1
    fi

    while [ "$current" -lt "$target_height" ]; do
        local before=$current
        rpc "$node" setgenerate true 1 > /dev/null 2>&1

        local waited=0
        local max_ticks=$((max_per_block * 10))
        while [ "$waited" -lt "$max_ticks" ]; do
            sleep 0.1
            current=$(get_blocks "$node")
            if is_int "$current" && [ "$current" -gt "$before" ]; then
                break
            fi
            waited=$((waited + 1))
        done

        if ! is_int "$current" || [ "$current" -le "$before" ]; then
            fail "Mining stalled at height $before while targeting $target_height"
            return 1
        fi

        if [ $((current % 25)) -eq 0 ] || [ "$current" -eq "$target_height" ]; then
            log "  ...height $current/$target_height"
        fi
    done

    return 0
}

mine_blocks() {
    local node=$1
    local count=$2
    local current
    current=$(get_blocks "$node")
    is_int "$current" || return 1
    mine_until_height "$node" "$((current + count))"
}

mine_until_mempool_empty() {
    local node=$1
    local max_blocks=${2:-200}
    local rounds=0
    local mp
    mp=$(get_mempool_count "$node")

    while [ "$mp" != "0" ] && [ "$rounds" -lt "$max_blocks" ]; do
        mine_blocks "$node" 1 || return 1
        rounds=$((rounds + 1))
        mp=$(get_mempool_count "$node")
        [ $((rounds % 20)) -eq 0 ] && log "  ...mined $rounds blocks, mempool: $mp"
    done

    [ "$mp" = "0" ]
}

analyze_block_window() {
    local start_height=$1
    local end_height=$2
    local submitted_txs=$3
    local adaptive_limit=$4
    local interval_file
    local metrics_file

    interval_file=$(mktemp "/tmp/innova_tps_intervals.XXXXXX")
    metrics_file=$(mktemp "/tmp/innova_tps_metrics.XXXXXX")

    local blocks=0
    local total_txs=0
    local total_user_txs=0
    local total_size=0
    local size_count=0
    local max_size=0
    local prev_time=""

    if [ "$start_height" -gt 0 ] 2>/dev/null; then
        local prev_block
        prev_block=$(get_block_json 0 "$((start_height - 1))")
        prev_time=$(json_field "$prev_block" "time")
        is_int "$prev_time" || prev_time=""
    fi

    for ((h=start_height; h<=end_height; h++)); do
        local block
        block=$(get_block_json 0 "$h")
        [ -z "$block" ] && continue

        local tx_count
        local user_count
        local size
        local btime
        tx_count=$(json_array_len "$block" "tx")
        user_count=$((tx_count > 0 ? tx_count - 1 : 0))
        size=$(json_field "$block" "size")
        btime=$(json_field "$block" "time")

        blocks=$((blocks + 1))
        total_txs=$((total_txs + tx_count))
        total_user_txs=$((total_user_txs + user_count))
        if is_int "$size"; then
            total_size=$((total_size + size))
            size_count=$((size_count + 1))
            [ "$size" -gt "$max_size" ] && max_size=$size
        fi

        if is_int "$btime"; then
            if [ -n "$prev_time" ]; then
                echo "$((btime - prev_time))" >> "$interval_file"
            fi
            prev_time=$btime
        fi
    done

    python3 - "$interval_file" "$blocks" "$total_txs" "$total_user_txs" "$submitted_txs" "$total_size" "$size_count" "$max_size" "$adaptive_limit" > "$metrics_file" <<'PY'
import sys

interval_path = sys.argv[1]
blocks = int(sys.argv[2])
total_txs = int(sys.argv[3])
total_user_txs = int(sys.argv[4])
submitted_txs = int(sys.argv[5])
total_size = int(sys.argv[6])
size_count = int(sys.argv[7])
max_size = int(sys.argv[8])
adaptive_limit = int(sys.argv[9])

intervals = []
try:
    with open(interval_path, "r", encoding="utf-8") as handle:
        intervals = [int(line.strip()) for line in handle if line.strip()]
except OSError:
    pass

def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    idx = int(round((len(values) - 1) * pct))
    return float(values[idx])

avg_interval = (sum(intervals) / len(intervals)) if intervals else 0.0
median_interval = percentile(intervals, 0.50)
p90_interval = percentile(intervals, 0.90)
avg_size = (total_size / size_count) if size_count else 0.0
tx_per_block = (submitted_txs / blocks) if blocks else 0.0
observed_user_tx_per_block = (total_user_txs / blocks) if blocks else 0.0
util_avg = (avg_size / adaptive_limit * 100.0) if adaptive_limit else 0.0
util_max = (max_size / adaptive_limit * 100.0) if adaptive_limit else 0.0
block_capacity_tps = (tx_per_block / avg_interval) if avg_interval > 0 else 0.0

print(f"WINDOW_BLOCKS={blocks}")
print(f"WINDOW_TOTAL_TXS={total_txs}")
print(f"WINDOW_USER_TXS={total_user_txs}")
print(f"WINDOW_TX_PER_BLOCK={tx_per_block:.2f}")
print(f"WINDOW_OBSERVED_USER_TX_PER_BLOCK={observed_user_tx_per_block:.2f}")
print(f"WINDOW_AVG_INTERVAL={avg_interval:.2f}")
print(f"WINDOW_MEDIAN_INTERVAL={median_interval:.2f}")
print(f"WINDOW_P90_INTERVAL={p90_interval:.2f}")
print(f"WINDOW_AVG_SIZE={avg_size:.0f}")
print(f"WINDOW_MAX_SIZE={max_size}")
print(f"WINDOW_UTIL_AVG={util_avg:.2f}")
print(f"WINDOW_UTIL_MAX={util_max:.2f}")
print(f"WINDOW_BLOCK_CAPACITY_TPS={block_capacity_tps:.2f}")
PY

    . "$metrics_file"
    rm -f "$interval_file" "$metrics_file"

    log "tx_per_block=$WINDOW_TX_PER_BLOCK, observed_user_tx_per_block=$WINDOW_OBSERVED_USER_TX_PER_BLOCK, blocks=$WINDOW_BLOCKS"
    log "block_interval_avg=${WINDOW_AVG_INTERVAL}s, median=${WINDOW_MEDIAN_INTERVAL}s, p90=${WINDOW_P90_INTERVAL}s"
    log "block sizes: avg=${WINDOW_AVG_SIZE} bytes, max=${WINDOW_MAX_SIZE} bytes, util_avg=${WINDOW_UTIL_AVG}%, util_max=${WINDOW_UTIL_MAX}%"
    log "block_capacity_tps=$WINDOW_BLOCK_CAPACITY_TPS (observed under this submitted load)"
}

finish() {
    local exit_code=$1
    header "Cleanup"
    cleanup
    header "RESULTS"
    echo -e "${GREEN}PASSED: $PASSED${NC}"
    echo -e "${RED}FAILED: $FAILED${NC}"
    exit "$exit_code"
}

# =====================================================================
header "IDAG TPS Measurement Test"
# =====================================================================

[ ! -f "$INNOVAD" ] && fail "innovad not found at $INNOVAD" && exit 1
setup || exit 1

# =====================================================================
header "Phase 1: Mine confirmed spendable funds"
# =====================================================================

log "Mining to height $INITIAL_HEIGHT with height polling"
mine_until_height 0 "$INITIAL_HEIGHT" || finish 1
wait_all_sync_at_or_above "$INITIAL_HEIGHT" 60 || fail "Cluster did not sync to height $INITIAL_HEIGHT"

HEIGHT=$(get_blocks 0)
BALANCE=$(get_balance 0)
UNSPENT_INITIAL=$(get_listunspent_count 0 1)
LAG=$(cluster_lag)
log "Height=$HEIGHT, balance=$BALANCE INN, spendable_utxos=$UNSPENT_INITIAL, sync_lag=$LAG blocks"

if amount_ge "$BALANCE" "$TARGET_UTXOS"; then
    success "Wallet has confirmed spendable funds for $TARGET_UTXOS split outputs"
else
    fail "Wallet balance $BALANCE is below requested split total $TARGET_UTXOS"
    finish 1
fi

# =====================================================================
header "Phase 2: Create and confirm UTXO fuel"
# =====================================================================

log "Splitting coins into $TARGET_UTXOS UTXOs of $UTXO_AMOUNT INN"
UTXO_CREATED=0
SENDMANY_FAILED=0
BATCHES=$(( (TARGET_UTXOS + UTXO_BATCH_SIZE - 1) / UTXO_BATCH_SIZE ))

for ((batch=0; batch<BATCHES; batch++)); do
    REMAINING=$((TARGET_UTXOS - UTXO_CREATED))
    [ "$REMAINING" -le 0 ] && break
    THIS_BATCH=$UTXO_BATCH_SIZE
    [ "$REMAINING" -lt "$THIS_BATCH" ] && THIS_BATCH=$REMAINING

    ADDRS_JSON="{"
    for ((j=0; j<THIS_BATCH; j++)); do
        A=$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')
        [ "$j" -gt 0 ] && ADDRS_JSON+=","
        ADDRS_JSON+="\"$A\":$UTXO_AMOUNT"
    done
    ADDRS_JSON+="}"

    RESULT=$(rpc_timed 0 "$RPC_CALL_TIMEOUT" sendmany "" "$ADDRS_JSON")
    TXID=$(normalize_txid "$RESULT")
    if [ -n "$TXID" ]; then
        UTXO_CREATED=$((UTXO_CREATED + THIS_BATCH))
    else
        SENDMANY_FAILED=$((SENDMANY_FAILED + 1))
        fail "sendmany batch $batch failed: $(compact "$RESULT")"
        break
    fi

    [ $((UTXO_CREATED % 250)) -eq 0 ] && log "  ...$UTXO_CREATED split outputs submitted"
done

[ "$UTXO_CREATED" -ge "$TARGET_UTXOS" ] && success "UTXO split submitted: $UTXO_CREATED outputs" || fail "Only $UTXO_CREATED split outputs submitted"
[ "$SENDMANY_FAILED" -eq 0 ] || finish 1

SPLIT_MP=$(get_mempool_count 0)
log "Split mempool entries before confirmation: $SPLIT_MP"
SPLIT_START_HEIGHT=$(get_blocks 0)
mine_until_mempool_empty 0 50 || fail "Split transactions did not fully confirm"
SPLIT_END_HEIGHT=$(get_blocks 0)
wait_all_sync_at_or_above "$SPLIT_END_HEIGHT" 60 || fail "Cluster did not sync after split confirmations"

SPENDABLE_UTXOS=$(get_listunspent_count 0 1)
log "Spendable UTXOs after split confirmation: $SPENDABLE_UTXOS"
if [ "$SPENDABLE_UTXOS" -ge "$MIN_SPENDABLE_UTXOS" ] 2>/dev/null; then
    success "Spendable UTXO validation: $SPENDABLE_UTXOS available"
else
    fail "Spendable UTXO validation failed: $SPENDABLE_UTXOS available, need $MIN_SPENDABLE_UTXOS"
    finish 1
fi

# =====================================================================
header "Phase 3: Adaptive block size status"
# =====================================================================

DAGINFO=$(rpc 0 getdaginfo 2>/dev/null)
DAG_ACTIVE=$(json_field "$DAGINFO" "dag_active")
DK_ACTIVE=$(json_field "$DAGINFO" "dagknight_active")
ADAPTIVE_LIMIT=$(json_field "$DAGINFO" "adaptive_block_limit")
ADAPTIVE_CEIL=$(json_field "$DAGINFO" "adaptive_block_ceiling")
ADAPTIVE_FLOOR=$(json_field "$DAGINFO" "adaptive_block_floor")
DAG_ENTRIES=$(json_field "$DAGINFO" "dag_entries")
DAG_TIPS=$(json_field "$DAGINFO" "dag_tips")
INFERRED_K=$(json_field "$DAGINFO" "inferred_k")
ALGO=$(json_field "$DAGINFO" "ordering_algorithm")

log "DAG: active=$DAG_ACTIVE, DAGKNIGHT=$DK_ACTIVE, entries=$DAG_ENTRIES, tips=$DAG_TIPS, inferred_k=$INFERRED_K, algo=$ALGO"
log "Adaptive: limit=$ADAPTIVE_LIMIT, ceiling=$ADAPTIVE_CEIL, floor=$ADAPTIVE_FLOOR"
[ "$DAG_ACTIVE" = "true" ] && success "DAG active before TPS measurement" || fail "DAG not active"
[ -n "$ADAPTIVE_LIMIT" ] && success "Adaptive block sizing reporting: limit=$ADAPTIVE_LIMIT" || fail "Adaptive not reporting"

# =====================================================================
header "Phase 4: RPC transaction submission"
# =====================================================================

log "Sending $TARGET_TXS transactions as fast as wallet RPC accepts them"

SPAM_ADDRS=()
for ((i=0; i<20; i++)); do
    SPAM_ADDRS+=("$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')")
done

TX_SENT=0
TX_FAILED=0
FAIL_STREAK=0
START_MS=$(now_ms)

for ((t=0; t<TARGET_TXS; t++)); do
    TARGET=${SPAM_ADDRS[$((t % 20))]}
    RESULT=$(rpc 0 sendtoaddress "$TARGET" 0.001 2>/dev/null)
    TXID=$(normalize_txid "$RESULT")
    if [ -n "$TXID" ]; then
        TX_SENT=$((TX_SENT + 1))
        FAIL_STREAK=0
    else
        TX_FAILED=$((TX_FAILED + 1))
        FAIL_STREAK=$((FAIL_STREAK + 1))
        [ "$FAIL_STREAK" -ge 30 ] && log "  30 consecutive failures, stopping" && break
    fi

    [ $((TX_SENT % 500)) -eq 0 ] && [ "$TX_SENT" -gt 0 ] && log "  ...$TX_SENT sent"
done

END_MS=$(now_ms)
SUBMIT_ELAPSED_MS=$((END_MS - START_MS))
[ "$SUBMIT_ELAPSED_MS" -le 0 ] && SUBMIT_ELAPSED_MS=1
RPC_SUBMIT_TPS=$(python3 - "$TX_SENT" "$SUBMIT_ELAPSED_MS" <<'PY'
import sys
txs = int(sys.argv[1])
elapsed_ms = max(int(sys.argv[2]), 1)
print(f"{txs * 1000.0 / elapsed_ms:.2f}")
PY
)
log "Submitted $TX_SENT txs in ${SUBMIT_ELAPSED_MS}ms ($TX_FAILED failed)"
log "rpc_submit_tps=$RPC_SUBMIT_TPS"

[ "$TX_SENT" -ge "$((TARGET_TXS / 2))" ] && success "TX blast submitted $TX_SENT txs" || fail "TX blast submitted only $TX_SENT txs"

# =====================================================================
header "Phase 5: Mine mempool and measure confirmation window"
# =====================================================================

MEMPOOL=$(get_mempool_count 0)
log "Mempool: $MEMPOOL txs to mine"

MINE_START_MS=$(now_ms)
BLOCKS_BEFORE=$(get_blocks 0)
mine_until_mempool_empty 0 200 || fail "TPS mempool did not fully drain"
MINE_END_MS=$(now_ms)
BLOCKS_AFTER=$(get_blocks 0)
MINE_ELAPSED_MS=$((MINE_END_MS - MINE_START_MS))
[ "$MINE_ELAPSED_MS" -le 0 ] && MINE_ELAPSED_MS=1
BLOCKS_MINED=$((BLOCKS_AFTER - BLOCKS_BEFORE))
FINAL_MP=$(get_mempool_count 0)

CONFIRMED_WALL_CLOCK_TPS=$(python3 - "$TX_SENT" "$MINE_ELAPSED_MS" <<'PY'
import sys
txs = int(sys.argv[1])
elapsed_ms = max(int(sys.argv[2]), 1)
print(f"{txs * 1000.0 / elapsed_ms:.2f}")
PY
)

log "Mining complete: $BLOCKS_MINED blocks in ${MINE_ELAPSED_MS}ms"
log "confirmed_wall_clock_tps=$CONFIRMED_WALL_CLOCK_TPS"
log "Final mempool: $FINAL_MP"

[ "$FINAL_MP" = "0" ] && success "Mempool drained after TPS measurement" || fail "Final mempool has $FINAL_MP txs"
[ "$BLOCKS_MINED" -gt 0 ] 2>/dev/null && success "Confirmations mined across $BLOCKS_MINED blocks" || fail "No blocks mined for TPS confirmation"

if [ "$BLOCKS_AFTER" -gt "$BLOCKS_BEFORE" ] 2>/dev/null; then
    analyze_block_window "$((BLOCKS_BEFORE + 1))" "$BLOCKS_AFTER" "$TX_SENT" "${ADAPTIVE_LIMIT:-0}"
fi

# =====================================================================
header "Phase 6: Post-run DAG and sync status"
# =====================================================================

DAGINFO2=$(rpc 0 getdaginfo 2>/dev/null)
ADAPTIVE2=$(json_field "$DAGINFO2" "adaptive_block_limit")
DAG_ENTRIES2=$(json_field "$DAGINFO2" "dag_entries")
DAG_TIPS2=$(json_field "$DAGINFO2" "dag_tips")
INFERRED_K2=$(json_field "$DAGINFO2" "inferred_k")
ALGO2=$(json_field "$DAGINFO2" "ordering_algorithm")
FINAL_HEIGHT=$(get_blocks 0)
wait_all_sync_at_or_above "$FINAL_HEIGHT" 60 || fail "Cluster did not sync after TPS run"
SYNC_LAG=$(cluster_lag)

log "Post-run DAG: entries=$DAG_ENTRIES2, tips=$DAG_TIPS2, inferred_k=$INFERRED_K2, algo=$ALGO2, adaptive_limit=$ADAPTIVE2"
log "Final height=$FINAL_HEIGHT, sync_lag=$SYNC_LAG blocks"
[ "$SYNC_LAG" = "0" ] && success "Final sync: all $NUM_NODES nodes aligned" || fail "Final sync lag: $SYNC_LAG blocks"

echo ""
echo "=== Performance Summary ==="
echo "  TX submitted:              $TX_SENT"
echo "  TX failed:                 $TX_FAILED"
echo "  rpc_submit_tps:            $RPC_SUBMIT_TPS"
echo "  confirmed_wall_clock_tps:  $CONFIRMED_WALL_CLOCK_TPS"
echo "  tx_per_block:              ${WINDOW_TX_PER_BLOCK:-0}"
echo "  block_interval_avg:        ${WINDOW_AVG_INTERVAL:-0}s"
echo "  block_interval_median:     ${WINDOW_MEDIAN_INTERVAL:-0}s"
echo "  block_interval_p90:        ${WINDOW_P90_INTERVAL:-0}s"
echo "  block_capacity_tps:        ${WINDOW_BLOCK_CAPACITY_TPS:-0}"
echo "  Blocks mined:              $BLOCKS_MINED"
echo "  Max block size:            ${WINDOW_MAX_SIZE:-0} bytes"
echo "  Avg block size:            ${WINDOW_AVG_SIZE:-0} bytes"
echo "  Adaptive limit:            $ADAPTIVE2"
echo "  Spendable UTXOs:           $SPENDABLE_UTXOS"
echo "  timing source:             observed block timestamps (netmhashps intentionally ignored)"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All TPS measurement checks passed!${NC}"
    finish 0
else
    echo -e "${RED}$FAILED test(s) failed${NC}"
    finish 1
fi
