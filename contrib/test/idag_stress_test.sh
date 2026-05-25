#!/bin/bash
# IDAG Heavy Stress Test v3 - multi-node funding, DAG/PoS, and tx flow metrics

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="${TEST_DIR:-/tmp/innova_stress}"
NUM_NODES="${NUM_NODES:-8}"
BASE_PORT="${BASE_PORT:-28000}"
BASE_RPC="${BASE_RPC:-28100}"
RPCUSER="${RPCUSER:-stresstest}"
RPCPASS="${RPCPASS:-stresstestpass}"

WORKER_FUNDING="${WORKER_FUNDING:-250}"
WORKER_MIN_BALANCE="${WORKER_MIN_BALANCE:-200}"
STRESS_TXS="${STRESS_TXS:-300}"
CROSS_TXS_PER_NODE="${CROSS_TXS_PER_NODE:-20}"
MIN_CROSS_SENT="${MIN_CROSS_SENT:-50}"
ROOT_SPLIT_UTXOS="${ROOT_SPLIT_UTXOS:-$STRESS_TXS}"
ROOT_SPLIT_AMOUNT="${ROOT_SPLIT_AMOUNT:-0.5}"
WORKER_SPLIT_UTXOS="${WORKER_SPLIT_UTXOS:-$((CROSS_TXS_PER_NODE + 10))}"
WORKER_SPLIT_AMOUNT="${WORKER_SPLIT_AMOUNT:-1.0}"
RPC_CALL_TIMEOUT="${RPC_CALL_TIMEOUT:-20}"
POLL_RPC_TIMEOUT="${POLL_RPC_TIMEOUT:-5}"
MINE_TIMEOUT_PER_BLOCK="${MINE_TIMEOUT_PER_BLOCK:-30}"
COINBASE_SPEND_DELAY="${COINBASE_SPEND_DELAY:-12}"
BOOTSTRAP_HEIGHT="${BOOTSTRAP_HEIGHT:-0}"

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

rpc_timed() {
    local node=$1
    local timeout=$2
    shift 2
    local port=$((BASE_RPC + node))

    python3 - "$timeout" "$INNOVAD" "$TEST_DIR/node$node" "$RPCUSER" "$RPCPASS" "$port" "$@" <<'PY'
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
            rpc "$i" getinfo > /dev/null 2>&1 && ((ready++))
        done
        [ $ready -eq "$NUM_NODES" ] && log "All $NUM_NODES nodes online" && return 0
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
        [ $synced -eq "$NUM_NODES" ] && return 0
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

wait_mempool_empty() {
    local node=$1
    local max_wait=${2:-30}

    for ((w=0; w<max_wait; w++)); do
        local mp
        mp=$(get_mempool_count "$node")
        [ "$mp" = "0" ] && return 0
        sleep 1
    done
    return 1
}

wait_mempool_at_least() {
    local node=$1
    local target=$2
    local max_wait=${3:-10}

    for ((w=0; w<max_wait; w++)); do
        local mp
        mp=$(get_mempool_count "$node")
        if [ "$mp" -ge "$target" ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

mine_until_mempool_empty() {
    local node=$1
    local max_blocks=${2:-100}
    local rounds=0
    local mp
    mp=$(get_mempool_count "$node")

    while [ "$mp" != "0" ] && [ "$rounds" -lt "$max_blocks" ]; do
        mine_blocks "$node" 1 || return 1
        rounds=$((rounds + 1))
        mp=$(get_mempool_count "$node")
        [ $((rounds % 10)) -eq 0 ] && log "  ...mined $rounds blocks, mempool: $mp"
    done

    [ "$mp" = "0" ]
}

create_split_outputs() {
    local node=$1
    local outputs=$2
    local amount=$3
    local label="$4"

    [ "$outputs" -le 0 ] && return 0

    local addrs_json="{"
    for ((j=0; j<outputs; j++)); do
        local addr
        addr=$(rpc "$node" getnewaddress 2>/dev/null | tr -d '"[:space:]')
        if [ -z "$addr" ]; then
            fail "$label split failed: could not get address $j from node $node"
            return 1
        fi
        [ "$j" -gt 0 ] && addrs_json+=","
        addrs_json+="\"$addr\":$amount"
    done
    addrs_json+="}"

    local result
    local txid
    result=$(rpc_timed "$node" "$RPC_CALL_TIMEOUT" sendmany "" "$addrs_json")
    txid=$(normalize_txid "$result")
    if [ -z "$txid" ]; then
        fail "$label split failed: $(compact "$result")"
        return 1
    fi

    log "  $label split txid=$txid outputs=$outputs amount=$amount"
    return 0
}

analyze_block_window() {
    local start_height=$1
    local end_height=$2
    local label="$3"
    local user_txs=${4:-0}
    local adaptive_limit=${5:-0}
    local interval_file
    local metrics_file

    interval_file=$(mktemp "/tmp/innova_stress_intervals.XXXXXX")
    metrics_file=$(mktemp "/tmp/innova_stress_metrics.XXXXXX")

    local blocks=0
    local total_txs=0
    local total_user_txs=0
    local total_size=0
    local size_count=0
    local max_size=0
    local pos_blocks=0
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
        local flags
        tx_count=$(json_array_len "$block" "tx")
        user_count=$((tx_count > 0 ? tx_count - 1 : 0))
        size=$(json_field "$block" "size")
        btime=$(json_field "$block" "time")
        flags=$(json_field "$block" "flags")

        blocks=$((blocks + 1))
        total_txs=$((total_txs + tx_count))
        total_user_txs=$((total_user_txs + user_count))
        if is_int "$size"; then
            total_size=$((total_size + size))
            size_count=$((size_count + 1))
            [ "$size" -gt "$max_size" ] && max_size=$size
        fi
        echo "$flags" | grep -qi "proof-of-stake" && pos_blocks=$((pos_blocks + 1))

        if is_int "$btime"; then
            if [ -n "$prev_time" ]; then
                echo "$((btime - prev_time))" >> "$interval_file"
            fi
            prev_time=$btime
        fi
    done

    python3 - "$interval_file" "$blocks" "$total_txs" "$total_user_txs" "$user_txs" "$total_size" "$size_count" "$max_size" "$adaptive_limit" "$pos_blocks" > "$metrics_file" <<'PY'
import sys

interval_path = sys.argv[1]
blocks = int(sys.argv[2])
total_txs = int(sys.argv[3])
total_user_txs = int(sys.argv[4])
submitted_user_txs = int(sys.argv[5])
total_size = int(sys.argv[6])
size_count = int(sys.argv[7])
max_size = int(sys.argv[8])
adaptive_limit = int(sys.argv[9])
pos_blocks = int(sys.argv[10])

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
avg_tx_block = (total_user_txs / blocks) if blocks else 0.0
confirmed_tx_block = (submitted_user_txs / blocks) if blocks else 0.0
util_avg = (avg_size / adaptive_limit * 100.0) if adaptive_limit else 0.0
util_max = (max_size / adaptive_limit * 100.0) if adaptive_limit else 0.0
capacity_tps = (confirmed_tx_block / avg_interval) if avg_interval > 0 else 0.0

print(f"WINDOW_BLOCKS={blocks}")
print(f"WINDOW_TOTAL_TXS={total_txs}")
print(f"WINDOW_USER_TXS={total_user_txs}")
print(f"WINDOW_AVG_TX_BLOCK={avg_tx_block:.2f}")
print(f"WINDOW_CONFIRMED_TX_BLOCK={confirmed_tx_block:.2f}")
print(f"WINDOW_AVG_INTERVAL={avg_interval:.2f}")
print(f"WINDOW_MEDIAN_INTERVAL={median_interval:.2f}")
print(f"WINDOW_P90_INTERVAL={p90_interval:.2f}")
print(f"WINDOW_AVG_SIZE={avg_size:.0f}")
print(f"WINDOW_MAX_SIZE={max_size}")
print(f"WINDOW_UTIL_AVG={util_avg:.2f}")
print(f"WINDOW_UTIL_MAX={util_max:.2f}")
print(f"WINDOW_CAPACITY_TPS={capacity_tps:.2f}")
print(f"WINDOW_POS_BLOCKS={pos_blocks}")
PY

    . "$metrics_file"
    rm -f "$interval_file" "$metrics_file"

    log "$label: blocks=$WINDOW_BLOCKS, submitted_tx/block=$WINDOW_CONFIRMED_TX_BLOCK, observed_user_tx/block=$WINDOW_AVG_TX_BLOCK"
    log "$label intervals: avg=${WINDOW_AVG_INTERVAL}s, median=${WINDOW_MEDIAN_INTERVAL}s, p90=${WINDOW_P90_INTERVAL}s"
    log "$label block size: avg=${WINDOW_AVG_SIZE} bytes, max=${WINDOW_MAX_SIZE} bytes, util_avg=${WINDOW_UTIL_AVG}%, util_max=${WINDOW_UTIL_MAX}%"
    log "$label observed block_capacity_tps=${WINDOW_CAPACITY_TPS}, PoS blocks=$WINDOW_POS_BLOCKS"
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
header "IDAG Stress Test v3 ($NUM_NODES nodes)"
# =====================================================================

[ ! -f "$INNOVAD" ] && fail "innovad not found at $INNOVAD" && exit 1
setup_cluster || exit 1

# =====================================================================
header "Phase 1: Mine spendable DAG-era funding"
# =====================================================================

REQUIRED_FUNDING=$(python3 - "$NUM_NODES" "$WORKER_FUNDING" <<'PY'
from decimal import Decimal
import sys
nodes = int(sys.argv[1])
funding = Decimal(sys.argv[2])
print(funding * (nodes - 1))
PY
)

COMPUTED_BOOTSTRAP=$(python3 - "$NUM_NODES" "$WORKER_FUNDING" "$COINBASE_SPEND_DELAY" <<'PY'
from decimal import Decimal, ROUND_UP
import sys
nodes = int(sys.argv[1])
funding = Decimal(sys.argv[2])
delay = int(sys.argv[3])
required_rewards = int(((funding * (nodes - 1)) / Decimal("50")).to_integral_value(rounding=ROUND_UP))
print(max(15, required_rewards + delay + 5))
PY
)

if [ "$BOOTSTRAP_HEIGHT" = "0" ]; then
    BOOTSTRAP_HEIGHT=$COMPUTED_BOOTSTRAP
fi

log "Mining to height $BOOTSTRAP_HEIGHT for DAG activation and at least $REQUIRED_FUNDING INN spendable funding"
mine_until_height 0 "$BOOTSTRAP_HEIGHT" || finish 1
wait_all_sync_at_or_above "$BOOTSTRAP_HEIGHT" 60 || fail "Cluster did not sync to height $BOOTSTRAP_HEIGHT"

HEIGHT=$(get_blocks 0)
ROOT_BALANCE=$(get_balance 0)
LAG=$(cluster_lag)
log "Node 0 height=$HEIGHT balance=$ROOT_BALANCE INN, sync_lag=$LAG blocks"

if amount_ge "$ROOT_BALANCE" "$REQUIRED_FUNDING"; then
    success "Node 0 has spendable funding: $ROOT_BALANCE INN"
else
    fail "Node 0 spendable balance $ROOT_BALANCE is below required $REQUIRED_FUNDING"
    finish 1
fi

# =====================================================================
header "Phase 2: Distribute and confirm worker funds"
# =====================================================================

ADDRS=()
for ((i=0; i<NUM_NODES; i++)); do
    ADDR=$(rpc "$i" getnewaddress 2>/dev/null | tr -d '"[:space:]')
    if [ -z "$ADDR" ]; then
        fail "Could not get address from node $i"
        finish 1
    fi
    ADDRS+=("$ADDR")
done

log "Sending $WORKER_FUNDING INN to each worker node"
DIST_FAILED=0
for ((i=1; i<NUM_NODES; i++)); do
    RESULT=$(rpc_timed 0 "$RPC_CALL_TIMEOUT" sendtoaddress "${ADDRS[$i]}" "$WORKER_FUNDING")
    TXID=$(normalize_txid "$RESULT")
    if [ -n "$TXID" ]; then
        log "  node $i funding txid=$TXID"
    else
        fail "Funding node $i failed: $(compact "$RESULT")"
        DIST_FAILED=$((DIST_FAILED + 1))
    fi
done

if [ "$DIST_FAILED" -ne 0 ]; then
    finish 1
fi
success "All worker funding RPCs returned txids"

MP_BEFORE_DIST=$(get_mempool_count 0)
log "Funding mempool entries before confirmation: $MP_BEFORE_DIST"
DIST_START_HEIGHT=$(get_blocks 0)
mine_until_mempool_empty 0 10 || fail "Funding transactions did not fully confirm"
DIST_END_HEIGHT=$(get_blocks 0)
wait_all_sync_at_or_above "$DIST_END_HEIGHT" 60 || fail "Cluster did not sync after funding confirmations"
wait_mempool_empty 0 20 || fail "Node 0 mempool not empty after funding confirmations"

FUNDED=0
for ((i=1; i<NUM_NODES; i++)); do
    BAL=$(get_balance "$i")
    if amount_ge "$BAL" "$WORKER_MIN_BALANCE"; then
        FUNDED=$((FUNDED + 1))
        [ $i -le 3 ] && log "  Node $i balance: $BAL INN"
    else
        warn "  Node $i balance below threshold: ${BAL:-0} INN"
    fi
done
log "$FUNDED/$((NUM_NODES - 1)) worker nodes funded above $WORKER_MIN_BALANCE INN"
[ "$FUNDED" -eq "$((NUM_NODES - 1))" ] && success "All worker nodes have confirmed spendable funds" || fail "Only $FUNDED worker nodes funded"

# =====================================================================
header "Phase 3: Split confirmed spam UTXOs"
# =====================================================================

log "Creating confirmed node-0 spam fuel: $ROOT_SPLIT_UTXOS outputs of $ROOT_SPLIT_AMOUNT INN"
create_split_outputs 0 "$ROOT_SPLIT_UTXOS" "$ROOT_SPLIT_AMOUNT" "node 0" || finish 1

log "Creating confirmed worker spam fuel: $WORKER_SPLIT_UTXOS outputs of $WORKER_SPLIT_AMOUNT INN per worker"
SPLIT_FAILED=0
for ((i=1; i<NUM_NODES; i++)); do
    create_split_outputs "$i" "$WORKER_SPLIT_UTXOS" "$WORKER_SPLIT_AMOUNT" "node $i" || SPLIT_FAILED=$((SPLIT_FAILED + 1))
done

if [ "$SPLIT_FAILED" -ne 0 ]; then
    finish 1
fi

EXPECTED_SPLIT_TXS=$NUM_NODES
wait_mempool_at_least 0 "$EXPECTED_SPLIT_TXS" 15 || warn "Node 0 mempool did not see all $EXPECTED_SPLIT_TXS split txs before first split confirmation"
SPLIT_MP=$(get_mempool_count 0)
log "Split mempool entries before confirmation: $SPLIT_MP"
mine_until_mempool_empty 0 30 || fail "Split transactions did not fully confirm"
sleep 2
SPLIT_LATE_MP=$(get_mempool_count 0)
if [ "$SPLIT_LATE_MP" != "0" ]; then
    log "Late split propagation left $SPLIT_LATE_MP txs; mining another split drain pass"
    mine_until_mempool_empty 0 20 || fail "Late split transactions did not fully confirm"
fi
SPLIT_END_HEIGHT=$(get_blocks 0)
wait_all_sync_at_or_above "$SPLIT_END_HEIGHT" 60 || fail "Cluster did not sync after split confirmations"

ROOT_UNSPENT=$(get_listunspent_count 0 1)
log "Node 0 spendable UTXOs after split: $ROOT_UNSPENT"
if [ "$ROOT_UNSPENT" -ge "$ROOT_SPLIT_UTXOS" ] 2>/dev/null; then
    success "Node 0 spam fuel confirmed: $ROOT_UNSPENT spendable UTXOs"
else
    fail "Node 0 has only $ROOT_UNSPENT spendable UTXOs after split"
fi

WORKER_FUEL=0
for ((i=1; i<NUM_NODES; i++)); do
    UTXOS=$(get_listunspent_count "$i" 1)
    if [ "$UTXOS" -ge "$CROSS_TXS_PER_NODE" ] 2>/dev/null; then
        WORKER_FUEL=$((WORKER_FUEL + 1))
        [ "$i" -le 3 ] && log "  Node $i spendable UTXOs: $UTXOS"
    else
        warn "  Node $i has only $UTXOS spendable UTXOs"
    fi
done
[ "$WORKER_FUEL" -eq "$((NUM_NODES - 1))" ] && success "All workers have enough spam UTXOs" || fail "Only $WORKER_FUEL workers have enough spam UTXOs"

# =====================================================================
header "Phase 4: DAG, DAGKNIGHT, and finality status"
# =====================================================================

DAGINFO=$(rpc 0 getdaginfo 2>/dev/null)
DAG_ACTIVE=$(json_field "$DAGINFO" "dag_active")
DK_ACTIVE=$(json_field "$DAGINFO" "dagknight_active")
DAG_ENTRIES=$(json_field "$DAGINFO" "dag_entries")
DAG_TIPS=$(json_field "$DAGINFO" "dag_tips")
INFERRED_K=$(json_field "$DAGINFO" "inferred_k")
ALGO=$(json_field "$DAGINFO" "ordering_algorithm")
ADAPTIVE_LIMIT=$(json_field "$DAGINFO" "adaptive_block_limit")

log "DAG: active=$DAG_ACTIVE, DAGKNIGHT=$DK_ACTIVE, entries=$DAG_ENTRIES, tips=$DAG_TIPS, inferred_k=$INFERRED_K, algo=$ALGO"
[ "$DAG_ACTIVE" = "true" ] && success "DAG active with $DAG_ENTRIES entries" || fail "DAG not active"
[ "$DK_ACTIVE" = "true" ] && success "DAGKNIGHT ordering active" || fail "DAGKNIGHT not active"

FININFO=$(rpc 0 getfinalityinfo 2>/dev/null)
TIER=$(json_field "$FININFO" "finality_tier")
VOTERS=$(json_field "$FININFO" "current_epoch_voters")
FINALIZED_HEIGHT=$(json_field "$FININFO" "finalized_height")
log "Finality: tier=$TIER, voters=$VOTERS, finalized_height=$FINALIZED_HEIGHT"
success "Finality RPC responded: tier=$TIER"

# =====================================================================
header "Phase 5: Wait for PoS blocks"
# =====================================================================

log "Waiting up to 60s for PoS blocks to appear..."
POS_FOUND=0
START_POS_HEIGHT=$(get_blocks 0)
LAST_POS_HEIGHT=$START_POS_HEIGHT
for ((w=0; w<60; w++)); do
    H=$(get_blocks 0)
    if is_int "$H" && is_int "$LAST_POS_HEIGHT" && [ "$H" -gt "$LAST_POS_HEIGHT" ]; then
        for ((ph=LAST_POS_HEIGHT + 1; ph<=H; ph++)); do
            BLOCK=$(get_block_json 0 "$ph")
            FLAGS=$(json_field "$BLOCK" "flags")
            if echo "$FLAGS" | grep -qi "proof-of-stake"; then
                POS_FOUND=$((POS_FOUND + 1))
                [ "$POS_FOUND" -eq 1 ] && log "First PoS block at height $ph"
            fi
        done
        LAST_POS_HEIGHT=$H
    fi
    [ "$POS_FOUND" -ge 3 ] && break
    sleep 1
done

log "PoS blocks found: $POS_FOUND in 60s window"
[ "$POS_FOUND" -gt 0 ] && success "PoS staking in DAG: $POS_FOUND blocks produced" || warn "No PoS blocks yet (stress continues with PoW mining)"

# =====================================================================
header "Phase 6: RPC submission sample"
# =====================================================================

BLOCKS_BEFORE=$(get_blocks 0)
log "Sending up to $STRESS_TXS node-0 transactions as fast as wallet RPC accepts them"

SPAM_ADDRS=()
for ((i=0; i<10; i++)); do
    SPAM_ADDRS+=("$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')")
done

TX_SENT=0
TX_FAILED=0
FAIL_STREAK=0
START_MS=$(now_ms)

for ((t=0; t<STRESS_TXS; t++)); do
    TARGET=${SPAM_ADDRS[$((t % 10))]}
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

    [ $((TX_SENT % 100)) -eq 0 ] && [ "$TX_SENT" -gt 0 ] && log "  ...$TX_SENT sent"
done

END_MS=$(now_ms)
ELAPSED_MS=$((END_MS - START_MS))
[ "$ELAPSED_MS" -le 0 ] && ELAPSED_MS=1
RPC_TPS=$((TX_SENT * 1000 / ELAPSED_MS))
log "Submitted $TX_SENT txs in ${ELAPSED_MS}ms ($TX_FAILED failed)"
log "rpc_submit_tps=$RPC_TPS"

[ "$TX_SENT" -ge 50 ] && success "RPC submission sample: $TX_SENT txs at ~$RPC_TPS TPS" || fail "Only $TX_SENT txs submitted"

# =====================================================================
header "Phase 7: Mine node-0 mempool and measure block window"
# =====================================================================

MEMPOOL_BEFORE=$(get_mempool_count 0)
log "Mempool before mining: $MEMPOOL_BEFORE txs"
MINE_START_MS=$(now_ms)
mine_until_mempool_empty 0 100 || fail "Node-0 spam mempool did not fully drain"
MINE_END_MS=$(now_ms)
BLOCKS_AFTER=$(get_blocks 0)
MINE_ELAPSED_MS=$((MINE_END_MS - MINE_START_MS))
[ "$MINE_ELAPSED_MS" -le 0 ] && MINE_ELAPSED_MS=1
BLOCKS_MINED=$((BLOCKS_AFTER - BLOCKS_BEFORE))
CONFIRMED_WALL_CLOCK_TPS=$(python3 - "$TX_SENT" "$MINE_ELAPSED_MS" <<'PY'
import sys
txs = int(sys.argv[1])
elapsed_ms = max(int(sys.argv[2]), 1)
print(f"{txs * 1000.0 / elapsed_ms:.2f}")
PY
)
MEMPOOL_AFTER=$(get_mempool_count 0)

log "Mining complete: $BLOCKS_MINED blocks in ${MINE_ELAPSED_MS}ms"
log "confirmed_wall_clock_tps=$CONFIRMED_WALL_CLOCK_TPS, mempool_after=$MEMPOOL_AFTER"
[ "$MEMPOOL_AFTER" = "0" ] && success "Node-0 mempool drained" || fail "Node-0 mempool still has $MEMPOOL_AFTER txs"

if [ "$BLOCKS_AFTER" -gt "$BLOCKS_BEFORE" ] 2>/dev/null; then
    analyze_block_window "$((BLOCKS_BEFORE + 1))" "$BLOCKS_AFTER" "Node-0 spam window" "$TX_SENT" "${ADAPTIVE_LIMIT:-0}"
else
    fail "No blocks mined during node-0 spam confirmation"
fi

# =====================================================================
header "Phase 8: Cross-node transaction spam"
# =====================================================================

log "All funded worker nodes sending $CROSS_TXS_PER_NODE txs each"
CROSS_BLOCKS_BEFORE=$(get_blocks 0)
CROSS_SENT=0
CROSS_FAILED=0

for ((i=1; i<NUM_NODES; i++)); do
    for ((t=0; t<CROSS_TXS_PER_NODE; t++)); do
        TARGET=${ADDRS[$(((i + t + 1) % NUM_NODES))]}
        RESULT=$(rpc "$i" sendtoaddress "$TARGET" 0.001 2>/dev/null)
        TXID=$(normalize_txid "$RESULT")
        if [ -n "$TXID" ]; then
            CROSS_SENT=$((CROSS_SENT + 1))
        else
            CROSS_FAILED=$((CROSS_FAILED + 1))
        fi
    done
done

log "Cross-node submitted: $CROSS_SENT txs ($CROSS_FAILED failed)"
wait_mempool_at_least 0 "$CROSS_SENT" 10 || warn "Node 0 mempool did not see all $CROSS_SENT cross-node txs before mining"
mine_until_mempool_empty 0 100 || fail "Cross-node mempool did not fully drain"
sleep 2
CROSS_LATE_MP=$(get_mempool_count 0)
if [ "$CROSS_LATE_MP" != "0" ]; then
    log "Late cross-node propagation left $CROSS_LATE_MP txs; mining another drain pass"
    mine_until_mempool_empty 0 20 || fail "Late cross-node mempool did not fully drain"
fi
CROSS_BLOCKS_AFTER=$(get_blocks 0)
wait_all_sync_at_or_above "$CROSS_BLOCKS_AFTER" 60 || fail "Cluster did not sync after cross-node spam"
CROSS_MP=$(get_mempool_count 0)

[ "$CROSS_SENT" -ge "$MIN_CROSS_SENT" ] && success "Cross-node spam: $CROSS_SENT txs from $((NUM_NODES - 1)) nodes" || fail "Cross-node spam below threshold: $CROSS_SENT"
[ "$CROSS_MP" = "0" ] && success "Cross-node mempool drained" || fail "Cross-node mempool has $CROSS_MP txs"

if [ "$CROSS_BLOCKS_AFTER" -gt "$CROSS_BLOCKS_BEFORE" ] 2>/dev/null; then
    analyze_block_window "$((CROSS_BLOCKS_BEFORE + 1))" "$CROSS_BLOCKS_AFTER" "Cross-node window" "$CROSS_SENT" "${ADAPTIVE_LIMIT:-0}"
fi

# =====================================================================
header "Phase 9: Final cluster sync and integrity"
# =====================================================================

sleep 5
FINAL_HEIGHT=$(get_blocks 0)
wait_all_sync_at_or_above "$FINAL_HEIGHT" 60
SYNC_LAG=$(cluster_lag)

log "Final height node0=$FINAL_HEIGHT, sync_lag=$SYNC_LAG blocks"
if [ "$SYNC_LAG" = "0" ]; then
    success "Final sync: all $NUM_NODES nodes aligned at height $FINAL_HEIGHT"
else
    fail "Final sync lag: $SYNC_LAG blocks"
fi

DAGINFO2=$(rpc 0 getdaginfo 2>/dev/null)
ENTRIES2=$(json_field "$DAGINFO2" "dag_entries")
TIPS2=$(json_field "$DAGINFO2" "dag_tips")
INFERRED_K2=$(json_field "$DAGINFO2" "inferred_k")
ALGO2=$(json_field "$DAGINFO2" "ordering_algorithm")
DK2=$(json_field "$DAGINFO2" "dagknight_active")
ADAPTIVE2=$(json_field "$DAGINFO2" "adaptive_block_limit")
log "Final DAG: entries=$ENTRIES2, tips=$TIPS2, inferred_k=$INFERRED_K2, DAGKNIGHT=$DK2, algo=$ALGO2, adaptive_limit=$ADAPTIVE2"
[ -n "$ENTRIES2" ] && [ "$ENTRIES2" -gt 0 ] 2>/dev/null && success "DAG intact: $ENTRIES2 entries" || fail "DAG entries: $ENTRIES2"

FININFO2=$(rpc 0 getfinalityinfo 2>/dev/null)
TIER2=$(json_field "$FININFO2" "finality_tier")
VOTERS2=$(json_field "$FININFO2" "current_epoch_voters")
FINALIZED2=$(json_field "$FININFO2" "finalized_height")
log "Finality: tier=$TIER2, voters=$VOTERS2, finalized_height=$FINALIZED2"
success "Finality status recorded"

FINAL_MP=$(get_mempool_count 0)
log "Final mempool: $FINAL_MP txs"
[ "$FINAL_MP" = "0" ] && success "Final mempool empty" || fail "Final mempool has $FINAL_MP txs"

echo ""
echo "=== Performance Summary ==="
echo "  Nodes:                    $NUM_NODES"
echo "  Final height:             $FINAL_HEIGHT"
echo "  Worker funding:           $WORKER_FUNDING INN each"
echo "  Node-0 TX submitted:      $TX_SENT"
echo "  Node-0 TX failed:         $TX_FAILED"
echo "  rpc_submit_tps:           ~$RPC_TPS"
echo "  confirmed_wall_clock_tps: $CONFIRMED_WALL_CLOCK_TPS"
echo "  spam blocks mined:        $BLOCKS_MINED"
echo "  cross-node txs:           $CROSS_SENT"
echo "  PoS blocks observed:      $POS_FOUND"
echo "  DAG entries:              $ENTRIES2"
echo "  DAG tips:                 $TIPS2"
echo "  inferred_k:               $INFERRED_K2"
echo "  adaptive limit:           $ADAPTIVE2"
echo "  timing source:            observed block timestamps (netmhashps intentionally ignored)"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All stress tests passed!${NC}"
    finish 0
else
    echo -e "${RED}$FAILED test(s) failed${NC}"
    finish 1
fi
