#!/bin/bash
# IDAG block propagation regression: active DAG-era block production and tx drain.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${TEST_DIR:-/tmp/innova_idag_block_prop}"
NUM_NODES="${NUM_NODES:-5}"
BASE_PORT="${BASE_PORT:-27980}"
BASE_RPC="${BASE_RPC:-28040}"
BASE_IDNS="${BASE_IDNS:-8080}"
RPCUSER="${RPCUSER:-idagblockprop}"
RPCPASS="${RPCPASS:-idagblockproppass}"

MIN_PEERS="${MIN_PEERS:-4}"
BOOTSTRAP_HEIGHT="${BOOTSTRAP_HEIGHT:-120}"
BOOTSTRAP_SYNC_INTERVAL="${BOOTSTRAP_SYNC_INTERVAL:-1}"
BURSTS="${BURSTS:-5}"
BURST_BLOCKS="${BURST_BLOCKS:-3}"
STARTMINING_THREADS="${STARTMINING_THREADS:-4}"
STARTMINING_BLOCKS="${STARTMINING_BLOCKS:-2}"
DELAYED_NODE="${DELAYED_NODE:-4}"
DELAYED_AHEAD_BLOCKS="${DELAYED_AHEAD_BLOCKS:-5}"
MINE_TIMEOUT_PER_BLOCK="${MINE_TIMEOUT_PER_BLOCK:-30}"
PROPAGATION_TIMEOUT="${PROPAGATION_TIMEOUT:-60}"
TX_VISIBILITY_MIN="${TX_VISIBILITY_MIN:-4}"
TX_VISIBILITY_TIMEOUT="${TX_VISIBILITY_TIMEOUT:-90}"
MEMPOOL_DRAIN_TIMEOUT="${MEMPOOL_DRAIN_TIMEOUT:-60}"
IDLE_CHECK_SECONDS="${IDLE_CHECK_SECONDS:-20}"
KEEP_DIR="${KEEP_DIR:-0}"

PASSED=0
FAILED=0

log() { echo -e "${YELLOW}[INFO]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }

node_dir() { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc() { echo $((BASE_RPC + $1)); }
node_idns() { echo $((BASE_IDNS + $1)); }

should_connect_pair() {
    local node="$1"
    local peer="$2"
    [ "$node" -lt "$peer" ]
}

rpc() {
    local node="$1"
    shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest \
        -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>&1
}

is_int() {
    echo "$1" | grep -qE '^[0-9]+$'
}

height() {
    rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'
}

best_hash() {
    rpc "$1" getbestblockhash 2>/dev/null | tr -d '"[:space:]'
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

cleanup() {
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        rpc "$node" stop >/dev/null 2>&1 || true
    done
    sleep 2
    pkill -f "innovad.*innova_idag_block_prop" 2>/dev/null || true
    if [ "$KEEP_DIR" = "1" ] || [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

write_config() {
    local node="$1"
    local dir
    dir="$(node_dir "$node")"
    mkdir -p "$dir"
    {
        echo "regtest=1"
        echo "server=1"
        echo "rpcuser=$RPCUSER"
        echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$node")"
        echo "port=$(node_port "$node")"
        echo "bind=127.0.0.1"
        echo "listen=1"
        echo "dnsseed=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "idnsport=$(node_idns "$node")"
        echo "debug=1"
        echo "debugtxrelay=1"
        echo "staking=0"
        echo "stakingmode=0"
        echo "nofinalityvoting=1"
        echo "getdatablockbatch=128"
        echo "maxconnections=32"
    } > "$dir/innova.conf"
}

start_node() {
    local node="$1"
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -daemon \
        -pid="$(node_dir "$node")/idag_block_prop.pid" >/dev/null 2>&1
}

wait_rpc() {
    local node="$1"
    local attempt
    for ((attempt=0; attempt<60; attempt++)); do
        rpc "$node" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

wait_rpc_down() {
    local node="$1"
    local timeout="${2:-60}"
    local attempt
    for ((attempt=0; attempt<timeout; attempt++)); do
        if ! rpc "$node" getinfo >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

connect_mesh() {
    local node
    local peer
    for ((node=0; node<NUM_NODES; node++)); do
        for ((peer=0; peer<NUM_NODES; peer++)); do
            [ "$node" -eq "$peer" ] && continue
            if should_connect_pair "$node" "$peer"; then
                rpc "$node" addnode "127.0.0.1:$(node_port "$peer")" onetry >/dev/null 2>&1 || true
            fi
        done
    done
}

peer_count() {
    rpc "$1" getpeerinfo 2>/dev/null | python3 -c '
import json
import sys
try:
    peers = json.load(sys.stdin)
    print(len(peers) if isinstance(peers, list) else 0)
except Exception:
    print(0)
'
}

min_peer_count() {
    local min=""
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        local count
        count="$(peer_count "$node")"
        if ! is_int "$count"; then
            echo 0
            return
        fi
        if [ -z "$min" ] || [ "$count" -lt "$min" ]; then
            min="$count"
        fi
    done
    echo "${min:-0}"
}

wait_peer_floor() {
    local target="$1"
    local timeout="${2:-45}"
    local attempt
    for ((attempt=0; attempt<timeout; attempt++)); do
        local min_count
        min_count="$(min_peer_count)"
        if is_int "$min_count" && [ "$min_count" -ge "$target" ]; then
            return 0
        fi
        connect_mesh
        sleep 1
    done
    return 1
}

mine_until_height() {
    local node="$1"
    local target="$2"
    local current
    current="$(height "$node")"
    is_int "$current" || return 1

    while [ "$current" -lt "$target" ]; do
        local before="$current"
        rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1

        local waited=0
        local max_ticks=$((MINE_TIMEOUT_PER_BLOCK * 10))
        while [ "$waited" -lt "$max_ticks" ]; do
            sleep 0.1
            current="$(height "$node")"
            if is_int "$current" && [ "$current" -gt "$before" ]; then
                break
            fi
            waited=$((waited + 1))
        done
        rpc "$node" setgenerate false 0 >/dev/null 2>&1 || true

        if ! is_int "$current" || [ "$current" -le "$before" ]; then
            log "Mining stalled on node $node at height $before while targeting $target"
            return 1
        fi
    done
}

mine_blocks() {
    local node="$1"
    local count="$2"
    local current
    current="$(height "$node")"
    is_int "$current" || return 1
    mine_until_height "$node" "$((current + count))"
}

mine_startmining_blocks() {
    local node="$1"
    local threads="$2"
    local count="$3"
    local before target current waited max_ticks

    before="$(height "$node")"
    is_int "$before" || return 1
    target=$((before + count))

    rpc "$node" startmining "$threads" >/dev/null 2>&1 || return 1
    waited=0
    max_ticks=$((MINE_TIMEOUT_PER_BLOCK * count * 10))
    [ "$max_ticks" -lt 300 ] && max_ticks=300
    current="$before"
    while [ "$waited" -lt "$max_ticks" ]; do
        sleep 0.1
        current="$(height "$node")"
        if is_int "$current" && [ "$current" -ge "$target" ]; then
            break
        fi
        waited=$((waited + 1))
    done
    rpc "$node" stopmining >/dev/null 2>&1 || rpc "$node" setgenerate false 0 >/dev/null 2>&1 || true

    current="$(height "$node")"
    if is_int "$current" && [ "$current" -ge "$target" ]; then
        return 0
    fi

    log "startmining stalled on node $node at height ${current:-?} while targeting $target"
    return 1
}

mine_bootstrap_until_height() {
    local node="$1"
    local target="$2"
    local interval="$BOOTSTRAP_SYNC_INTERVAL"
    local current
    current="$(height "$node")"
    is_int "$current" || return 1
    is_int "$interval" && [ "$interval" -gt 0 ] || interval=1

    while [ "$current" -lt "$target" ]; do
        local next=$((current + interval))
        [ "$next" -gt "$target" ] && next="$target"
        mine_until_height "$node" "$next" || return 1
        wait_all_same_tip "$next" "$PROPAGATION_TIMEOUT" || return 1
        current="$next"
    done
}

tip_summary() {
    local parts=""
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        local h hash
        h="$(height "$node")"
        hash="$(best_hash "$node")"
        parts="$parts node$node=${h:-?}:${hash:0:12}"
    done
    echo "$parts"
}

wait_all_same_tip() {
    local target="$1"
    local timeout="${2:-$PROPAGATION_TIMEOUT}"
    local attempt
    for ((attempt=0; attempt<timeout; attempt++)); do
        local node
        local expected_height=""
        local expected_hash=""
        local ok=1
        for ((node=0; node<NUM_NODES; node++)); do
            local h hash
            h="$(height "$node")"
            hash="$(best_hash "$node")"
            if ! is_int "$h" || [ "$h" -lt "$target" ] || [ -z "$hash" ]; then
                ok=0
                break
            fi
            if [ -z "$expected_height" ]; then
                expected_height="$h"
                expected_hash="$hash"
            elif [ "$h" != "$expected_height" ] || [ "$hash" != "$expected_hash" ]; then
                ok=0
                break
            fi
        done
        [ "$ok" -eq 1 ] && return 0
        sleep 1
    done
    log "Tip mismatch after ${timeout}s:$(tip_summary)"
    return 1
}

wait_selected_same_tip() {
    local target="$1"
    local timeout="${2:-$PROPAGATION_TIMEOUT}"
    shift 2
    local attempt
    for ((attempt=0; attempt<timeout; attempt++)); do
        local node
        local expected_height=""
        local expected_hash=""
        local ok=1
        for node in "$@"; do
            local h hash
            h="$(height "$node")"
            hash="$(best_hash "$node")"
            if ! is_int "$h" || [ "$h" -lt "$target" ] || [ -z "$hash" ]; then
                ok=0
                break
            fi
            if [ -z "$expected_height" ]; then
                expected_height="$h"
                expected_hash="$hash"
            elif [ "$h" != "$expected_height" ] || [ "$hash" != "$expected_hash" ]; then
                ok=0
                break
            fi
        done
        [ "$ok" -eq 1 ] && return 0
        sleep 1
    done
    log "Selected tip mismatch after ${timeout}s:$(tip_summary)"
    return 1
}

mempool_count() {
    rpc "$1" getrawmempool 2>/dev/null | python3 -c '
import json
import sys
try:
    pool = json.load(sys.stdin)
    print(len(pool) if isinstance(pool, list) else -1)
except Exception:
    print(-1)
'
}

mempool_has_tx() {
    local node="$1"
    local txid="$2"
    rpc "$node" getrawmempool 2>/dev/null | grep -q "$txid"
}

tx_visibility_count() {
    local txid="$1"
    local seen=0
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        if mempool_has_tx "$node" "$txid"; then
            seen=$((seen + 1))
        fi
    done
    echo "$seen"
}

wait_tx_visibility() {
    local txid="$1"
    local min_seen="$2"
    local timeout="$3"
    local attempt
    for ((attempt=0; attempt<timeout; attempt++)); do
        local seen
        seen="$(tx_visibility_count "$txid")"
        if is_int "$seen" && [ "$seen" -ge "$min_seen" ]; then
            return 0
        fi
        sleep 1
    done
    log "Tx $txid visible on $(tx_visibility_count "$txid")/$NUM_NODES mempools after ${timeout}s"
    return 1
}

wait_all_mempools_empty() {
    local timeout="$1"
    local attempt
    for ((attempt=0; attempt<timeout; attempt++)); do
        local node
        local total=0
        local ok=1
        for ((node=0; node<NUM_NODES; node++)); do
            local count
            count="$(mempool_count "$node")"
            if ! is_int "$count" || [ "$count" -lt 0 ]; then
                ok=0
                break
            fi
            total=$((total + count))
        done
        [ "$ok" -eq 1 ] && [ "$total" -eq 0 ] && return 0
        sleep 1
    done
    return 1
}

total_banned_count() {
    local total=0
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        local count
        count="$(rpc "$node" listbanned 2>/dev/null | python3 -c '
import json
import sys
try:
    banned = json.load(sys.stdin)
    print(len(banned) if isinstance(banned, list) else 0)
except Exception:
    print(0)
')"
        is_int "$count" || count=0
        total=$((total + count))
    done
    echo "$total"
}

same_height_stall_log_count() {
    python3 - "$TEST_DIR" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(r"Sync stall recovery:.*\bch=(\d+)\s+our=(\d+)")
count = 0
for log_path in root.glob("node*/**/debug.log"):
    try:
        text = log_path.read_text(errors="replace")
    except OSError:
        continue
    for match in pattern.finditer(text):
        if match.group(1) == match.group(2):
            count += 1
print(count)
PY
}

recv_flood_disconnect_count() {
    python3 - "$TEST_DIR" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(r"DEBUG-DISCONNECT recv-flood(?:-hard)?")
count = 0
for log_path in root.glob("node*/**/debug.log"):
    try:
        text = log_path.read_text(errors="replace")
    except OSError:
        continue
    count += len(pattern.findall(text))
print(count)
PY
}

main() {
    if [ ! -x "$INNOVAD" ]; then
        fail "innovad not found at $INNOVAD"
        return 1
    fi

    rm -rf "$TEST_DIR"
    trap cleanup EXIT

    local node
    for ((node=0; node<NUM_NODES; node++)); do
        write_config "$node"
        start_node "$node"
    done

    for ((node=0; node<NUM_NODES; node++)); do
        if wait_rpc "$node"; then
            pass "node $node RPC ready"
        else
            fail "node $node RPC did not become ready"
            return 1
        fi
    done

    connect_mesh
    if wait_peer_floor "$MIN_PEERS" 60; then
        pass "all nodes have at least $MIN_PEERS peers"
    else
        fail "peer floor not met; min peer count $(min_peer_count)"
        return 1
    fi

    log "Mining to height $BOOTSTRAP_HEIGHT for spendable DAG-era funds"
    mine_bootstrap_until_height 0 "$BOOTSTRAP_HEIGHT" || { fail "bootstrap mining/sync failed"; return 1; }
    pass "all nodes synced to bootstrap tip"

    local daginfo dag_active
    daginfo="$(rpc 0 getdaginfo 2>/dev/null)"
    dag_active="$(json_field "$daginfo" "dag_active")"
    if [ "$dag_active" = "true" ]; then
        pass "DAG is active before propagation bursts"
    else
        fail "DAG expected active after bootstrap, got $dag_active"
        return 1
    fi

    log "Running multi-thread startmining on a post-DAG tip"
    if mine_startmining_blocks 0 "$STARTMINING_THREADS" "$STARTMINING_BLOCKS"; then
        local mt_height
        mt_height="$(height 0)"
        if wait_all_same_tip "$mt_height" "$PROPAGATION_TIMEOUT"; then
            pass "multi-thread startmining converged at matching height/hash"
        else
            fail "multi-thread startmining did not converge to a matching tip"
            return 1
        fi
        rpc 0 getinfo >/dev/null 2>&1 && pass "RPC responsive after startmining stop" || fail "RPC unresponsive after startmining stop"
    else
        fail "multi-thread startmining did not produce post-DAG blocks"
        return 1
    fi

    log "Stopping node $DELAYED_NODE, mining ahead, then requiring P2P catch-up"
    rpc "$DELAYED_NODE" stop >/dev/null 2>&1 || true
    wait_rpc_down "$DELAYED_NODE" 60 || { fail "delayed node $DELAYED_NODE did not stop"; return 1; }
    mine_blocks 0 "$DELAYED_AHEAD_BLOCKS" || { fail "ahead mining for delayed-node catch-up failed"; return 1; }
    local delayed_target
    local -a active_nodes
    delayed_target="$(height 0)"
    active_nodes=()
    for ((node=0; node<NUM_NODES; node++)); do
        [ "$node" -eq "$DELAYED_NODE" ] && continue
        active_nodes+=("$node")
    done
    wait_selected_same_tip "$delayed_target" "$PROPAGATION_TIMEOUT" "${active_nodes[@]}" || {
        fail "active nodes did not converge while delayed node was offline"
        return 1
    }
    start_node "$DELAYED_NODE"
    wait_rpc "$DELAYED_NODE" || { fail "delayed node $DELAYED_NODE did not restart"; return 1; }
    connect_mesh
    wait_peer_floor "$MIN_PEERS" 60 || { fail "peer floor not restored after delayed node restart"; return 1; }
    if wait_all_same_tip "$delayed_target" "$PROPAGATION_TIMEOUT"; then
        pass "delayed node caught up via mined block relay without submitblock"
    else
        fail "delayed node failed to converge to the mined branch"
        return 1
    fi

    local burst
    for ((burst=1; burst<=BURSTS; burst++)); do
        local producer target
        producer=$(((burst - 1) % NUM_NODES))
        log "Burst $burst/$BURSTS: node $producer producing $BURST_BLOCKS DAG blocks"
        mine_blocks "$producer" "$BURST_BLOCKS" || { fail "burst $burst production failed"; return 1; }
        target="$(height "$producer")"
        if wait_all_same_tip "$target" "$PROPAGATION_TIMEOUT"; then
            pass "burst $burst propagated with matching height/hash at $target"
        else
            fail "burst $burst did not converge to a matching tip"
            return 1
        fi
        if wait_peer_floor "$MIN_PEERS" 15; then
            pass "peer floor held after burst $burst"
        else
            fail "peer floor collapsed after burst $burst; min peer count $(min_peer_count)"
            return 1
        fi
    done

    log "Submitting transparent wallet tx and checking local five-node visibility"
    local addr txid
    addr="$(rpc 1 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    txid="$(rpc 0 sendtoaddress "$addr" 1.0 2>/dev/null | tr -d '"[:space:]')"
    if ! echo "$txid" | grep -qE '^[0-9a-f]{64}$'; then
        fail "sendtoaddress failed: $txid"
        return 1
    fi

    if wait_tx_visibility "$txid" "$TX_VISIBILITY_MIN" "$TX_VISIBILITY_TIMEOUT"; then
        pass "tx visible on at least $TX_VISIBILITY_MIN/$NUM_NODES mempools"
    else
        fail "tx visibility below $TX_VISIBILITY_MIN/$NUM_NODES for $txid"
        return 1
    fi

    log "Mining submitted tx and requiring mempool drain"
    mine_blocks 2 1 || { fail "failed to mine tx confirmation block"; return 1; }
    local confirm_height
    confirm_height="$(height 2)"
    wait_all_same_tip "$confirm_height" "$PROPAGATION_TIMEOUT" || { fail "tx confirmation block did not propagate"; return 1; }
    if wait_all_mempools_empty "$MEMPOOL_DRAIN_TIMEOUT"; then
        pass "all mempools drained after mined traffic"
    else
        fail "mempools did not drain after mined traffic"
        return 1
    fi

    if [ "$(total_banned_count)" = "0" ]; then
        pass "no peers banned during propagation test"
    else
        fail "unexpected local peer bans detected"
    fi

    if [ "$(recv_flood_disconnect_count)" = "0" ]; then
        pass "no receive-flood disconnects logged"
    else
        fail "receive-flood disconnects logged"
    fi

    local stalls_before stalls_after final_height
    stalls_before="$(same_height_stall_log_count)"
    final_height="$(height 0)"
    wait_all_same_tip "$final_height" "$PROPAGATION_TIMEOUT" || { fail "final tips did not match"; return 1; }
    log "Holding equal-height network idle for ${IDLE_CHECK_SECONDS}s"
    sleep "$IDLE_CHECK_SECONDS"
    stalls_after="$(same_height_stall_log_count)"
    if is_int "$stalls_before" && is_int "$stalls_after" && [ "$stalls_after" -eq "$stalls_before" ]; then
        pass "no same-height sync-stall recovery while idle"
    else
        fail "same-height sync-stall recovery increased while idle ($stalls_before -> $stalls_after)"
    fi

    echo
    echo "IDAG block propagation regression: $PASSED passed, $FAILED failed"
    [ "$FAILED" -eq 0 ]
}

main "$@"
