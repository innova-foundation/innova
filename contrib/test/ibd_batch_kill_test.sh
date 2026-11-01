#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# A syncing node with batched index commits is SIGKILLed repeatedly mid-sync; each restart
# must resume without -reindex and finish on the source's tip with the same money supply.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init ibd_batch_kill_test || exit 1

INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="$(iv5_test_dir "${IBD_KILL_TEST_DIR:-/tmp/innova_ibd_kill_$$}")"
BASE_PORT="$(iv5_port 0 27850)"
BASE_RPC="$(iv5_port 16 27870)"
BASE_IDNS="$(iv5_port 32 27890)"
RPCUSER=ibdkill
RPCPASS=ibdkillpass
NUM_NODES=2
HEIGHT="${IBD_KILL_HEIGHT:-3000}"
KILLS="${IBD_KILL_COUNT:-20}"
BATCH="${IBD_KILL_BATCH:-200}"
MAX_WAIT="${IBD_KILL_MAX_WAIT:-0.5}"
CONVERGE_TIMEOUT="${IBD_KILL_TIMEOUT:-900}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
PASSED=0; FAILED=0
log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
header()  { echo -e "\n${CYAN}== $* ==${NC}"; }

node_dir()  { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc()  { echo $((BASE_RPC + $1)); }
node_idns() { echo $((BASE_IDNS + $1)); }
node_argv() { echo "-datadir=$(node_dir "$1") -regtest -daemon"; }

rpc() {
    local node="$1"; shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser="$RPCUSER" \
        -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>/dev/null
}
is_int()    { echo "$1" | grep -qE '^-?[0-9]+$'; }
height()    { rpc "$1" getblockcount | tr -d '"[:space:]'; }
best_hash() { rpc "$1" getbestblockhash | tr -d '"[:space:]'; }
peer_count() {
    rpc "$1" getpeerinfo | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print(-1)'
}
orphans() {
    rpc "$1" getinfo | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("orphanblocks", -1))
except Exception: print(-1)'
}
debug_log() { find "$(node_dir "$1")" -name debug.log 2>/dev/null | head -1; }
log_lines() { local f; f="$(debug_log "$1")"; if [ -n "$f" ]; then wc -l < "$f" | tr -d ' '; else echo 0; fi; }
# Lines matching a pattern in node's debug.log after line FROM.
count_since() {
    local f; f="$(debug_log "$1")"
    [ -n "$f" ] || { echo 0; return; }
    tail -n +"$(( $2 + 1 ))" "$f" | grep -c -- "$3"
}

# write_conf <node> <listen 0|1> [connect-target-node]
write_conf() {
    local node="$1" listen="$2" target="${3:-}" dir; dir="$(node_dir "$node")"
    mkdir -p "$dir"
    {
        echo "regtest=1"
        echo "server=1"
        echo "rpcuser=$RPCUSER"
        echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$node")"
        echo "port=$(node_port "$node")"
        echo "bind=127.0.0.1"
        echo "listen=$listen"
        echo "dnsseed=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "idnsport=$(node_idns "$node")"
        echo "staking=0"
        echo "stakingmode=0"
        echo "nofinalityvoting=1"
        echo "debug=1"
        [ "$node" = "0" ] && { echo "ibdbatchalways=1"; echo "ibdbatchsize=$BATCH"; }
        if [ -n "$target" ]; then
            echo "connect=127.0.0.1:$(node_port "$target")"
        else
            # A -connect target nothing listens on: the node dials nowhere.
            echo "connect=127.0.0.1:$(node_port 3)"
        fi
    } > "$dir/innova.conf"
}

start_node() {
    # shellcheck disable=SC2046
    "$INNOVAD" $(node_argv "$1") >/dev/null 2>&1
    for _ in $(seq 1 300); do
        rpc "$1" getblockcount >/dev/null && return 0
        sleep 1
    done
    return 1
}

stop_node() {
    rpc "$1" setgenerate false 0 >/dev/null || true
    rpc "$1" stop >/dev/null || true
    local pid; pid="$(cat "$(node_dir "$1")/regtest/innovad.pid" 2>/dev/null)"
    [ -n "$pid" ] || return 0
    for _ in $(seq 1 120); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 1
    done
    return 1
}

cleanup() {
    local n
    for ((n=0; n<NUM_NODES; n++)); do stop_node "$n" >/dev/null 2>&1; done
    echo
    echo "passed: $PASSED  failed: $FAILED"
    if [ "$FAILED" -eq 0 ] && [ "${KEEP_DIR:-0}" != "1" ]; then
        rm -rf "$TEST_DIR"
    else
        echo "kept $TEST_DIR"
    fi
    iv5_ports_release
}
trap cleanup EXIT

# Mine on NODE until TARGET, re-arming the generator if it stops short.
mine_to() {
    local node="$1" target="$2" h last stall=0
    h="$(height "$node")"; is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$node" setgenerate true $((target - h)) >/dev/null
    while :; do
        sleep 1
        h="$(height "$node")"
        if is_int "$h" && [ "$h" -ge "$target" ]; then
            rpc "$node" setgenerate false 0 >/dev/null
            return 0
        fi
        if [ "$h" = "$last" ]; then
            stall=$((stall + 1))
            [ "$stall" -ge 60 ] && { rpc "$node" setgenerate false 0 >/dev/null; return 1; }
            [ $((stall % 10)) -eq 0 ] && is_int "$h" && rpc "$node" setgenerate true $((target - h)) >/dev/null
        else
            stall=0; last="$h"
        fi
    done
}

supply() {
    rpc "$1" getinfo | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("moneysupply", -1))
except Exception: print(-1)'
}

header "Batched IBD commits survive SIGKILL ($KILLS kills, batch $BATCH, $HEIGHT blocks)"
[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }
iv5_require_free_ports "$(node_port 0)" "$(node_port 1)" "$(node_port 3)" \
    "$(node_rpc 0)" "$(node_rpc 1)" "$(node_idns 0)" "$(node_idns 1)" || exit 1
rm -rf "$TEST_DIR"; mkdir -p "$TEST_DIR"

write_conf 1 1
# A pre-mined regtest chain saves the mining time: its regtest/ directory becomes node1's.
if [ -n "${IBD_KILL_SOURCE:-}" ]; then
    cp -a "$IBD_KILL_SOURCE/regtest" "$(node_dir 1)/" || { fail "cannot copy $IBD_KILL_SOURCE"; exit 1; }
    rm -f "$(node_dir 1)/regtest/innovad.pid" "$(node_dir 1)/regtest/peers.dat"
fi
start_node 1 || { fail "node1 did not start"; exit 1; }
mine_to 1 "$HEIGHT" || { fail "node1 could not mine $HEIGHT blocks"; exit 1; }
TIP="$(best_hash 1)"; SUPPLY="$(supply 1)"
success "node1 mined to $(height 1)"

write_conf 0 0 1
T0=$(date +%s)
start_node 0 || { fail "node0 did not start"; exit 1; }
K=0; LAST=-1; STUCK=0
while [ "$K" -lt "$KILLS" ]; do
    sleep "$(python3 -c "import random; print(round(random.uniform(0.05, $MAX_WAIT), 2))")"
    H="$(height 0)"
    [ "$(best_hash 0)" = "$TIP" ] && break
    PID="$(cat "$(node_dir 0)/regtest/innovad.pid" 2>/dev/null)"
    [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null || { fail "no live node0 to kill at height $H"; exit 1; }
    for _ in $(seq 1 30); do kill -0 "$PID" 2>/dev/null || break; sleep 0.2; done
    K=$((K + 1))
    log "kill $K at height $H"
    start_node 0 || { fail "node0 did not restart after kill $K"; exit 1; }
    H2="$(height 0)"
    if is_int "$H" && is_int "$H2" && [ "$H2" -lt $((H - BATCH - 50)) ]; then
        fail "restart after kill $K lost more than a batch ($H -> $H2)"
    fi
    if [ "$H2" = "$LAST" ]; then STUCK=$((STUCK + 1)); else STUCK=0; fi
    LAST="$H2"
done
log "$K kills"

CONVERGED=0
for ((i=0; i<CONVERGE_TIMEOUT; i++)); do
    [ "$(best_hash 0)" = "$TIP" ] && { CONVERGED=1; break; }
    sleep 1
done
echo "METRIC kills=$K converged=$CONVERGED seconds=$(( $(date +%s) - T0 )) node0=$(height 0) node1=$(height 1)"
[ "$CONVERGED" -eq 1 ] && success "node0 on node1's tip after $K kills" \
    || fail "node0 at $(height 0), node1 at $(height 1)"
[ "$(supply 0)" = "$SUPPLY" ] && success "money supply matches ($SUPPLY)" \
    || fail "money supply $(supply 0) vs $SUPPLY"
REINDEX="$(grep -c -- "-reindex\|reindex required\|Corrupted block database" "$(debug_log 0)")"
[ "$REINDEX" -eq 0 ] && success "no restart asked for a reindex" \
    || fail "$REINDEX log lines ask for a reindex"

exit $(( FAILED > 0 ? 1 : 0 ))
