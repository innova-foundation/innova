#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# A joiner far behind syncs from block headers: the chain carries merged DAG side branches and
# is longer than one headers reply, and getblocks is sent only as a fallback.
# DAG_MERGE_DEPTH (64) bounds the fork depth a miner merges, so DEPTH + LEAD stays under it.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init header_fetch_sync_regtest_test || exit 1

INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
# Optional second joiner build, timed over the same chain after the first.
COMPARE_INNOVAD="${COMPARE_INNOVAD:-}"
# A saved node1 chain (from HDR_FETCH_SAVE_CHAIN) skips the build.
CHAIN_DIR="${HDR_FETCH_CHAIN_DIR:-}"
JOINER_INNOVAD="$INNOVAD"
TEST_DIR="$(iv5_test_dir "${HDR_FETCH_TEST_DIR:-/tmp/innova_hdr_fetch_$$}")"
BASE_PORT="$(iv5_port 0 27950)"
BASE_RPC="$(iv5_port 16 27970)"
BASE_IDNS="$(iv5_port 32 27990)"
RPCUSER=hdrfetch
RPCPASS=hdrfetchpass
NUM_NODES=3
COMMON="${HDR_FETCH_COMMON:-20}"
DEPTH="${HDR_FETCH_DEPTH:-12}"
LEAD="${HDR_FETCH_LEAD:-6}"
BRANCHES="${HDR_FETCH_BRANCHES:-3}"
TOTAL="${HDR_FETCH_TOTAL:-2600}"
CONVERGE_TIMEOUT="${HDR_FETCH_TIMEOUT:-900}"
MAX_GETBLOCKS="${HDR_FETCH_MAX_GETBLOCKS:-2}"

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
        [ "$node" = "0" ] && echo "debugnet=1" && echo "logtimestamps=1"
        if [ -n "$target" ]; then
            echo "connect=127.0.0.1:$(node_port "$target")"
        else
            # A -connect target nothing listens on: the node dials nowhere.
            echo "connect=127.0.0.1:$(node_port 3)"
        fi
    } > "$dir/innova.conf"
}

start_node() {
    local bin="$INNOVAD"
    [ "$1" = "0" ] && bin="$JOINER_INNOVAD"
    # shellcheck disable=SC2046
    "$bin" $(node_argv "$1") >/dev/null 2>&1
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

has_block() { rpc "$1" getblock "$2" >/dev/null; }
dag_parents() {
    rpc "$1" getblock "$2" | python3 -c 'import json,sys
try: print(" ".join(json.load(sys.stdin).get("dagparents", [])))
except Exception: print("")'
}

header "Chain with $BRANCHES merged side branches, then to height $TOTAL"
[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }
[ $((DEPTH + LEAD)) -lt 64 ] || { fail "DEPTH + LEAD must stay under DAG_MERGE_DEPTH"; exit 1; }
iv5_require_free_ports "$(node_port 0)" "$(node_port 1)" "$(node_port 2)" "$(node_port 3)" \
    "$(node_rpc 0)" "$(node_rpc 1)" "$(node_rpc 2)" \
    "$(node_idns 0)" "$(node_idns 1)" "$(node_idns 2)" || exit 1
rm -rf "$TEST_DIR"; mkdir -p "$TEST_DIR"

if [ -n "$CHAIN_DIR" ] && [ -s "$CHAIN_DIR/side_tips" ]; then
    write_conf 1 1
    cp -a "$CHAIN_DIR/regtest" "$(node_dir 1)/"
    rm -f "$(node_dir 1)/regtest/innovad.pid" "$(node_dir 1)/regtest/.lock"
    start_node 1 || { fail "node1 did not start on the saved chain"; exit 1; }
    SIDE_TIPS="$(cat "$CHAIN_DIR/side_tips")"
    success "node1 on the saved chain at $(height 1)"
else
write_conf 1 1
write_conf 2 0 1
for n in 1 2; do start_node "$n" || { fail "node$n did not start"; exit 1; }; done
for _ in $(seq 1 60); do [ "$(peer_count 1)" = "1" ] && break; sleep 1; done
mine_to 1 "$COMMON" || { fail "node1 could not mine the prefix"; exit 1; }
for _ in $(seq 1 120); do [ "$(best_hash 2)" = "$(best_hash 1)" ] && break; sleep 1; done
[ "$(best_hash 2)" = "$(best_hash 1)" ] || { fail "the prefix did not reach node2"; exit 1; }

SIDE_TIPS=""
for b in $(seq 1 "$BRANCHES"); do
    stop_node 2 || { fail "node2 did not stop"; exit 1; }
    write_conf 2 0
    start_node 2 || { fail "node2 did not restart isolated"; exit 1; }
    H1="$(height 1)"
    mine_to 2 $((H1 + DEPTH)) &
    P2=$!
    mine_to 1 $((H1 + DEPTH + LEAD)) &
    P1=$!
    wait "$P2"; R2=$?; wait "$P1"; R1=$?
    [ "$R1" -eq 0 ] && [ "$R2" -eq 0 ] || { fail "mining stopped short in round $b"; exit 1; }
    YTIP="$(best_hash 2)"
    stop_node 2 || { fail "node2 did not stop"; exit 1; }
    write_conf 2 0 1
    start_node 2 || { fail "node2 did not reconnect"; exit 1; }
    for _ in $(seq 1 180); do has_block 1 "$YTIP" && break; sleep 1; done
    has_block 1 "$YTIP" || { fail "node1 never received branch $b"; exit 1; }
    MERGER=""
    for i in 1 2 3 4 5; do
        mine_to 1 $(( $(height 1) + 1 )) || break
        TIP="$(best_hash 1)"
        case " $(dag_parents 1 "$TIP") " in *" $YTIP "*) MERGER="$TIP"; break;; esac
    done
    [ -n "$MERGER" ] || { fail "no node1 block merged side tip $b"; exit 1; }
    [ "$(best_hash 1)" != "$YTIP" ] || { fail "side branch $b became node1's main chain"; exit 1; }
    for _ in $(seq 1 120); do [ "$(best_hash 2)" = "$(best_hash 1)" ] && break; sleep 1; done
    SIDE_TIPS="$SIDE_TIPS $YTIP"
    success "branch $b: side tip ${YTIP:0:16} merged by ${MERGER:0:16} at $(height 1)"
done
stop_node 2 || { fail "node2 did not stop"; exit 1; }
mine_to 1 "$TOTAL" || { fail "node1 could not mine to $TOTAL"; exit 1; }
success "node1 at $(height 1)"
if [ -n "${HDR_FETCH_SAVE_CHAIN:-}" ]; then
    stop_node 1 || { fail "node1 did not stop"; exit 1; }
    mkdir -p "$HDR_FETCH_SAVE_CHAIN"; cp -a "$(node_dir 1)/regtest" "$HDR_FETCH_SAVE_CHAIN/"
    echo "$SIDE_TIPS" > "$HDR_FETCH_SAVE_CHAIN/side_tips"
    start_node 1 || { fail "node1 did not restart"; exit 1; }
fi
fi

header "node0 joins from genesis"
write_conf 0 0 1
T1=$(date +%s)
start_node 0 || { fail "node0 did not start"; exit 1; }
CONVERGED=0
for ((i=0; i<CONVERGE_TIMEOUT; i++)); do
    if [ "$(best_hash 0)" = "$(best_hash 1)" ]; then CONVERGED=1; break; fi
    sleep 1
done
ELAPSED=$(( $(date +%s) - T1 ))
MISSING=0
for t in $SIDE_TIPS; do has_block 0 "$t" || MISSING=$((MISSING + 1)); done
# getblocks toward no stop hash; orphan-root requests carry the orphan's root as the stop.
GETBLOCKS="$(count_since 0 0 "Pushing getblocks.* to 0000000000000000000000000000000000000000000000000000000000000000$")"
ORPHAN_GETBLOCKS="$(( $(count_since 0 0 "Pushing getblocks") - GETBLOCKS ))"
QUEUED="$(count_since 0 0 "header fetch: ")"
VIAHDR="$(count_since 0 0 "(headers)")"
echo "METRIC converged=$CONVERGED seconds=$ELAPSED height=$(height 0) getblocks=$GETBLOCKS orphan_root_getblocks=$ORPHAN_GETBLOCKS header_runs=$QUEUED header_getdata=$VIAHDR missing_side=$MISSING"
[ "$CONVERGED" -eq 1 ] && success "node0 on node1's tip at $(height 0) after ${ELAPSED}s" \
    || fail "node0 at $(height 0), node1 at $(height 1)"
[ "$MISSING" -eq 0 ] && success "node0 holds all $BRANCHES merged side branches" \
    || fail "node0 is missing $MISSING merged side tips"
[ "$QUEUED" -ge 2 ] && success "$QUEUED header runs queued (more than one headers reply)" \
    || fail "only $QUEUED header runs queued"
[ "$VIAHDR" -ge $((TOTAL / 2)) ] && success "$VIAHDR blocks fetched from the header queue" \
    || fail "only $VIAHDR blocks fetched from the header queue"
[ "$GETBLOCKS" -le "$MAX_GETBLOCKS" ] && success "$GETBLOCKS getblocks sent (bound $MAX_GETBLOCKS)" \
    || fail "$GETBLOCKS getblocks sent (bound $MAX_GETBLOCKS)"

if [ -n "$COMPARE_INNOVAD" ]; then
    header "node0 joins again with $COMPARE_INNOVAD"
    stop_node 0 || { fail "node0 did not stop"; exit 1; }
    mv "$(node_dir 0)" "$TEST_DIR/node0-first"; write_conf 0 0 1
    JOINER_INNOVAD="$COMPARE_INNOVAD"
    T1=$(date +%s)
    start_node 0 || { fail "comparison node0 did not start"; exit 1; }
    CONVERGED=0
    for ((i=0; i<CONVERGE_TIMEOUT; i++)); do
        if [ "$(best_hash 0)" = "$(best_hash 1)" ]; then CONVERGED=1; break; fi
        sleep 1
    done
    echo "METRIC_COMPARE converged=$CONVERGED seconds=$(( $(date +%s) - T1 )) height=$(height 0) getblocks=$(count_since 0 0 "Pushing getblocks")"
fi

exit $(( FAILED > 0 ? 1 : 0 ))
