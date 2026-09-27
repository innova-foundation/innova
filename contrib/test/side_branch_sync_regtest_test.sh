#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# A near-tip node handed the tip of a branch deeper than the 750-block orphan allowance
# must converge via inv relay (-sendheaders=0) with no orphan-allowance hits.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init side_branch_sync_regtest_test || exit 1

INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="$(iv5_test_dir "${SIDE_BRANCH_TEST_DIR:-/tmp/innova_side_branch_$$}")"
BASE_PORT="$(iv5_port 0 27650)"
BASE_RPC="$(iv5_port 16 27700)"
BASE_IDNS="$(iv5_port 32 27750)"
RPCUSER=sidebranch
RPCPASS=sidebranchpass
NUM_NODES=3

# The fork sits above the first regtest epoch boundary (height 10).
COMMON="${SIDE_BRANCH_COMMON:-20}"
SHORT="${SIDE_BRANCH_SHORT:-1810}"
LONG="${SIDE_BRANCH_LONG:-1900}"
CONVERGE_TIMEOUT="${SIDE_BRANCH_TIMEOUT:-600}"
# Parks allowed on node0. The tips node1 relays past the first one park above
# it (LONG - SHORT of them); one in-flight window covers that and reordering.
MAX_PARKS="${SIDE_BRANCH_MAX_PARKS:-128}"

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
        [ "$node" = "0" ] && echo "sendheaders=${SIDE_BRANCH_SENDHEADERS:-0}"
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
    # The daemon's exact argv, matched whatever the binary is named; an rpc
    # client's argv never contains it.
    for _ in $(seq 1 120); do
        pgrep -f -- "$(node_argv "$1")" >/dev/null 2>&1 || return 0
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

header "Deep side-branch sync ($LONG-block branch against $SHORT, fork at $COMMON)"
[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }
[ "$LONG" -gt "$SHORT" ] || { fail "the long branch must outweigh the short one"; exit 1; }
[ $((LONG - SHORT)) -lt 128 ] || { fail "the height gap must stay inside one in-flight window"; exit 1; }
iv5_require_free_ports "$(node_port 0)" "$(node_port 1)" "$(node_port 2)" "$(node_port 3)" \
    "$(node_rpc 0)" "$(node_rpc 1)" "$(node_rpc 2)" \
    "$(node_idns 0)" "$(node_idns 1)" "$(node_idns 2)" || exit 1
rm -rf "$TEST_DIR"; mkdir -p "$TEST_DIR"

write_conf 1 1
write_conf 0 0 1
write_conf 2 0 1
for n in 1 0 2; do start_node "$n" || { fail "node$n did not start"; exit 1; }; done
for _ in $(seq 1 60); do [ "$(peer_count 1)" = "2" ] && break; sleep 1; done
[ "$(peer_count 1)" = "2" ] || { fail "node1 has $(peer_count 1) peers, not 2"; exit 1; }
mine_to 0 "$COMMON" || { fail "node0 could not mine the prefix"; exit 1; }
for _ in $(seq 1 120); do
    [ "$(best_hash 1)" = "$(best_hash 0)" ] && [ "$(best_hash 2)" = "$(best_hash 0)" ] && break
    sleep 1
done
[ "$(best_hash 2)" = "$(best_hash 0)" ] && [ "$(best_hash 1)" = "$(best_hash 0)" ] \
    && success "a $COMMON-block prefix on all three" \
    || { fail "the prefix did not reach every node"; exit 1; }

stop_node 2 || { fail "node2 did not stop"; exit 1; }
write_conf 2 0
start_node 2 || { fail "node2 did not restart isolated"; exit 1; }
for _ in $(seq 1 30); do [ "$(peer_count 1)" = "1" ] && break; sleep 1; done
[ "$(peer_count 1)" = "1" ] && [ "$(peer_count 2)" = "0" ] \
    && success "node0 connected to node1, node2 isolated" \
    || { fail "topology: node1 has $(peer_count 1) peers, node2 has $(peer_count 2)"; exit 1; }

T0=$(date +%s)
mine_to 0 $((COMMON + SHORT)) &
P0=$!
mine_to 2 $((COMMON + LONG)) &
P2=$!
wait "$P0"; R0=$?
wait "$P2"; R2=$?
[ "$R0" -eq 0 ] && [ "$R2" -eq 0 ] \
    && success "mined $SHORT and $LONG blocks past the fork in $(( $(date +%s) - T0 ))s" \
    || { fail "mining stopped short (node0 $(height 0), node2 $(height 2))"; exit 1; }
for _ in $(seq 1 120); do [ "$(best_hash 1)" = "$(best_hash 0)" ] && break; sleep 1; done
[ "$(best_hash 1)" = "$(best_hash 0)" ] && success "node1 follows node0 at $(height 1)" \
    || { fail "node1 did not follow node0 (node1 $(height 1), node0 $(height 0))"; exit 1; }
TIP2="$(best_hash 2)"

header "node2 joins node1"
FROM0="$(log_lines 0)"
stop_node 2 || { fail "node2 did not stop"; exit 1; }
write_conf 2 0 1
T1=$(date +%s)
start_node 2 || { fail "node2 did not restart"; exit 1; }

CONVERGED=0
PEAK=0
for ((i=0; i<CONVERGE_TIMEOUT; i++)); do
    O="$(orphans 0)"; is_int "$O" && [ "$O" -gt "$PEAK" ] && PEAK="$O"
    A="$(best_hash 0)"; B="$(best_hash 1)"
    if [ "$A" = "$TIP2" ] && [ "$B" = "$TIP2" ]; then CONVERGED=1; break; fi
    sleep 1
done
ELAPSED=$(( $(date +%s) - T1 ))

PARKS="$(count_since 0 "$FROM0" "ProcessBlock: ORPHAN BLOCK")"
LIMIT="$(count_since 0 "$FROM0" "orphan limit")"
AHEAD="$(count_since 0 "$FROM0" "ahead of the sync front")"
FILL="$(count_since 0 "$FROM0" "ancestry fill")"
echo "METRIC converged=$CONVERGED seconds=$ELAPSED parks=$PARKS peak_orphans=$PEAK" \
     "limit_hits=$LIMIT ahead_drops=$AHEAD fill_lines=$FILL" \
     "node0=$(height 0) node1=$(height 1) node2=$(height 2)"

if [ "$CONVERGED" -eq 1 ]; then
    success "node0 and node1 on node2's tip after ${ELAPSED}s"
else
    fail "no common tip after ${ELAPSED}s (node0 $(height 0), node1 $(height 1), node2 $(height 2))"
fi
[ "$LIMIT" -eq 0 ] && success "node0 never reached the per-peer orphan allowance" \
    || fail "node0 hit the orphan allowance $LIMIT times"
[ "$PARKS" -le "$MAX_PARKS" ] && success "node0 parked $PARKS blocks (bound $MAX_PARKS)" \
    || fail "node0 parked $PARKS blocks fetching the branch (bound $MAX_PARKS)"

exit $(( FAILED > 0 ? 1 : 0 ))
