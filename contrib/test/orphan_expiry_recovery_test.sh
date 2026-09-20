#!/usr/bin/env bash
# Copyright (c) 2026 The Innova developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# After an orphan expires (-orphanexpiry), the node must re-request the branch and reach
# the tip. Stops only its own daemons, by datadir.

set -u

INNOVA_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="${ORPHAN_RECOVERY_TEST_DIR:-/tmp/innova_orphan_recovery_$$}"
BASE_PORT="${ORPHAN_RECOVERY_BASE_PORT:-27450}"
BASE_RPC="${ORPHAN_RECOVERY_BASE_RPC:-27500}"
RPCUSER=orphanrecovery
RPCPASS=orphanrecoverypass
EXPIRY_SECS=5
CHAIN_BLOCKS=40
PARKED_HEIGHT=25

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
PASSED=0; FAILED=0
log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
header()  { echo -e "\n${CYAN}== $* ==${NC}"; }

node_dir()  { echo "$TEST_DIR/node$1"; }
node_rpc()  { echo $((BASE_RPC + $1)); }
node_port() { echo $((BASE_PORT + $1)); }

rpc() {
    local node="$1"; shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser="$RPCUSER" \
        -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@"
}
height()  { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
orphans() { rpc "$1" getinfo 2>/dev/null | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("orphanblocks", -1))
except Exception: print(-1)'; }
is_int()  { echo "$1" | grep -qE '^-?[0-9]+$'; }

write_conf() {
    local node="$1" dir; dir="$(node_dir "$node")"
    mkdir -p "$dir"
    {
        echo "regtest=1"
        echo "rpcuser=$RPCUSER"
        echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$node")"
        echo "port=$(node_port "$node")"
        echo "listen=1"
        echo "dnsseed=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "staking=0"
        echo "orphanexpiry=$EXPIRY_SECS"
        echo "debug=1"
    } > "$dir/innova.conf"
}

start_node() {
    for _ in 1 2 3 4 5 6; do
        "$INNOVAD" -datadir="$(node_dir "$1")" -regtest -daemon >/dev/null 2>&1
        for _ in $(seq 1 120); do
            rpc "$1" getblockcount >/dev/null 2>&1 && return 0
            sleep 1
        done
        sleep 3
    done
    return 1
}

stop_node() {
    rpc "$1" setgenerate false 0 >/dev/null 2>&1 || true
    rpc "$1" stop >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
        rpc "$1" getblockcount >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

cleanup() {
    for n in 0 1; do stop_node "$n"; done
    echo
    echo "passed: $PASSED  failed: $FAILED"
    if [ "$FAILED" -eq 0 ] && [ "${KEEP_DIR:-0}" != "1" ]; then
        rm -rf "$TEST_DIR"
    else
        echo "kept $TEST_DIR"
    fi
}
trap cleanup EXIT

header "A node that expired an orphan asks again"
[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }
rm -rf "$TEST_DIR"; mkdir -p "$TEST_DIR"

for n in 0 1; do write_conf "$n"; start_node "$n" || { fail "node$n did not start"; exit 1; }; done
success "two nodes up, with a $EXPIRY_SECS s orphan expiry and no peers"

rpc 0 setgenerate true "$CHAIN_BLOCKS" 1 >/dev/null 2>&1
for _ in $(seq 1 300); do
    H="$(height 0)"; is_int "$H" && [ "$H" -ge "$CHAIN_BLOCKS" ] && break
    sleep 1
done
rpc 0 setgenerate false 0 >/dev/null 2>&1
H="$(height 0)"
is_int "$H" && [ "$H" -ge "$CHAIN_BLOCKS" ] && success "node0 mined a chain of $H blocks" \
    || { fail "node0 reached height ${H:-none}"; exit 1; }

# A block from the middle of A's chain, handed to B which has none of its ancestors.
HASH="$(rpc 0 getblockhash "$PARKED_HEIGHT" | tr -d '"[:space:]')"
RAW="$(rpc 0 getblock "$HASH" 0 | tr -d '"[:space:]')"
[ ${#RAW} -gt 100 ] && success "took block $PARKED_HEIGHT from node0 as ${#RAW} hex characters" \
    || { fail "could not read block $PARKED_HEIGHT as hex"; exit 1; }

rpc 1 submitblock "$RAW" >/dev/null 2>&1
PARKED=""
for _ in $(seq 1 30); do
    PARKED="$(orphans 1)"
    is_int "$PARKED" && [ "$PARKED" -ge 1 ] && break
    sleep 1
done
is_int "$PARKED" && [ "$PARKED" -ge 1 ] && success "node1 parked it: its parent is missing" \
    || { fail "node1 holds ${PARKED:-none} orphans, so nothing was parked to expire"; exit 1; }
[ "$(height 1)" = "0" ] && success "node1 is still at the genesis block" \
    || log "node1 height is $(height 1)"

header "The expiry fires"
DRAINED=""
for _ in $(seq 1 60); do
    DRAINED="$(orphans 1)"
    is_int "$DRAINED" && [ "$DRAINED" -eq 0 ] && break
    sleep 2
done
is_int "$DRAINED" && [ "$DRAINED" -eq 0 ] && success "node1 dropped the expired orphan" \
    || { fail "node1 still holds ${DRAINED:-none} orphans after the expiry"; exit 1; }

header "And the node asks again"
# B meets A only now; reaching the tip means it re-requested the branch.
rpc 1 addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1
SYNCED=""
for _ in $(seq 1 180); do
    SYNCED="$(height 1)"
    is_int "$SYNCED" && [ "$SYNCED" -ge "$H" ] && break
    sleep 1
done
is_int "$SYNCED" && [ "$SYNCED" -ge "$H" ] \
    && success "node1 reached node0's tip at height $SYNCED after the expiry" \
    || fail "node1 stalled at height ${SYNCED:-none} of $H: the expiry left it idle, not recovering"

exit $(( FAILED > 0 ? 1 : 0 ))
