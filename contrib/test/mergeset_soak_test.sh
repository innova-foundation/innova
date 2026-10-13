#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Mergeset soak: four nodes past the fork mine at once with payments flowing, so side blocks
# and merges happen on their own; afterwards every node must hold the same chain and state.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init mergeset_soak_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${MERGESET_TEST_DIR:-/tmp/innova_mergeset_soak_$$}"
NUM_NODES=4
BASE_PORT="${MERGESET_BASE_PORT:-$(iv5_port 0 28800)}"
BASE_RPC="${MERGESET_BASE_RPC:-$(iv5_port 16 28860)}"
BASE_IDNS="${MERGESET_BASE_IDNS:-$(iv5_port 32 8880)}"
RPCUSER="mergeset"
RPCPASS="mergesetpass"
WALLETPASS="iv5sibwallet"

# Regtest epoch layout: DAG fork 11, 300-block epochs. Epoch 2 covers [311, 610]
# and is the first epoch whose state carries IV5 accumulators, so Boundary B is
# placed at its first height and every sibling is built inside it.
BOUNDARY_B=311
EPOCH=2
EPOCH_START=311
EPOCH_END=610
FUND_HEIGHT=340
PEER_FUND=200
SETTLE_HEIGHT=355
EPOCH_DONE_HEIGHT=620
MERGESET_HEIGHT=311

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

node_dir()  { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc()  { echo $((BASE_RPC + $1)); }
node_idns() { echo $((BASE_IDNS + $1)); }

rpc() {
    local node="$1"; shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser="$RPCUSER" \
        -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>&1
}

is_int() { echo "$1" | grep -qE '^-?[0-9]+$'; }

# Field of a flat JSON object; booleans print lowercase, absent prints empty.
jget() {
    FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"], None)
    if isinstance(v, bool): print(str(v).lower())
    elif v is None: print("")
    else: print(v)
except Exception:
    pass
' <<< "$1" 2>/dev/null
}

height()     { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
block_hash() { rpc "$1" getblockhash "$2" 2>/dev/null | tr -d '"[:space:]'; }
best_hash()  { rpc "$1" getbestblockhash 2>/dev/null | tr -d '"[:space:]'; }

peer_count() {
    rpc "$1" getpeerinfo 2>/dev/null | python3 -c '
import json, sys
try:
    p = json.load(sys.stdin)
    print(len(p) if isinstance(p, list) else 0)
except Exception:
    print(0)
'
}

wait_rpc() {
    for _ in $(seq 1 120); do
        rpc "$1" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

# The daemon's exact argv. A bare datadir match also catches this harness's own
# short-lived rpc client processes, so the node never looks stopped.
wait_rpc_down() {
    for _ in $(seq 1 180); do
        pgrep -f -- "-datadir=$(node_dir "$1") -regtest -daemon" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

start_node() {
    "$INNOVAD" -datadir="$(node_dir "$1")" -regtest -daemon >/dev/null 2>&1
    wait_rpc "$1"
}

stop_node() {
    rpc "$1" stop >/dev/null 2>&1 || true
    wait_rpc_down "$1"
}

write_config() {
    local node="$1" dir
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
        echo "maxconnections=32"
        echo "staking=0"
        echo "stakingmode=0"
        echo "nofinalityvoting=1"
        echo "regtestboundaryb=$BOUNDARY_B"
        echo "regtestiv5rehearsal=1"
        echo "regtestmergeset=$MERGESET_HEIGHT"
    } > "$dir/innova.conf"
}

connect_nodes() {
    rpc 0 setban "127.0.0.1" remove >/dev/null 2>&1 || true
    rpc 1 setban "127.0.0.1" remove >/dev/null 2>&1 || true
    rpc 0 addnode "127.0.0.1:$(node_port 1)" onetry >/dev/null 2>&1 || true
    rpc 1 addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1 || true
}

wait_peers() {
    for _ in $(seq 1 60); do
        local c0 c1
        c0="$(peer_count 0)"; c1="$(peer_count 1)"
        if is_int "$c0" && is_int "$c1" && [ "$c0" -ge 1 ] && [ "$c1" -ge 1 ]; then
            return 0
        fi
        connect_nodes
        sleep 2
    done
    return 1
}

# A hard partition: the ban list is consulted for both inbound accepts and
# outbound dials, so the two nodes cannot find each other again by gossip.
partition_nodes() {
    rpc 0 setban "127.0.0.1" add 3600 >/dev/null 2>&1 || true
    rpc 1 setban "127.0.0.1" add 3600 >/dev/null 2>&1 || true
    rpc 0 disconnectnode "127.0.0.1:$(node_port 1)" >/dev/null 2>&1 || true
    rpc 1 disconnectnode "127.0.0.1:$(node_port 0)" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
        local c0 c1
        c0="$(peer_count 0)"; c1="$(peer_count 1)"
        if [ "${c0:-1}" = "0" ] && [ "${c1:-1}" = "0" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Re-dial every ordered pair to re-trigger a missed block request. Idempotent for
# connected peers and refused by bans, so it cannot rejoin a partition.
redial_nodes() {
    local a b
    for ((a=0; a<NUM_NODES; a++)); do
        for ((b=0; b<NUM_NODES; b++)); do
            [ "$a" = "$b" ] && continue
            rpc "$a" addnode "127.0.0.1:$(node_port "$b")" onetry >/dev/null 2>&1 || true
        done
    done
}

wait_sync() {
    local target="$1" max="${2:-1200}" n h
    for ((i=0; i<max; i++)); do
        local ok=1
        for ((n=0; n<NUM_NODES; n++)); do
            h="$(height "$n")"
            if ! is_int "$h" || [ "$h" -lt "$target" ]; then ok=0; break; fi
        done
        [ "$ok" -eq 1 ] && return 0
        # Mining at regtest speed outruns block announcement often enough that a
        # node arrives here stalled a few blocks short with its peers still up.
        [ $((i % 30)) -eq 29 ] && redial_nodes
        sleep 1
    done
    return 1
}

wait_same_tip() {
    local i
    for ((i=0; i<180; i++)); do
        local a b
        a="$(best_hash 0)"; b="$(best_hash 1)"
        if [ ${#a} -eq 64 ] && [ "$a" = "$b" ]; then return 0; fi
        [ $((i % 30)) -eq 29 ] && redial_nodes
        sleep 1
    done
    return 1
}

# Mine on NODE until TARGET. setgenerate takes a block count and a template that
# loses a race consumes one, so re-arm whenever the height stalls.
mine_to() {
    local node="$1" target="$2" h last stall=0
    h="$(height "$node")"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$node" setgenerate true $((target - h)) >/dev/null 2>&1
    for ((i=0; i<3000; i++)); do
        h="$(height "$node")"
        if is_int "$h" && [ "$h" -ge "$target" ]; then
            rpc "$node" setgenerate false 0 >/dev/null 2>&1
            return 0
        fi
        if [ "$h" = "$last" ]; then
            stall=$((stall + 1))
        else
            stall=0
            last="$h"
            [ $((h % 100)) -eq 0 ] && log "  ...node$node height $h/$target"
        fi
        if [ "$stall" -ge 20 ]; then
            rpc "$node" setgenerate true $((target - h)) >/dev/null 2>&1
            stall=0
        fi
        sleep 1
    done
    rpc "$node" setgenerate false 0 >/dev/null 2>&1
    return 1
}

mine_one() {
    local node="$1" before
    before="$(height "$node")"
    is_int "$before" || return 1
    mine_to "$node" $((before + 1))
}

block_contains_tx() {
    TXID="$3" python3 -c '
import json, os, sys
try: print("yes" if os.environ["TXID"] in json.load(sys.stdin).get("tx", []) else "no")
except Exception: print("no")
' <<< "$(rpc "$1" getblock "$2" 2>/dev/null)" 2>/dev/null
}

block_has_dag_parent() {
    PARENT="$3" python3 -c '
import json, os, sys
try: print("yes" if os.environ["PARENT"] in json.load(sys.stdin).get("dagparents", []) else "no")
except Exception: print("no")
' <<< "$(rpc "$1" getblock "$2" 2>/dev/null)" 2>/dev/null
}

in_mempool() {
    TXID="$2" python3 -c '
import json, os, sys
try: print("yes" if os.environ["TXID"] in json.load(sys.stdin) else "no")
except Exception: print("no")
' <<< "$(rpc "$1" getrawmempool 2>/dev/null)" 2>/dev/null
}

wait_mempool() {
    local node="$1" txid="$2"
    for _ in $(seq 1 60); do
        [ "$(in_mempool "$node" "$txid")" = "yes" ] && return 0
        sleep 1
    done
    return 1
}

# A losing sibling only becomes a merge candidate once the miner's node holds it,
# so the races below have to wait for the block itself, not just for the peer.
wait_block_known() {
    local node="$1" hash="$2"
    for _ in $(seq 1 90); do
        [ "$(jget "$(rpc "$node" getblock "$hash" 2>/dev/null)" hash)" = "$hash" ] && return 0
        sleep 1
    done
    return 1
}

unlock() { rpc "$1" walletpassphrase "$WALLETPASS" 36000 >/dev/null 2>&1; }

# Where the chain connected a transaction, empty when it connected it nowhere.
# A merge block never gets a txindex entry, so empty is also the answer for a
# transaction that only ever rode one.
confirmed_in_block() { jget "$(rpc "$1" getrawtransaction "$2" 1 2>/dev/null)" blockhash; }

iv5_tree_size()  { jget "$(rpc "$1" z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_size; }
iv5_store_size() { jget "$(rpc "$1" z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_store_size; }
iv5_tree_root()  { jget "$(rpc "$1" z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_root; }

# Two nodes on one tip must hold one tree; the root is order sensitive. Both values
# come from the last COMPLETED epoch, so they move only at an epoch boundary.
assert_iv5_agrees() {
    local what="$1" t0 t1 s0 s1 r0 r1
    t0="$(iv5_tree_size 0)";  t1="$(iv5_tree_size 1)"
    s0="$(iv5_store_size 0)"; s1="$(iv5_store_size 1)"
    r0="$(iv5_tree_root 0)";  r1="$(iv5_tree_root 1)"
    if is_int "$t0" && is_int "$t1" && [ "$t0" = "$t1" ]; then
        success "$what: both nodes hold a $t0-leaf IV5 tree"
    else
        fail "$what: the nodes hold different IV5 trees (node0=$t0 node1=$t1)"
    fi
    if [ -n "$r0" ] && [ "$r0" = "$r1" ]; then
        success "$what: both nodes derived the same tree root (${r0:0:16})"
    else
        fail "$what: the nodes derived different tree roots ($r0 / $r1)"
    fi
    if is_int "$s0" && [ "$s0" = "$t0" ] && is_int "$s1" && [ "$s1" = "$t1" ]; then
        success "$what: each node's tree store is level with its tree"
    else
        fail "$what: a tree store is not level with its tree (node0 $s0/$t0, node1 $s1/$t1)"
    fi
}

encrypt_and_restart() {
    local node="$1"
    rpc "$node" encryptwallet "$WALLETPASS" >/dev/null 2>&1
    wait_rpc_down "$node" || return 1
    start_node "$node" || return 1
    unlock "$node"
}

cleanup() {
    local n
    for ((n=0; n<NUM_NODES; n++)); do stop_node "$n" >/dev/null 2>&1 || true; done
    [ "${MERGESET_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

SOAK_MINUTES="${MERGESET_SOAK_MINUTES:-60}"
connect_all() {
    local a b
    for ((a=0; a<NUM_NODES; a++)); do
        rpc "$a" setban "127.0.0.1" remove >/dev/null 2>&1 || true
        for ((b=0; b<NUM_NODES; b++)); do
            [ "$a" = "$b" ] && continue
            rpc "$a" addnode "127.0.0.1:$(node_port "$b")" onetry >/dev/null 2>&1 || true
        done
    done
}
state_of() {
    local n="$1"
    python3 -c '
import json, sys
info, sh = json.loads(sys.argv[1]), json.loads(sys.argv[2])
print(info.get("blocks"), info.get("moneysupply"), sh.get("privacy_vnext_tree_size"), sh.get("privacy_vnext_tree_root"))
' "$(rpc "$n" getinfo 2>/dev/null)" "$(rpc "$n" z_getshieldedinfo 2>/dev/null)" 2>/dev/null
}

header "Mergeset soak: $NUM_NODES nodes, $SOAK_MINUTES minutes"
rm -rf "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done
for ((n=0; n<NUM_NODES; n++)); do start_node "$n" || { fail "node$n did not start"; exit 1; }; done
connect_all
mine_to 0 "$SETTLE_HEIGHT" || { fail "node0 could not mine to $SETTLE_HEIGHT"; exit 1; }
wait_sync "$SETTLE_HEIGHT" || { fail "nodes did not sync"; exit 1; }
declare -a ADDR
for ((n=0; n<NUM_NODES; n++)); do ADDR[$n]="$(rpc "$n" getnewaddress 2>/dev/null | tr -d '"[:space:]')"; done
for ((n=1; n<NUM_NODES; n++)); do rpc 0 sendtoaddress "${ADDR[$n]}" 500 >/dev/null 2>&1; done
mine_to 0 $((SETTLE_HEIGHT + 20)) || { fail "could not fund the nodes"; exit 1; }
wait_sync $((SETTLE_HEIGHT + 20)) || { fail "nodes did not sync after funding"; exit 1; }
success "$NUM_NODES nodes past the fork, funded"

START_H="$(height 0)"
END_AT=$(( $(date +%s) + SOAK_MINUTES * 60 ))
for ((n=0; n<NUM_NODES; n++)); do
    ( while [ "$(date +%s)" -lt "$END_AT" ]; do
          rpc "$n" setgenerate true 1 >/dev/null 2>&1
          sleep "0.$((RANDOM % 9 + 1))"
          to=$(( (n + 1 + RANDOM % (NUM_NODES - 1)) % NUM_NODES ))
          rpc "$n" sendtoaddress "${ADDR[$to]}" "0.$((RANDOM % 90 + 10))" >/dev/null 2>&1
      done ) &
done
LAST_H="$START_H"; STALLS=0
while [ "$(date +%s)" -lt "$END_AT" ]; do
    sleep 60
    connect_all
    H="$(height 0)"
    if is_int "$H" && [ "$H" -gt "$LAST_H" ]; then LAST_H="$H"; STALLS=0; else STALLS=$((STALLS + 1)); fi
    log "  height $H"
    [ "$STALLS" -ge 5 ] && { fail "no progress for 5 minutes at height $H"; break; }
done
wait
for ((n=0; n<NUM_NODES; n++)); do rpc "$n" setgenerate false 0 >/dev/null 2>&1; done
connect_all
mine_one 0 >/dev/null 2>&1
TIP_H="$(height 0)"
wait_sync "$TIP_H" 600 || fail "nodes did not converge in height"
sleep 10; connect_all; sleep 10

MERGES=0; ACCEPTED=0
for ((h=START_H+1; h<=TIP_H; h++)); do
    B="$(rpc 0 getblock "$(block_hash 0 "$h")" 2>/dev/null)"
    read -r m a <<< "$(python3 -c '
import json, sys
b = json.loads(sys.argv[1]); print(len(b.get("mergedblocks", [])), len(b.get("mergesetacceptedtx", [])))
' "$B" 2>/dev/null)"
    MERGES=$((MERGES + ${m:-0})); ACCEPTED=$((ACCEPTED + ${a:-0}))
done
if [ "$MERGES" -gt 0 ]; then
    success "$((TIP_H - START_H)) canonical blocks merged $MERGES side blocks and applied $ACCEPTED of their txs"
else
    fail "no side block was merged; the soak did not exercise the fork"
fi

REF="$(state_of 0)"
SAME=1
for ((n=1; n<NUM_NODES; n++)); do
    [ "$(best_hash "$n")" = "$(best_hash 0)" ] && [ "$(state_of "$n")" = "$REF" ] || SAME=0
done
if [ "$SAME" = "1" ]; then
    success "all $NUM_NODES nodes hold one tip, money supply and IV5 tree ($REF)"
else
    fail "the nodes disagree: $(for ((n=0; n<NUM_NODES; n++)); do echo -n "[$n: $(best_hash "$n" | cut -c1-12) $(state_of "$n")] "; done)"
fi
ERRS=0
for ((n=0; n<NUM_NODES; n++)); do
    ERRS=$((ERRS + $(grep -cE "ConnectBlock\(\) : (mergeset|coinbase omits|epoch active|finality stake proof spent by)|Couldn.t find collateralnode payment" "$(node_dir "$n")/regtest/debug.log" 2>/dev/null || echo 0)))
done
[ "$ERRS" -eq 0 ] && success "no mergeset validation errors in any node's log" || fail "$ERRS mergeset validation errors logged"

header "Results"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
[ "$FAILED" -eq 0 ]
