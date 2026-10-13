#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Mergeset acceptance regtest: a merged block's transactions are applied by the canonical
# block that merges it, exactly once, and undone with it.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init mergeset_accept_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${MERGESET_TEST_DIR:-/tmp/innova_mergeset_$$}"
NUM_NODES=2
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
        [ "${MERGESET_EMISSION:-1}" = "1" ] && echo "regtestmergesetemission=1"
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

mergeset_field() {
    FIELD="$3" TXID="$4" python3 -c '
import json, os, sys
try: print("yes" if os.environ["TXID"] in json.load(sys.stdin).get(os.environ["FIELD"], []) else "no")
except Exception: print("no")
' <<< "$(rpc "$1" getblock "$2" 2>/dev/null)" 2>/dev/null
}

header "Mergeset acceptance regtest (fork at $MERGESET_HEIGHT)"

rm -rf "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done

start_node 0 || { fail "node0 did not start"; exit 1; }
mine_to 0 "$FUND_HEIGHT" || { fail "node0 could not mine to $FUND_HEIGHT"; exit 1; }
start_node 1 || { fail "node1 did not start"; exit 1; }
connect_nodes
wait_peers || { fail "the two nodes never peered"; exit 1; }
wait_sync "$FUND_HEIGHT" || { fail "node1 did not sync"; exit 1; }
ADDR1="$(rpc 1 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
FUNDTX="$(rpc 0 sendtoaddress "$ADDR1" "$PEER_FUND" 2>&1 | tr -d '"[:space:]')"
[ ${#FUNDTX} -eq 64 ] || { fail "could not fund node1: $FUNDTX"; exit 1; }
mine_to 0 "$SETTLE_HEIGHT" || { fail "could not confirm the funding"; exit 1; }
wait_sync "$SETTLE_HEIGHT" || { fail "nodes did not resync after funding"; exit 1; }
success "two nodes past the fork height, node1 funded"
ADDR0="$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')"

# ============================================================
header "1. A payment carried only by a losing block is applied when merged"
# ============================================================
SPLIT="$(height 0)"
partition_nodes || { fail "could not partition"; exit 1; }
TXM="$(rpc 1 sendtoaddress "$ADDR0" 5 2>&1 | tr -d '"[:space:]')"
[ ${#TXM} -eq 64 ] || { fail "node1 could not send: $TXM"; exit 1; }
mine_one 1 || { fail "node1 could not mine its side block"; exit 1; }
SIDE="$(block_hash 1 $((SPLIT + 1)))"
[ "$(block_contains_tx 1 "$SIDE" "$TXM")" = "yes" ] || { fail "the side block does not carry the payment"; exit 1; }
mine_to 0 $((SPLIT + 3)) || { fail "node0 could not outrun"; exit 1; }
connect_nodes
wait_peers || { fail "no re-peer"; exit 1; }
wait_block_known 0 "$SIDE" || { fail "node0 never got the side block"; exit 1; }
wait_same_tip || { fail "no convergence"; exit 1; }
[ "$(block_hash 0 $((SPLIT + 1)))" != "$SIDE" ] && success "the side block ${SIDE:0:16} lost the race" || { fail "the side block won"; exit 1; }
mine_one 0 || { fail "node0 could not mine the merging block"; exit 1; }
MERGER="$(best_hash 0)"
if [ "$(block_has_dag_parent 0 "$MERGER" "$SIDE")" = "yes" ]; then
    success "canonical block ${MERGER:0:16} merges the side block"
else
    fail "the next canonical block did not merge the side block"; exit 1
fi
wait_same_tip || { fail "no convergence after the merge"; exit 1; }
if [ "$(confirmed_in_block 0 "$TXM")" = "$MERGER" ] && [ "$(confirmed_in_block 1 "$TXM")" = "$MERGER" ]; then
    success "both nodes confirm the payment in the merging block"
else
    fail "payment not confirmed by the merging block (node0 '$(confirmed_in_block 0 "$TXM")', node1 '$(confirmed_in_block 1 "$TXM")')"
fi
if [ "$(mergeset_field 0 "$MERGER" mergesetacceptedtx "$TXM")" = "yes" ] && \
   [ "$(mergeset_field 0 "$MERGER" mergedblocks "$SIDE")" = "yes" ]; then
    success "getblock lists the side block and the accepted payment"
else
    fail "getblock does not list the mergeset acceptance"
fi
sleep 3
if [ "$(in_mempool 0 "$TXM")" = "no" ] && [ "$(in_mempool 1 "$TXM")" = "no" ]; then
    success "the accepted payment left both mempools"
else
    fail "the accepted payment is still in a mempool"
fi

# ============================================================
header "2. A tx carried by a side block and the canonical chain applies once"
# ============================================================
TXB="$(rpc 1 sendtoaddress "$ADDR0" 3 2>&1 | tr -d '"[:space:]')"
[ ${#TXB} -eq 64 ] || { fail "node1 could not send: $TXB"; exit 1; }
wait_mempool 0 "$TXB" || { fail "the tx did not reach node0"; exit 1; }
SPLIT2="$(height 0)"
partition_nodes || { fail "could not partition"; exit 1; }
mine_one 1 || { fail "node1 could not mine"; exit 1; }
SIDE2="$(block_hash 1 $((SPLIT2 + 1)))"
mine_to 0 $((SPLIT2 + 3)) || { fail "node0 could not outrun"; exit 1; }
OWN2="$(confirmed_in_block 0 "$TXB")"
connect_nodes
wait_peers || { fail "no re-peer"; exit 1; }
wait_block_known 0 "$SIDE2" || { fail "node0 never got the side block"; exit 1; }
wait_same_tip || { fail "no convergence"; exit 1; }
mine_one 0 || { fail "node0 could not mine the merging block"; exit 1; }
MERGER2="$(best_hash 0)"
wait_same_tip || { fail "no convergence after the merge"; exit 1; }
if [ "$(block_contains_tx 1 "$SIDE2" "$TXB")" = "yes" ] && [ ${#OWN2} -eq 64 ] && \
   [ "$(confirmed_in_block 0 "$TXB")" = "$OWN2" ] && \
   [ "$(mergeset_field 0 "$MERGER2" mergesetskippedtx "$TXB")" = "yes" ]; then
    success "the side block's copy was skipped; the canonical copy stays confirmed in ${OWN2:0:16}"
else
    fail "double application check failed (own '$OWN2', now '$(confirmed_in_block 0 "$TXB")')"
fi

# ============================================================
header "3. Disconnecting the merging block takes the payment back"
# ============================================================
rpc 0 invalidateblock "$MERGER" >/dev/null 2>&1
if [ "$(confirmed_in_block 0 "$TXM")" != "$MERGER" ]; then
    success "after invalidating the merging block the payment is no longer confirmed by it"
else
    fail "the payment stayed confirmed after its merging block was disconnected"
fi
rpc 0 reconsiderblock "$MERGER" >/dev/null 2>&1
wait_same_tip || { fail "no convergence after reconsider"; exit 1; }
if [ "$(confirmed_in_block 0 "$TXM")" = "$MERGER" ]; then
    success "reconnecting the merging block applies the payment again"
else
    fail "the payment is not re-applied (now '$(confirmed_in_block 0 "$TXM")')"
fi

# ============================================================
header "4. An IV5 shield carried only by a losing block is applied when merged"
# ============================================================
encrypt_and_restart 1 || { fail "node1 wallet could not be encrypted"; exit 1; }
SEED1="$(rpc 1 z_createiv5seed 2>&1)"
echo "$SEED1" | grep -q '"created"' || { fail "node1 z_createiv5seed failed: $(echo "$SEED1" | head -2)"; exit 1; }
connect_nodes
wait_peers || { fail "no re-peer after node1 restart"; exit 1; }
wait_same_tip || { fail "no convergence after node1 restart"; exit 1; }
TREE_BEFORE="$(iv5_tree_size 0)"
SPLIT3="$(height 0)"
partition_nodes || { fail "could not partition"; exit 1; }
unlock 1
SHIELD="$(rpc 1 z_shieldall 2>&1)"
TXS="$(jget "$SHIELD" txid)"
[ ${#TXS} -eq 64 ] || { fail "node1 z_shieldall failed: $(echo "$SHIELD" | head -2)"; exit 1; }
mine_one 1 || { fail "node1 could not mine"; exit 1; }
SIDE3="$(block_hash 1 $((SPLIT3 + 1)))"
[ "$(block_contains_tx 1 "$SIDE3" "$TXS")" = "yes" ] || { fail "the side block does not carry the shield"; exit 1; }
mine_to 0 $((SPLIT3 + 3)) || { fail "node0 could not outrun"; exit 1; }
connect_nodes
wait_peers || { fail "no re-peer"; exit 1; }
wait_block_known 0 "$SIDE3" || { fail "node0 never got the side block"; exit 1; }
wait_same_tip || { fail "no convergence"; exit 1; }
mine_one 0 || { fail "node0 could not mine the merging block"; exit 1; }
MERGER3="$(best_hash 0)"
wait_same_tip || { fail "no convergence after the merge"; exit 1; }
if [ "$(mergeset_field 0 "$MERGER3" mergesetacceptedtx "$TXS")" = "yes" ] && \
   [ "$(confirmed_in_block 0 "$TXS")" = "$MERGER3" ] && [ "$(confirmed_in_block 1 "$TXS")" = "$MERGER3" ]; then
    success "the IV5 shield was accepted by merging block ${MERGER3:0:16} on both nodes"
else
    fail "the IV5 shield was not accepted (node0 '$(confirmed_in_block 0 "$TXS")')"
fi

# ============================================================
header "5. The epoch built over a merged shield is the same on both nodes"
# ============================================================
mine_to 0 $((EPOCH_END + 3)) || { fail "could not close the epoch"; exit 1; }
wait_sync $((EPOCH_END + 3)) || { fail "nodes did not sync past the epoch"; exit 1; }
assert_iv5_agrees "after a merged shield"
TREE_AFTER="$(iv5_tree_size 0)"
if is_int "$TREE_BEFORE" && is_int "$TREE_AFTER" && [ "$TREE_AFTER" -gt "$TREE_BEFORE" ]; then
    success "the merged shield's leaves are in the epoch tree ($TREE_BEFORE -> $TREE_AFTER)"
else
    fail "the epoch tree did not grow ($TREE_BEFORE -> $TREE_AFTER)"
fi

# ============================================================
header "6. A reorg across an epoch boundary rebuilds the mergeset-era epoch"
# ============================================================
NEXT_END=$((EPOCH_END + 300))
mine_to 0 $((NEXT_END - 3)) || { fail "could not approach the next boundary"; exit 1; }
wait_sync $((NEXT_END - 3)) || { fail "no sync before the boundary race"; exit 1; }
partition_nodes || { fail "could not partition"; exit 1; }
TXR="$(rpc 1 sendtoaddress "$ADDR0" 2 2>&1 | tr -d '"[:space:]')"
mine_to 0 $((NEXT_END + 2)) || { fail "node0 could not cross the boundary"; exit 1; }
mine_to 1 $((NEXT_END + 6)) || { fail "node1 could not build the longer branch"; exit 1; }
connect_nodes
wait_peers || { fail "no re-peer"; exit 1; }
wait_same_tip || { fail "no convergence after the boundary race"; exit 1; }
if [ "$(best_hash 0)" = "$(best_hash 1)" ] && [ "$(height 0)" -ge $((NEXT_END + 6)) ]; then
    success "node0 reorganized across the epoch boundary onto node1's branch"
else
    fail "the boundary reorg did not converge"
fi
mine_one 0 >/dev/null 2>&1; wait_same_tip
assert_iv5_agrees "after a reorg across a mergeset-era epoch boundary"

# ============================================================
header "7. A blue side block's miner is paid by the merging block"
# ============================================================
coinbase_ipay() {
    python3 -c '
import json, sys
b = json.load(sys.stdin)
for o in b["tx"][0]["vout"]:
    h = o["scriptPubKey"]["hex"]
    if h.startswith("6a") and "49504159" in h[:12]:
        i = h.index("49504159") + 8
        print(h[i:]); break
' <<< "$(rpc "$1" getblock "$2" 2 2>/dev/null)" 2>/dev/null
}
coinbase_pays() {
    SCRIPT="$3" python3 -c '
import json, os, sys
b = json.load(sys.stdin)
print(sum(int(round(o["value"] * 1e8)) for o in b["tx"][0]["vout"] if o["scriptPubKey"]["hex"] == os.environ["SCRIPT"]))
' <<< "$(rpc "$1" getblock "$2" 2 2>/dev/null)" 2>/dev/null
}
SPLIT7="$(height 0)"
partition_nodes || { fail "could not partition"; exit 1; }
mine_one 1 || { fail "node1 could not mine"; exit 1; }
SIDE7="$(block_hash 1 $((SPLIT7 + 1)))"
PAYEE7="$(coinbase_ipay 1 "$SIDE7")"
[ -n "$PAYEE7" ] && success "node1's block commits a payee (${PAYEE7:0:20}...)" || fail "node1's block carries no IPAY payee"
mine_to 0 $((SPLIT7 + 3)) || { fail "node0 could not outrun"; exit 1; }
connect_nodes
wait_peers || { fail "no re-peer"; exit 1; }
wait_block_known 0 "$SIDE7" || { fail "node0 never got the side block"; exit 1; }
wait_same_tip || { fail "no convergence"; exit 1; }
mine_one 0 || { fail "node0 could not mine the merging block"; exit 1; }
MERGER7="$(best_hash 0)"
wait_same_tip || { fail "node1 did not accept the merging block"; exit 1; }
PAID7="$(coinbase_pays 0 "$MERGER7" "$PAYEE7")"
if [ "$(block_has_dag_parent 0 "$MERGER7" "$SIDE7")" = "yes" ] && is_int "$PAID7" && [ "$PAID7" -gt 0 ]; then
    success "merging block ${MERGER7:0:16} pays the side block's miner $PAID7 sat, and node1 accepts it"
else
    fail "the merging block did not pay the side block's miner (paid '$PAID7')"
fi

header "Results"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
[ "$FAILED" -eq 0 ]
