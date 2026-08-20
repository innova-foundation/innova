#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 DAG-sibling regtest: build the DAG shapes an epoch state has to survive.
#
# Every other IV5 harness runs on a single-parent chain, so the epoch build and
# ConnectBlock always saw the same transactions and the two derivations of a
# block's active set could not be told apart. This one puts a real sibling block
# carrying an IV5 payload into the DAG and then merges it, in the two shapes that
# separate them:
#
#   A. Two nodes mine the same IV5 transaction at the same height. One block wins
#      the chain, the other is merged. The merged block is never connected, so
#      nothing it carries may reach the epoch tree, the pool, the spent-key set or
#      the active-transaction id list that the tree store and the wallet replay.
#
#   B. A node in a partition mines its own IV5 transaction, loses the race, and
#      the transaction is re-mined into a later canonical block that merges the
#      losing block. ConnectBlock connects that transaction; an epoch build that
#      resolves conflicts from its own running order drops it, and the value it
#      shielded disappears from the tree.
#
# The whole test is about one invariant: the epoch state records exactly the
# transactions ConnectBlock connected, and nothing else.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_SIBLING_TEST_DIR:-/tmp/innova_iv5_sibling_$$}"
NUM_NODES=2
BASE_PORT="${IV5_SIBLING_BASE_PORT:-28800}"
BASE_RPC="${IV5_SIBLING_BASE_RPC:-28860}"
BASE_IDNS="${IV5_SIBLING_BASE_IDNS:-8880}"
RPCUSER="iv5sib"
RPCPASS="iv5sibpass"
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

wait_sync() {
    local target="$1" max="${2:-1200}" n h
    for ((i=0; i<max; i++)); do
        local ok=1
        for ((n=0; n<NUM_NODES; n++)); do
            h="$(height "$n")"
            if ! is_int "$h" || [ "$h" -lt "$target" ]; then ok=0; break; fi
        done
        [ "$ok" -eq 1 ] && return 0
        sleep 1
    done
    return 1
}

wait_same_tip() {
    for _ in $(seq 1 180); do
        local a b
        a="$(best_hash 0)"; b="$(best_hash 1)"
        if [ ${#a} -eq 64 ] && [ "$a" = "$b" ]; then return 0; fi
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
    [ "${IV5_SIBLING_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 DAG-sibling regtest"

rm -rf "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done

# ============================================================
header "1. Two nodes, IV5 active, both able to shield"
# ============================================================

start_node 0 || { fail "node0 did not start"; exit 1; }
encrypt_and_restart 0 || { fail "node0 wallet could not be encrypted"; exit 1; }
SEED0="$(rpc 0 z_createiv5seed 2>&1)"
echo "$SEED0" | grep -q '"created"' || { fail "node0 z_createiv5seed failed: $(echo "$SEED0" | head -2)"; exit 1; }

mine_to 0 "$FUND_HEIGHT" || { fail "node0 could not mine to $FUND_HEIGHT"; exit 1; }

start_node 1 || { fail "node1 did not start"; exit 1; }
encrypt_and_restart 1 || { fail "node1 wallet could not be encrypted"; exit 1; }
SEED1="$(rpc 1 z_createiv5seed 2>&1)"
echo "$SEED1" | grep -q '"created"' || { fail "node1 z_createiv5seed failed: $(echo "$SEED1" | head -2)"; exit 1; }

connect_nodes
wait_peers || { fail "the two nodes never peered"; exit 1; }
wait_sync "$FUND_HEIGHT" || { fail "node1 did not sync to $FUND_HEIGHT"; exit 1; }
success "two peered nodes synced at $FUND_HEIGHT with IV5 seeds"

INFO0="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
if [ "$(jget "$INFO0" boundary_b_active)" = "true" ] && \
   [ "$(jget "$INFO0" privacy_vnext_transactions_accepted)" = "true" ]; then
    success "Boundary B active at $BOUNDARY_B and consensus accepts IV5 transactions"
else
    fail "IV5 is not accepting on node0"
    exit 1
fi

# getblock's verbosity parameter: check all four forms before the races use it.
VERB_BLOCK="$(best_hash 0)"
VERB_OK=1
[ ${#VERB_BLOCK} -eq 64 ] || VERB_OK=0
VERB_HEX0="$(rpc 0 getblock "$VERB_BLOCK" 0 2>/dev/null | tr -d '"[:space:]')"
VERB_HEXF="$(rpc 0 getblock "$VERB_BLOCK" false 2>/dev/null | tr -d '"[:space:]')"
VERB_J1="$(jget "$(rpc 0 getblock "$VERB_BLOCK" 1 2>/dev/null)" hash)"
VERB_JT="$(jget "$(rpc 0 getblock "$VERB_BLOCK" true 2>/dev/null)" hash)"
VERB_J2="$(rpc 0 getblock "$VERB_BLOCK" 2 2>/dev/null)"
VERB_TXOBJ="$(python3 -c '
import json, sys
try:
    tx = json.load(sys.stdin).get("tx", [])
    print("yes" if tx and isinstance(tx[0], dict) else "no")
except Exception:
    print("no")
' <<< "$VERB_J2" 2>/dev/null)"
if [ "$VERB_OK" = "1" ] && [ ${#VERB_HEX0} -ge 100 ] && [ "$VERB_HEX0" = "$VERB_HEXF" ] && \
   [ "$VERB_J1" = "$VERB_BLOCK" ] && [ "$VERB_JT" = "$VERB_BLOCK" ]; then
    success "getblock accepts 0/false and 1/true and agrees between the two forms"
else
    fail "getblock does not accept its documented numeric verbosity (hex0 ${#VERB_HEX0}, hexfalse ${#VERB_HEXF}, j1 '$VERB_J1', jtrue '$VERB_JT')"
fi
if [ "$VERB_TXOBJ" = "yes" ]; then
    success "getblock verbosity 2 expands the block's transactions"
else
    fail "getblock verbosity 2 did not expand transactions: $(echo "$VERB_J2" | head -2)"
fi

# node1 needs transparent funds of its own so it can build an IV5 transaction
# nobody else has seen.
ADDR1="$(rpc 1 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
[ ${#ADDR1} -gt 20 ] || { fail "could not get a node1 address"; exit 1; }
unlock 0
FUNDTX="$(rpc 0 sendtoaddress "$ADDR1" "$PEER_FUND" 2>&1 | tr -d '"[:space:]')"
[ ${#FUNDTX} -eq 64 ] || { fail "could not fund node1: $FUNDTX"; exit 1; }
mine_to 0 "$SETTLE_HEIGHT" || { fail "could not confirm the node1 funding"; exit 1; }
wait_sync "$SETTLE_HEIGHT" || { fail "nodes did not resync after funding"; exit 1; }
BAL1="$(rpc 1 getbalance 2>/dev/null | tr -d '"[:space:]')"
if [ "$(python3 -c "print(1 if float('${BAL1:-0}') >= 1 else 0)" 2>/dev/null)" = "1" ]; then
    success "node1 funded with $BAL1 INN"
else
    fail "node1 has no spendable balance ($BAL1)"
    exit 1
fi

# ============================================================
header "2. Shape A: a sibling block carrying the same IV5 payload"
# ============================================================

unlock 0
SHIELD0="$(rpc 0 z_shieldall 2>&1)"
TXA="$(jget "$SHIELD0" txid)"
SHIELDED0="$(jget "$SHIELD0" shielded)"
if [ ${#TXA} -eq 64 ]; then
    success "node0 built an IV5 shield of $SHIELDED0 INN (${TXA:0:16})"
else
    fail "node0 z_shieldall failed: $(echo "$SHIELD0" | head -3)"
    exit 1
fi

wait_mempool 1 "$TXA" || { fail "the shield never reached node1's mempool"; exit 1; }
success "both nodes hold the shield in their mempool"

SPLIT_HEIGHT="$(height 0)"
partition_nodes || { fail "the nodes could not be partitioned"; exit 1; }
success "nodes partitioned at height $SPLIT_HEIGHT"

mine_one 0 || { fail "node0 could not mine its side of the race"; exit 1; }
mine_one 1 || { fail "node1 could not mine its side of the race"; exit 1; }
SIB_HEIGHT=$((SPLIT_HEIGHT + 1))
A0="$(block_hash 0 "$SIB_HEIGHT")"
A1="$(block_hash 1 "$SIB_HEIGHT")"
if [ ${#A0} -eq 64 ] && [ ${#A1} -eq 64 ] && [ "$A0" != "$A1" ]; then
    success "two distinct blocks at height $SIB_HEIGHT: ${A0:0:16} and ${A1:0:16}"
else
    fail "the partition did not produce a sibling pair ($A0 / $A1)"
    exit 1
fi
if [ "$(block_contains_tx 0 "$A0" "$TXA")" = "yes" ] && \
   [ "$(block_contains_tx 1 "$A1" "$TXA")" = "yes" ]; then
    success "both siblings carry the IV5 payload ${TXA:0:16}"
else
    fail "the siblings do not both carry the IV5 transaction"
    exit 1
fi

connect_nodes
wait_peers || { fail "the nodes did not re-peer after the race"; exit 1; }
wait_block_known 0 "$A1" || { fail "node0 never received the competing block"; exit 1; }
wait_block_known 1 "$A0" || { fail "node1 never received the competing block"; exit 1; }
# One more block resolves the tie and commits the loser as a merge parent.
mine_one 0 || { fail "node0 could not extend after the race"; exit 1; }
wait_same_tip || { fail "the nodes did not converge on one tip after the race"; exit 1; }
CANON_SIB="$(block_hash 0 "$SIB_HEIGHT")"
if [ "$CANON_SIB" = "$A0" ]; then MERGE_A="$A1"; else MERGE_A="$A0"; fi
MERGE_A_HEIGHT="$(jget "$(rpc 0 getblock "$MERGE_A" 2>/dev/null)" height)"
if [ "$MERGE_A_HEIGHT" = "$SIB_HEIGHT" ] && [ "$MERGE_A" != "$CANON_SIB" ]; then
    success "the losing sibling ${MERGE_A:0:16} survives off-chain at height $SIB_HEIGHT"
else
    fail "the losing sibling is not known to node0 as an off-chain block"
    exit 1
fi

MERGER_A="$(block_hash 0 $((SIB_HEIGHT + 1)))"
if [ "$(block_has_dag_parent 0 "$MERGER_A" "$MERGE_A")" = "yes" ]; then
    success "canonical block ${MERGER_A:0:16} commits the losing sibling as a DAG merge parent"
else
    fail "no canonical block merged the losing sibling; the shape under test was not built"
    exit 1
fi

# ============================================================
header "3. Shape B: a merged sibling's payload re-mined by the canonical chain"
# ============================================================

mine_to 0 $((SIB_HEIGHT + 5)) || { fail "could not settle after shape A"; exit 1; }
wait_sync $((SIB_HEIGHT + 5)) || { fail "nodes did not resync after shape A"; exit 1; }

SPLIT_B="$(height 0)"
partition_nodes || { fail "the nodes could not be partitioned for shape B"; exit 1; }

unlock 1
SHIELD1="$(rpc 1 z_shieldall 2>&1)"
TXB="$(jget "$SHIELD1" txid)"
SHIELDED1="$(jget "$SHIELD1" shielded)"
if [ ${#TXB} -eq 64 ]; then
    success "node1 built an IV5 shield of $SHIELDED1 INN in isolation (${TXB:0:16})"
else
    fail "node1 z_shieldall failed: $(echo "$SHIELD1" | head -3)"
    exit 1
fi
RAWB="$(rpc 1 getrawtransaction "$TXB" 2>/dev/null | tr -d '"[:space:]')"

mine_one 1 || { fail "node1 could not mine its isolated block"; exit 1; }
MERGE_B="$(block_hash 1 $((SPLIT_B + 1)))"
if [ "$(block_contains_tx 1 "$MERGE_B" "$TXB")" = "yes" ]; then
    success "node1's isolated block ${MERGE_B:0:16} carries its IV5 payload"
else
    fail "node1's block does not carry its IV5 transaction"
    exit 1
fi

# node0 outruns the isolated branch, so node1's block loses and its transaction
# comes back to the mempool.
mine_to 0 $((SPLIT_B + 3)) || { fail "node0 could not outrun the isolated branch"; exit 1; }

connect_nodes
wait_peers || { fail "the nodes did not re-peer for shape B"; exit 1; }
wait_block_known 0 "$MERGE_B" || { fail "node0 never received node1's isolated block"; exit 1; }
wait_same_tip || { fail "the nodes did not converge after shape B's race"; exit 1; }
if [ "$(block_hash 0 $((SPLIT_B + 1)))" != "$MERGE_B" ]; then
    success "node1's block lost the race and is off-chain"
else
    fail "node1's branch won; shape B needs the isolated block to lose"
    exit 1
fi

if [ "$(in_mempool 0 "$TXB")" != "yes" ] && [ ${#RAWB} -gt 100 ]; then
    rpc 0 sendrawtransaction "$RAWB" >/dev/null 2>&1 || true
fi
wait_mempool 0 "$TXB" || { fail "node1's shield never returned to a mempool"; exit 1; }

mine_one 0 || { fail "node0 could not re-mine node1's shield"; exit 1; }
REMINE_H="$(height 0)"
REMINE="$(block_hash 0 "$REMINE_H")"
if [ "$(block_contains_tx 0 "$REMINE" "$TXB")" = "yes" ]; then
    success "canonical block ${REMINE:0:16} at $REMINE_H re-mined node1's shield"
else
    fail "the canonical chain did not re-mine node1's shield"
    exit 1
fi
if [ "$(block_has_dag_parent 0 "$REMINE" "$MERGE_B")" = "yes" ]; then
    success "the re-mining block also merges the losing block ${MERGE_B:0:16}"
else
    fail "the re-mining block does not merge the losing block; shape B was not built"
    exit 1
fi

# ============================================================
header "4. The epoch state records only what ConnectBlock connected"
# ============================================================

mine_to 0 "$EPOCH_DONE_HEIGHT" || { fail "could not complete epoch $EPOCH"; exit 1; }
wait_sync "$EPOCH_DONE_HEIGHT" || { fail "nodes did not resync to $EPOCH_DONE_HEIGHT"; exit 1; }
wait_same_tip || { fail "nodes hold different tips at $EPOCH_DONE_HEIGHT"; exit 1; }

EPOCHINFO0="$(rpc 0 getepochinfo "$EPOCH" 2>/dev/null)"
EPOCHINFO1="$(rpc 1 getepochinfo "$EPOCH" 2>/dev/null)"

# Blocks in the epoch's DAG order that are not the canonical block at their own
# height are merge blocks. ConnectBlock never ran on them.
CANON_LIST="$TEST_DIR/canonical_hashes.txt"
: > "$CANON_LIST"
for ((h=EPOCH_START; h<=EPOCH_END; h++)); do
    # block_hash strips all whitespace, so the newline has to be added back or
    # every hash lands on one line and nothing ever matches.
    echo "$(block_hash 0 "$h")" >> "$CANON_LIST"
done
if [ "$(grep -c . "$CANON_LIST")" != "$((EPOCH_END - EPOCH_START + 1))" ]; then
    fail "could not read the canonical block hashes for epoch $EPOCH"
    exit 1
fi

MERGE_REPORT="$(EPOCHJSON="$EPOCHINFO0" CANONFILE="$CANON_LIST" python3 <<'PY'
import json, os, sys
try:
    st = json.loads(os.environ["EPOCHJSON"])
except Exception as e:
    print("ERROR parse %s" % e); sys.exit(0)
canon = set(x.strip() for x in open(os.environ["CANONFILE"]) if x.strip())
blocks = st.get("blocks", [])
counts = st.get("iv5_active_block_tx_counts", None)
if counts is None:
    print("ERROR no_iv5_counts"); sys.exit(0)
if len(counts) != len(blocks):
    print("ERROR misaligned %d %d" % (len(counts), len(blocks))); sys.exit(0)
merges = [(h, c) for h, c in zip(blocks, counts) if h not in canon]
bad = [(h, c) for h, c in merges if c != 0]
print("OK %d %d %d %d %s" % (
    len(blocks), len(merges), len(bad),
    sum(counts),
    ",".join("%s:%d" % (h[:16], c) for h, c in bad[:4]) or "-"))
PY
)"

set -- $MERGE_REPORT
STATUS="$1"; N_BLOCKS="$2"; N_MERGES="$3"; N_BAD="$4"; SUM_COUNTS="$5"; BAD_LIST="$6"

if [ "$STATUS" != "OK" ]; then
    fail "could not read the epoch's IV5 active-set counts: $MERGE_REPORT"
    exit 1
fi

EXPECTED_CANON=$((EPOCH_END - EPOCH_START + 1))
if [ "$N_MERGES" -ge 2 ]; then
    success "epoch $EPOCH ordered $N_BLOCKS blocks over $EXPECTED_CANON canonical heights: $N_MERGES merge block(s)"
else
    fail "epoch $EPOCH contains $N_MERGES merge blocks; the shapes under test are not in the epoch"
    exit 1
fi

if [ "$N_BAD" = "0" ]; then
    success "every merge block contributes zero transactions to the IV5 active set"
else
    fail "$N_BAD merge block(s) contribute transactions to the IV5 active set ($BAD_LIST)"
fi

ACTIVE_COUNT="$(jget "$EPOCHINFO0" iv5_active_tx_count)"
if [ "$ACTIVE_COUNT" = "$SUM_COUNTS" ]; then
    success "the active-transaction id list matches the per-block counts ($ACTIVE_COUNT)"
else
    fail "active-set id list ($ACTIVE_COUNT) disagrees with the per-block counts ($SUM_COUNTS)"
fi

DIGEST0="$(jget "$EPOCHINFO0" epoch_state_digest)"
DIGEST1="$(jget "$EPOCHINFO1" epoch_state_digest)"
if [ ${#DIGEST0} -eq 64 ] && [ "$DIGEST0" = "$DIGEST1" ]; then
    success "both nodes derived the same epoch state (${DIGEST0:0:16})"
else
    fail "the two nodes derived different epoch states ($DIGEST0 / $DIGEST1)"
fi

# ============================================================
header "5. The replayers can still rebuild the tree the epoch committed"
# ============================================================

for node in 0 1; do
    INFO="$(rpc $node z_getshieldedinfo 2>/dev/null)"
    TREE="$(jget "$INFO" privacy_vnext_tree_size)"
    STORE="$(jget "$INFO" privacy_vnext_tree_store_size)"
    if is_int "$TREE" && [ "${TREE:-0}" -gt 0 ] && [ "$TREE" = "$STORE" ]; then
        success "node$node tree store is level with the epoch tree at $STORE leaves"
    else
        fail "node$node tree store froze at ${STORE:-?} against an epoch tree of ${TREE:-?}"
    fi
done

BAL_V0="$(jget "$(rpc 0 z_getshieldedinfo 2>/dev/null)" privacy_vnext_balance)"
NOTES0="$(jget "$(rpc 0 z_getshieldedinfo 2>/dev/null)" privacy_vnext_note_count)"
BAL_V1="$(jget "$(rpc 1 z_getshieldedinfo 2>/dev/null)" privacy_vnext_balance)"
NOTES1="$(jget "$(rpc 1 z_getshieldedinfo 2>/dev/null)" privacy_vnext_note_count)"

# A shielded balance is only reported for notes the wallet could place in the
# tree, so a zero balance against a nonzero note count is the wallet replayer
# refusing to assign leaf indices.
if [ "$(python3 -c "print(1 if float('${BAL_V0:-0}') > 0 else 0)" 2>/dev/null)" = "1" ]; then
    success "node0 can place its own $NOTES0 note(s): $BAL_V0 INN"
else
    fail "node0 holds $NOTES0 note(s) it cannot place in the tree (balance $BAL_V0)"
fi
if [ "$(python3 -c "print(1 if float('${BAL_V1:-0}') > 0 else 0)" 2>/dev/null)" = "1" ]; then
    success "node1's re-mined shield reached the tree: $BAL_V1 INN over $NOTES1 note(s)"
else
    fail "node1's re-mined shield never reached the tree (balance $BAL_V1, notes $NOTES1)"
fi

# ============================================================
header "6. The pool holds exactly what the two wallets own"
# ============================================================

POOL="$(jget "$EPOCHINFO0" iv5_pool_balance)"
if [ -n "$POOL" ] && [ -n "$BAL_V0" ] && [ -n "$BAL_V1" ]; then
    if [ "$(python3 -c "print(1 if abs(float('$POOL') - (float('$BAL_V0') + float('$BAL_V1'))) < 1e-8 else 0)" 2>/dev/null)" = "1" ]; then
        success "pool balance $POOL INN equals the owned notes ($BAL_V0 + $BAL_V1)"
    else
        fail "pool balance $POOL INN does not match the owned notes ($BAL_V0 + $BAL_V1)"
    fi
else
    fail "could not read the epoch pool balance"
fi

# ============================================================
header "7. A losing chain that carried an IV5 payload is taken back"
# ============================================================

# Chain race: node1 connects an IV5 payload, then reorgs to a longer chain without it.
# The disconnect must remove the leaf, nullifier and pool value, or the trees split.

REORG_BASE="$(height 0)"
unlock 0
REFUND="$(rpc 0 sendtoaddress "$ADDR1" "$PEER_FUND" 2>&1 | tr -d '"[:space:]')"
if [ ${#REFUND} -eq 64 ]; then
    mine_to 0 $((REORG_BASE + 3)) || { fail "could not confirm the node1 re-funding"; exit 1; }
    wait_sync $((REORG_BASE + 3)) || { fail "nodes did not resync after re-funding"; exit 1; }
    success "node1 re-funded for the chain race"
else
    fail "could not re-fund node1: $REFUND"
fi

REORG_SPLIT="$(height 0)"
TREE_BEFORE0="$(iv5_tree_size 0)"
partition_nodes || { fail "the nodes could not be partitioned for the chain race"; exit 1; }

unlock 1
SHIELD_R="$(rpc 1 z_shieldall 2>&1)"
TXR="$(jget "$SHIELD_R" txid)"
if [ ${#TXR} -eq 64 ]; then
    success "node1 built an IV5 shield the winning chain never sees (${TXR:0:16})"
else
    fail "node1 z_shieldall failed: $(echo "$SHIELD_R" | head -3)"
fi

# node1 connects its own payload on the side of the partition that is about to lose.
mine_one 1 || { fail "node1 could not mine its shield"; exit 1; }
LOSER_HEIGHT=$((REORG_SPLIT + 1))
LOSER_BLOCK="$(block_hash 1 "$LOSER_HEIGHT")"
if [ "$(block_contains_tx 1 "$LOSER_BLOCK" "$TXR")" = "yes" ]; then
    success "node1 connected the payload in ${LOSER_BLOCK:0:16} at $LOSER_HEIGHT"
else
    fail "node1's block does not carry the IV5 payload"
fi
mine_one 1 || warn "node1 could not extend its losing chain"

# The tree is named by the last COMPLETED epoch, so a race inside one epoch must
# leave it exactly where it was. Anything else would mean a leaf reached the tree
# without an epoch closing over it.
TREE_LOSER1="$(iv5_tree_size 1)"
if [ "$TREE_LOSER1" = "$TREE_BEFORE0" ]; then
    success "node1's mid-epoch payload did not move the tree ($TREE_BEFORE0 leaves)"
else
    fail "node1's tree moved inside an epoch ($TREE_BEFORE0 -> $TREE_LOSER1)"
fi

# The winning chain is longer and carries none of it.
mine_to 0 $((REORG_SPLIT + 5)) || { fail "node0 could not build the winning chain"; exit 1; }

# Anti-vacuity, asserted while the partition still holds: two nodes that never
# diverged converge trivially, and every check below this point would then be
# reporting a race that did not happen.
RACE_TIP0="$(best_hash 0)"
RACE_TIP1="$(best_hash 1)"
if [ ${#RACE_TIP0} -eq 64 ] && [ ${#RACE_TIP1} -eq 64 ] && [ "$RACE_TIP0" != "$RACE_TIP1" ] && \
   [ "$(block_hash 1 "$LOSER_HEIGHT")" = "$LOSER_BLOCK" ]; then
    success "the two chains diverged: node0 on ${RACE_TIP0:0:16}, node1 on ${RACE_TIP1:0:16} over its own payload"
else
    fail "the nodes did not diverge (node0 $RACE_TIP0, node1 $RACE_TIP1); the reorg below has nothing to undo"
fi

connect_nodes
wait_peers || { fail "the nodes did not re-peer after the chain race"; exit 1; }
wait_same_tip || { fail "the nodes did not converge after the chain race"; exit 1; }
REORG_TIP="$(best_hash 0)"
success "both nodes converged on ${REORG_TIP:0:16} at height $(height 0)"

# node1 must have left its own chain. If its tip is still the block it mined, the
# reorg never happened and the rest of the section proves nothing.
if [ "$(block_hash 1 "$LOSER_HEIGHT")" != "$LOSER_BLOCK" ]; then
    success "node1 disconnected the block that carried its payload"
else
    fail "node1 never left its losing chain; the reorg under test did not occur"
fi

assert_iv5_agrees "after the chain reorg"

# ============================================================
header "8. Blocks that arrive out of order rebuild the same tree"
# ============================================================

# Out-of-order delivery: a run with the payload in the middle is delivered scrambled,
# gap-closing block last. node1 must stay at the split height until the gap closes.

OOO_SPLIT="$(height 0)"
partition_nodes || { fail "the nodes could not be partitioned for the ordering test"; exit 1; }

OOO_RUN=8
OOO_PAYLOAD_OFFSET=3

# Two plain blocks first, so the payload lands at OOO_SPLIT+3 and has a parent
# inside the run that the delivery order can withhold from it.
mine_to 0 $((OOO_SPLIT + OOO_PAYLOAD_OFFSET - 1)) || { fail "node0 could not mine ahead of the payload"; exit 1; }

unlock 0
SHIELD_O="$(rpc 0 z_shieldall 2>&1)"
TXO="$(jget "$SHIELD_O" txid)"
OOO_OK=1
if [ ${#TXO} -eq 64 ]; then
    success "node0 built an IV5 shield to carry mid-run (${TXO:0:16})"
else
    fail "node0 z_shieldall produced no shield for the ordering test: $(echo "$SHIELD_O" | head -2)"
    OOO_OK=0
fi

mine_to 0 $((OOO_SPLIT + OOO_RUN)) || { fail "node0 could not mine the run"; exit 1; }
OOO_TIP="$(best_hash 0)"

# Which block actually carries the payload. Asserted rather than assumed: a shield
# that landed outside the run, or in the first block of it, gives the reorder
# nothing to hold.
OOO_PAYLOAD_HEIGHT=0
for ((i=1; i<=OOO_RUN; i++)); do
    if [ "$(block_contains_tx 0 "$(block_hash 0 $((OOO_SPLIT + i)))" "$TXO")" = "yes" ]; then
        OOO_PAYLOAD_HEIGHT=$((OOO_SPLIT + i))
        OOO_PAYLOAD_OFFSET=$i
        break
    fi
done
if [ "$OOO_PAYLOAD_HEIGHT" -gt 0 ] && [ "$OOO_PAYLOAD_OFFSET" -ge 2 ]; then
    success "the v2008 payload sits at offset $OOO_PAYLOAD_OFFSET of the run, so its parent is inside it"
else
    fail "the v2008 payload is not inside the run past its first block (offset '$OOO_PAYLOAD_OFFSET')"
    OOO_OK=0
fi

# A scrambled delivery order, not a reverse one. The split's own child is held to
# the end, so nothing node1 receives before it has a CONNECTED parent -- delivering
# a block whose parent is itself still an orphan is the same case.
OOO_ORDER=(5 3 8 4 7 2 6 1)
OOO_LAST="${OOO_ORDER[$((${#OOO_ORDER[@]} - 1))]}"
OOO_COVER="$(printf '%s\n' "${OOO_ORDER[@]}" | sort -n | tr '\n' ' ')"
OOO_EXPECT="$(seq 1 "$OOO_RUN" | tr '\n' ' ')"
if [ "$OOO_COVER" = "$OOO_EXPECT" ]; then
    success "the delivery order is a permutation of the $OOO_RUN-block run"
else
    fail "the delivery order does not cover the run once each ($OOO_COVER vs $OOO_EXPECT)"
    OOO_OK=0
fi

# The premise the section rests on, read off the order rather than asserted about
# it: the gap-closing block is last, so the other seven arrive with no connected
# parent, and the payload block is not the gap-closer.
if [ "$OOO_LAST" -eq 1 ] && [ "$OOO_PAYLOAD_OFFSET" -ne 1 ]; then
    success "the order withholds the gap-closing block, so $((OOO_RUN - 1)) blocks arrive with no connected parent, the v2008 block among them"
else
    fail "the order does not withhold the gap-closing block (last=$OOO_LAST, payload offset=$OOO_PAYLOAD_OFFSET)"
    OOO_OK=0
fi

# Deliver everything except the gap-closing block.
if [ "$OOO_OK" = "1" ]; then
    for idx in "${OOO_ORDER[@]}"; do
        [ "$idx" -eq 1 ] && continue
        h=$((OOO_SPLIT + idx))
        bh="$(block_hash 0 "$h")"
        # Verbosity 0 is the documented numeric form for raw hex; section 1 checks
        # that the boolean form still means the same thing.
        hex="$(rpc 0 getblock "$bh" 0 2>/dev/null | tr -d '"[:space:]')"
        if [ ${#hex} -lt 100 ]; then
            fail "could not read block $h as raw hex"
            OOO_OK=0
            break
        fi
        # An orphan is expected to be refused or parked; only the final parent has
        # to be accepted, so the result of each individual call is not the assertion.
        rpc 1 submitblock "$hex" >/dev/null 2>&1 || true
    done
fi

# Nothing may have connected yet: every block delivered so far is missing an
# ancestor. A node that advanced was not holding them, and the run below would then
# be an ordinary in-order sync.
if [ "$OOO_OK" = "1" ]; then
    sleep 5
    OOO_HELD="$(height 1)"
    if is_int "$OOO_HELD" && [ "$OOO_HELD" -eq "$OOO_SPLIT" ]; then
        success "node1 held $((OOO_RUN - 1)) parentless blocks without connecting any of them"
    else
        fail "node1 advanced to $OOO_HELD before the gap was closed, so nothing was held out of order"
        OOO_OK=0
    fi
fi

# Now the block that closes the gap.
if [ "$OOO_OK" = "1" ]; then
    bh="$(block_hash 0 $((OOO_SPLIT + 1)))"
    hex="$(rpc 0 getblock "$bh" 0 2>/dev/null | tr -d '"[:space:]')"
    if [ ${#hex} -ge 100 ]; then
        rpc 1 submitblock "$hex" >/dev/null 2>&1 || true
        success "delivered the gap-closing block last"
    else
        fail "could not read the gap-closing block as raw hex"
        OOO_OK=0
    fi
fi

if [ "$OOO_OK" = "1" ]; then
    for _ in $(seq 1 120); do
        [ "$(best_hash 1)" = "$OOO_TIP" ] && break
        sleep 1
    done
    if [ "$(best_hash 1)" = "$OOO_TIP" ]; then
        success "node1 reached the same tip from out-of-order delivery"
    else
        fail "node1 did not reach the tip after out-of-order delivery (at $(height 1), tip $(best_hash 1 | cut -c1-16) vs ${OOO_TIP:0:16})"
    fi
    # The payload block specifically has to be the one node1's chain connected, not
    # a block it kept as an orphan while agreeing on a shorter tip.
    OOO_PAYLOAD_BLOCK="$(block_hash 1 "$OOO_PAYLOAD_HEIGHT")"
    if [ ${#OOO_PAYLOAD_BLOCK} -eq 64 ] && \
       [ "$OOO_PAYLOAD_BLOCK" = "$(block_hash 0 "$OOO_PAYLOAD_HEIGHT")" ] && \
       [ "$(block_contains_tx 1 "$OOO_PAYLOAD_BLOCK" "$TXO")" = "yes" ]; then
        success "node1 connected the v2008 payload in the block it arrived parentless in"
    else
        fail "node1 did not connect the v2008 payload where the winner did (node1 has '$OOO_PAYLOAD_BLOCK' at $OOO_PAYLOAD_HEIGHT)"
    fi
    assert_iv5_agrees "after out-of-order delivery"
fi

# Put the fleet back together so the section leaves no partition behind.
connect_nodes
wait_peers >/dev/null 2>&1 || true

# ============================================================
header "9. A reorg that undoes a CLOSED epoch takes its leaves back"
# ============================================================

# The tree is named by the last completed epoch, so only a reorg across an epoch
# boundary can change it. node1 closes epoch 3 over its own IV5 payload, then a
# longer chain takes that epoch away; the recomputed tree must match node0's.

EPOCH3_END=910
mine_to 0 $((EPOCH3_END - 6)) || { fail "could not approach the epoch-3 boundary"; exit 1; }
wait_sync $((EPOCH3_END - 6)) || { fail "nodes did not sync before the boundary race"; exit 1; }

unlock 0
EFUND="$(rpc 0 sendtoaddress "$ADDR1" "$PEER_FUND" 2>&1 | tr -d '"[:space:]')"
if [ ${#EFUND} -eq 64 ]; then
    mine_to 0 $((EPOCH3_END - 4)) || { fail "could not confirm the boundary-race funding"; exit 1; }
    wait_sync $((EPOCH3_END - 4)) || { fail "nodes did not resync before the boundary race"; exit 1; }
    success "node1 funded ahead of the epoch-3 boundary"
else
    fail "could not fund node1 for the boundary race: $EFUND"
fi

TREE_PRE0="$(iv5_tree_size 0)"
ROOT_PRE0="$(iv5_tree_root 0)"
partition_nodes || { fail "the nodes could not be partitioned at the boundary"; exit 1; }

unlock 1
SHIELD_E="$(rpc 1 z_shieldall 2>&1)"
TXE="$(jget "$SHIELD_E" txid)"
if [ ${#TXE} -eq 64 ]; then
    success "node1 built the payload its epoch will close over (${TXE:0:16})"
else
    fail "node1 z_shieldall failed at the boundary: $(echo "$SHIELD_E" | head -3)"
fi

# node1 closes epoch 3 over its own payload, then keeps going far enough that the
# epoch is genuinely complete on its side.
mine_to 1 $((EPOCH3_END + 3)) || { fail "node1 could not close epoch 3"; exit 1; }
TREE_LOSER="$(iv5_tree_size 1)"
ROOT_LOSER="$(iv5_tree_root 1)"
# Premise, not a measurement: an epoch that committed no leaf gives the reorg
# nothing to undo, and the assertion at the end of the section then holds for a
# tree the two nodes shared all along.
if is_int "$TREE_LOSER" && is_int "$TREE_PRE0" && [ "$TREE_LOSER" -gt "$TREE_PRE0" ]; then
    success "node1 closed epoch 3 with a larger tree ($TREE_PRE0 -> $TREE_LOSER leaves)"
else
    fail "node1's closed epoch committed no leaf ($TREE_PRE0 -> $TREE_LOSER), so the reorg below has nothing to take back"
fi

# node0 closes the same epoch over a longer chain that never saw the payload.
mine_to 0 $((EPOCH3_END + 8)) || { fail "node0 could not close epoch 3 on the winning chain"; exit 1; }
TREE_WINNER="$(iv5_tree_size 0)"
ROOT_WINNER="$(iv5_tree_root 0)"

# Anti-vacuity, asserted while the partition still holds: the two nodes are on
# different chains AND on different epoch-3 boundaries. Convergence between two
# nodes that never parted is not a reorg across a v2008 block.
B_TIP0="$(best_hash 0)"
B_TIP1="$(best_hash 1)"
B_BOUND0="$(block_hash 0 "$EPOCH3_END")"
B_BOUND1="$(block_hash 1 "$EPOCH3_END")"
if [ ${#B_TIP0} -eq 64 ] && [ ${#B_TIP1} -eq 64 ] && [ "$B_TIP0" != "$B_TIP1" ] && \
   [ ${#B_BOUND0} -eq 64 ] && [ ${#B_BOUND1} -eq 64 ] && [ "$B_BOUND0" != "$B_BOUND1" ]; then
    success "the chains diverged across the boundary: epoch-3 ends at ${B_BOUND0:0:12} on node0 and ${B_BOUND1:0:12} on node1"
else
    fail "the two chains did not diverge across the boundary (tips $B_TIP0 / $B_TIP1, boundaries $B_BOUND0 / $B_BOUND1)"
fi

connect_nodes
wait_peers || { fail "the nodes did not re-peer at the boundary"; exit 1; }
wait_same_tip || { fail "the nodes did not converge after the boundary race"; exit 1; }
success "both nodes converged at height $(height 0) after the boundary race"

# The second premise, and the load-bearing one: equal roots mean the two epoch-3
# derivations agreed, so no divergent state was ever undone.
if [ "$ROOT_LOSER" != "$ROOT_WINNER" ]; then
    success "the two epoch-3 derivations really did differ (${ROOT_LOSER:0:12} vs ${ROOT_WINNER:0:12})"
else
    fail "both sides closed epoch 3 on the same root (${ROOT_LOSER:0:12}); the undo this section tests never happened"
fi

assert_iv5_agrees "after undoing a closed epoch"

# The surviving tree has to be the winning chain's, not merely a tree the two
# nodes happen to share.
if [ "$(iv5_tree_root 1)" = "$ROOT_WINNER" ] && [ "$(iv5_tree_size 1)" = "$TREE_WINNER" ]; then
    success "node1 rebuilt the winning chain's tree ($TREE_WINNER leaves, ${ROOT_WINNER:0:16})"
else
    fail "node1 kept a tree that is not the winning chain's (root $(iv5_tree_root 1) size $(iv5_tree_size 1), expected ${ROOT_WINNER} / $TREE_WINNER)"
fi


# ============================================================
header "10. Two distinct spends of one note in sibling blocks"
# ============================================================

# Two different transactions spending one note on two nodes; only the DAG can resolve
# it. Transparent voting drives finality; every premise is a hard failure.

S10_OK=1
s10_premise() { if [ "$1" = "1" ]; then success "$2"; else fail "$3"; S10_OK=0; fi; }

# A distinct transaction carrying the same payload. nTime is not in the binding
# hash for this transaction version, so the twin has a new txid, the same key
# images and a payload that still verifies.
restamp_raw() {
    local raw="$1" le n h
    le="${raw:8:8}"
    n=$(( 16#${le:6:2}${le:4:2}${le:2:2}${le:0:2} ))
    n=$(( n - 1 ))
    h="$(printf '%08x' "$n")"
    echo "${raw:0:8}${h:6:2}${h:4:2}${h:2:2}${h:0:2}${raw:16}"
}

debug_log()   { echo "$(node_dir "$1")/regtest/debug.log"; }
log_lines()   { { wc -l < "$(debug_log "$1")" 2>/dev/null || echo 0; } | tr -d '[:space:]'; }

# A refusal names the key image it refused and the transaction already holding
# it, and is the only way to read a payload's key image from outside the node.
# Both refusal texts put the key image in field 4 and the holder last.
refused_field() {
    local node="$1" from="$2" field="$3"
    tail -n +"$((from + 1))" "$(debug_log "$node")" 2>/dev/null |
        grep -oE "IV5 spent key [0-9a-f]+ (is reserved by|was already consumed by) [0-9a-f]+" |
        tail -1 | awk -v f="$field" '{print (f=="ki") ? $4 : $NF}'
}

det_finalized_height() { jget "$(rpc "$1" getfinalityinfo 2>/dev/null)" deterministic_finalized_height; }

# Transparent votes only: each wallet casts one, FINALITY_MIN_VOTERS is 2, and
# both nodes hold coins under their own keys by now. Mining is paused at the
# boundary so every vote lands inside the epoch's inclusion window.
vote_round() {
    local boundary="$1"
    mine_to 0 "$boundary" || return 1
    wait_sync "$boundary" || return 1
    sleep 20
    mine_to 0 $((boundary + 3)) || return 1
    wait_sync $((boundary + 3)) || return 1
}

enable_finality_voting() {
    local node="$1" dir
    dir="$(node_dir "$node")"
    stop_node "$node" || return 1
    grep -v -e '^nofinalityvoting=' -e '^finalityvotemode=' "$dir/innova.conf" > "$dir/innova.conf.new"
    {
        echo "nofinalityvoting=0"
        echo "finalityvotemode=transparent"
    } >> "$dir/innova.conf.new"
    mv "$dir/innova.conf.new" "$dir/innova.conf"
    start_node "$node" || return 1
    unlock "$node"
}

epoch_for_height() { python3 -c "h=$1; print(1 + (h - 11) // 300 if h >= 11 else 0)" 2>/dev/null; }
epoch_end_height() { python3 -c "e=$1; print(310 + 300 * (e - 1))" 2>/dev/null; }

epoch_field() { jget "$(rpc "$1" getepochinfo "$2" 2>/dev/null)" "$3"; }

# ---- premise: a chain that finalizes ----

# One wallet casts one vote and FINALITY_MIN_VOTERS is 2, so both nodes have to
# hold coins under their own keys. Section 9 shielded node1's transparent side,
# which would leave it with nothing to vote on.
unlock 0
S10_FUND="$(rpc 0 sendtoaddress "$ADDR1" "$PEER_FUND" 2>&1 | tr -d '"[:space:]')"
if [ ${#S10_FUND} -eq 64 ]; then
    mine_to 0 $(( $(height 0) + 3 )) || { fail "could not confirm the voting stake"; S10_OK=0; }
    wait_sync "$(height 0)" || { fail "the nodes did not sync the voting stake"; S10_OK=0; }
fi
S10_BAL1="$(rpc 1 getbalance 2>/dev/null | tr -d '"[:space:]')"
s10_premise "$(python3 -c "print(1 if float('${S10_BAL1:-0}') > 0 else 0)" 2>/dev/null)" \
    "node1 holds $S10_BAL1 INN of votable stake under its own key" \
    "node1 has no votable stake, so no epoch can reach two voters (balance '$S10_BAL1')"

for node in 0 1; do
    enable_finality_voting "$node" || { fail "node$node did not restart with finality voting on"; S10_OK=0; }
done
connect_nodes
wait_peers || { fail "the nodes did not re-peer after enabling finality voting"; S10_OK=0; }

FIN_HEIGHT=0
if [ "$S10_OK" = "1" ]; then
    # Epoch E starts at 11 + 300*(E-1). Voting starts at the first boundary above
    # the tip section 9 left, and a finalized height needs three consecutive HARD
    # epochs, so at least three rounds run before one exists.
    S10_START="$(height 0)"
    NEXT_EPOCH=$(( $(epoch_for_height "$S10_START") + 1 ))
    for round in 1 2 3 4 5; do
        BOUND=$(( 11 + 300 * (NEXT_EPOCH - 1) ))
        vote_round "$BOUND" || { fail "the epoch-$NEXT_EPOCH vote round failed"; S10_OK=0; break; }
        # A tier is only carried by a COMPLETED epoch, so close this one before
        # asking. One block past the next boundary is the earliest that is true,
        # and it leaves the next round the whole vote window.
        CLOSE=$(( BOUND + 301 ))
        mine_to 0 "$CLOSE" || { fail "could not close epoch $NEXT_EPOCH"; S10_OK=0; break; }
        wait_sync "$CLOSE" || { fail "the nodes did not sync while closing epoch $NEXT_EPOCH"; S10_OK=0; break; }
        TIER="$(epoch_field 0 "$NEXT_EPOCH" finality_tier)"
        log "  epoch $NEXT_EPOCH closed tier=$TIER at height $(height 0)"
        FH="$(det_finalized_height 0)"
        if is_int "$FH" && [ "$FH" -gt 0 ]; then FIN_HEIGHT="$FH"; break; fi
        NEXT_EPOCH=$((NEXT_EPOCH + 1))
    done
fi
s10_premise "$( [ "${FIN_HEIGHT:-0}" -gt 0 ] && echo 1 || echo 0 )" \
    "transparent voting drove a deterministic finalized height of $FIN_HEIGHT" \
    "no finalized height was reached, so no spend can be anchored (got '$FIN_HEIGHT')"

# ---- premise: a note to spend ----

SPEND_AMOUNT=1
ZBAL0=""
ZADDR0=""
if [ "$S10_OK" = "1" ]; then
    unlock 0
    ZBAL0="$(jget "$(rpc 0 z_getshieldedinfo 2>/dev/null)" privacy_vnext_balance)"
    ZADDR0="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
    ZADDR0B="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
fi
s10_premise "$(python3 -c "print(1 if float('${ZBAL0:-0}') >= $SPEND_AMOUNT + 1 else 0)" 2>/dev/null)" \
    "node0 holds $ZBAL0 INN of spendable shielded value" \
    "node0 has no shielded value to spend twice (balance '$ZBAL0')"
s10_premise "$( [ ${#ZADDR0} -gt 20 ] && [ ${#ZADDR0B} -gt 20 ] && [ "$ZADDR0" != "$ZADDR0B" ] && echo 1 || echo 0 )" \
    "node0 allocated two IV5 destinations, one per spend" \
    "could not allocate two distinct IV5 destination addresses"

# ---- premise: two distinct spends of one note, one per side ----

DS_TXID_A=""
DS_TXID_B=""
DS_RAW_A=""
DS_RAW_B=""
DS_NOTES=0
DS_KI_0=""
DS_KI_1=""
DS_HOLDER_0=""
DS_HOLDER_1=""

if [ "$S10_OK" = "1" ]; then
    DS_SPLIT="$(height 0)"
    partition_nodes || { fail "the nodes could not be partitioned for the double spend"; S10_OK=0; }
fi

# The second spend must come from a wallet that never saw the first, so node0 is
# rolled back to a pre-build copy; a re-stamp would hit the output-owner index.
if [ "$S10_OK" = "1" ]; then
    # backupwallet keeps only the filename and writes under <datadir>/backups, and
    # it locks the wallet for the copy without unlocking it again.
    DS_BACKUP="$(node_dir 0)/regtest/backups/prespend_wallet.dat"
    rm -f "$DS_BACKUP"
    rpc 0 backupwallet "prespend_wallet.dat" >/dev/null 2>&1
    unlock 0

    XFER_B="$(rpc 0 z_iv5transfer "$ZADDR0" "$SPEND_AMOUNT" 2>&1)"
    DS_TXID_FIRST="$(jget "$XFER_B" txid)"
    DS_NOTES="$(jget "$XFER_B" notes)"
    if [ ${#DS_TXID_FIRST} -eq 64 ]; then
        DS_RAW_B="$(rpc 0 getrawtransaction "$DS_TXID_FIRST" 2>/dev/null | tr -d '"[:space:]')"
        # node1 never saw it, so its mempool and its spent-key index are both clean
        # and it judges the spend entirely on its own merits.
        DS_TXID_B="$(rpc 1 sendrawtransaction "$DS_RAW_B" 2>&1 | tr -d '"[:space:]')"
    fi

    if [ ! -s "$DS_BACKUP" ]; then
        fail "node0 produced no pre-spend wallet copy, so the second spend cannot be built"
        S10_OK=0
    elif [ ${#DS_TXID_B} -eq 64 ]; then
        stop_node 0
        cp "$DS_BACKUP" "$(node_dir 0)/regtest/wallet.dat"
        rm -f "$(node_dir 0)/regtest/database/"*
        if start_node 0; then
            unlock 0
            XFER_A="$(rpc 0 z_iv5transfer "$ZADDR0B" "$SPEND_AMOUNT" 2>&1)"
            DS_TXID_A="$(jget "$XFER_A" txid)"
            DS_RAW_A="$(rpc 0 getrawtransaction "$DS_TXID_A" 2>/dev/null | tr -d '"[:space:]')"
        else
            fail "node0 did not restart on its pre-spend wallet"
            S10_OK=0
        fi
    fi
fi

s10_premise "$( [ ${#DS_TXID_B} -eq 64 ] && echo 1 || echo 0 )" \
    "node1 holds a spend of $SPEND_AMOUNT INN over ${DS_NOTES:-?} note(s) (${DS_TXID_B:0:16})" \
    "node1 did not accept the first spend: ${DS_TXID_B:0:120}${XFER_B:+ / }$(echo "${XFER_B:-}" | head -2)"
s10_premise "$( [ ${#DS_TXID_A} -eq 64 ] && echo 1 || echo 0 )" \
    "node0 rebuilt a second, independent spend of the same note (${DS_TXID_A:0:16})" \
    "node0 could not rebuild a second spend of the note: $(echo "${XFER_A:-}" | head -2)"
s10_premise "$( [ ${#DS_RAW_A} -gt 32 ] && [ ${#DS_RAW_B} -gt 32 ] && [ "${DS_RAW_A:16}" != "${DS_RAW_B:16}" ] && echo 1 || echo 0 )" \
    "the two spends carry independently built payloads, not one payload re-stamped" \
    "the two spends carry the same payload bytes, so they are not independent builds"
s10_premise "$( [ ${#DS_TXID_A} -eq 64 ] && [ ${#DS_TXID_B} -eq 64 ] && [ "$DS_TXID_A" != "$DS_TXID_B" ] && echo 1 || echo 0 )" \
    "the two spends are different transactions (${DS_TXID_A:0:16} / ${DS_TXID_B:0:16})" \
    "the two spends are not distinct transactions ($DS_TXID_A / $DS_TXID_B)"
s10_premise "$( [ "$(in_mempool 0 "$DS_TXID_A")" = "yes" ] && [ "$(in_mempool 1 "$DS_TXID_B")" = "yes" ] && \
                [ "$(in_mempool 0 "$DS_TXID_B")" = "no" ] && [ "$(in_mempool 1 "$DS_TXID_A")" = "no" ] && echo 1 || echo 0 )" \
    "each node holds only its own spend: the conflict is in no single mempool" \
    "a node holds both spends, so the conflict is inside one mempool and not a DAG case"

# Cross-submit: both nodes must name the same refused key image before this counts as
# a double spend.
if [ "$S10_OK" = "1" ]; then
    L0="$(log_lines 0)"
    rpc 0 sendrawtransaction "$DS_RAW_B" >/dev/null 2>&1 || true
    DS_KI_0="$(refused_field 0 "$L0" ki)"
    DS_HOLDER_0="$(refused_field 0 "$L0" holder)"

    L1="$(log_lines 1)"
    rpc 1 sendrawtransaction "$DS_RAW_A" >/dev/null 2>&1 || true
    DS_KI_1="$(refused_field 1 "$L1" ki)"
    DS_HOLDER_1="$(refused_field 1 "$L1" holder)"
fi

s10_premise "$( [ -n "$DS_KI_0" ] && [ -n "$DS_KI_1" ] && [ "$DS_KI_0" = "$DS_KI_1" ] && echo 1 || echo 0 )" \
    "both nodes independently name the same key image $DS_KI_0: the two spends spend one note" \
    "the nodes did not agree that the two spends share a key image (node0 '$DS_KI_0', node1 '$DS_KI_1')"
s10_premise "$( [ -n "$DS_HOLDER_0" ] && [ "$DS_HOLDER_0" = "${DS_TXID_A:0:10}" ] && \
                [ -n "$DS_HOLDER_1" ] && [ "$DS_HOLDER_1" = "${DS_TXID_B:0:10}" ] && echo 1 || echo 0 )" \
    "each refusal names that node's own spend as the holder of the key image" \
    "a refusal named the wrong holder (node0 '$DS_HOLDER_0' vs ${DS_TXID_A:0:10}, node1 '$DS_HOLDER_1' vs ${DS_TXID_B:0:10})"

# ---- premise: one spend per sibling block, and both blocks reach both nodes ----

DS_HEIGHT=0
DS_BLOCK_A=""
DS_BLOCK_B=""
if [ "$S10_OK" = "1" ]; then
    mine_one 0 || { fail "node0 could not mine its spend"; S10_OK=0; }
    mine_one 1 || { fail "node1 could not mine its spend"; S10_OK=0; }
    DS_HEIGHT=$((DS_SPLIT + 1))
    DS_BLOCK_A="$(block_hash 0 "$DS_HEIGHT")"
    DS_BLOCK_B="$(block_hash 1 "$DS_HEIGHT")"
fi

s10_premise "$( [ ${#DS_BLOCK_A} -eq 64 ] && [ ${#DS_BLOCK_B} -eq 64 ] && [ "$DS_BLOCK_A" != "$DS_BLOCK_B" ] && echo 1 || echo 0 )" \
    "two sibling blocks at height $DS_HEIGHT (${DS_BLOCK_A:0:16} / ${DS_BLOCK_B:0:16})" \
    "the partition did not produce a sibling pair ($DS_BLOCK_A / $DS_BLOCK_B)"
s10_premise "$( [ "$(block_contains_tx 0 "$DS_BLOCK_A" "$DS_TXID_A")" = "yes" ] && \
                [ "$(block_contains_tx 1 "$DS_BLOCK_B" "$DS_TXID_B")" = "yes" ] && echo 1 || echo 0 )" \
    "each sibling carries its own side's spend" \
    "a sibling does not carry the spend its node built"

if [ "$S10_OK" = "1" ]; then
    connect_nodes
    wait_peers || { fail "the nodes did not re-peer after the double-spend race"; S10_OK=0; }
    wait_block_known 0 "$DS_BLOCK_B" || { fail "node0 never received the competing block"; S10_OK=0; }
    wait_block_known 1 "$DS_BLOCK_A" || { fail "node1 never received the competing block"; S10_OK=0; }
fi
# Both sides are read back by hash, so the length test is what stops two empty
# hashes from comparing equal and reporting a pass over a race that never ran.
s10_premise "$( [ ${#DS_BLOCK_A} -eq 64 ] && [ ${#DS_BLOCK_B} -eq 64 ] && \
                [ "$(jget "$(rpc 0 getblock "$DS_BLOCK_B" 2>/dev/null)" hash)" = "$DS_BLOCK_B" ] && \
                [ "$(jget "$(rpc 1 getblock "$DS_BLOCK_A" 2>/dev/null)" hash)" = "$DS_BLOCK_A" ] && echo 1 || echo 0 )" \
    "both sibling blocks reached both nodes" \
    "a sibling block never reached the other node, so no node ever had to resolve the conflict"

# ---- conclusion ----

if [ "$S10_OK" != "1" ]; then
    fail "section 10 premises did not hold; its conclusions were not run"
else
    DS_EPOCH="$(epoch_for_height "$DS_HEIGHT")"
    DS_EPOCH_END="$(epoch_end_height "$DS_EPOCH")"
    NULL_BEFORE="$(epoch_field 0 $((DS_EPOCH - 1)) iv5_nullifier_count)"

    # One more block resolves the tie and commits the loser as a merge parent.
    mine_one 0 || fail "node0 could not extend after the double-spend race"
    wait_same_tip || fail "the nodes did not converge after the double-spend race"

    CANON0="$(block_hash 0 "$DS_HEIGHT")"
    CANON1="$(block_hash 1 "$DS_HEIGHT")"
    if [ "$CANON0" = "$DS_BLOCK_A" ]; then
        LOSER_BLOCK="$DS_BLOCK_B"; WIN_TX="$DS_TXID_A"; LOSE_TX="$DS_TXID_B"; LOSE_RAW="$DS_RAW_B"
    else
        LOSER_BLOCK="$DS_BLOCK_A"; WIN_TX="$DS_TXID_B"; LOSE_TX="$DS_TXID_A"; LOSE_RAW="$DS_RAW_A"
    fi

    if [ ${#CANON0} -eq 64 ] && [ "$CANON0" = "$CANON1" ] && \
       { [ "$CANON0" = "$DS_BLOCK_A" ] || [ "$CANON0" = "$DS_BLOCK_B" ]; }; then
        success "exactly one sibling is canonical at $DS_HEIGHT and both nodes name it (${CANON0:0:16})"
    else
        fail "the nodes do not agree on one canonical sibling (node0 $CANON0, node1 $CANON1)"
    fi

    # The chain writes a txindex entry only for what ConnectBlock connected, so
    # the winner resolves to the canonical sibling and the loser resolves to
    # nothing at all -- on both nodes.
    W0="$(confirmed_in_block 0 "$WIN_TX")"; W1="$(confirmed_in_block 1 "$WIN_TX")"
    L0C="$(confirmed_in_block 0 "$LOSE_TX")"; L1C="$(confirmed_in_block 1 "$LOSE_TX")"
    if [ ${#W0} -eq 64 ] && [ "$W0" = "$CANON0" ] && [ "$W1" = "$CANON0" ]; then
        success "both nodes confirm the surviving spend ${WIN_TX:0:16} in the canonical sibling"
    else
        fail "the nodes disagree about the surviving spend (node0 '$W0', node1 '$W1', canonical $CANON0)"
    fi
    if [ -z "$L0C" ] && [ -z "$L1C" ]; then
        success "neither node connected the losing spend ${LOSE_TX:0:16}"
    else
        fail "the losing spend was connected somewhere (node0 '$L0C', node1 '$L1C')"
    fi

    # The losing sibling has to be in the DAG as a merge block, or the conflict
    # was resolved by throwing the block away and the epoch build never saw it.
    MERGER="$(block_hash 0 $((DS_HEIGHT + 1)))"
    if [ "$(block_has_dag_parent 0 "$MERGER" "$LOSER_BLOCK")" = "yes" ]; then
        success "the canonical chain merged the losing sibling ${LOSER_BLOCK:0:16}"
    else
        fail "no canonical block merged the losing sibling; the DAG never had to resolve the conflict"
    fi

    # A re-stamped twin of the loser is the only respend attempt that reaches the
    # key-image logic: the loser's own txid is refused by DAG-sibling dedup first.
    LOSE_TWIN="$(restamp_raw "$LOSE_RAW")"
    for n in 0 1; do
        LN="$(log_lines "$n")"
        RESP="$(rpc "$n" sendrawtransaction "$LOSE_TWIN" 2>&1 | tr -d '"[:space:]')"
        REASON="$(tail -n +$((LN + 1)) "$(debug_log "$n")" 2>/dev/null | grep -c "was already consumed by")"
        if [ ${#RESP} -eq 64 ]; then
            fail "node$n accepted a respend of the note the canonical sibling already spent: ${RESP:0:16}"
        elif [ "${REASON:-0}" -ge 1 ]; then
            success "node$n refuses a respend because the key image was already consumed"
        else
            # The RPC only ever says "TX rejected", so the reason has to come from
            # the log or a wrong-reason refusal is indistinguishable from the right one.
            OTHER="$(tail -n +$((LN + 1)) "$(debug_log "$n")" 2>/dev/null |
                     grep -m1 -oE "CTxMemPool::accept\(\) : .*" | cut -c1-140)"
            fail "node$n refused the respend for the wrong reason: ${OTHER:-$RESP}"
        fi
    done

    # Close the epoch the race sits in, so its state can be read.
    mine_to 0 $((DS_EPOCH_END + 4)) || fail "could not close epoch $DS_EPOCH over the race"
    wait_sync $((DS_EPOCH_END + 4)) || fail "the nodes did not sync while closing epoch $DS_EPOCH"
    wait_same_tip || fail "the nodes hold different tips after closing epoch $DS_EPOCH"

    # The active set is the id list both replayers walk. The losing sibling is in
    # the epoch's DAG order and must contribute nothing to it.
    ACTIVE_REPORT="$(EPOCHJSON="$(rpc 0 getepochinfo "$DS_EPOCH" 2>/dev/null)" \
                     LOSER="$LOSER_BLOCK" WINNER="$CANON0" python3 <<'PY'
import json, os, sys
try:
    st = json.loads(os.environ["EPOCHJSON"])
except Exception as e:
    print("ERROR parse"); sys.exit(0)
blocks = st.get("blocks", [])
counts = st.get("iv5_active_block_tx_counts", None)
if counts is None or len(counts) != len(blocks):
    print("ERROR counts"); sys.exit(0)
idx = {h: c for h, c in zip(blocks, counts)}
loser = os.environ["LOSER"]; winner = os.environ["WINNER"]
if loser not in idx:
    print("ERROR loser_not_ordered"); sys.exit(0)
if winner not in idx:
    print("ERROR winner_not_ordered"); sys.exit(0)
print("OK %d %d" % (idx[loser], idx[winner]))
PY
)"
    set -- $ACTIVE_REPORT
    A_STATUS="$1"; A_LOSER="$2"; A_WINNER="$3"
    if [ "$A_STATUS" != "OK" ]; then
        fail "could not read the race epoch's IV5 active-set counts: $ACTIVE_REPORT"
    elif [ "$A_LOSER" = "0" ] && [ "${A_WINNER:-0}" -ge 1 ]; then
        success "the IV5 active set took the canonical sibling's $A_WINNER transaction(s) and none of the loser's"
    else
        fail "the IV5 active set is not one-sided (loser contributed $A_LOSER, winner $A_WINNER)"
    fi

    # The decisive count: one note was spent once, so the epoch's key-image set
    # grew by exactly one spend's worth. Two would mean both siblings' spends
    # reached the ledger.
    NULL_AFTER="$(epoch_field 0 "$DS_EPOCH" iv5_nullifier_count)"
    if is_int "$NULL_BEFORE" && is_int "$NULL_AFTER" && is_int "$DS_NOTES"; then
        if [ $((NULL_AFTER - NULL_BEFORE)) -eq "$DS_NOTES" ]; then
            success "the epoch recorded exactly one spend of the note ($NULL_BEFORE -> $NULL_AFTER key images)"
        else
            fail "the epoch recorded $((NULL_AFTER - NULL_BEFORE)) key images for a $DS_NOTES-note spend ($NULL_BEFORE -> $NULL_AFTER)"
        fi
    else
        fail "could not read the epoch key-image counts ('$NULL_BEFORE' -> '$NULL_AFTER', notes '$DS_NOTES')"
    fi

    DS_DIGEST0="$(epoch_field 0 "$DS_EPOCH" epoch_state_digest)"
    DS_DIGEST1="$(epoch_field 1 "$DS_EPOCH" epoch_state_digest)"
    if [ ${#DS_DIGEST0} -eq 64 ] && [ "$DS_DIGEST0" = "$DS_DIGEST1" ]; then
        success "both nodes derived the same epoch state over the resolved conflict (${DS_DIGEST0:0:16})"
    else
        fail "the nodes derived different epoch states over the conflict ($DS_DIGEST0 / $DS_DIGEST1)"
    fi

    assert_iv5_agrees "after resolving the sibling double spend"
fi

connect_nodes
wait_peers >/dev/null 2>&1 || true

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
