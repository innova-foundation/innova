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
header "7. A losing branch disconnects a block that carried an IV5 payload"
# ============================================================

# Sections 2 and 3 raced siblings that both nodes already held, and neither losing
# block was ever connected. This one connects a payload on one side of a partition
# and then loses the race outright, so the block is disconnected after the fact.
# That is a different input to the epoch build: a block that ConnectBlock ran on
# and then undid. If the build still counts it, the two nodes commit different
# spent-key sets and roots at the same tip.
#
# The tree itself only moves when an epoch is built, so nothing here can be read
# off the committed tree mid-epoch -- the checks below deliberately wait for the
# epoch carrying the reorg to close before asking what it recorded.

tree_root() { jget "$(rpc "$1" z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_root; }
tree_size() { jget "$(rpc "$1" z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_size; }
epoch_pool() { jget "$(rpc "$1" getepochinfo "$2" 2>/dev/null)" iv5_pool_balance; }

# Epoch 3 covers [611, 910] and is the one the reorg below lands in.
REORG_EPOCH=3
REORG_EPOCH_START=611
REORG_EPOCH_END=910
REORG_EPOCH_DONE=920

PRE_ROOT0="$(tree_root 0)"
PRE_SIZE0="$(tree_size 0)"
if [ ${#PRE_ROOT0} -eq 64 ] && is_int "$PRE_SIZE0"; then
    success "pre-reorg committed tree recorded: $PRE_SIZE0 leaves at ${PRE_ROOT0:0:16}"
else
    fail "could not read node0's tree before the reorg (root '$PRE_ROOT0' size '$PRE_SIZE0')"
fi

SPLIT_C="$(height 0)"
partition_nodes || { fail "the nodes could not be partitioned for the reorg"; exit 1; }

unlock 0
SHIELD_R="$(rpc 0 z_shieldall 2>&1)"
TXR="$(jget "$SHIELD_R" txid)"
if [ ${#TXR} -eq 64 ]; then
    success "node0 shielded $(jget "$SHIELD_R" shielded) INN in isolation (${TXR:0:16})"
else
    fail "node0 could not build a shield for the reorg test: $(echo "$SHIELD_R" | head -3)"
    exit 1
fi
RAWR="$(rpc 0 getrawtransaction "$TXR" 2>/dev/null | tr -d '"[:space:]')"

mine_one 0 || { fail "node0 could not mine the block under test"; exit 1; }
LOSER="$(block_hash 0 $((SPLIT_C + 1)))"
if [ "$(block_contains_tx 0 "$LOSER" "$TXR")" = "yes" ]; then
    success "node0 connected ${LOSER:0:16} carrying the IV5 payload"
else
    fail "node0's block does not carry the shield; the reorg shape was not built"
    exit 1
fi

# node1 never saw the shield, so its branch cannot carry it. Three blocks against
# one make the losing side unambiguous.
mine_to 1 $((SPLIT_C + 3)) || { fail "node1 could not build the winning branch"; exit 1; }

connect_nodes
wait_peers || { fail "the nodes did not re-peer for the reorg"; exit 1; }
wait_same_tip || { fail "the nodes did not converge after the reorg"; exit 1; }

if [ "$(block_hash 0 $((SPLIT_C + 1)))" != "$LOSER" ]; then
    success "node0 reorganised off ${LOSER:0:16}"
else
    fail "node0's block won; the reorg under test did not happen"
    exit 1
fi

# The payload is only back out of the state if the chain no longer carries it.
STILL_ON_CHAIN="no"
for ((h=SPLIT_C+1; h<=$(height 0); h++)); do
    if [ "$(block_contains_tx 0 "$(block_hash 0 "$h")" "$TXR")" = "yes" ]; then
        STILL_ON_CHAIN="yes"; break
    fi
done

# A cleanly disconnected payload is still a valid transaction, so the chain has to
# be able to take it back.
if [ "$STILL_ON_CHAIN" = "no" ]; then
    if [ "$(in_mempool 0 "$TXR")" != "yes" ] && [ ${#RAWR} -gt 100 ]; then
        rpc 0 sendrawtransaction "$RAWR" >/dev/null 2>&1 || true
    fi
    if wait_mempool 0 "$TXR"; then
        mine_one 0 || { fail "node0 could not re-mine the disconnected shield"; exit 1; }
        wait_same_tip || { fail "the nodes did not converge after the re-mine"; exit 1; }
        success "the disconnected shield was re-mined onto the winning branch"
        STILL_ON_CHAIN="yes"
    else
        fail "the disconnected shield never returned to a mempool"
    fi
fi

# Now close the epoch that carries the reorg and ask what it recorded. This is
# the check the mid-epoch tree cannot give: the disconnected block is still a DAG
# merge parent inside this epoch, so the build sees it and has to contribute
# nothing for it.
mine_to 0 "$REORG_EPOCH_DONE" || { fail "could not close epoch $REORG_EPOCH"; exit 1; }
wait_sync "$REORG_EPOCH_DONE" || { fail "nodes did not resync to $REORG_EPOCH_DONE"; exit 1; }
wait_same_tip || { fail "nodes hold different tips at $REORG_EPOCH_DONE"; exit 1; }

RE_EPOCH0="$(rpc 0 getepochinfo "$REORG_EPOCH" 2>/dev/null)"
RE_EPOCH1="$(rpc 1 getepochinfo "$REORG_EPOCH" 2>/dev/null)"

RE_DIGEST0="$(jget "$RE_EPOCH0" epoch_state_digest)"
RE_DIGEST1="$(jget "$RE_EPOCH1" epoch_state_digest)"
if [ ${#RE_DIGEST0} -eq 64 ] && [ "$RE_DIGEST0" = "$RE_DIGEST1" ]; then
    success "both nodes built epoch $REORG_EPOCH to the same digest (${RE_DIGEST0:0:16})"
else
    fail "the reorg epoch built to different digests ($RE_DIGEST0 / $RE_DIGEST1)"
fi

RE_CANON="$TEST_DIR/reorg_canonical.txt"
: > "$RE_CANON"
for ((h=REORG_EPOCH_START; h<=REORG_EPOCH_END; h++)); do
    echo "$(block_hash 0 "$h")" >> "$RE_CANON"
done

RE_REPORT="$(EPOCHJSON="$RE_EPOCH0" CANONFILE="$RE_CANON" LOSERHASH="$LOSER" python3 <<'PY'
import json, os, sys
try:
    st = json.loads(os.environ["EPOCHJSON"])
except Exception as e:
    print("ERROR parse %s" % e); sys.exit(0)
canon = set(x.strip() for x in open(os.environ["CANONFILE"]) if x.strip())
loser = os.environ["LOSERHASH"]
blocks = st.get("blocks", [])
counts = st.get("iv5_active_block_tx_counts", None)
if counts is None or len(counts) != len(blocks):
    print("ERROR counts"); sys.exit(0)
merges = [(h, c) for h, c in zip(blocks, counts) if h not in canon]
bad = [(h, c) for h, c in merges if c != 0]
loser_seen = loser in blocks
loser_count = dict(zip(blocks, counts)).get(loser, -1)
print("OK %d %d %d %s %d %d" % (
    len(blocks), len(merges), len(bad),
    "yes" if loser_seen else "no", loser_count, sum(counts)))
PY
)"

set -- $RE_REPORT
RE_STATUS="$1"; RE_BLOCKS="$2"; RE_MERGES="$3"; RE_BAD="$4"
RE_LOSER_SEEN="$5"; RE_LOSER_COUNT="$6"; RE_SUM="$7"

if [ "$RE_STATUS" != "OK" ]; then
    fail "could not read the reorg epoch's active-set counts: $RE_REPORT"
else
    if [ "$RE_LOSER_SEEN" = "yes" ]; then
        if [ "$RE_LOSER_COUNT" = "0" ]; then
            success "the disconnected block is in the epoch's DAG order and contributes 0 transactions"
        else
            fail "the disconnected block contributes $RE_LOSER_COUNT transactions to the active set"
        fi
    else
        warn "the disconnected block ${LOSER:0:16} is not in epoch $REORG_EPOCH's DAG order, so only the merge-wide check applies"
    fi

    if [ "$RE_BAD" = "0" ]; then
        success "all $RE_MERGES merge block(s) in the reorg epoch contribute zero transactions"
    else
        fail "$RE_BAD merge block(s) in the reorg epoch contribute transactions"
    fi

    RE_ACTIVE="$(jget "$RE_EPOCH0" iv5_active_tx_count)"
    if [ "$RE_ACTIVE" = "$RE_SUM" ]; then
        success "the reorg epoch's id list matches its per-block counts ($RE_ACTIVE over $RE_BLOCKS blocks)"
    else
        fail "the reorg epoch's id list ($RE_ACTIVE) disagrees with its counts ($RE_SUM)"
    fi
fi

# The committed tree may only have taken the shield if the canonical chain kept it.
POST_ROOT0="$(tree_root 0)"
POST_SIZE0="$(tree_size 0)"
POST_ROOT1="$(tree_root 1)"
POST_SIZE1="$(tree_size 1)"
if [ ${#POST_ROOT0} -eq 64 ] && [ "$POST_ROOT0" = "$POST_ROOT1" ] && [ "$POST_SIZE0" = "$POST_SIZE1" ]; then
    success "both nodes hold one committed tree after the reorg epoch (${POST_ROOT0:0:16}, $POST_SIZE0 leaves)"
else
    fail "the nodes hold different trees after the reorg epoch (${POST_ROOT0:0:16}/$POST_SIZE0 vs ${POST_ROOT1:0:16}/$POST_SIZE1)"
fi

if [ "$STILL_ON_CHAIN" = "yes" ]; then
    if is_int "$POST_SIZE0" && [ "$POST_SIZE0" -gt "$PRE_SIZE0" ]; then
        success "the re-mined shield reached the committed tree ($PRE_SIZE0 -> $POST_SIZE0 leaves)"
    else
        fail "the shield is on the chain but the committed tree did not grow ($PRE_SIZE0 -> ${POST_SIZE0:-?})"
    fi
else
    if [ "$POST_SIZE0" = "$PRE_SIZE0" ]; then
        success "the disconnected shield left no leaf behind ($POST_SIZE0 leaves)"
    else
        fail "a disconnected payload still grew the tree ($PRE_SIZE0 -> $POST_SIZE0)"
    fi
fi

# ============================================================
header "8. A node that syncs the whole DAG cold derives the same tree"
# ============================================================

# Cold sync delivers the DAG in a different order and builds epochs in batches; the
# third node must reach the same root at the same tip.

wait_same_tip || { fail "the pair holds different tips before the cold sync"; exit 1; }

TIP_HEIGHT="$(height 0)"
TIP_HASH="$(best_hash 0)"

write_config 2
start_node 2 || { fail "node2 did not start"; exit 1; }
NUM_NODES=3
rpc 2 addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1 || true
rpc 2 addnode "127.0.0.1:$(node_port 1)" onetry >/dev/null 2>&1 || true

SYNCED=0
for _ in $(seq 1 900); do
    if [ "$(best_hash 2)" = "$TIP_HASH" ]; then SYNCED=1; break; fi
    rpc 2 addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1 || true
    sleep 2
done
if [ "$SYNCED" = "1" ]; then
    success "node2 cold-synced $TIP_HEIGHT blocks to the same tip (${TIP_HASH:0:16})"
else
    fail "node2 did not reach the fleet tip (at $(height 2) vs $TIP_HEIGHT)"
fi

COLD_ROOT="$(tree_root 2)"
COLD_SIZE="$(tree_size 2)"
LIVE_ROOT="$(tree_root 0)"
LIVE_SIZE="$(tree_size 0)"
if [ ${#COLD_ROOT} -eq 64 ] && [ "$COLD_ROOT" = "$LIVE_ROOT" ] && [ "$COLD_SIZE" = "$LIVE_SIZE" ]; then
    success "the cold-synced tree is identical: $COLD_SIZE leaves at ${COLD_ROOT:0:16}"
else
    fail "the cold-synced tree differs (${COLD_ROOT:0:16}/${COLD_SIZE:-?} vs ${LIVE_ROOT:0:16}/${LIVE_SIZE:-?})"
fi

COLD_STORE="$(jget "$(rpc 2 z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_store_size)"
if [ "$COLD_STORE" = "$COLD_SIZE" ]; then
    success "node2's tree store is level with its epoch tree at $COLD_STORE leaves"
else
    fail "node2's store holds ${COLD_STORE:-?} against an epoch tree of ${COLD_SIZE:-?}"
fi

COLD_EPOCH="$(rpc 2 getepochinfo "$EPOCH" 2>/dev/null)"
COLD_DIGEST="$(jget "$COLD_EPOCH" epoch_state_digest)"
if [ ${#COLD_DIGEST} -eq 64 ] && [ "$COLD_DIGEST" = "$DIGEST0" ]; then
    success "node2 rebuilt epoch $EPOCH to the same digest (${COLD_DIGEST:0:16})"
else
    fail "node2 rebuilt epoch $EPOCH to a different digest ($COLD_DIGEST vs $DIGEST0)"
fi

COLD_POOL="$(jget "$COLD_EPOCH" iv5_pool_balance)"
LIVE_POOL="$(epoch_pool 0 "$EPOCH")"
if [ -n "$COLD_POOL" ] && [ "$COLD_POOL" = "$LIVE_POOL" ]; then
    success "node2 derived the same epoch pool balance ($COLD_POOL INN)"
else
    fail "node2 derived a different epoch pool balance (${COLD_POOL:-?} vs ${LIVE_POOL:-?})"
fi

COLD_NULLS="$(jget "$COLD_EPOCH" iv5_nullifier_count)"
LIVE_NULLS="$(jget "$(rpc 0 getepochinfo "$EPOCH" 2>/dev/null)" iv5_nullifier_count)"
if [ -n "$COLD_NULLS" ] && [ "$COLD_NULLS" = "$LIVE_NULLS" ]; then
    success "node2 derived the same spent-key set ($COLD_NULLS)"
else
    fail "node2 derived a different spent-key set (${COLD_NULLS:-?} vs ${LIVE_NULLS:-?})"
fi

# The reorg epoch is the interesting one to rebuild cold: node2 never saw the
# losing block arrive as a tip, only as a merge parent inside a batch.
COLD_REORG="$(jget "$(rpc 2 getepochinfo "$REORG_EPOCH" 2>/dev/null)" epoch_state_digest)"
if [ ${#COLD_REORG} -eq 64 ] && [ "$COLD_REORG" = "$RE_DIGEST0" ]; then
    success "node2 rebuilt the reorg epoch $REORG_EPOCH to the same digest (${COLD_REORG:0:16})"
else
    fail "node2 rebuilt the reorg epoch to a different digest ($COLD_REORG vs $RE_DIGEST0)"
fi

# ============================================================
header "9. No private coinstake is reachable on a DAG-active chain"
# ============================================================

# Proof-of-stake blocks are rejected above the DAG height. Stake in private mode and
# check the chain never takes a NullStake block.

STAKE_START="$(height 0)"
STAKE_DIR="$(node_dir 0)"
cp "$STAKE_DIR/innova.conf" "$STAKE_DIR/innova.conf.bak"
stop_node 0 || { fail "node0 would not stop for the staking test"; exit 1; }
{
    grep -v '^staking=\|^stakingmode=\|^nofinalityvoting=' "$STAKE_DIR/innova.conf.bak"
    echo "staking=1"
    echo "stakingmode=nullstake"
    echo "nofinalityvoting=1"
} > "$STAKE_DIR/innova.conf"
start_node 0 || { fail "node0 would not restart in private staking mode"; exit 1; }
unlock 0

STAKEINFO="$(rpc 0 getstakinginfo 2>&1)"
if echo "$STAKEINFO" | grep -q "staking"; then
    success "node0 restarted with -stakingmode=nullstake (staking=$(jget "$STAKEINFO" staking))"
else
    fail "getstakinginfo did not report a staking state: $(echo "$STAKEINFO" | head -2)"
fi

# A staking window on an idle chain proves nothing: the kernel only competes when
# blocks are being produced, so keep the chain moving while the staker runs.
sleep 30
mine_to 0 $((STAKE_START + 20)) || warn "node0 could not mine during the staking window"
sleep 30

STAKE_END="$(height 0)"
POS_FOUND=""
if is_int "$STAKE_END" && [ "$STAKE_END" -gt "$STAKE_START" ]; then
    for ((h=STAKE_START+1; h<=STAKE_END; h++)); do
        if rpc 0 getblock "$(block_hash 0 "$h")" 2>/dev/null | grep -q "proof-of-stake"; then
            POS_FOUND="$h"; break
        fi
    done
fi
if [ "$STAKE_END" -le "$STAKE_START" ]; then
    fail "the chain did not advance during the staking window, so nothing was proven"
elif [ -z "$POS_FOUND" ]; then
    success "no proof-of-stake block over $((STAKE_END - STAKE_START)) blocks ($STAKE_START..$STAKE_END) with private staking on"
else
    fail "a proof-of-stake block was accepted at height $POS_FOUND on a DAG-active chain"
fi

# The whole post-DAG range has to be proof-of-work, not just the staking window.
POW_SAMPLES=0
POW_BAD=0
STEP=$(( (STAKE_END - BOUNDARY_B) / 20 )); [ "$STEP" -lt 1 ] && STEP=1
for ((h=BOUNDARY_B; h<=STAKE_END; h+=STEP)); do
    FLAGS="$(jget "$(rpc 0 getblock "$(block_hash 0 "$h")" 2>/dev/null)" flags)"
    POW_SAMPLES=$((POW_SAMPLES + 1))
    case "$FLAGS" in
        proof-of-work*) ;;
        *) POW_BAD=$((POW_BAD + 1)); warn "height $h reports flags '$FLAGS'" ;;
    esac
done
if [ "$POW_SAMPLES" -gt 0 ] && [ "$POW_BAD" -eq 0 ]; then
    success "all $POW_SAMPLES sampled post-Boundary-B blocks are proof-of-work"
else
    fail "$POW_BAD of $POW_SAMPLES sampled post-Boundary-B blocks are not proof-of-work"
fi

stop_node 0 || true
mv "$STAKE_DIR/innova.conf.bak" "$STAKE_DIR/innova.conf"
start_node 0 || { fail "node0 would not restart after the staking test"; exit 1; }

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
