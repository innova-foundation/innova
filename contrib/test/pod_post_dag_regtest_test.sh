#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Proof-of-data stamps under DAG ordering on two nodes: canonical reads, losing siblings,
# and reorgs. Reorganize() never re-queues txs on regtest, so recoveries rebroadcast.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${POD_DAG_TEST_DIR:-/tmp/innova_pod_dag_$$}"
NUM_NODES=2
BASE_PORT="${POD_DAG_BASE_PORT:-28900}"
BASE_RPC="${POD_DAG_BASE_RPC:-28960}"
BASE_IDNS="${POD_DAG_BASE_IDNS:-8980}"
RPCUSER="poddag"
RPCPASS="poddagpass"

# Regtest ladder: POEM 9, finality 10, DAG 11, DAGKnight 13; every stamp is above all four.
DAG_HEIGHT=11
DAGKNIGHT_HEIGHT=13
SEED_HEIGHT=80

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
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser=$RPCUSER \
        -rpcpassword=$RPCPASS -rpcport=$(node_rpc "$node") "$@" 2>&1
}

is_int() { echo "$1" | grep -qE '^-?[0-9]+$'; }

jget() {
    FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"])
    print("" if v is None else v)
except Exception:
    print("")
' <<< "$1" 2>/dev/null
}

height()    { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
best_hash() { rpc "$1" getbestblockhash 2>/dev/null | tr -d '"[:space:]'; }
block_hash(){ rpc "$1" getblockhash "$2" 2>/dev/null | tr -d '"[:space:]'; }
peer_count(){ rpc "$1" getconnectioncount 2>/dev/null | tr -d '"[:space:]'; }
balance()   { rpc "$1" getbalance 2>/dev/null | tr -d '"[:space:]'; }

write_conf() {
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
        echo "listen=1"
        echo "idnsport=$(node_idns "$node")"
        echo "dnsseed=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "maxconnections=32"
        echo "staking=0"
        echo "stakingmode=0"
        echo "nofinalityvoting=1"
        echo "enablefilerpc=1"
    } > "$dir/innova.conf"
}

start_node() {
    local node="$1"
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -daemon >/dev/null 2>&1
    for _ in $(seq 1 120); do
        rpc "$node" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

stop_node() {
    local node="$1"
    rpc "$node" stop >/dev/null 2>&1 || true
    for _ in $(seq 1 180); do
        rpc "$node" getinfo >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
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

# The ban list is consulted for inbound accepts and outbound dials alike, so the
# two nodes cannot find each other again by gossip while it holds.
partition_nodes() {
    rpc 0 setban "127.0.0.1" add 3600 >/dev/null 2>&1 || true
    rpc 1 setban "127.0.0.1" add 3600 >/dev/null 2>&1 || true
    rpc 0 disconnectnode "127.0.0.1:$(node_port 1)" >/dev/null 2>&1 || true
    rpc 1 disconnectnode "127.0.0.1:$(node_port 0)" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
        local c0 c1
        c0="$(peer_count 0)"; c1="$(peer_count 1)"
        if [ "${c0:-1}" = "0" ] && [ "${c1:-1}" = "0" ]; then return 0; fi
        sleep 1
    done
    return 1
}

wait_sync() {
    local target="$1" n h
    for _ in $(seq 1 600); do
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

# setgenerate takes a block count, and a template that loses a race consumes one,
# so re-arm whenever the height stalls.
mine_to() {
    local node="$1" target="$2" h last stall=0
    h="$(height "$node")"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$node" setgenerate true $((target - h)) >/dev/null 2>&1
    for ((i=0; i<2000; i++)); do
        h="$(height "$node")"
        if is_int "$h" && [ "$h" -ge "$target" ]; then
            rpc "$node" setgenerate false 0 >/dev/null 2>&1
            return 0
        fi
        if [ "$h" = "$last" ]; then
            stall=$((stall + 1))
        else
            stall=0; last="$h"
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

in_mempool() {
    TXID="$2" python3 -c '
import json, os, sys
try: print("yes" if os.environ["TXID"] in json.load(sys.stdin) else "no")
except Exception: print("no")
' <<< "$(rpc "$1" getrawmempool 2>/dev/null)" 2>/dev/null
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

wait_block_known() {
    local node="$1" hash="$2"
    for _ in $(seq 1 90); do
        [ "$(jget "$(rpc "$node" getblock "$hash" 2>/dev/null)" hash)" = "$hash" ] && return 0
        sleep 1
    done
    return 1
}

# Where the chain connected a transaction; empty if unconnected (no txindex entry).
confirmed_in_block() { jget "$(rpc "$1" getrawtransaction "$2" 1 2>/dev/null)" blockhash; }

# Mines until the stamp is in a block, and reports where.
confirm_stamp() {
    local node="$1" txid="$2" where
    for _ in $(seq 1 20); do
        where="$(confirmed_in_block "$node" "$txid")"
        [ ${#where} -eq 64 ] && { echo "$where"; return 0; }
        mine_one "$node" >/dev/null 2>&1
        sleep 1
    done
    echo ""
    return 1
}

stamp_file() {
    local node="$1" path="$2"
    rpc "$node" proofofdata "$path" false
}

cleanup() {
    local n
    for ((n=0; n<NUM_NODES; n++)); do
        rpc "$n" setgenerate false 0 >/dev/null 2>&1 || true
        stop_node "$n" || true
    done
    [ "${POD_DAG_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "Proof of data under DAG ordering"

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_conf "$n"; done
for ((n=0; n<NUM_NODES; n++)); do
    start_node "$n" || { fail "node$n did not start"; exit 1; }
done
success "two regtest nodes started"

wait_peers || { fail "the nodes never peered"; exit 1; }
success "nodes peered"

# ============================================================
header "1. A stamp connected post-DAG reads the same on both nodes"
# ============================================================

mine_to 0 "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }
wait_sync "$SEED_HEIGHT" || { fail "nodes did not sync to $SEED_HEIGHT"; exit 1; }
wait_same_tip || { fail "nodes hold different tips at $SEED_HEIGHT"; exit 1; }
success "chain at $(height 0), both nodes on one tip"

FILE_A="$TEST_DIR/subject_a.bin"
head -c 32768 /dev/urandom > "$FILE_A"
SHA_A="$(sha256sum "$FILE_A" | cut -d' ' -f1)"

OUT="$(stamp_file 0 "$FILE_A")"
TXID_A="$(jget "$OUT" podtxid)"
DIGEST_A="$(jget "$OUT" stampdigest)"
if [ ${#TXID_A} -eq 64 ] && [ "$DIGEST_A" = "$SHA_A" ]; then
    success "node0 published a plain stamp, on-chain digest equals sha256sum"
else
    fail "stamp not published: $(echo "$OUT" | head -4)"; exit 1
fi

BLOCK_A="$(confirm_stamp 0 "$TXID_A")"
[ ${#BLOCK_A} -eq 64 ] || { fail "the stamp never confirmed"; exit 1; }
wait_sync "$(height 0)" || { fail "node1 did not follow"; exit 1; }
wait_same_tip || { fail "nodes diverged after the stamp"; exit 1; }

V0="$(rpc 0 podverify "$SHA_A" "$TXID_A")"
V1="$(rpc 1 podverify "$SHA_A" "$TXID_A")"
H0="$(jget "$V0" height)"; H1="$(jget "$V1" height)"
T0="$(jget "$V0" blocktime)"; T1="$(jget "$V1" blocktime)"
B0="$(jget "$V0" blockhash)"; B1="$(jget "$V1" blockhash)"

if [ "$(jget "$V0" match)" = "True" ] && [ "$(jget "$V1" match)" = "True" ]; then
    success "the stamp verifies on the node that made it and on its peer"
else
    fail "fleet-wide verification failed: node0=$(jget "$V0" match) node1=$(jget "$V1" match)"
fi

if [ -n "$H0" ] && [ "$H0" = "$H1" ] && [ "$T0" = "$T1" ] && [ "$B0" = "$B1" ] \
   && [ "$B0" = "$BLOCK_A" ]; then
    success "both nodes attest the same block at height $H0, time $T0"
else
    fail "the nodes disagree: h=$H0/$H1 t=$T0/$T1 b=${B0:0:16}/${B1:0:16}"
fi

if is_int "$H0" && [ "$H0" -gt "$DAGKNIGHT_HEIGHT" ]; then
    success "the stamp is above the DAG ($DAG_HEIGHT) and DAGKnight ($DAGKNIGHT_HEIGHT) forks"
else
    fail "the stamp is not post-DAG: height $H0"
fi

# The attested time is the containing block's; section 3 distinguishes it from tx nTime.
TXNTIME="$(jget "$(rpc 0 getrawtransaction "$TXID_A" 1 2>/dev/null)" time)"
BLKTIME="$(jget "$(rpc 0 getblock "$BLOCK_A" 2>/dev/null)" time)"
if [ "$T0" = "$BLKTIME" ]; then
    success "the attested time is the block's ($BLKTIME; transaction nTime $TXNTIME)"
else
    fail "attested time $T0 is not the block time $BLKTIME"
fi

# ============================================================
header "2. A stamp on a losing sibling, and its re-mined copy"
# ============================================================

# node1 needs coins of its own to stamp with, and a spendable balance means
# blocks it mined itself.
mine_to 1 $((SEED_HEIGHT + 40)) || { fail "node1 could not mine its own funds"; exit 1; }
wait_sync $((SEED_HEIGHT + 40)) || { fail "nodes did not sync after node1 mined"; exit 1; }
wait_same_tip || { fail "nodes hold different tips before the partition"; exit 1; }
log "node1 balance $(balance 1) at height $(height 1)"

partition_nodes || { fail "the nodes could not be partitioned"; exit 1; }
SPLIT_HEIGHT="$(height 1)"
success "nodes partitioned at height $SPLIT_HEIGHT"

FILE_B="$TEST_DIR/subject_b.bin"
head -c 16384 /dev/urandom > "$FILE_B"
SHA_B="$(sha256sum "$FILE_B" | cut -d' ' -f1)"

OUT="$(stamp_file 1 "$FILE_B")"
TXID_B="$(jget "$OUT" podtxid)"
if [ ${#TXID_B} -eq 64 ]; then
    success "node1 published a stamp ${TXID_B:0:16} inside the partition"
else
    fail "node1 could not stamp: $(echo "$OUT" | head -4)"; exit 1
fi

# Captured now: once its block loses, the tx is in no index or mempool.
RAW_B="$(rpc 1 getrawtransaction "$TXID_B" 2>/dev/null | tr -d '"[:space:]')"
if [ ${#RAW_B} -gt 100 ]; then
    success "the stamp transaction was captured for rebroadcast (${#RAW_B} hex chars)"
else
    fail "could not capture the stamp transaction"; exit 1
fi

# node1 mines one block carrying it; node0 mines two, so node0's branch wins and
# node1's block becomes an off-chain sibling a canonical block can merge.
mine_one 1 || { fail "node1 could not mine its stamp"; exit 1; }
LOSER="$(best_hash 1)"
LOSER_HEIGHT="$(height 1)"
if [ "$(block_contains_tx 1 "$LOSER" "$TXID_B")" = "yes" ]; then
    success "node1's block ${LOSER:0:16} at height $LOSER_HEIGHT carries the stamp"
else
    fail "node1's block does not carry the stamp"; exit 1
fi

mine_to 0 $((SPLIT_HEIGHT + 2)) || { fail "node0 could not out-mine the partition"; exit 1; }
success "node0 built to height $(height 0) on its own branch"

connect_nodes
wait_peers || { fail "the nodes did not re-peer"; exit 1; }
wait_same_tip || { fail "the nodes did not converge after the partition"; exit 1; }
success "nodes converged on node0's branch at height $(height 0)"

wait_block_known 0 "$LOSER" || { fail "node0 never received the losing block"; exit 1; }
if [ "$(jget "$(rpc 0 getblock "$LOSER")" hash)" = "$LOSER" ] \
   && [ "$(block_hash 0 "$LOSER_HEIGHT")" != "$LOSER" ]; then
    success "the losing block survives off-chain at height $LOSER_HEIGHT"
else
    fail "the losing block is not off-chain on node0"
fi

# Before anything re-mines it, a stamp that rode only the losing block attests
# nothing: no block, no height, no time.
V0="$(rpc 0 podverify "$SHA_B" "$TXID_B")"
V1="$(rpc 1 podverify "$SHA_B" "$TXID_B")"
UNATTESTED=1
for V in "$V0" "$V1"; do
    echo "$V" | grep -q "No transaction with that txid" && continue
    [ -z "$(jget "$V" height)" ] || UNATTESTED=0
done
if [ "$UNATTESTED" = "1" ]; then
    success "a stamp carried only by the losing sibling attests no height on either node"
else
    fail "a merged-only stamp reported a height: node0=$(jget "$V0" height) node1=$(jget "$V1" height)"
fi

# A merge parent is never connected, so nothing it holds is indexed.
mine_one 0 >/dev/null 2>&1
mine_one 0 >/dev/null 2>&1
wait_same_tip || warn "tips have not converged after mining on"

TOP="$(height 0)"
MERGER=""; MERGER_HEIGHT=""
for ((h=LOSER_HEIGHT; h<=TOP; h++)); do
    CAND="$(block_hash 0 "$h")"
    [ ${#CAND} -eq 64 ] || continue
    if [ "$(block_has_dag_parent 0 "$CAND" "$LOSER")" = "yes" ]; then
        MERGER="$CAND"; MERGER_HEIGHT="$h"; break
    fi
done
if [ -n "$MERGER" ]; then
    success "canonical block ${MERGER:0:16} at height $MERGER_HEIGHT merges the losing block"
else
    fail "no canonical block merged the losing block; the shape under test was not built"
fi

if [ -z "$(confirmed_in_block 0 "$TXID_B")" ] && [ -z "$(confirmed_in_block 1 "$TXID_B")" ]; then
    success "the merged block is a DAG parent of the chain and still indexes none of its transactions"
else
    fail "a merged block's transaction was indexed"
fi

# Recovery: rebroadcast the publisher's copy (see the header).
SENT="$(rpc 0 sendrawtransaction "$RAW_B" 2>&1 | tr -d '"[:space:]')"
if [ "$SENT" = "$TXID_B" ]; then
    success "the stamp transaction is still acceptable and was rebroadcast"
else
    fail "the stamp transaction could not be rebroadcast: $(echo "$SENT" | head -c 200)"
fi

REBLOCK="$(confirm_stamp 0 "$TXID_B")"
wait_same_tip || warn "tips have not converged after the rebroadcast"
WHERE0="$(confirmed_in_block 0 "$TXID_B")"
WHERE1="$(confirmed_in_block 1 "$TXID_B")"
V0="$(rpc 0 podverify "$SHA_B" "$TXID_B")"
V1="$(rpc 1 podverify "$SHA_B" "$TXID_B")"
NEW_HEIGHT="$(jget "$V0" height)"

if [ ${#REBLOCK} -eq 64 ] && [ "$WHERE0" = "$REBLOCK" ] && [ "$WHERE1" = "$REBLOCK" ] \
   && [ "$REBLOCK" != "$LOSER" ]; then
    success "the rebroadcast copy connected in canonical block ${REBLOCK:0:16}, not the losing one"
else
    fail "the rebroadcast copy did not connect canonically: node0=${WHERE0:0:16} node1=${WHERE1:0:16}"
fi

if [ "$(jget "$V0" match)" = "True" ] && [ "$(jget "$V1" match)" = "True" ] \
   && [ "$NEW_HEIGHT" = "$(jget "$V1" height)" ]; then
    success "both nodes now attest the same digest at height $NEW_HEIGHT"
else
    fail "the recovered stamp does not read the same on both nodes: $(echo "$V0" | head -3)"
fi

if [ -n "$NEW_HEIGHT" ] && [ "$NEW_HEIGHT" != "$LOSER_HEIGHT" ]; then
    success "the attested height is the canonical one ($NEW_HEIGHT), never the losing block's ($LOSER_HEIGHT)"
else
    fail "the attested height did not move off the losing block: $NEW_HEIGHT"
fi

# ============================================================
header "3. A reorg moves the height and time a stamp attests to"
# ============================================================

wait_same_tip || warn "tips not converged entering section 3"
FILE_C="$TEST_DIR/subject_c.bin"
head -c 8192 /dev/urandom > "$FILE_C"
SHA_C="$(sha256sum "$FILE_C" | cut -d' ' -f1)"

OUT="$(stamp_file 0 "$FILE_C")"
TXID_C="$(jget "$OUT" podtxid)"
[ ${#TXID_C} -eq 64 ] || { fail "could not stamp for the reorg test: $(echo "$OUT" | head -3)"; exit 1; }
RAW_C="$(rpc 0 getrawtransaction "$TXID_C" 2>/dev/null | tr -d '"[:space:]')"

BLOCK_C="$(confirm_stamp 0 "$TXID_C")"
[ ${#BLOCK_C} -eq 64 ] || { fail "the reorg-test stamp never confirmed"; exit 1; }
V0="$(rpc 0 podverify "$SHA_C" "$TXID_C")"
FIRST_HEIGHT="$(jget "$V0" height)"
FIRST_TIME="$(jget "$V0" blocktime)"
FIRST_FINAL="$(jget "$V0" finalized)"
if [ "$(jget "$V0" match)" = "True" ] && is_int "$FIRST_HEIGHT"; then
    success "the stamp attests height $FIRST_HEIGHT at time $FIRST_TIME (finalized=$FIRST_FINAL)"
else
    fail "the reorg-test stamp did not verify: $(echo "$V0" | head -5)"; exit 1
fi

if [ "$FIRST_FINAL" = "False" ]; then
    success "with no finality advancing, the stamp is reported not finalized"
else
    warn "the stamp reports finalized=$FIRST_FINAL before any epoch finalised"
fi

# Disconnect the containing block. The transaction is not re-queued on regtest,
# so this is the state a stamp is in the moment its block leaves the chain.
rpc 0 invalidateblock "$BLOCK_C" >/dev/null 2>&1
sleep 5
V0="$(rpc 0 podverify "$SHA_C" "$TXID_C")"
AFTER_HEIGHT="$(jget "$V0" height)"
if [ -z "$AFTER_HEIGHT" ]; then
    success "with the containing block disconnected, the stamp attests no height"
else
    fail "a disconnected stamp still attests height $AFTER_HEIGHT"
fi

# Re-mine it: a different block at a different time carries the same digest.
rpc 0 sendrawtransaction "$RAW_C" >/dev/null 2>&1
BLOCK_C2="$(confirm_stamp 0 "$TXID_C")"
if [ ${#BLOCK_C2} -eq 64 ] && [ "$BLOCK_C2" != "$BLOCK_C" ]; then
    success "the stamp re-confirmed in a different block ${BLOCK_C2:0:16}"
else
    fail "the stamp did not re-confirm into a new block (${BLOCK_C2:0:16})"
fi

V0="$(rpc 0 podverify "$SHA_C" "$TXID_C")"
SECOND_HEIGHT="$(jget "$V0" height)"
SECOND_TIME="$(jget "$V0" blocktime)"
if [ "$(jget "$V0" match)" = "True" ]; then
    success "the same digest still verifies after the reorg"
else
    fail "the digest stopped verifying after the reorg: $(echo "$V0" | head -5)"
fi

if [ "$SECOND_TIME" != "$FIRST_TIME" ] || [ "$SECOND_HEIGHT" != "$FIRST_HEIGHT" ]; then
    success "the attested anchor moved: height $FIRST_HEIGHT/time $FIRST_TIME -> height $SECOND_HEIGHT/time $SECOND_TIME"
else
    fail "the attested anchor did not move across a reorg, so the test says nothing"
fi

# The tx is byte-identical across the reorg, so a changed attested time is the block's.
# nTime is read from raw bytes: verbose getrawtransaction emits "time" twice.
NTIME2="$(jget "$(rpc 0 decoderawtransaction "$RAW_C" 2>/dev/null)" time)"
BLKTIME2="$(jget "$(rpc 0 getblock "$BLOCK_C2" 2>/dev/null)" time)"
if [ "$SECOND_TIME" = "$BLKTIME2" ] && [ "$SECOND_TIME" != "$FIRST_TIME" ] \
   && [ -n "$NTIME2" ]; then
    success "the unchanged transaction (nTime $NTIME2) attests its new block's time $BLKTIME2"
else
    fail "attested time $SECOND_TIME is not the new block time $BLKTIME2 (nTime $NTIME2)"
fi

rpc 0 reconsiderblock "$BLOCK_C" >/dev/null 2>&1 || true

# ============================================================
header "4. The finalized verdict is deterministic, not node-local"
# ============================================================

wait_same_tip || warn "tips not converged entering section 4"
V0="$(rpc 0 podverify "$SHA_A" "$TXID_A")"
V1="$(rpc 1 podverify "$SHA_A" "$TXID_A")"
F0="$(jget "$V0" finalized)"; F1="$(jget "$V1" finalized)"
FH0="$(jget "$V0" finalizedheight)"; FH1="$(jget "$V1" finalizedheight)"

if [ -n "$F0" ] && [ "$F0" = "$F1" ]; then
    success "both nodes report the same finalized verdict ($F0) for one stamp"
else
    fail "the nodes disagree about finality: node0=$F0 node1=$F1"
fi

if [ "$FH0" = "$FH1" ]; then
    success "both nodes report the same finalized height (${FH0:-none})"
else
    fail "the nodes report different finalized heights: $FH0 vs $FH1"
fi

# A stamp above the finalized height must never be reported finalized.
SA_HEIGHT="$(jget "$V0" height)"
if is_int "$FH0" && is_int "$SA_HEIGHT"; then
    if [ "$SA_HEIGHT" -le "$FH0" ]; then EXPECT="True"; else EXPECT="False"; fi
    if [ "$F0" = "$EXPECT" ]; then
        success "finalized=$F0 agrees with height $SA_HEIGHT against finalized height $FH0"
    else
        fail "finalized=$F0 contradicts height $SA_HEIGHT against finalized height $FH0"
    fi
else
    if [ "$F0" = "False" ]; then
        success "with no completed epoch state, the stamp is reported not finalized"
    else
        fail "a stamp with no epoch state reported finalized=$F0"
    fi
fi

# ============================================================
header "Summary"
# ============================================================
echo -e "${GREEN}Passed:${NC}  $PASSED"
echo -e "${RED}Failed:${NC}  $FAILED"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
