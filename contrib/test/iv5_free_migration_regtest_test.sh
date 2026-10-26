#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Fee-exempt migration regtest: a zero-fee shield of pre-snapshot coins confirms inside
# the window, at most 4 per block; a post-snapshot coin or a mixed-owner shield still
# needs a fee. Fee-paying shields of migration shape are not relay limited, and the
# exempt entries leave the mempool when a reorg closes the window. Two nodes must agree.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_free_migration_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_MIG_TEST_DIR:-/tmp/innova_iv5_migration_$$}"
NUM_NODES=2
BASE_PORT="${IV5_MIG_BASE_PORT:-$(iv5_port 0 29700)}"
BASE_RPC="${IV5_MIG_BASE_RPC:-$(iv5_port 16 29760)}"
BASE_IDNS="${IV5_MIG_BASE_IDNS:-$(iv5_port 32 9780)}"
RPCUSER="iv5mig"
RPCPASS="iv5migpass"
WALLETPASS="iv5migwallet"

BOUNDARY_B=311
MIGRATION=340
SNAPSHOT=$((MIGRATION - 1))
SEED_HEIGHT=250
QUOTA=4
FLOOD=6
PAID_FEE=1000000

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
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
jget() {
    FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"], None)
    print("" if v is None else v)
except Exception:
    pass
' <<< "$1" 2>/dev/null
}

height()     { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
block_hash() { rpc "$1" getblockhash "$2" 2>/dev/null | tr -d '"[:space:]'; }
best_hash()  { rpc "$1" getbestblockhash 2>/dev/null | tr -d '"[:space:]'; }
in_mempool() { rpc "$1" getrawmempool 2>/dev/null | grep -q "$2"; }
mempool_count() {
    rpc "$1" getrawmempool 2>/dev/null | python3 -c '
import json, sys
try: print(len(json.load(sys.stdin)))
except Exception: print(-1)
'
}

wait_rpc() {
    for _ in $(seq 1 120); do
        rpc "$1" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
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
        echo "regtestmigration=$MIGRATION"
    } > "$dir/innova.conf"
}

connect_nodes() {
    rpc 0 addnode "127.0.0.1:$(node_port 1)" onetry >/dev/null 2>&1 || true
    rpc 1 addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1 || true
}

wait_same_tip() {
    for ((i=0; i<240; i++)); do
        local a b
        a="$(best_hash 0)"; b="$(best_hash 1)"
        if [ ${#a} -eq 64 ] && [ "$a" = "$b" ]; then return 0; fi
        [ $((i % 20)) -eq 19 ] && connect_nodes
        sleep 1
    done
    return 1
}

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

unlock() { rpc 0 walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1; }

# "txid vout address scripthex" per spendable output confirmed at or below a height.
utxos_at_or_below() {
    local maxh="$1" tip
    tip="$(height 0)"
    rpc 0 listunspent 1 9999999 2>/dev/null | TIP="$tip" MAXH="$maxh" python3 -c '
import json, os, sys
tip = int(os.environ["TIP"]); maxh = int(os.environ["MAXH"])
for u in json.load(sys.stdin):
    h = tip - int(u["confirmations"]) + 1
    if h <= maxh:
        print(u["txid"], u["vout"], u.get("address", ""), u["scriptPubKey"], "%.8f" % u["amount"])
'
}

build() {
    # build <fee> <txid:vout>...
    local fee="$1"; shift
    local arr="[" first=1 op
    for op in "$@"; do
        [ $first -eq 1 ] || arr="$arr,"
        arr="$arr{\"txid\":\"${op%%:*}\",\"vout\":${op##*:}}"
        first=0
    done
    arr="$arr]"
    rpc 0 iv5migrationshield "$arr" "$fee"
}

submit() { rpc 0 sendrawtransaction "$1" 2>&1 | tr -d '"[:space:]'; }

block_txs() {
    rpc 0 getblock "$(block_hash 0 "$1")" 2>/dev/null | python3 -c '
import json, sys
try: print(" ".join(json.load(sys.stdin)["tx"]))
except Exception: pass
'
}

cleanup() {
    for ((n=0; n<NUM_NODES; n++)); do stop_node "$n" || true; done
    [ "${IV5_MIG_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "Fee-exempt migration (fork $MIGRATION, snapshot $SNAPSHOT, quota $QUOTA)"

rm -rf "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done
start_node 0 || { fail "node0 did not start"; exit 1; }
start_node 1 || { fail "node1 did not start"; exit 1; }
connect_nodes

mine_to 0 "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }
rpc 0 encryptwallet "$WALLETPASS" >/dev/null 2>&1
wait_rpc_down 0
start_node 0 || { fail "node0 did not restart"; exit 1; }
connect_nodes
unlock
SEED="$(rpc 0 z_createiv5seed 2>&1)"
echo "$SEED" | grep -q '"created"' || { fail "z_createiv5seed: $(echo "$SEED" | head -2)"; exit 1; }
success "node0 seeded at height $(height 0)"

# ============================================================
header "1. Pre-snapshot coins: a dust P2PKH and a P2PK of the coinbase key"
# ============================================================
mine_to 0 320 || { fail "could not mine to 320"; exit 1; }
unlock
DUST_ADDR="$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
DUST_TX="$(rpc 0 sendtoaddress "$DUST_ADDR" 0.01 2>&1 | tr -d '"[:space:]')"
[ ${#DUST_TX} -eq 64 ] || { fail "dust send: $DUST_TX"; exit 1; }

# A P2PK output (the stake script form) of the coinbase key, next to that key's P2PKH.
CB=()
while IFS= read -r line; do CB+=("$line"); done < <(utxos_at_or_below 300 | awk 'substr($4, 1, 6) == "76a914"')
[ "${#CB[@]}" -ge $((FLOOD + 9)) ] || { fail "only ${#CB[@]} coinbases available"; exit 1; }
read -r P2PK_SRC_TXID P2PK_SRC_N PAIR_ADDR PAIR_SCRIPT PAIR_AMT <<< "${CB[0]}"
read -r PAIR_TXID PAIR_N _ <<< "${CB[1]}"
PUBKEY="$(jget "$(rpc 0 validateaddress "$PAIR_ADDR")" pubkey)"
[ ${#PUBKEY} -eq 66 ] || { fail "no compressed pubkey for $PAIR_ADDR"; exit 1; }
P2PK_AMT="$(python3 -c "print('%.8f' % ($PAIR_AMT - 0.01))")"
RAW="$(rpc 0 createrawtransaction "[{\"txid\":\"$P2PK_SRC_TXID\",\"vout\":$P2PK_SRC_N}]" "{\"$PAIR_ADDR\":$P2PK_AMT}" | tr -d '"[:space:]')"
H160="${PAIR_SCRIPT:6:40}"
RAW="${RAW/1976a914${H160}88ac/2321${PUBKEY}ac}"
SIGNED="$(jget "$(rpc 0 signrawtransaction "$RAW")" hex)"
PAIR_PAY="$(rpc 0 sendrawtransaction "$SIGNED" 2>&1 | tr -d '"[:space:]')"
[ ${#PAIR_PAY} -eq 64 ] || { fail "P2PK send: $PAIR_PAY"; exit 1; }
mine_to 0 330 || { fail "could not mine to 330"; exit 1; }
success "dust ${DUST_TX:0:12} and P2PK ${PAIR_PAY:0:12} confirmed below the snapshot"

DUST_N="$(rpc 0 listunspent 1 9999999 2>/dev/null | TX="$DUST_TX" python3 -c '
import json, os, sys
for u in json.load(sys.stdin):
    if u["txid"] == os.environ["TX"] and abs(u["amount"] - 0.01) < 1e-9: print(u["vout"])
')"
PAIR_PAY_N=0
is_int "$DUST_N" && is_int "$PAIR_PAY_N" || { fail "could not locate dust/pair outputs"; exit 1; }

# ============================================================
header "2. Before the fork a zero-fee migration is refused"
# ============================================================
unlock
R="$(build 0 "$DUST_TX:$DUST_N")"
HEX="$(jget "$R" hex)"
[ -n "$HEX" ] || { fail "build failed: $(echo "$R" | head -2)"; exit 1; }
S="$(submit "$HEX")"
if [ ${#S} -ne 64 ]; then
    success "zero-fee migration refused at tip $(height 0) (window opens at $MIGRATION)"
else
    fail "zero-fee migration accepted before the fork: $S"
fi

mine_to 0 "$SNAPSHOT" || { fail "could not mine to $SNAPSHOT"; exit 1; }
wait_same_tip || { fail "nodes disagree at $SNAPSHOT"; exit 1; }

# ============================================================
header "3. Inside the window: dust and same-owner P2PK+P2PKH go free"
# ============================================================
unlock
declare -a EXEMPT
R="$(build 0 "$DUST_TX:$DUST_N")"; S="$(submit "$(jget "$R" hex)")"
if [ ${#S} -eq 64 ]; then success "dust migration accepted at fee 0"; EXEMPT+=("$S"); else fail "dust migration: $S"; fi
R="$(build 0 "$PAIR_TXID:$PAIR_N" "$PAIR_PAY:$PAIR_PAY_N")"; S="$(submit "$(jget "$R" hex)")"
if [ ${#S} -eq 64 ]; then success "P2PK + same-key P2PKH accepted at fee 0"; EXEMPT+=("$S"); else fail "same-owner pair: $S"; fi

# Two owners in one migration need the fee.
read -r M1_TXID M1_N _ <<< "${CB[2]}"
R="$(build 0 "$M1_TXID:$M1_N" "$DUST_TX:$DUST_N")"; S="$(submit "$(jget "$R" hex)")"
if [ ${#S} -ne 64 ]; then success "a two-owner zero-fee migration is refused"; else fail "two-owner migration accepted: $S"; fi

# Flood past the quota with single-coinbase migrations.
for ((k=3; k<3+FLOOD; k++)); do
    read -r F_TXID F_N _ <<< "${CB[$k]}"
    R="$(build 0 "$F_TXID:$F_N")"; S="$(submit "$(jget "$R" hex)")"
    if [ ${#S} -eq 64 ]; then EXEMPT+=("$S"); else fail "flood migration $k: $S"; fi
done
TOTAL=${#EXEMPT[@]}
[ "$TOTAL" -eq $((FLOOD + 2)) ] && success "$TOTAL zero-fee migrations in the mempool"

# ============================================================
header "4. Each block carries at most $QUOTA"
# ============================================================
CONFIRMED=0
H0="$(height 0)"
for ((b=1; b<=4; b++)); do
    mine_to 0 $((H0 + b)) || { fail "could not mine"; break; }
    TXS="$(block_txs $((H0 + b)))"
    N=0
    for t in "${EXEMPT[@]}"; do echo "$TXS" | grep -q "$t" && N=$((N + 1)); done
    CONFIRMED=$((CONFIRMED + N))
    if [ "$N" -le "$QUOTA" ]; then
        success "block $((H0 + b)) carries $N migrations"
    else
        fail "block $((H0 + b)) carries $N migrations, over the quota"
    fi
    [ "$CONFIRMED" -ge "$TOTAL" ] && break
done
FIRST_N=0
TXS="$(block_txs $((H0 + 1)))"
for t in "${EXEMPT[@]}"; do echo "$TXS" | grep -q "$t" && FIRST_N=$((FIRST_N + 1)); done
[ "$FIRST_N" -eq "$QUOTA" ] && success "the first window block fills the quota exactly" || fail "first block carries $FIRST_N, expected $QUOTA"
[ "$CONFIRMED" -eq "$TOTAL" ] && success "all $TOTAL migrations confirmed" || fail "$CONFIRMED of $TOTAL migrations confirmed"

# ============================================================
header "5. A post-snapshot coin needs a fee"
# ============================================================
unlock
POST_ADDR="$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
POST_TX="$(rpc 0 sendtoaddress "$POST_ADDR" 2 2>&1 | tr -d '"[:space:]')"
mine_to 0 $(( $(height 0) + 1 )) || { fail "could not confirm post-snapshot coin"; exit 1; }
POST_N="$(rpc 0 listunspent 1 9999999 2>/dev/null | TX="$POST_TX" A="$POST_ADDR" python3 -c '
import json, os, sys
for u in json.load(sys.stdin):
    if u["txid"] == os.environ["TX"] and u.get("address") == os.environ["A"]: print(u["vout"])
')"
unlock
R="$(build 0 "$POST_TX:$POST_N")"; S="$(submit "$(jget "$R" hex)")"
if [ ${#S} -ne 64 ]; then success "zero-fee shield of a post-snapshot coin refused"; else fail "post-snapshot coin went free: $S"; fi
R="$(build "$PAID_FEE" "$POST_TX:$POST_N")"; S="$(submit "$(jget "$R" hex)")"
if [ ${#S} -eq 64 ]; then
    success "the same coin shields with a fee"
    mine_to 0 $(( $(height 0) + 1 ))
    echo "$(block_txs "$(height 0)")" | grep -q "$S" && success "fee-paying shield confirmed" || fail "fee-paying shield not mined"
else
    fail "fee-paying shield refused: $S"
fi

# ============================================================
header "5b. Fee-paying migration-shaped shields are not relay limited"
# ============================================================
unlock
declare -a PAID
for ((k=FLOOD+3; k<FLOOD+5; k++)); do
    read -r Z_TXID Z_N _ <<< "${CB[$k]}"
    R="$(build 0 "$Z_TXID:$Z_N")"; submit "$(jget "$R" hex)" >/dev/null
done
for ((k=FLOOD+5; k<FLOOD+8; k++)); do
    read -r P_TXID P_N _ <<< "${CB[$k]}"
    R="$(build "$PAID_FEE" "$P_TXID:$P_N")"; S="$(submit "$(jget "$R" hex)")"
    if [ ${#S} -eq 64 ]; then PAID+=("$S"); else fail "paid migration-shaped shield $k: $S"; fi
done
SEEN=0
for _ in $(seq 1 60); do
    SEEN=0
    for t in "${PAID[@]}"; do in_mempool 1 "$t" && SEEN=$((SEEN + 1)); done
    [ "$SEEN" -eq "${#PAID[@]}" ] && break
    sleep 1
done
if [ "${#PAID[@]}" -eq 3 ] && [ "$SEEN" -eq 3 ]; then
    success "node1 took all 3 fee-paying shields after the zero-fee budget was spent"
else
    fail "node1 holds $SEEN of ${#PAID[@]} fee-paying shields"
fi
mine_to 0 $(( $(height 0) + 2 )) || fail "could not mine the paid shields"
wait_same_tip || fail "nodes disagree after the paid shields"

# ============================================================
header "5c. A reorg below the fork purges pending exempt migrations"
# ============================================================
unlock
read -r W_TXID W_N _ <<< "${CB[$((FLOOD + 8))]}"
R="$(build 0 "$W_TXID:$W_N")"; WAIT_TX="$(submit "$(jget "$R" hex)")"
if [ ${#WAIT_TX} -eq 64 ] && in_mempool 0 "$WAIT_TX"; then
    success "pending zero-fee migration ${WAIT_TX:0:12} in the mempool"
    TIP_BEFORE="$(height 0)"
    rpc 0 invalidateblock "$(block_hash 0 "$SNAPSHOT")" >/dev/null 2>&1
    H="$(height 0)"
    if is_int "$H" && [ "$H" -lt "$SNAPSHOT" ]; then
        if in_mempool 0 "$WAIT_TX"; then
            fail "exempt migration still pooled at tip $H, window closed"
        else
            success "exempt migration purged after the reorg to $H"
        fi
    else
        fail "invalidateblock left tip at $H"
    fi
    rpc 0 reconsiderblock "$(block_hash 1 "$SNAPSHOT")" >/dev/null 2>&1
    for _ in $(seq 1 120); do
        H="$(height 0)"; is_int "$H" && [ "$H" -ge "$TIP_BEFORE" ] && break
        sleep 1
    done
    [ "$(height 0)" -ge "$TIP_BEFORE" ] && success "node0 restored to $(height 0)" || fail "node0 did not restore ($(height 0) < $TIP_BEFORE)"
else
    fail "pending migration not accepted: $WAIT_TX"
fi

# ============================================================
header "6. Both nodes agree"
# ============================================================
if wait_same_tip; then
    success "node0 and node1 share tip $(best_hash 0 | cut -c1-16) at $(height 1)"
else
    fail "tips differ: node0 $(height 0) $(best_hash 0 | cut -c1-16), node1 $(height 1) $(best_hash 1 | cut -c1-16)"
fi
REJ="$(grep -c "fee-exempt migrations\|not paying required fee" "$(node_dir 1)/regtest/debug.log" 2>/dev/null)"
[ "${REJ:-0}" = "0" ] && success "node1 rejected no block" || fail "node1 logged $REJ block rejections"

echo
echo -e "Passed: ${GREEN}$PASSED${NC}  Failed: ${RED}$FAILED${NC}"
[ "$FAILED" -eq 0 ]
