#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Fee-exempt migration through the wallet: z_shieldall pays the fee before the fork;
# inside the window z_migratetopool moves dust and a same-key P2PK+P2PKH at fee 0 into one
# note each, sends a post-snapshot coin with a fee, and paces free sends to the relay limit.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_free_migration_wallet_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_MIGW_TEST_DIR:-/tmp/innova_iv5_migwallet_$$}"
NUM_NODES=2
BASE_PORT="${IV5_MIGW_BASE_PORT:-$(iv5_port 0 29800)}"
BASE_RPC="${IV5_MIGW_BASE_RPC:-$(iv5_port 16 29860)}"
BASE_IDNS="${IV5_MIGW_BASE_IDNS:-$(iv5_port 32 9880)}"
RPCUSER="iv5mig"
RPCPASS="iv5migpass"
WALLETPASS="iv5migwallet"

BOUNDARY_B=311
MIGRATION=340
SNAPSHOT=$((MIGRATION - 1))
SEED_HEIGHT=250
SHIELD_FEE=0.001

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
        echo "debugtxrelay=1"
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
    [ "${IV5_MIGW_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT


w() { rpc 1 "$@"; }
jtx() {
    # jtx <json> <python expr over list t of transactions>
    EXPR="$2" python3 -c '
import json, os, sys
try:
    t = json.load(sys.stdin).get("transactions", [])
    print(eval(os.environ["EXPR"]))
except Exception as e:
    print("ERR", e)
' <<< "$1" 2>/dev/null
}
confirmed() {
    local c
    c="$(jget "$(w gettransaction "$1")" confirmations)"
    is_int "$c" && [ "$c" -ge 1 ]
}
mine_confirm() {
    # Mine until every txid is confirmed on node1, at most $1 blocks.
    local max="$1"; shift
    for ((b=0; b<max; b++)); do
        local all=1 t
        for t in "$@"; do confirmed "$t" || all=0; done
        [ $all -eq 1 ] && return 0
        mine_to 0 $(( $(height 0) + 1 )) || return 1
        wait_same_tip || return 1
    done
    for t in "$@"; do confirmed "$t" || return 1; done
}
wait_mempool0() {
    local t
    for _ in $(seq 1 90); do
        local all=1
        for t in "$@"; do in_mempool 0 "$t" || all=0; done
        [ $all -eq 1 ] && return 0
        sleep 1
    done
    return 1
}

header "Wallet fee-exempt migration (fork $MIGRATION, snapshot $SNAPSHOT)"

rm -rf "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done
start_node 0 || { fail "node0 did not start"; exit 1; }
start_node 1 || { fail "node1 did not start"; exit 1; }
connect_nodes
mine_to 0 "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }
wait_same_tip || { fail "nodes disagree at $SEED_HEIGHT"; exit 1; }
for n in 0 1; do
    rpc "$n" encryptwallet "$WALLETPASS" >/dev/null 2>&1
    wait_rpc_down "$n"
    start_node "$n" || { fail "node$n did not restart"; exit 1; }
    rpc "$n" walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
done
connect_nodes
SEED="$(w z_createiv5seed 2>&1)"
echo "$SEED" | grep -q '"created"' || { fail "node1 z_createiv5seed: $(echo "$SEED" | head -2)"; exit 1; }
success "node1 seeded"

# ============================================================
header "1. Fund node1 below the snapshot"
# ============================================================
mine_to 0 320 || { fail "could not mine to 320"; exit 1; }
D_ADDR="$(w getnewaddress | tr -d '"[:space:]')"
K_ADDR="$(w getnewaddress | tr -d '"[:space:]')"
F_ADDR="$(w getnewaddress | tr -d '"[:space:]')"
G_ADDR="$(w getnewaddress | tr -d '"[:space:]')"
H_ADDR="$(w getnewaddress | tr -d '"[:space:]')"
K_PUB="$(jget "$(w validateaddress "$K_ADDR")" pubkey)"
[ ${#K_PUB} -eq 66 ] || { fail "no pubkey for $K_ADDR"; exit 1; }
for pair in "$D_ADDR 0.0005" "$K_ADDR 3" "$F_ADDR 4" "$G_ADDR 0.0003" "$H_ADDR 0.0004"; do
    set -- $pair
    T="$(rpc 0 sendtoaddress "$1" "$2" 2>&1 | tr -d '"[:space:]')"
    [ ${#T} -eq 64 ] || { fail "send $2 to $1: $T"; exit 1; }
done
# A P2PK output of K's key next to its P2PKH.
K_SCRIPT="$(jget "$(w validateaddress "$K_ADDR")" scriptPubKey)"
[ -n "$K_SCRIPT" ] || K_SCRIPT="76a914$(python3 - "$K_ADDR" <<'PY'
import sys
a='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
n=0
for c in sys.argv[1]: n=n*58+a.index(c)
print(n.to_bytes(25,'big')[1:21].hex())
PY
)88ac"
read -r SRC_TXID SRC_N _ _ SRC_AMT <<< "$(utxos_at_or_below 300 | awk 'substr($4, 1, 6) == "76a914"' | head -1)"
P2PK_AMT="$(python3 -c "print('%.8f' % ($SRC_AMT - 0.01))")"
RAW="$(rpc 0 createrawtransaction "[{\"txid\":\"$SRC_TXID\",\"vout\":$SRC_N}]" "{\"$K_ADDR\":$P2PK_AMT}" | tr -d '"[:space:]')"
H160="${K_SCRIPT:6:40}"
RAW="${RAW/1976a914${H160}88ac/2321${K_PUB}ac}"
SIGNED="$(jget "$(rpc 0 signrawtransaction "$RAW")" hex)"
P2PK_TX="$(rpc 0 sendrawtransaction "$SIGNED" 2>&1 | tr -d '"[:space:]')"
[ ${#P2PK_TX} -eq 64 ] || { fail "P2PK send: $P2PK_TX"; exit 1; }
mine_to 0 330 || { fail "could not mine to 330"; exit 1; }
wait_same_tip || { fail "nodes disagree at 330"; exit 1; }
success "node1 holds dust, P2PK+P2PKH of one key, and two more coins below the snapshot"

# ============================================================
header "2. Before the fork the wallet pays the fee"
# ============================================================
R="$(w z_shieldall "$F_ADDR")"
FREE="$(jget "$R" free)"; FEE="$(jget "$R" fee)"; PRE_TX="$(jget "$R" txid)"
if [ "$FREE" = "False" ] && python3 -c "import sys; sys.exit(0 if abs(float('$FEE') - $SHIELD_FEE) < 1e-9 else 1)" 2>/dev/null; then
    success "z_shieldall before the fork: fee $FEE, free $FREE"
else
    fail "pre-fork z_shieldall: $(echo "$R" | tr '\n' ' ')"
fi
R="$(w z_shieldall "$D_ADDR")"
echo "$R" | grep -q "does not cover" && success "dust is refused before the fork (fee not covered)" || fail "dust pre-fork: $(echo "$R" | head -2)"
mine_confirm 5 "$PRE_TX" && success "fee-paying shield ${PRE_TX:0:12} confirmed" || fail "pre-fork shield not confirmed"

mine_to 0 "$SNAPSHOT" || { fail "could not mine to $SNAPSHOT"; exit 1; }
wait_same_tip || { fail "nodes disagree at $SNAPSHOT"; exit 1; }
# A post-snapshot coin at the dust address, mined at the fork height.
POST_TX="$(rpc 0 sendtoaddress "$D_ADDR" 2 2>&1 | tr -d '"[:space:]')"
[ ${#POST_TX} -eq 64 ] || { fail "post-snapshot send: $POST_TX"; exit 1; }
mine_to 0 "$MIGRATION" || { fail "could not mine to $MIGRATION"; exit 1; }
wait_same_tip || { fail "nodes disagree at $MIGRATION"; exit 1; }
confirmed "$POST_TX" && success "post-snapshot coin confirmed at $(height 1)" || fail "post-snapshot coin not seen by node1"

INFO="$(w z_getshieldedinfo)"
[ "$(jget "$INFO" migration_window_open)" = "True" ] && [ "$(jget "$INFO" migration_end_height)" = "$((MIGRATION + 31536000))" ] \
    && success "z_getshieldedinfo reports the window open until $(jget "$INFO" migration_end_height)" \
    || fail "window info: $(echo "$INFO" | grep migration | tr '\n' ' ')"

# ============================================================
header "3. z_migratetopool inside the window"
# ============================================================
R="$(w z_migratetopool)"
echo "$R" > "$TEST_DIR/migrate1.json"
SENT="$(jget "$R" sent)"; FREE_SENT="$(jget "$R" free_sent)"
DEFER="$(jget "$R" free_deferred_addresses)"; RETRY="$(jget "$R" free_retry_after)"
log "sent=$SENT free_sent=$FREE_SENT deferred=$DEFER retry=$RETRY more=$(jget "$R" more)"
[ "$FREE_SENT" = "2" ] && success "two free migrations sent (the per-minute relay budget)" || fail "free_sent=$FREE_SENT: $(echo "$R" | tr '\n' ' ')"
K_FREE="$(jtx "$R" "[x['txid'] for x in t if x['address']=='$K_ADDR' and x['free'] and x['fee']==0 and x['inputs']==2][0]")"
D_FREE="$(jtx "$R" "[x['txid'] for x in t if x['address']=='$D_ADDR' and x['free'] and x['fee']==0 and x['inputs']==1 and abs(x['shielded']-0.0005)<1e-9][0]")"
D_PAID="$(jtx "$R" "[x['txid'] for x in t if x['address']=='$D_ADDR' and not x['free'] and abs(x['fee']-$SHIELD_FEE)<1e-9 and x['inputs']==1][0]")"
[ ${#K_FREE} -eq 64 ] && success "P2PK + P2PKH of one key migrated at fee 0 in one tx" || fail "K free: $K_FREE"
[ ${#D_FREE} -eq 64 ] && success "dust 0.0005 (below the 0.001 fee) migrated at fee 0" || fail "dust free: $D_FREE"
[ ${#D_PAID} -eq 64 ] && success "post-snapshot coin at the same address went in a separate fee-paying tx" || fail "post paid: $D_PAID"
if [ "$DEFER" = "2" ] && is_int "$RETRY" && [ "$RETRY" -gt 0 ] && [ "$(jget "$R" more)" = "True" ]; then
    success "two more free addresses deferred, retry in ${RETRY}s"
else
    fail "deferral: deferred=$DEFER retry=$RETRY"
fi
for t in "$K_FREE" "$D_FREE"; do
    HEX="$(rpc 1 getrawtransaction "$t" 2>/dev/null | tr -d '"[:space:]')"
    VOUT="$(jget "$(rpc 1 decoderawtransaction "$HEX")" vout | python3 -c 'import sys,ast; print(len(ast.literal_eval(sys.stdin.read() or "[]")))' 2>/dev/null)"
    [ "$VOUT" = "0" ] && success "${t:0:12} has no transparent output" || fail "${t:0:12} vout=$VOUT"
done
wait_mempool0 "$K_FREE" "$D_FREE" "$D_PAID" && success "node0 accepted all three from node1 by relay" || fail "relay to node0 incomplete"
mine_confirm 5 "$K_FREE" "$D_FREE" "$D_PAID" && success "all three confirmed" || fail "migrations not confirmed"

R="$(w z_shieldall "$G_ADDR")"
if echo "$R" | grep -q "relay limit"; then
    success "z_shieldall refuses a free shield over the relay budget instead of paying"
else
    fail "z_shieldall over budget: $(echo "$R" | head -3 | tr '\n' ' ')"
fi

# ============================================================
header "4. After the relay window the deferred address goes free"
# ============================================================
# A third-party free migration relayed by node1 uses one of node0's per-minute slots for
# node1, so one of node1's two wallet free txs is dropped and must be re-fetched later.
SEED0="$(rpc 0 z_createiv5seed 2>&1)"
echo "$SEED0" | grep -q '"created"' || fail "node0 z_createiv5seed: $(echo "$SEED0" | head -2)"
read -r TP_TXID TP_N _ _ _ <<< "$(utxos_at_or_below "$SNAPSHOT" | awk 'substr($4, 1, 6) == "76a914"' | head -1)"
TP_HEX="$(jget "$(build 0 "$TP_TXID:$TP_N")" hex)"
sleep $((RETRY + 1))
TP_TX="$(rpc 1 sendrawtransaction "$TP_HEX" 2>&1 | tr -d '"[:space:]')"
[ ${#TP_TX} -eq 64 ] && success "third-party free migration submitted at node1" || fail "third-party submit: $TP_TX"
wait_mempool0 "$TP_TX" || fail "third-party tx not relayed to node0"
R="$(w z_migratetopool)"
G_FREE="$(jtx "$R" "[x['txid'] for x in t if x['address']=='$G_ADDR' and x['free'] and x['fee']==0][0]")"
H_FREE="$(jtx "$R" "[x['txid'] for x in t if x['address']=='$H_ADDR' and x['free'] and x['fee']==0][0]")"
[ ${#G_FREE} -eq 64 ] && [ ${#H_FREE} -eq 64 ] && success "deferred addresses migrated free on the next call" || fail "G/H: $(echo "$R" | tr '\n' ' ')"
for _ in $(seq 1 200); do
    in_mempool 0 "$G_FREE" && in_mempool 0 "$H_FREE" && break
    sleep 1
done
DROPS="$(grep -c "TXRELAY migration rate limit" "$(node_dir 0)/regtest/debug.log" 2>/dev/null)"
log "node0 rate-limit drops: ${DROPS:-0}"
if in_mempool 0 "$G_FREE" && in_mempool 0 "$H_FREE"; then
    success "all 3 free txs reached node0 (resend after a rate-limit drop)"
else
    fail "free txs missing from node0 mempool"
fi
mine_confirm 5 "$TP_TX" "$G_FREE" "$H_FREE" && success "3 free txs from one peer in one minute all confirmed" || fail "free txs not confirmed"
R="$(w z_migratetopool)"
[ "$(jget "$R" sent)" = "0" ] && [ "$(jget "$R" more)" = "False" ] && success "nothing left to migrate" || fail "leftover: $(echo "$R" | tr '\n' ' ')"

# ============================================================
header "5. Both nodes agree"
# ============================================================
wait_same_tip && success "shared tip at $(height 1)" || fail "tips differ"
REJ="$(grep -c "fee-exempt migrations\|not paying required fee" "$(node_dir 0)/regtest/debug.log" 2>/dev/null)"
[ "${REJ:-0}" = "0" ] && success "node0 logged no fee rejection" || fail "node0 logged $REJ fee rejections"

echo
echo -e "Passed: ${GREEN}$PASSED${NC}  Failed: ${RED}$FAILED${NC}"
[ "$FAILED" -eq 0 ]
