#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 shielded spend regtest: both spend paths on a finalizing chain. Three wallets
# vote every epoch; epoch 1 keeps a single voter as the negative control.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_SPEND_TEST_DIR:-/tmp/innova_iv5_spend_$$}"
NUM_NODES=3
BASE_PORT="${IV5_SPEND_BASE_PORT:-28450}"
BASE_RPC="${IV5_SPEND_BASE_RPC:-28500}"
BASE_IDNS="${IV5_SPEND_BASE_IDNS:-8560}"
RPCUSER="iv5spend"
RPCPASS="iv5spendpass"
WALLETPASS="iv5spendwallet"

BOUNDARY_B=311
FUND_AMOUNT=100
FUND_HEIGHT=20
FUND_CONFIRM_HEIGHT=25
SHIELD_HEIGHT=330
SHIELD_CONFIRM_HEIGHT=345
# Epochs 2, 3 and 4 are the HARD run; epoch 4 ends at 1210, and a spend must sit
# in the epoch after the one that finalized.
FINALIZED_HEIGHT=1210
SPEND_HEIGHT=1245
TRANSFER_AMOUNT=100
UNSHIELD_AMOUNT=50
SHIELD_FEE="0.00100000"

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

jlen() {
    FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"], [])
    print(len(v) if isinstance(v, (list, dict)) else 0)
except Exception:
    print(-1)
' <<< "$1" 2>/dev/null
}

height()     { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
block_hash() { rpc "$1" getblockhash "$2" 2>/dev/null | tr -d '"[:space:]'; }

block_json() {
    local h; h="$(block_hash "$1" "$2")"
    [ ${#h} -eq 64 ] || return 1
    rpc "$1" getblock "$h" 2>/dev/null
}

# Total value paid by a block's coinbase.
coinbase_value() {
    local bh cb
    bh="$(block_hash "$1" "$2")"
    [ ${#bh} -eq 64 ] || return 1
    cb="$(rpc "$1" getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["tx"][0])
except Exception: pass
')"
    [ ${#cb} -eq 64 ] || return 1
    rpc "$1" getrawtransaction "$cb" 1 2>/dev/null | python3 -c '
import json, sys
try: print("%.8f" % sum(float(o["value"]) for o in json.load(sys.stdin)["vout"]))
except Exception: pass
'
}

feq() { [ "$(python3 -c "print(1 if abs($1 - $2) < 1e-8 else 0)" 2>/dev/null)" = "1" ]; }

# A spend block's coinbase may exceed a plain one by the spend's fee and by
# nothing else: the released pool value is the transaction's own input, not a
# surplus the miner may claim.
assert_coinbase_conserved() {
    local label="$1" spend_height="$2" cb_spend cb_plain excess txs
    cb_spend="$(coinbase_value 0 "$spend_height")"
    cb_plain="$(coinbase_value 0 $((spend_height - 1)))"
    txs="$(jlen "$(block_json 0 "$spend_height")" tx)"
    if [ -z "$cb_spend" ] || [ -z "$cb_plain" ]; then
        fail "$label block coinbase could not be read"
        return
    fi
    excess="$(python3 -c "print('%.8f' % ($cb_spend - $cb_plain))")"
    if [ "$txs" != "2" ]; then
        fail "$label block carries $txs transactions; the coinbase comparison would not be exact"
        return
    fi
    if feq "$excess" "$SHIELD_FEE"; then
        success "$label block coinbase is $cb_spend against $cb_plain for a plain block: exactly the $SHIELD_FEE fee"
    else
        fail "$label inflated its block's coinbase by $excess, expected $SHIELD_FEE ($cb_spend against $cb_plain)"
    fi
}

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
    for _ in $(seq 1 90); do
        rpc "$1" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

# The daemon's exact argv: a bare datadir match also catches this harness's own
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

connect_mesh() {
    local n p
    for ((n=0; n<NUM_NODES; n++)); do
        for ((p=0; p<NUM_NODES; p++)); do
            [ "$n" -eq "$p" ] && continue
            rpc "$n" addnode "127.0.0.1:$(node_port "$p")" onetry >/dev/null 2>&1 || true
        done
    done
}

wait_peers() {
    for _ in $(seq 1 60); do
        local ok=1 n c
        for ((n=0; n<NUM_NODES; n++)); do
            c="$(peer_count "$n")"
            if ! is_int "$c" || [ "$c" -lt 2 ]; then ok=0; break; fi
        done
        [ "$ok" -eq 1 ] && return 0
        connect_mesh
        sleep 2
    done
    return 1
}

wait_sync() {
    local target="$1" max="${2:-900}" n h
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

# Mine on NODE until TARGET. Re-arms the miner if height stalls: setgenerate
# takes a block count, and a template that loses a race consumes one.
mine_to() {
    local node="$1" target="$2" h last stall=0
    h="$(height "$node")"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$node" setgenerate true $((target - h)) >/dev/null 2>&1
    for ((i=0; i<2400; i++)); do
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
            [ $((h % 100)) -eq 0 ] && log "  ...height $h/$target"
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

# Transparent finality votes for the epoch starting at BOUNDARY. Each node casts
# on its own 5s cycle and relays; mining is paused at the boundary so every vote
# lands inside the [H_E, H_E+24) inclusion window.
vote_round() {
    local boundary="$1"
    mine_to 0 "$boundary" || return 1
    wait_sync "$boundary" || return 1
    sleep 18
    mine_to 0 $((boundary + 3)) || return 1
    wait_sync $((boundary + 3)) || return 1
}

# Coin selection can pick the coinbase of the current tip, which the wallet calls
# mature at regtest depth 1 but ConnectInputs still refuses. Mining one more
# block and retrying moves it out of reach.
fund_peer() {
    local addr="$1" amount="$2" sent
    for _ in 1 2 3 4; do
        sent="$(rpc 0 sendtoaddress "$addr" "$amount" 2>&1 | tr -d '"[:space:]')"
        if [ ${#sent} -eq 64 ]; then
            echo "$sent"
            return 0
        fi
        mine_to 0 $(( $(height 0) + 1 )) || return 1
    done
    return 1
}

votes_in_range() {
    local node="$1" from="$2" to="$3" total=0 h c
    for ((h=from; h<=to; h++)); do
        c="$(jlen "$(block_json "$node" "$h")" finality_votes)"
        is_int "$c" && [ "$c" -gt 0 ] && total=$((total + c))
    done
    echo "$total"
}

write_config() {
    local node="$1" dir peer
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
        # Only node0 produces blocks; PoS would fork the pre-DAG stretch where
        # every wallet is being funded.
        echo "staking=0"
        echo "nofinalityvoting=0"
        echo "finalityvotemode=transparent"
        echo "regtestboundaryb=$BOUNDARY_B"
        echo "regtestiv5rehearsal=1"
        for ((peer=0; peer<NUM_NODES; peer++)); do
            [ "$peer" -eq "$node" ] && continue
            echo "addnode=127.0.0.1:$(node_port "$peer")"
        done
    } > "$dir/innova.conf"
}

cleanup() {
    local n
    for ((n=0; n<NUM_NODES; n++)); do rpc "$n" setgenerate false 0 >/dev/null 2>&1 || true; done
    for ((n=0; n<NUM_NODES; n++)); do rpc "$n" stop >/dev/null 2>&1 || true; done
    for ((n=0; n<NUM_NODES; n++)); do wait_rpc_down "$n" >/dev/null 2>&1 || true; done
    pkill -f "datadir=$TEST_DIR" 2>/dev/null || true
    if [ "${IV5_SPEND_KEEP_DIR:-0}" = "1" ] || [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}
trap cleanup EXIT

header "IV5 shielded spend regtest"

[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done

for ((n=0; n<NUM_NODES; n++)); do
    start_node "$n" || { fail "node$n did not start"; exit 1; }
done
wait_peers || { fail "fleet did not mesh"; exit 1; }
success "$NUM_NODES-node fleet up and meshed (Boundary B at $BOUNDARY_B, IV5 rehearsal on)"

# ============================================================
header "1. node0 holds an IV5 seed in an encrypted wallet"
# ============================================================

rpc 0 encryptwallet "$WALLETPASS" >/dev/null 2>&1
wait_rpc_down 0 || { fail "node0 did not stop after encrypting the wallet"; exit 1; }
start_node 0 || { fail "node0 did not restart after encrypting the wallet"; exit 1; }
connect_mesh
wait_peers || { fail "node0 did not rejoin the mesh"; exit 1; }

UNLOCK="$(rpc 0 walletpassphrase "$WALLETPASS" 100000 2>&1)"
if echo "$UNLOCK" | grep -qiE "error"; then
    fail "could not unlock node0: $(echo "$UNLOCK" | head -2)"
    exit 1
fi
SEED="$(rpc 0 z_createiv5seed 2>&1)"
if echo "$SEED" | grep -q '"created"'; then
    success "IV5 seed created into node0's encrypted wallet"
else
    fail "z_createiv5seed failed: $(echo "$SEED" | head -3)"
    exit 1
fi

# ============================================================
header "2. One voter is not enough to make an epoch HARD"
# ============================================================

# Negative control. Only node0 holds stake at the epoch-1 boundary, so its vote
# connects but the epoch stays below FINALITY_MIN_VOTERS.
vote_round 11 || { fail "epoch 1 vote round failed"; exit 1; }
E1_VOTES="$(votes_in_range 0 11 14)"
if [ "$E1_VOTES" = "1" ]; then
    success "epoch 1 carried exactly one connected finality vote"
else
    fail "epoch 1 carried $E1_VOTES finality votes, expected 1"
fi

# ============================================================
header "3. Three distinct wallets hold votable stake"
# ============================================================

# FINALITY_MIN_VOTERS is 2 and one wallet casts exactly one vote, so the peers
# must own coins under their own keys before the next epoch boundary.
mine_to 0 "$FUND_HEIGHT" || { fail "mining to the funding height failed"; exit 1; }
wait_sync "$FUND_HEIGHT" || { fail "peers did not sync the funding chain"; exit 1; }

FUND_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    ADDR="$(rpc "$n" getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    if [ ${#ADDR} -lt 20 ]; then FUND_OK=0; break; fi
    SENT="$(fund_peer "$ADDR" "$FUND_AMOUNT")"
    if [ ${#SENT} -ne 64 ]; then
        fail "funding node$n failed"
        FUND_OK=0
        break
    fi
    log "  node$n funded with $FUND_AMOUNT INN (txid ${SENT:0:16})"
done
[ "$FUND_OK" -eq 1 ] || { fail "could not fund the peer wallets"; exit 1; }

mine_to 0 "$FUND_CONFIRM_HEIGHT" || { fail "could not confirm the funding transactions"; exit 1; }
wait_sync "$FUND_CONFIRM_HEIGHT" || { fail "peers did not sync the funding blocks"; exit 1; }

STAKE_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    BAL="$(rpc "$n" getbalance 2>/dev/null | tr -d '"[:space:]')"
    feq "${BAL:-0}" "$FUND_AMOUNT" || STAKE_OK=0
done
if [ "$STAKE_OK" -eq 1 ]; then
    success "each peer wallet holds $FUND_AMOUNT INN under its own key"
else
    fail "peer wallets are not funded"
    exit 1
fi

# ============================================================
header "4. Value enters the pool inside epoch 2"
# ============================================================

vote_round "$BOUNDARY_B" || { fail "epoch 2 vote round failed"; exit 1; }
E2_VOTES="$(votes_in_range 2 "$BOUNDARY_B" $((BOUNDARY_B + 4)))"
if is_int "$E2_VOTES" && [ "$E2_VOTES" -ge 2 ]; then
    success "epoch 2 carried $E2_VOTES relayed finality votes"
else
    fail "epoch 2 carried $E2_VOTES finality votes, need >= 2"
fi

E1="$(rpc 0 getepochinfo 1 2>/dev/null)"
E1_TIER="$(jget "$E1" finality_tier)"
E1_HARD="$(jget "$E1" consecutive_hard_epochs)"
E1_FIN="$(jget "$E1" finalized_height_as_of)"
if [ "$E1_TIER" = "none" ] && [ "$E1_HARD" = "0" ] && [ "$E1_FIN" = "0" ]; then
    success "the single-voter epoch stayed tier=$E1_TIER with nothing finalized"
else
    fail "a single voter changed epoch 1 (tier=$E1_TIER consecutive_hard=$E1_HARD finalized=$E1_FIN)"
fi

INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
B_ACTIVE="$(jget "$INFO" boundary_b_active)"
B_ACCEPT="$(jget "$INFO" privacy_vnext_transactions_accepted)"
if [ "$B_ACTIVE" = "true" ] && [ "$B_ACCEPT" = "true" ]; then
    success "Boundary B active and consensus accepts IV5 transactions"
else
    fail "IV5 inactive (boundary_b_active=$B_ACTIVE accepted=$B_ACCEPT)"
    exit 1
fi

mine_to 0 "$SHIELD_HEIGHT" || { fail "could not mine to the shield height"; exit 1; }
wait_sync "$SHIELD_HEIGHT" || { fail "peers did not sync to the shield height"; exit 1; }

SHIELD="$(rpc 0 z_shieldall 2>&1)"
SHIELD_TXID="$(jget "$SHIELD" txid)"
SHIELDED="$(jget "$SHIELD" shielded)"
SHIELD_INPUTS="$(jget "$SHIELD" inputs)"
if [ ${#SHIELD_TXID} -eq 64 ]; then
    success "shield accepted: $SHIELD_INPUTS input(s), $SHIELDED INN, txid ${SHIELD_TXID:0:16}"
else
    fail "z_shieldall failed: $(echo "$SHIELD" | head -3)"
    exit 1
fi

mine_to 0 "$SHIELD_CONFIRM_HEIGHT" || { fail "could not confirm the shield"; exit 1; }
wait_sync "$SHIELD_CONFIRM_HEIGHT" || { fail "peers did not accept the shield block"; exit 1; }
SHIELD_CONF="$(rpc 0 gettransaction "$SHIELD_TXID" 2>&1)"
SHIELD_BLOCK="$(jget "$SHIELD_CONF" blockhash)"
if [ ${#SHIELD_BLOCK} -eq 64 ]; then
    success "shield confirmed and relayed to the whole fleet"
else
    fail "shield did not confirm: $(echo "$SHIELD_CONF" | head -3)"
    exit 1
fi

# ============================================================
header "5. Three consecutive HARD epochs produce a finalized height"
# ============================================================

vote_round 611 || { fail "epoch 3 vote round failed"; exit 1; }
vote_round 911 || { fail "epoch 4 vote round failed"; exit 1; }
vote_round 1211 || { fail "epoch 5 vote round failed"; exit 1; }

# Epoch E's state is built once the chain crosses into E+1, so the run only
# becomes readable one boundary later.
for e in 2 3; do
    EI="$(rpc 0 getepochinfo "$e" 2>/dev/null)"
    T="$(jget "$EI" finality_tier)"
    H="$(jget "$EI" consecutive_hard_epochs)"
    if [ "$T" = "hard" ] && [ "$H" = "$((e - 1))" ]; then
        success "epoch $e is tier=$T consecutive_hard=$H"
    else
        fail "epoch $e did not reach HARD (tier=$T consecutive_hard=$H)"
        exit 1
    fi
done

E4="$(rpc 0 getepochinfo 4 2>/dev/null)"
E4_TIER="$(jget "$E4" finality_tier)"
E4_HARD="$(jget "$E4" consecutive_hard_epochs)"
E4_FIN="$(jget "$E4" finalized_height_as_of)"
E4_FINALIZED="$(jget "$E4" finalized)"
if [ "$E4_TIER" = "hard" ] && [ "$E4_HARD" = "3" ] && \
   [ "$E4_FIN" = "$FINALIZED_HEIGHT" ] && [ "$E4_FINALIZED" = "true" ]; then
    success "epoch 4 finalizes height $E4_FIN after $E4_HARD consecutive HARD epochs"
else
    fail "epoch 4 did not finalize (tier=$E4_TIER consecutive_hard=$E4_HARD finalized_height_as_of=$E4_FIN finalized=$E4_FINALIZED)"
    exit 1
fi

DIFF_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    PEER_FIN="$(jget "$(rpc "$n" getepochinfo 4 2>/dev/null)" finalized_height_as_of)"
    [ "$PEER_FIN" = "$E4_FIN" ] || DIFF_OK=0
done
if [ "$DIFF_OK" -eq 1 ]; then
    success "every node agrees the finalized height is $E4_FIN"
else
    fail "nodes disagree on the finalized height"
    exit 1
fi

mine_to 0 "$SPEND_HEIGHT" || { fail "could not mine to the spend height"; exit 1; }
wait_sync "$SPEND_HEIGHT" || { fail "peers did not sync to the spend height"; exit 1; }

INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
POOL_BAL_0="$(jget "$INFO" privacy_vnext_balance)"
POOL_UNCONF_0="$(jget "$INFO" privacy_vnext_unconfirmed_balance)"
POOL_NOTES_0="$(jget "$INFO" privacy_vnext_note_count)"
TREE_0="$(jget "$INFO" privacy_vnext_tree_size)"
STORE_0="$(jget "$INFO" privacy_vnext_tree_store_size)"
if [ "$(python3 -c "print(1 if float('${POOL_BAL_0:-0}') > 0 else 0)")" = "1" ]; then
    success "wallet holds $POOL_BAL_0 INN spendable in $POOL_NOTES_0 note(s), tree=$TREE_0"
else
    fail "no spendable shielded balance (balance=$POOL_BAL_0 unconfirmed=$POOL_UNCONF_0 notes=$POOL_NOTES_0)"
    exit 1
fi
[ "$TREE_0" = "$STORE_0" ] || fail "tree ($TREE_0) and store ($STORE_0) disagree before the spends"

# ============================================================
header "6. A transfer spends notes without touching transparent value"
# ============================================================

TO_ADDR="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
if [ ${#TO_ADDR} -lt 20 ]; then
    fail "z_getnewiv5address failed"
    exit 1
fi

XFER="$(rpc 0 z_iv5transfer "$TO_ADDR" "$TRANSFER_AMOUNT" 2>&1)"
XFER_TXID="$(jget "$XFER" txid)"
XFER_NOTES="$(jget "$XFER" notes)"
if [ ${#XFER_TXID} -eq 64 ]; then
    success "transfer built and accepted: $TRANSFER_AMOUNT INN from $XFER_NOTES note(s), txid ${XFER_TXID:0:16}"
else
    fail "z_iv5transfer failed: $(echo "$XFER" | head -3)"
    exit 1
fi

# nTime is outside the IV5 binding hash: re-stamping gives a new txid over the same
# payload and key image, so the key-image check is reached past txid dedup.
restamp_raw() {
    local raw="$1"
    local le="${raw:8:8}"
    local n=$(( 16#${le:6:2}${le:4:2}${le:2:2}${le:0:2} ))
    n=$(( n - 1 ))
    local h
    h="$(printf '%08x' "$n")"
    echo "${raw:0:8}${h:6:2}${h:4:2}${h:2:2}${h:0:2}${raw:16}"
}

# While the transfer is still unconfirmed its key image is only reserved in the
# mempool, which is a different refusal path from the on-disk spent-key set.
XFER_RAW="$(rpc 0 getrawtransaction "$XFER_TXID" 2>/dev/null | tr -d '"[:space:]')"
XFER_TWIN="$(restamp_raw "$XFER_RAW")"
if [ ${#XFER_RAW} -gt 100 ] && [ "$XFER_TWIN" != "$XFER_RAW" ] && \
   [ ${#XFER_TWIN} -eq ${#XFER_RAW} ]; then
    success "built a distinct transaction carrying the same IV5 payload"
else
    fail "could not re-stamp the transfer into a distinct transaction"
fi

RESERVED="$(rpc 0 sendrawtransaction "$XFER_TWIN" 2>&1)"
RESERVED_TXID="$(echo "$RESERVED" | tr -d '"[:space:]')"
if [ ${#RESERVED_TXID} -eq 64 ]; then
    fail "the mempool accepted a second spend of a reserved note: ${RESERVED_TXID:0:16}"
elif echo "$RESERVED" | grep -qiE "reserved|already|consumed|spent|denied|error"; then
    success "the mempool refuses a distinct transaction reusing a reserved key image"
else
    fail "the reserved-key-image double spend was refused for the wrong reason: $(echo "$RESERVED" | head -2)"
fi

XFER_TARGET=$(( $(height 0) + 3 ))
mine_to 0 "$XFER_TARGET" || { fail "could not mine the transfer"; exit 1; }
wait_sync "$XFER_TARGET" || { fail "peers did not accept the transfer block"; exit 1; }

XC="$(rpc 0 gettransaction "$XFER_TXID" 2>&1)"
XFER_BLOCK="$(jget "$XC" blockhash)"
XFER_CONF="$(jget "$XC" confirmations)"
if [ ${#XFER_BLOCK} -eq 64 ] && is_int "$XFER_CONF" && [ "$XFER_CONF" -ge 1 ]; then
    success "transfer confirmed in a block ($XFER_CONF confirmation(s))"
else
    fail "transfer did not confirm: confirmations='$XFER_CONF' blockhash='$XFER_BLOCK'"
    exit 1
fi

XFER_HEIGHT="$(jget "$(rpc 0 getblock "$XFER_BLOCK" 2>/dev/null)" height)"
if [ "$(block_hash 1 "$XFER_HEIGHT")" = "$XFER_BLOCK" ] && \
   [ "$(block_hash 2 "$XFER_HEIGHT")" = "$XFER_BLOCK" ]; then
    success "peers that did not build the spend accepted its block at height $XFER_HEIGHT"
else
    fail "the transfer block did not converge across the fleet"
fi

XRAW="$(rpc 0 getrawtransaction "$XFER_TXID" 1 2>&1)"
XVOUT="$(jlen "$XRAW" vout)"
XVIN="$(jlen "$XRAW" vin)"
if [ "$XVOUT" = "0" ] && [ "$XVIN" = "0" ]; then
    success "transfer carries no transparent input or output"
else
    fail "transfer leaked transparent value (vin=$XVIN vout=$XVOUT)"
fi

assert_coinbase_conserved "transfer" "$XFER_HEIGHT"

# ============================================================
header "7. An unshield releases pool value to the output it named"
# ============================================================

# An unshield's transparent output is covered by the vout/nLockTime digest in the
# payload prefix, which consensus recomputes from the carrying transaction.
T_ADDR="$(rpc 0 getnewaddress 2>&1 | tr -d '"[:space:]')"
[ ${#T_ADDR} -ge 20 ] || { fail "getnewaddress failed"; exit 1; }

UNSH="$(rpc 0 z_iv5unshield "$T_ADDR" "$UNSHIELD_AMOUNT" 2>&1)"
UNSH_TXID="$(jget "$UNSH" txid)"
UNSH_NOTES="$(jget "$UNSH" notes)"
if [ ${#UNSH_TXID} -eq 64 ]; then
    success "unshield built and accepted: $UNSHIELD_AMOUNT INN from $UNSH_NOTES note(s), txid ${UNSH_TXID:0:16}"
else
    fail "z_iv5unshield failed: $(echo "$UNSH" | head -3)"
    exit 1
fi

# Captured before it confirms; the tamper cases below rewrite exactly these bytes.
UNSH_RAW="$(rpc 0 getrawtransaction "$UNSH_TXID" 2>/dev/null | tr -d '"[:space:]')"
[ ${#UNSH_RAW} -gt 100 ] || { fail "could not fetch the raw unshield"; exit 1; }

UNSH_TARGET=$(( $(height 0) + 3 ))
mine_to 0 "$UNSH_TARGET" || { fail "could not mine the unshield"; exit 1; }
wait_sync "$UNSH_TARGET" || { fail "peers did not accept the unshield block"; exit 1; }

UC="$(rpc 0 gettransaction "$UNSH_TXID" 2>&1)"
UNSH_BLOCK="$(jget "$UC" blockhash)"
UNSH_CONF="$(jget "$UC" confirmations)"
if [ ${#UNSH_BLOCK} -eq 64 ] && is_int "$UNSH_CONF" && [ "$UNSH_CONF" -ge 1 ]; then
    success "unshield confirmed in a block ($UNSH_CONF confirmation(s))"
else
    fail "unshield did not confirm: confirmations='$UNSH_CONF' blockhash='$UNSH_BLOCK'"
    exit 1
fi

UNSH_HEIGHT="$(jget "$(rpc 0 getblock "$UNSH_BLOCK" 2>/dev/null)" height)"
if [ "$(block_hash 1 "$UNSH_HEIGHT")" = "$UNSH_BLOCK" ] && \
   [ "$(block_hash 2 "$UNSH_HEIGHT")" = "$UNSH_BLOCK" ]; then
    success "peers that did not build the unshield accepted its block at height $UNSH_HEIGHT"
else
    fail "the unshield block did not converge across the fleet"
fi

# Exactly one transparent output, for exactly the requested amount, to exactly
# the requested address.
URAW="$(rpc 0 getrawtransaction "$UNSH_TXID" 1 2>&1)"
UVOUT="$(jlen "$URAW" vout)"
UVIN="$(jlen "$URAW" vin)"
UOUT_VALUE="$(echo "$URAW" | python3 -c '
import json, sys
try: print("%.8f" % float(json.load(sys.stdin)["vout"][0]["value"]))
except Exception: pass
')"
UOUT_ADDR="$(echo "$URAW" | python3 -c '
import json, sys
try:
    a = json.load(sys.stdin)["vout"][0]["scriptPubKey"].get("addresses") or []
    print(a[0] if a else "")
except Exception: pass
')"
if [ "$UVOUT" = "1" ] && [ "$UVIN" = "0" ]; then
    success "unshield carries exactly one transparent output and no transparent input"
else
    fail "unshield has the wrong transparent shape (vin=$UVIN vout=$UVOUT)"
fi
if feq "${UOUT_VALUE:-0}" "$UNSHIELD_AMOUNT"; then
    success "the transparent output pays exactly $UOUT_VALUE INN"
else
    fail "the transparent output pays $UOUT_VALUE INN, expected $UNSHIELD_AMOUNT"
fi
if [ "$UOUT_ADDR" = "$T_ADDR" ]; then
    success "the transparent output pays the address that was asked for"
else
    fail "the transparent output pays $UOUT_ADDR, expected $T_ADDR"
fi

TBAL="$(rpc 0 getreceivedbyaddress "$T_ADDR" 0 2>/dev/null | tr -d '"[:space:]')"
if feq "${TBAL:-0}" "$UNSHIELD_AMOUNT"; then
    success "the recipient address received $TBAL INN"
else
    fail "the recipient address received $TBAL INN, expected $UNSHIELD_AMOUNT"
fi

# The released value is the transaction's own input, not a surplus: the miner may
# take the fee and nothing more.
assert_coinbase_conserved "unshield" "$UNSH_HEIGHT"

# ============================================================
header "7b. A rewritten transparent side is refused"
# ============================================================

# Both rewrites keep the payload intact and change only the transparent side: retarget
# the output, or delete it (released value would fall to the fee).
tamper_vout() {
    RAWHEX="$1" MODE="$2" python3 - <<'PY'
import os, sys

raw = bytes.fromhex(os.environ["RAWHEX"])
mode = os.environ["MODE"]
pos = 0

def take(n):
    global pos
    chunk = raw[pos:pos + n]
    if len(chunk) != n:
        raise SystemExit("truncated transaction")
    pos += n
    return chunk

def compact():
    first = take(1)[0]
    if first < 253:
        return first
    if first == 253:
        return int.from_bytes(take(2), "little")
    if first == 254:
        return int.from_bytes(take(4), "little")
    return int.from_bytes(take(8), "little")

def put_compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")

start = pos
take(4)                      # nVersion
take(4)                      # nTime
for _ in range(compact()):   # vin
    take(36)
    take(compact())
    take(4)
head = raw[start:pos]

vout = []
for _ in range(compact()):
    value = int.from_bytes(take(8), "little", signed=True)
    vout.append((value, take(compact())))
tail = raw[pos:]             # nLockTime and the payload envelope, untouched

if mode == "retarget":
    value, script = vout[0]
    script = bytearray(script)
    # A P2PKH script is OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG, so
    # this repoints the payment at a different key hash and changes nothing else.
    script[-3] ^= 0xff
    vout[0] = (value, bytes(script))
elif mode == "delete":
    vout = []
else:
    raise SystemExit("unknown tamper mode")

body = put_compact(len(vout))
for value, script in vout:
    body += value.to_bytes(8, "little", signed=True) + put_compact(len(script)) + script
sys.stdout.write((head + body + tail).hex())
PY
}

for mode in retarget delete; do
    TAMPERED="$(tamper_vout "$UNSH_RAW" "$mode")"
    if [ ${#TAMPERED} -lt 100 ] || [ "$TAMPERED" = "$UNSH_RAW" ]; then
        fail "could not build the $mode tamper case"
        continue
    fi
    for n in 0 1; do
        REJECT="$(rpc "$n" sendrawtransaction "$TAMPERED" 2>&1)"
        if echo "$REJECT" | grep -qi "bind"; then
            success "node$n refuses the $mode tamper because the payload does not bind it"
        elif echo "$REJECT" | grep -qiE "error|denied|rejected|invalid"; then
            fail "node$n refused the $mode tamper, but not on the binding: $(echo "$REJECT" | head -2)"
        else
            fail "node$n ACCEPTED a $mode-tampered unshield: $REJECT"
        fi
    done
done

# Tampering must not have moved any value: the honest output stands, and nothing
# else was paid.
TBAL_AFTER="$(rpc 0 getreceivedbyaddress "$T_ADDR" 0 2>/dev/null | tr -d '"[:space:]')"
if feq "${TBAL_AFTER:-0}" "$UNSHIELD_AMOUNT"; then
    success "the recipient still holds exactly $TBAL_AFTER INN after both tamper attempts"
else
    fail "a tamper attempt changed the recipient balance to $TBAL_AFTER INN"
fi

# ============================================================
header "8. A confirmed spend cannot be replayed or respent"
# ============================================================

for pair in "transfer:$XFER_TXID" "unshield:$UNSH_TXID"; do
    NAME="${pair%%:*}"
    TXID="${pair#*:}"
    RAW="$(rpc 0 getrawtransaction "$TXID" 2>/dev/null | tr -d '"[:space:]')"
    if [ ${#RAW} -lt 100 ]; then
        fail "could not fetch the raw $NAME for the replay case"
        continue
    fi
    REPLAY="$(rpc 0 sendrawtransaction "$RAW" 2>&1)"
    if echo "$REPLAY" | grep -qiE "already|error|denied|exists|consumed|spent"; then
        success "replaying the confirmed $NAME is refused"
    else
        fail "the chain accepted a replay of the confirmed $NAME: $REPLAY"
    fi
    # The peers hold the same nullifier set and must refuse it too.
    REPLAY1="$(rpc 1 sendrawtransaction "$RAW" 2>&1)"
    if echo "$REPLAY1" | grep -qiE "already|error|denied|exists|consumed|spent"; then
        success "a peer also refuses the replayed $NAME"
    else
        fail "a peer accepted a replay of the confirmed $NAME: $REPLAY1"
    fi

    # Resubmitting the same bytes never reaches the key-image logic: txid dedup
    # answers first. A re-stamped twin has a different txid and the same key
    # image, which is the case an attacker actually has.
    TWIN="$(restamp_raw "$RAW")"
    if [ "$TWIN" = "$RAW" ]; then
        fail "could not re-stamp the confirmed $NAME"
        continue
    fi
    DS="$(rpc 0 sendrawtransaction "$TWIN" 2>&1)"
    DS_TXID="$(echo "$DS" | tr -d '"[:space:]')"
    if [ ${#DS_TXID} -eq 64 ]; then
        fail "a distinct transaction respent the confirmed $NAME note: ${DS_TXID:0:16}"
    elif echo "$DS" | grep -qiE "consumed|spent|already|denied|error"; then
        success "a distinct transaction reusing the confirmed $NAME key image is refused"
    else
        fail "the $NAME key-image double spend was refused for the wrong reason: $(echo "$DS" | head -2)"
    fi

    DS1="$(rpc 1 sendrawtransaction "$TWIN" 2>&1)"
    DS1_TXID="$(echo "$DS1" | tr -d '"[:space:]')"
    if [ ${#DS1_TXID} -eq 64 ]; then
        fail "a peer accepted a distinct respend of the confirmed $NAME: ${DS1_TXID:0:16}"
    elif echo "$DS1" | grep -qiE "consumed|spent|already|denied|error"; then
        success "a peer also refuses the distinct $NAME key-image double spend"
    else
        fail "a peer refused the $NAME double spend for the wrong reason: $(echo "$DS1" | head -2)"
    fi

    # Neither refusal may disturb the pool: the note stays spent exactly once.
    if [ "$(rpc 0 getrawmempool 2>/dev/null | tr -d '"[:space:], ' | wc -c)" -le 4 ]; then
        success "no double-spend attempt was left sitting in the mempool"
    else
        fail "a refused double spend is still in the mempool"
    fi
done

# ============================================================
header "9. Pool accounting moved by exactly the spent value"
# ============================================================

INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
POOL_BAL_1="$(jget "$INFO" privacy_vnext_balance)"
POOL_UNCONF_1="$(jget "$INFO" privacy_vnext_unconfirmed_balance)"
TREE_1="$(jget "$INFO" privacy_vnext_tree_size)"
STORE_1="$(jget "$INFO" privacy_vnext_tree_store_size)"

# A transfer moves value inside the pool, so it costs the pool only its fee. An
# unshield additionally takes the released amount out of the pool entirely.
EXPECTED_DROP="$(python3 -c "print('%.8f' % ($SHIELD_FEE + $UNSHIELD_AMOUNT + $SHIELD_FEE))")"
ACTUAL_DROP="$(python3 -c "print('%.8f' % ((float('${POOL_BAL_0:-0}') + float('${POOL_UNCONF_0:-0}')) - (float('${POOL_BAL_1:-0}') + float('${POOL_UNCONF_1:-0}'))))")"
if feq "$ACTUAL_DROP" "$EXPECTED_DROP"; then
    success "pool value fell by exactly $ACTUAL_DROP INN (both fees and the unshielded amount)"
else
    fail "pool value fell by $ACTUAL_DROP INN, expected $EXPECTED_DROP (before ${POOL_BAL_0}/${POOL_UNCONF_0}, after ${POOL_BAL_1}/${POOL_UNCONF_1})"
fi

if [ "$TREE_1" = "$STORE_1" ]; then
    success "tree and node-local store stay level at $TREE_1 leaves"
else
    fail "tree ($TREE_1) and store ($STORE_1) diverged across the spends"
fi

STORE_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    PI="$(rpc "$n" z_getshieldedinfo 2>/dev/null)"
    [ "$(jget "$PI" privacy_vnext_tree_size)" = "$TREE_1" ] || STORE_OK=0
    [ "$(jget "$PI" privacy_vnext_tree_store_size)" = "$STORE_1" ] || STORE_OK=0
done
if [ "$STORE_OK" -eq 1 ]; then
    success "every node holds the same tree and store size"
else
    fail "peers disagree on the tree or store size"
fi

# ============================================================
header "10. The fleet reports no errors"
# ============================================================

ERR_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    E="$(jget "$(rpc "$n" getinfo 2>/dev/null)" errors)"
    [ -z "$E" ] || { fail "node$n reports errors: $E"; ERR_OK=0; }
    if grep -qiE "IV5 pool balance|takes more from the pool|does not validate|IV5 finalized context rejected" \
            "$(node_dir "$n")/regtest/debug.log" 2>/dev/null; then
        fail "node$n log carries an IV5 pool or validation complaint"
        grep -iE "IV5 pool balance|takes more from the pool|does not validate|IV5 finalized context rejected" \
            "$(node_dir "$n")/regtest/debug.log" | tail -3
        ERR_OK=0
    fi
done
[ "$ERR_OK" -eq 1 ] && success "no node reports errors or IV5 validation complaints"

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
