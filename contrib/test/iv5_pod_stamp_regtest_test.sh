#!/bin/bash
# Copyright (c) 2026 The Innova developers
# POD stamp carried by a v2008 NOTE_TRANSFER: balance 0, a fee, no transparent input and one
# zero-value OP_RETURN covered by the transparent binding.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_POD_TEST_DIR:-/tmp/innova_iv5_pod_$$}"
NUM_NODES=3
BASE_PORT="${IV5_POD_BASE_PORT:-28650}"
BASE_RPC="${IV5_POD_BASE_RPC:-28700}"
BASE_IDNS="${IV5_POD_BASE_IDNS:-8760}"
RPCUSER="iv5pod"
RPCPASS="iv5podpass"
WALLETPASS="iv5podwallet"

BOUNDARY_B=311
FUND_AMOUNT=100
FUND_HEIGHT=20
FUND_CONFIRM_HEIGHT=25
SHIELD_HEIGHT=330
SHIELD_CONFIRM_HEIGHT=345
# Epochs 2, 3 and 4 are the HARD run; epoch 4 ends at 1210, and a spend must sit
# in the epoch after the one that finalized.
STAMP_HEIGHT=1245
# Above everything here, so the sections keep the pre-retirement behaviour and a
# transparent stamp stays buildable for the disclosure comparison.
FEE_NOTE_HEIGHT=2000
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

# A stamp block's coinbase may exceed a plain one by the stamp's fee and nothing
# more: the pool releases the fee, never a surplus the miner may claim.
assert_coinbase_conserved() {
    local label="$1" h="$2" cb_stamp cb_plain excess txs
    cb_stamp="$(coinbase_value 0 "$h")"
    cb_plain="$(coinbase_value 0 $((h - 1)))"
    txs="$(jlen "$(block_json 0 "$h")" tx)"
    if [ -z "$cb_stamp" ] || [ -z "$cb_plain" ]; then
        fail "$label block coinbase could not be read"
        return
    fi
    if [ "$txs" != "2" ]; then
        fail "$label block carries $txs transactions; the coinbase comparison would not be exact"
        return
    fi
    excess="$(python3 -c "print('%.8f' % ($cb_stamp - $cb_plain))")"
    if feq "$excess" "$SHIELD_FEE"; then
        success "$label block coinbase is $cb_stamp against $cb_plain: exactly the $SHIELD_FEE fee"
    else
        fail "$label inflated its block's coinbase by $excess, expected $SHIELD_FEE"
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

vote_round() {
    local boundary="$1"
    mine_to 0 "$boundary" || return 1
    wait_sync "$boundary" || return 1
    sleep 18
    mine_to 0 $((boundary + 3)) || return 1
    wait_sync $((boundary + 3)) || return 1
}

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
        echo "staking=0"
        echo "nofinalityvoting=0"
        echo "finalityvotemode=transparent"
        echo "regtestboundaryb=$BOUNDARY_B"
        echo "regtestiv5rehearsal=1"
        echo "regtestiv5feenote=$FEE_NOTE_HEIGHT"
        echo "enablefilerpc=1"
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
    if [ "${IV5_POD_KEEP_DIR:-0}" = "1" ] || [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}
trap cleanup EXIT

header "IV5 POD shielded-funded stamp regtest"

[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done

STAMP_FILE="$TEST_DIR/stamped.txt"
printf 'innova pod shielded funding rehearsal\n' > "$STAMP_FILE"
FILE_SHA="$(python3 -c "
import hashlib,sys
print(hashlib.sha256(open('$STAMP_FILE','rb').read()).hexdigest())")"

for ((n=0; n<NUM_NODES; n++)); do
    start_node "$n" || { fail "node$n did not start"; exit 1; }
done
wait_peers || { fail "fleet did not mesh"; exit 1; }
success "$NUM_NODES-node fleet up and meshed (DAG at 11, Boundary B at $BOUNDARY_B)"

# ============================================================
header "1. node0 holds an IV5 seed"
# ============================================================

rpc 0 encryptwallet "$WALLETPASS" >/dev/null 2>&1
wait_rpc_down 0 || { fail "node0 did not stop after encrypting the wallet"; exit 1; }
start_node 0 || { fail "node0 did not restart"; exit 1; }
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
header "2. Three wallets hold votable stake"
# ============================================================

vote_round 11 || { fail "epoch 1 vote round failed"; exit 1; }

mine_to 0 "$FUND_HEIGHT" || { fail "mining to the funding height failed"; exit 1; }
wait_sync "$FUND_HEIGHT" || { fail "peers did not sync"; exit 1; }

FUND_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    ADDR="$(rpc "$n" getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    if [ ${#ADDR} -lt 20 ]; then FUND_OK=0; break; fi
    SENT="$(fund_peer "$ADDR" "$FUND_AMOUNT")"
    if [ ${#SENT} -ne 64 ]; then fail "funding node$n failed"; FUND_OK=0; break; fi
done
[ "$FUND_OK" -eq 1 ] || { fail "could not fund the peer wallets"; exit 1; }

mine_to 0 "$FUND_CONFIRM_HEIGHT" || { fail "could not confirm funding"; exit 1; }
wait_sync "$FUND_CONFIRM_HEIGHT" || { fail "peers did not sync funding blocks"; exit 1; }
success "peer wallets funded so the epochs can go HARD"

# ============================================================
header "3. A transparent stamp names the address that paid it"
# ============================================================

# Transparent baseline for comparison, with no IV5 involvement.
T_STAMP="$(rpc 0 proofofdata "$STAMP_FILE" false 2>&1)"
T_TXID="$(jget "$T_STAMP" podtxid)"
T_FUND="$(jget "$T_STAMP" funding)"
if [ ${#T_TXID} -eq 64 ] && [ "$T_FUND" = "transparent" ]; then
    success "transparent stamp built: ${T_TXID:0:16} (funding=$T_FUND)"
else
    fail "transparent proofofdata failed: $(echo "$T_STAMP" | head -3)"
    exit 1
fi

T_TARGET=$(( $(height 0) + 3 ))
mine_to 0 "$T_TARGET" || { fail "could not mine the transparent stamp"; exit 1; }
wait_sync "$T_TARGET" || { fail "peers did not accept it"; exit 1; }

T_RAW="$(rpc 0 getrawtransaction "$T_TXID" 1 2>&1)"
T_IN_ADDRS="$(echo "$T_RAW" | python3 -c '
import json, sys
print(len(json.load(sys.stdin).get("vin", [])))')"
T_OUT_ADDRS="$(echo "$T_RAW" | python3 -c '
import json, sys
n = 0
for o in json.load(sys.stdin).get("vout", []):
    n += len(o.get("scriptPubKey", {}).get("addresses") or [])
print(n)')"
if is_int "$T_IN_ADDRS" && [ "$T_IN_ADDRS" -ge 1 ] && [ "$T_OUT_ADDRS" -ge 1 ]; then
    success "the transparent stamp spends $T_IN_ADDRS input(s) and names $T_OUT_ADDRS payout address(es)"
else
    fail "the transparent stamp has no transparent side to compare against"
fi

# ============================================================
header "4. Value enters the pool and the chain finalizes"
# ============================================================

vote_round "$BOUNDARY_B" || { fail "epoch 2 vote round failed"; exit 1; }

INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
if [ "$(jget "$INFO" boundary_b_active)" = "true" ] && \
   [ "$(jget "$INFO" privacy_vnext_transactions_accepted)" = "true" ]; then
    success "Boundary B active and consensus accepts IV5 transactions"
else
    fail "IV5 inactive: $INFO"
    exit 1
fi

mine_to 0 "$SHIELD_HEIGHT" || { fail "could not mine to the shield height"; exit 1; }
wait_sync "$SHIELD_HEIGHT" || { fail "peers did not sync"; exit 1; }

SHIELD_TXID="$(jget "$(rpc 0 z_shieldall 2>&1)" txid)"
if [ ${#SHIELD_TXID} -eq 64 ]; then
    success "shield accepted: ${SHIELD_TXID:0:16}"
else
    fail "z_shieldall failed"
    exit 1
fi

mine_to 0 "$SHIELD_CONFIRM_HEIGHT" || { fail "could not confirm the shield"; exit 1; }
wait_sync "$SHIELD_CONFIRM_HEIGHT" || { fail "peers did not accept the shield block"; exit 1; }

vote_round 611  || { fail "epoch 3 vote round failed"; exit 1; }
vote_round 911  || { fail "epoch 4 vote round failed"; exit 1; }
vote_round 1211 || { fail "epoch 5 vote round failed"; exit 1; }

FIN="$(jget "$(rpc 0 getepochinfo 4 2>/dev/null)" finalized_height_as_of)"
if is_int "$FIN" && [ "$FIN" -gt 0 ]; then
    success "the chain has a finalized height ($FIN) for a spend to anchor to"
else
    fail "nothing finalized (finalized_height_as_of=$FIN); a pool spend cannot anchor"
    exit 1
fi

mine_to 0 "$STAMP_HEIGHT" || { fail "could not mine to the stamp height"; exit 1; }
wait_sync "$STAMP_HEIGHT" || { fail "peers did not sync to the stamp height"; exit 1; }

# ============================================================
header "5. A pool-funded stamp is built, relayed and mined"
# ============================================================

# The only output is the OP_RETURN (nTxnOut 0), so relay relies on the IsStandardTx
# carve-out, consulted from CTxMemPool::accept on the wallet's commit.
P_STAMP="$(rpc 0 proofofdata "$STAMP_FILE" false true 2>&1)"
P_TXID="$(jget "$P_STAMP" podtxid)"
P_FUND="$(jget "$P_STAMP" funding)"
P_DIGEST="$(jget "$P_STAMP" stampdigest)"
if [ ${#P_TXID} -eq 64 ] && [ "$P_FUND" = "shielded" ]; then
    success "pool-funded stamp built and accepted: ${P_TXID:0:16} (funding=$P_FUND)"
else
    fail "pool-funded proofofdata failed: $(echo "$P_STAMP" | head -5)"
    exit 1
fi

if [ "$P_DIGEST" = "$FILE_SHA" ]; then
    success "the stamped digest is the file's plain SHA-256"
else
    fail "stamp digest $P_DIGEST does not match sha256 $FILE_SHA"
fi

# Captured before it confirms; section 7 rewrites exactly these bytes.
P_RAWHEX="$(rpc 0 getrawtransaction "$P_TXID" 2>/dev/null | tr -d '"[:space:]')"
[ ${#P_RAWHEX} -gt 100 ] || { fail "could not fetch the raw stamp"; exit 1; }

P_TARGET=$(( $(height 0) + 3 ))
mine_to 0 "$P_TARGET" || { fail "could not mine the stamp"; exit 1; }
wait_sync "$P_TARGET" || { fail "peers did not accept the stamp block"; exit 1; }

P_CONF="$(rpc 0 gettransaction "$P_TXID" 2>&1)"
P_BLOCK="$(jget "$P_CONF" blockhash)"
if [ ${#P_BLOCK} -eq 64 ]; then
    success "the pool-funded stamp confirmed"
else
    fail "the stamp did not confirm: $(echo "$P_CONF" | head -3)"
    exit 1
fi

P_HEIGHT="$(jget "$(rpc 0 getblock "$P_BLOCK" 2>/dev/null)" height)"
if [ "$(block_hash 1 "$P_HEIGHT")" = "$P_BLOCK" ] && \
   [ "$(block_hash 2 "$P_HEIGHT")" = "$P_BLOCK" ]; then
    success "peers that did not build it accepted its block at height $P_HEIGHT"
else
    fail "the stamp block did not converge across the fleet"
fi

# ============================================================
header "6. The stamp's shape is the one consensus was shown to allow"
# ============================================================

P_RAW="$(rpc 0 getrawtransaction "$P_TXID" 1 2>&1)"
P_VER="$(jget "$P_RAW" version)"
P_VIN="$(jlen "$P_RAW" vin)"
P_VOUT="$(jlen "$P_RAW" vout)"

if [ "$P_VER" = "2008" ]; then
    success "the stamp is a v2008 envelope"
else
    fail "the stamp is version $P_VER, expected 2008"
fi

if [ "$P_VIN" = "0" ] && [ "$P_VOUT" = "1" ]; then
    success "no transparent input, exactly one output"
else
    fail "wrong transparent shape (vin=$P_VIN vout=$P_VOUT)"
fi

P_OUT_VALUE="$(echo "$P_RAW" | python3 -c '
import json, sys
try: print("%.8f" % float(json.load(sys.stdin)["vout"][0]["value"]))
except Exception: pass
')"
P_OUT_TYPE="$(echo "$P_RAW" | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["vout"][0]["scriptPubKey"]["type"])
except Exception: pass
')"
P_OUT_ADDRS="$(echo "$P_RAW" | python3 -c '
import json, sys
n = 0
for o in json.load(sys.stdin).get("vout", []):
    n += len(o.get("scriptPubKey", {}).get("addresses") or [])
print(n)')"

if feq "${P_OUT_VALUE:-1}" "0"; then
    success "the stamp output carries zero value"
else
    fail "the stamp output carries $P_OUT_VALUE, expected 0"
fi
if [ "$P_OUT_TYPE" = "nulldata" ]; then
    success "the stamp output is a standard nulldata script"
else
    fail "the stamp output is type '$P_OUT_TYPE', expected nulldata"
fi

# The transparent baseline names payer and payee; this stamp names neither.
if [ "$P_VIN" = "0" ] && [ "$P_OUT_ADDRS" = "0" ]; then
    success "the pool-funded stamp names no address anywhere (transparent baseline named $T_OUT_ADDRS)"
else
    fail "the pool-funded stamp leaked an address (vin=$P_VIN out_addresses=$P_OUT_ADDRS)"
fi

P_MASK="$(echo "$P_RAW" | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["privacy_vnext"]["disclosure_mask"])
except Exception: pass
')"
if [ "$P_MASK" = "7" ]; then
    success "the payload declares the fully private mask 7"
else
    fail "the payload declares mask '$P_MASK', expected 7"
fi

# The pool released the fee and nothing else.
assert_coinbase_conserved "pool-funded stamp" "$P_HEIGHT"

VERIFY="$(rpc 0 podverify "$STAMP_FILE" "$P_TXID" 2>&1)"
if [ "$(jget "$VERIFY" match)" = "true" ] && [ "$(jget "$VERIFY" legacy)" = "false" ]; then
    success "podverify matches the pool-funded stamp against the original file"
else
    fail "podverify did not match the stamp: $(echo "$VERIFY" | head -5)"
fi

# The same stamp must not verify a file it does not cover.
VERIFY_BAD="$(rpc 0 podverify \
    "0000000000000000000000000000000000000000000000000000000000000001" \
    "$P_TXID" 2>&1)"
if [ "$(jget "$VERIFY_BAD" match)" = "false" ]; then
    success "podverify refuses a digest the stamp does not carry"
else
    fail "podverify matched a digest the stamp does not carry"
fi

# ============================================================
header "7. A rewritten stamp output is refused"
# ============================================================

# The payload prefix commits to vout and nLockTime under the signing hash.
tamper() {
    RAWHEX="$P_RAWHEX" MODE="$1" python3 -c '
import os, sys
raw = bytes.fromhex(os.environ["RAWHEX"])
mode = os.environ["MODE"]
# The stamp payload is the only OP_RETURN push in the transaction; flip a byte of
# the digest it carries. That is the "publish a different file" rewrite.
i = raw.find(bytes([0x6a]))
if i < 0:
    sys.exit(1)
b = bytearray(raw)
if mode == "digest":
    j = i + 8
    if j >= len(b):
        sys.exit(1)
    b[j] ^= 0xff
sys.stdout.write(bytes(b).hex())
' 2>/dev/null
}

TAMPERED="$(tamper digest)"
if [ -n "$TAMPERED" ] && [ "$TAMPERED" != "$P_RAWHEX" ]; then
    REJECT="$(rpc 1 sendrawtransaction "$TAMPERED" 2>&1)"
    if echo "$REJECT" | grep -qiE "bind|reject|error|invalid|denied"; then
        success "a peer refused a stamp whose digest was rewritten"
    else
        fail "a rewritten stamp digest was accepted: $(echo "$REJECT" | head -3)"
    fi
else
    warn "could not construct the rewritten-digest case"
fi

# ============================================================
header "8. Two pool-funded stamps share no visible funding"
# ============================================================

# Repeat transparent stamps link through the paying address; shielded ones share no
# transparent field.
printf 'second innova pod rehearsal file\n' > "$TEST_DIR/stamped2.txt"
P2_STAMP="$(rpc 0 proofofdata "$TEST_DIR/stamped2.txt" false true 2>&1)"
P2_TXID="$(jget "$P2_STAMP" podtxid)"
if [ ${#P2_TXID} -eq 64 ]; then
    P2_TARGET=$(( $(height 0) + 3 ))
    mine_to 0 "$P2_TARGET" >/dev/null || true
    wait_sync "$P2_TARGET" >/dev/null || true
    P2_RAW="$(rpc 0 getrawtransaction "$P2_TXID" 1 2>&1)"
    P2_VIN="$(jlen "$P2_RAW" vin)"
    P2_OUT_ADDRS="$(echo "$P2_RAW" | python3 -c '
import json, sys
n = 0
for o in json.load(sys.stdin).get("vout", []):
    n += len(o.get("scriptPubKey", {}).get("addresses") or [])
print(n)')"
    if [ "$P2_VIN" = "0" ] && [ "$P2_OUT_ADDRS" = "0" ]; then
        success "a second pool-funded stamp also names no address; the two share no transparent field"
    else
        fail "the second stamp exposed a transparent field (vin=$P2_VIN out_addresses=$P2_OUT_ADDRS)"
    fi
else
    fail "the second pool-funded stamp failed: $(echo "$P2_STAMP" | head -3)"
fi

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
