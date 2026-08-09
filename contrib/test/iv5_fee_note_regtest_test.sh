#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 fee note + unshield retirement: post-fork the coinbase allowance excludes IV5
# fees and a coinbase pool note may carry exactly that sum. Single node.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_FN_TEST_DIR:-/tmp/innova_iv5_feenote_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${IV5_FN_PORT:-29400}"
RPC="${IV5_FN_RPC:-29401}"
IDNS="${IV5_FN_IDNS:-29402}"
RPCUSER="iv5fn"
RPCPASS="iv5fnpass"
WALLETPASS="iv5fnwallet"

BOUNDARY_B=311
FEE_NOTE=340
SEED_HEIGHT=250
SHIELD_FEE="0.00100000"

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() { "$INNOVAD" -datadir="$NODE_DIR" -regtest -rpcuser=$RPCUSER \
        -rpcpassword=$RPCPASS -rpcport=$RPC "$@" 2>&1; }

height() { rpc getblockcount 2>/dev/null | tr -d '"[:space:]'; }
is_int() { echo "$1" | grep -qE '^[0-9]+$'; }
jstr()   { echo "$1" | sed -n "s/.*\"$2\" *: *\"\([^\"]*\)\".*/\1/p" | head -1; }

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

feq() { [ "$(python3 -c "print(1 if abs($1 - $2) < 1e-8 else 0)" 2>/dev/null)" = "1" ]; }

block_hash() { rpc getblockhash "$1" 2>/dev/null | tr -d '"[:space:]'; }

coinbase_txid() {
    local bh; bh="$(block_hash "$1")"
    [ ${#bh} -eq 64 ] || return 1
    rpc getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["tx"][0])
except Exception: pass
'
}

# Total transparent value a block's coinbase pays.
coinbase_value() {
    local cb; cb="$(coinbase_txid "$1")"
    [ ${#cb} -eq 64 ] || return 1
    rpc getrawtransaction "$cb" 1 2>/dev/null | python3 -c '
import json, sys
try: print("%.8f" % sum(float(o["value"]) for o in json.load(sys.stdin)["vout"]))
except Exception: pass
'
}

coinbase_version() {
    local cb; cb="$(coinbase_txid "$1")"
    [ ${#cb} -eq 64 ] || return 1
    rpc getrawtransaction "$cb" 1 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["version"])
except Exception: pass
'
}

# The serialized coinbase carries the payload; its size is what tells a note apart
# from an ordinary coinbase without a decoder.
coinbase_raw_len() {
    local cb; cb="$(coinbase_txid "$1")"
    [ ${#cb} -eq 64 ] || return 1
    rpc getrawtransaction "$cb" 2>/dev/null | tr -d '"[:space:]' | wc -c | tr -d ' '
}

pool_value() { jget "$(rpc z_getshieldedinfo 2>/dev/null)" privacy_vnext_pool_value; }

block_tx_count() {
    local bh; bh="$(block_hash "$1")"
    [ ${#bh} -eq 64 ] || return 1
    rpc getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print(len(json.load(sys.stdin)["tx"]))
except Exception: print(-1)
'
}

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    for _ in $(seq 1 180); do
        pgrep -f -- "-datadir=$NODE_DIR -regtest -daemon" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

start_node() {
    "$INNOVAD" -datadir="$NODE_DIR" -regtest -daemon >/dev/null 2>&1
    for _ in $(seq 1 90); do
        rpc getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

unlock() { rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1; }

mine_to_exact() {
    local target="$1" h last=-1 idle=0
    h="$(height)"
    is_int "$h" || return 1
    [ "$h" -eq "$target" ] && return 0
    [ "$h" -gt "$target" ] && return 1
    rpc setgenerate true $(( target - h )) >/dev/null 2>&1
    for _ in $(seq 1 300); do
        sleep 2
        h="$(height)"
        is_int "$h" || continue
        [ "$h" -ge "$target" ] && break
        if [ "$h" = "$last" ]; then
            idle=$(( idle + 1 ))
            [ "$idle" -ge 5 ] && { rpc setgenerate true $(( target - h )) >/dev/null 2>&1; idle=0; }
        else
            idle=0; last="$h"
        fi
    done
    [ "$(height)" -eq "$target" ]
}

cleanup() {
    stop_node || true
    [ "${IV5_FN_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 coinbase fee note and unshield retirement"

rm -rf "$TEST_DIR"; mkdir -p "$NODE_DIR"
cat > "$NODE_DIR/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPC
port=$PORT
listen=1
idnsport=$IDNS
dnsseed=0
stakingmode=0
nofinalityvoting=1
maxconnections=125
regtestboundaryb=$BOUNDARY_B
regtestiv5rehearsal=1
regtestiv5feenote=$FEE_NOTE
EOF

start_node || { fail "node did not start"; exit 1; }
success "node started: Boundary B $BOUNDARY_B, fee-note fork $FEE_NOTE"

# ============================================================
header "1. A seeded wallet with coins, below both forks"
# ============================================================

mine_to_exact "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }

rpc encryptwallet "$WALLETPASS" >/dev/null 2>&1
for _ in $(seq 1 60); do
    pgrep -f -- "-datadir=$NODE_DIR -regtest -daemon" >/dev/null 2>&1 || break
    sleep 1
done
start_node || { fail "node did not restart after encrypting the wallet"; exit 1; }
unlock
SEED="$(rpc z_createiv5seed 2>&1)"
if echo "$SEED" | grep -q '"created"'; then
    success "wallet encrypted, unlocked and seeded"
else
    fail "z_createiv5seed failed: $(echo "$SEED" | head -2)"
    exit 1
fi

INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
FN_HEIGHT="$(jget "$INFO" privacy_vnext_fee_note_height)"
FN_ACTIVE="$(jget "$INFO" privacy_vnext_fee_note_active)"
if [ "$FN_HEIGHT" = "$FEE_NOTE" ] && [ "$FN_ACTIVE" = "False" ]; then
    success "the fork reports height $FN_HEIGHT and inactive at $(height)"
else
    fail "fork reports height=$FN_HEIGHT active=$FN_ACTIVE at $(height)"
fi

# ============================================================
header "2. Pre-fork: the miner is paid the IV5 fee transparently"
# ============================================================

mine_to_exact "$BOUNDARY_B" || { fail "could not mine to $BOUNDARY_B"; exit 1; }

PLAIN_H=$(( BOUNDARY_B + 1 ))
mine_to_exact "$PLAIN_H" || { fail "could not mine to $PLAIN_H"; exit 1; }

# The baseline is only a baseline if the block really is empty. A stray wallet
# transaction pays its fee into the coinbase, which shifts every later
# comparison by that fee and reports as a fee-note accounting fault. Advance
# until a block carries the coinbase alone rather than assuming this one does.
for _ in $(seq 1 6); do
    [ "$(block_tx_count "$PLAIN_H")" = "1" ] && break
    PLAIN_H=$(( PLAIN_H + 1 ))
    mine_to_exact "$PLAIN_H" || { fail "could not mine to $PLAIN_H"; exit 1; }
done
if [ "$(block_tx_count "$PLAIN_H")" != "1" ]; then
    fail "no transaction-free block found for the baseline"; exit 1
fi

PLAIN_CB="$(coinbase_value "$PLAIN_H")"
[ -n "$PLAIN_CB" ] || { fail "could not read a plain coinbase"; exit 1; }
success "a block with no transactions pays $PLAIN_CB (height $PLAIN_H)"

POOL_BEFORE="$(pool_value)"
SH="$(rpc z_shieldall 2>&1)"
SH_TXID="$(jstr "$SH" txid)"
if [ ${#SH_TXID} -eq 64 ]; then
    success "pre-fork shield accepted: ${SH_TXID:0:16}"
else
    fail "z_shieldall failed: $(echo "$SH" | head -3)"
    exit 1
fi

PRE_H=$(( PLAIN_H + 1 ))
mine_to_exact "$PRE_H" || { fail "could not mine the pre-fork shield"; exit 1; }
[ "$(block_tx_count "$PRE_H")" = "2" ] || { fail "block $PRE_H does not carry exactly the coinbase and the shield"; exit 1; }
PRE_CB="$(coinbase_value "$PRE_H")"
PRE_EXCESS="$(python3 -c "print('%.8f' % ($PRE_CB - $PLAIN_CB))")"
if feq "$PRE_EXCESS" "$SHIELD_FEE"; then
    success "pre-fork coinbase is $PRE_CB, exactly $SHIELD_FEE above a plain block"
else
    fail "pre-fork coinbase excess is $PRE_EXCESS, expected $SHIELD_FEE"
fi
PRE_VER="$(coinbase_version "$PRE_H")"
if [ "$PRE_VER" = "1" ]; then
    success "the pre-fork coinbase carries no IV5 payload (version $PRE_VER)"
else
    fail "the pre-fork coinbase is version $PRE_VER"
fi

# ============================================================
header "3. The fork block: the fee is a note, not coinbase value"
# ============================================================

# Drive the tip to one below the fork before building, so the shield is selected
# into the activation block itself and not into some block along the way.
mine_to_exact $(( FEE_NOTE - 1 )) || { fail "could not mine to $(( FEE_NOTE - 1 ))"; exit 1; }
POOL_PRE_FORK="$(pool_value)"
SH2="$(rpc z_shieldall 2>&1)"
SH2_TXID="$(jstr "$SH2" txid)"
if [ ${#SH2_TXID} -eq 64 ]; then
    success "a shield is queued for the fork block: ${SH2_TXID:0:16}"
else
    fail "could not build a shield for the fork block: $(echo "$SH2" | head -3)"
    exit 1
fi

mine_to_exact "$FEE_NOTE" || { fail "could not mine the fork block"; exit 1; }

FORK_TXS="$(block_tx_count "$FEE_NOTE")"
if [ "$FORK_TXS" = "2" ]; then
    success "the fork block carries the coinbase and the shield only"
else
    fail "the fork block carries $FORK_TXS transactions; a held unshield may have crossed"
fi

FORK_CB="$(coinbase_value "$FEE_NOTE")"
FORK_VER="$(coinbase_version "$FEE_NOTE")"
if [ "$FORK_VER" = "2008" ]; then
    success "the fork coinbase carries an IV5 payload (version $FORK_VER)"
else
    fail "the fork coinbase is version $FORK_VER, expected 2008"
fi

# A block carrying a fee note must claim exactly a plain block's amount; a double
# payment shows up as PLAIN_CB + SHIELD_FEE.
if feq "$FORK_CB" "$PLAIN_CB"; then
    success "the fork coinbase pays $FORK_CB transparently: the IV5 fee is not claimed"
else
    # Which side it lands on names a different fault, so do not report both as
    # a double claim: above the baseline is the mint this test exists to catch,
    # below it means the baseline block was not fee-free.
    if python3 -c "import sys; sys.exit(0 if float('$FORK_CB') > float('$PLAIN_CB') else 1)"; then
        fail "the fork coinbase pays $FORK_CB against $PLAIN_CB for a plain block; the IV5 fee was claimed transparently as well as noted"
    else
        fail "the fork coinbase pays $FORK_CB, below the $PLAIN_CB baseline; the baseline block carried fees a plain block should not have"
    fi
fi

FORK_LEN="$(coinbase_raw_len "$FEE_NOTE")"
PLAIN_LEN="$(coinbase_raw_len "$PLAIN_H")"
if is_int "$FORK_LEN" && is_int "$PLAIN_LEN" && [ "$FORK_LEN" -gt "$PLAIN_LEN" ]; then
    success "the fork coinbase is $FORK_LEN hex characters against $PLAIN_LEN plain: the note is on the wire"
else
    fail "the fork coinbase is not carrying a payload (len $FORK_LEN against $PLAIN_LEN)"
fi

# The shield takes (value - fee) into the pool and the note takes the fee, so the
# pool rises by the whole shielded value and the fee is not destroyed.
POOL_FORK="$(pool_value)"
SH2_VALUE="$(jget "$SH2" shielded)"
if [ -n "$POOL_PRE_FORK" ] && [ -n "$POOL_FORK" ] && [ -n "$SH2_VALUE" ]; then
    POOL_RISE="$(python3 -c "print('%.8f' % ($POOL_FORK - $POOL_PRE_FORK))")"
    EXPECTED_RISE="$(python3 -c "print('%.8f' % ($SH2_VALUE + $SHIELD_FEE))")"
    if feq "$POOL_RISE" "$EXPECTED_RISE"; then
        success "the pool rose by $POOL_RISE: the shielded value plus the fee the note collected"
    else
        fail "the pool rose by $POOL_RISE, expected $EXPECTED_RISE (before $POOL_PRE_FORK, after $POOL_FORK)"
    fi
else
    fail "could not read the pool balance across the fork block"
fi

# ============================================================
header "4. A block with no IV5 fees carries no note"
# ============================================================

EMPTY_H=$(( FEE_NOTE + 1 ))
mine_to_exact "$EMPTY_H" || { fail "could not mine an empty post-fork block"; exit 1; }
EMPTY_VER="$(coinbase_version "$EMPTY_H")"
EMPTY_CB="$(coinbase_value "$EMPTY_H")"
if [ "$EMPTY_VER" = "1" ]; then
    success "a post-fork block with no IV5 fees carries no coinbase payload"
else
    fail "a post-fork block with no IV5 fees carries a version-$EMPTY_VER coinbase"
fi
if feq "$EMPTY_CB" "$PLAIN_CB"; then
    success "its coinbase is unchanged at $EMPTY_CB"
else
    fail "its coinbase is $EMPTY_CB against $PLAIN_CB before the fork"
fi

# ============================================================
header "5. Two consecutive note blocks issue distinct owners"
# ============================================================

# I = Hp(O): a repeated output owner shares the first note's key image, so
# ConnectBlock refuses it. Two note blocks in a row is the case that catches a
# miner deriving the same note every block.
NOTE_A=$(( EMPTY_H + 1 ))
NOTE_B=$(( EMPTY_H + 2 ))
SHA="$(rpc z_shieldall 2>&1)"

SHA_TXID="$(jstr "$SHA" txid)"
if [ ${#SHA_TXID} -ne 64 ]; then
    warn "no transparent value left to shield; the consecutive-note case is skipped"
else
    mine_to_exact "$NOTE_A" || { fail "could not mine the first note block"; exit 1; }
    SHB="$(rpc z_shieldall 2>&1)"
    SHB_TXID="$(jstr "$SHB" txid)"
    if [ ${#SHB_TXID} -ne 64 ]; then
        warn "no second shield available; the consecutive-note case is skipped"
    else
        mine_to_exact "$NOTE_B" || { fail "could not mine the second note block"; exit 1; }
        VA="$(coinbase_version "$NOTE_A")"
        VB="$(coinbase_version "$NOTE_B")"
        if [ "$VA" = "2008" ] && [ "$VB" = "2008" ]; then
            success "two consecutive blocks each connected with their own fee note"
        else
            fail "consecutive note blocks did not both connect (versions $VA, $VB)"
        fi
        # A repeated owner is a consensus reject, not a silent collision, so its
        # absence from the log is what says the second note carried a fresh one.
        if grep -qi "output owner .* was already issued" "$NODE_DIR/regtest/debug.log" 2>/dev/null; then
            fail "the second fee note reused the first note's owner"
            grep -i "output owner .* was already issued" "$NODE_DIR/regtest/debug.log" | tail -2
        else
            success "neither note reused an owner already on chain"
        fi
    fi
fi

# ============================================================
header "6. The wallet refuses to build an unshield after the fork"
# ============================================================

T_ADDR="$(rpc getnewaddress 2>/dev/null | tr -d '"[:space:]')"
BUILD="$(rpc z_iv5unshield "$T_ADDR" 1 2>&1)"
if echo "$BUILD" | grep -qi "retired"; then
    success "the wallet refuses to build an unshield: $(echo "$BUILD" | grep -oi 'IV5 unshield is retired[^"]*' | head -1)"
else
    fail "z_iv5unshield did not report retirement: $(echo "$BUILD" | head -3)"
fi

# Relay and ConnectBlock refuse a real released payload as well, but building one
# needs notes anchored to a finalized epoch, which one node cannot reach. That
# boundary is covered by the fleet in iv5_spend_regtest_test.sh.

# ============================================================
header "7. A transfer still works after the fork"
# ============================================================

# The retirement's whole premise is that the private side keeps working: a gate
# keyed on the pool delta instead of the declared balance would refuse every
# transfer, because a transfer's delta is legitimately negative by its fee.
Z_ADDR="$(jstr "$(rpc z_getnewiv5address 2>&1)" address)"
if [ ${#Z_ADDR} -lt 20 ]; then
    Z_ADDR="$(rpc z_getnewiv5address 2>/dev/null | tr -d '"[:space:]')"
fi
if [ ${#Z_ADDR} -lt 20 ]; then
    warn "could not obtain an IV5 address; the transfer case is skipped"
else
    XF="$(rpc z_iv5transfer "$Z_ADDR" 1 2>&1)"
    XF_TXID="$(jstr "$XF" txid)"
    if [ ${#XF_TXID} -eq 64 ]; then
        success "a post-fork transfer is accepted: ${XF_TXID:0:16}"
    elif echo "$XF" | grep -qi "finali"; then
        warn "a transfer needs finality this single node cannot reach: $(echo "$XF" | head -1)"
    else
        fail "a post-fork transfer was refused: $(echo "$XF" | head -3)"
    fi
fi

# ============================================================
header "8. A reorg across a note block reconciles the pool"
# ============================================================

# DisconnectBlock reverses vtx[0] last, so the pool never dips below its prior value;
# reconnecting must restore the same pool value.
REORG_H="$FEE_NOTE"
POOL_NOW="$(pool_value)"
REORG_HASH="$(block_hash "$REORG_H")"
if [ ${#REORG_HASH} -ne 64 ]; then
    fail "could not read the hash of the note block $REORG_H"
else
    rpc invalidateblock "$REORG_HASH" >/dev/null 2>&1
    for _ in $(seq 1 30); do
        [ "$(height)" = "$(( REORG_H - 1 ))" ] && break
        sleep 1
    done
    if [ "$(height)" = "$(( REORG_H - 1 ))" ]; then
        POOL_DISC="$(pool_value)"
        if feq "$POOL_DISC" "$POOL_PRE_FORK"; then
            success "disconnecting the note block returned the pool to $POOL_DISC"
        else
            fail "the pool is $POOL_DISC after disconnect, expected $POOL_PRE_FORK"
        fi
    else
        fail "the tip is $(height) after invalidating $REORG_H"
    fi

    rpc reconsiderblock "$REORG_HASH" >/dev/null 2>&1
    for _ in $(seq 1 60); do
        [ "$(height)" -ge "$REORG_H" ] && break
        sleep 1
    done
    POOL_RECON="$(pool_value)"
    if feq "$POOL_RECON" "$POOL_NOW"; then
        success "reconnecting returns the pool to $POOL_RECON at tip $(height)"
    else
        fail "the pool is $POOL_RECON after reconnect, expected $POOL_NOW"
    fi
fi

# ============================================================
header "9. The node logged no pool or reward complaint"
# ============================================================

if grep -qiE "coinbase reward exceeded|block mints value|IV5 pool balance|coinbase IV5|IV5 fee sum" \
     "$NODE_DIR/regtest/debug.log" 2>/dev/null; then
    fail "the node log carries a reward or IV5 pool complaint"
    grep -iE "coinbase reward exceeded|block mints value|IV5 pool balance|coinbase IV5|IV5 fee sum" \
        "$NODE_DIR/regtest/debug.log" | tail -5
else
    success "no reward or IV5 pool complaint in the node log"
fi

ERRORS="$(jstr "$(rpc getinfo 2>/dev/null)" errors)"
if [ -z "$ERRORS" ]; then
    success "getinfo reports no errors"
else
    fail "getinfo reports: $ERRORS"
fi

header "Results"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ]
