#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Total-supply cap: from the cap fork the subsidy is clamped to the headroom under MAX_MONEY.
# -regtestsupplycap lowers the cap and -regtestsupplycapheight places the fork mid-chain.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${SC_TEST_DIR:-/tmp/innova_supplycap_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${SC_PORT:-29500}"
RPC="${SC_RPC:-29501}"
IDNS="${SC_IDNS:-29502}"
RPCUSER="sc"
RPCPASS="scpass"

# Regtest pays a flat 50 INN per PoW block. Genesis is height 0 and pays nothing,
# so supply after height H is 50*H INN.
SUBSIDY=50
# Fork below the first clamped block, and a cap that is NOT a multiple of the
# subsidy so the boundary block has to pay a partial remainder.
CAP_HEIGHT=30
CAP_INN=1225.5
CAP_SAT=122550000000
# 1225.5 / 50 = 24.51, so heights 1..24 pay in full (1200 INN), height 25 pays
# the 25.5 INN remainder, and every height after it pays zero.
FULL_LAST=24
BOUNDARY=25

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

# What the producer of block H claimed: vout 0 of its coinbase. Other coinbase
# outputs belong to other parties (a finality voter, a collateralnode), and
# summing them in would misreport what the subsidy rule paid.
coinbase_value() {
    local bh cb
    bh="$(block_hash "$1")"; [ ${#bh} -eq 64 ] || return 1
    cb="$(rpc getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["tx"][0])
except Exception: pass
')"
    [ ${#cb} -eq 64 ] || return 1
    rpc getrawtransaction "$cb" 1 2>/dev/null | python3 -c '
import json, sys
try: print("%.8f" % float(json.load(sys.stdin)["vout"][0]["value"]))
except Exception: pass
'
}

money_supply() { jget "$(rpc getinfo 2>/dev/null)" moneysupply; }

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
    [ "${SC_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "Total-supply cap"

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
regtestsupplycapheight=$CAP_HEIGHT
regtestsupplycap=$CAP_SAT
EOF

start_node || { fail "node did not start"; exit 1; }
success "node started: cap fork $CAP_HEIGHT, cap $CAP_INN INN"

# ============================================================
header "1. Below the fork the schedule is untouched"
# ============================================================

# The cap sits at 1225.5 INN but the fork is at height 30, so heights 25..29 --
# every one of them past the cap in value terms -- must still pay a full subsidy.
# This is the historical-verdict property: activation height, not supply, decides.
mine_to_exact 29 || { fail "could not mine to 29"; exit 1; }

ALL_FULL=1
for H in $(seq 1 29); do
    V="$(coinbase_value "$H")"
    feq "$V" "$SUBSIDY" || { ALL_FULL=0; fail "height $H paid $V, expected $SUBSIDY"; break; }
done
[ "$ALL_FULL" = "1" ] && success "heights 1..29 each paid the full $SUBSIDY INN, cap ignored below the fork"

SUP="$(money_supply)"
if [ "$(python3 -c "print(1 if $SUP > $CAP_INN else 0)")" = "1" ]; then
    success "supply $SUP INN is already above the $CAP_INN cap and no block was rejected"
else
    fail "supply $SUP INN did not exceed the cap; the pre-fork window proves nothing"
fi

# ============================================================
header "2. Past the fork, an already-over-cap chain pays zero subsidy"
# ============================================================

mine_to_exact 34 || { fail "could not mine past the fork"; exit 1; }

ALL_ZERO=1
for H in $(seq "$CAP_HEIGHT" 34); do
    V="$(coinbase_value "$H")"
    feq "$V" 0 || { ALL_ZERO=0; fail "height $H paid $V, expected 0"; break; }
done
[ "$ALL_ZERO" = "1" ] && success "heights $CAP_HEIGHT..34 each paid 0: subsidy stops at the cap"

SUP_AFTER="$(money_supply)"
if feq "$SUP_AFTER" "$SUP"; then
    success "money supply frozen at $SUP_AFTER INN across five post-fork blocks"
else
    fail "money supply moved from $SUP to $SUP_AFTER after the cap"
fi

# ============================================================
header "3. A fresh chain clamped from a low fork: the boundary block"
# ============================================================

# Restart on a wiped datadir with the fork at height 1, so the clamp governs the
# whole chain and the exact-remainder case is reachable.
stop_node || warn "node did not stop cleanly"
rm -rf "$NODE_DIR"; mkdir -p "$NODE_DIR"
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
regtestsupplycapheight=1
regtestsupplycap=$CAP_SAT
EOF
start_node || { fail "node did not restart on the fresh chain"; exit 1; }

mine_to_exact 30 || { fail "could not mine the clamped chain"; exit 1; }

ALL_FULL=1
for H in $(seq 1 "$FULL_LAST"); do
    V="$(coinbase_value "$H")"
    feq "$V" "$SUBSIDY" || { ALL_FULL=0; fail "height $H paid $V, expected $SUBSIDY"; break; }
done
[ "$ALL_FULL" = "1" ] && success "heights 1..$FULL_LAST paid in full while headroom lasted"

# 1225.5 - 24*50 = 25.5 INN
REMAINDER="$(python3 -c "print('%.8f' % ($CAP_INN - $FULL_LAST * $SUBSIDY))")"
V_BOUND="$(coinbase_value "$BOUNDARY")"
if feq "$V_BOUND" "$REMAINDER"; then
    success "boundary height $BOUNDARY paid the exact remainder $REMAINDER INN, not $SUBSIDY and not 0"
else
    fail "boundary height $BOUNDARY paid $V_BOUND, expected the remainder $REMAINDER"
fi

ALL_ZERO=1
for H in $(seq $((BOUNDARY + 1)) 30); do
    V="$(coinbase_value "$H")"
    feq "$V" 0 || { ALL_ZERO=0; fail "height $H paid $V, expected 0"; break; }
done
[ "$ALL_ZERO" = "1" ] && success "every height past the boundary paid 0"

SUP_FINAL="$(money_supply)"
if feq "$SUP_FINAL" "$CAP_INN"; then
    success "supply landed exactly on the cap: $SUP_FINAL INN"
else
    fail "supply is $SUP_FINAL INN, expected exactly $CAP_INN"
fi

# ============================================================
header "4. Fees still flow past the cap"
# ============================================================

# Spend a capped-out coinbase to itself so the confirming block carries a fee;
# the cap must still pay the producer that fee and nothing else.
ADDR="$(rpc getnewaddress 2>/dev/null | tr -d '"[:space:]')"
if [ ${#ADDR} -lt 20 ]; then
    warn "could not get an address; skipping the fee check"
else
    # Mature the early coinbases before spending one.
    mine_to_exact 100 >/dev/null 2>&1 || warn "could not mine to maturity"
    H_BEFORE="$(height)"
    TXID="$(rpc sendtoaddress "$ADDR" 1.0 2>&1 | tr -d '"[:space:]')"
    if [ ${#TXID} -ne 64 ]; then
        warn "sendtoaddress failed ($TXID); skipping the fee check"
    else
        mine_to_exact $(( H_BEFORE + 1 )) >/dev/null 2>&1 || warn "could not confirm the fee tx"
        FEE_H=$(( H_BEFORE + 1 ))
        V_FEE="$(coinbase_value "$FEE_H")"
        if [ "$(python3 -c "print(1 if $V_FEE > 0 else 0)" 2>/dev/null)" = "1" ]; then
            success "block $FEE_H past the cap paid $V_FEE INN: subsidy 0 plus the fee"
        else
            fail "block $FEE_H paid $V_FEE; fees stopped flowing at the cap"
        fi
        SUP_FEE="$(money_supply)"
        if feq "$SUP_FEE" "$CAP_INN"; then
            success "paying that fee did not move supply off the cap ($SUP_FEE INN)"
        else
            fail "supply moved to $SUP_FEE while only fees were paid"
        fi
    fi
fi

# ============================================================
header "Result"
# ============================================================
echo -e "${GREEN}passed: $PASSED${NC}  ${RED}failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ]
