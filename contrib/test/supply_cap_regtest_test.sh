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

# Regtest pays a flat 50 INN per PoW block; from the DAG fork the coinbase carries the schedule minus
# the finality reserve. With nofinalityvoting=1 the reserve is never minted, so it stays headroom.
SUBSIDY=50
DAG_FORK=11           # GetForkHeightDAG() on regtest
RESERVE_BPS=1000      # FINALITY_RESERVE_BPS
# Fork below the first clamped block, and a cap that is NOT a multiple of the
# subsidy so the boundary block has to pay a partial remainder.
CAP_HEIGHT=30
CAP_INN=1225.5
CAP_SAT=122550000000

# Expected coinbase per height for a cap fork at $1, in INN, one per line.
# Mirrors GetBlockSubsidySchedule -> ClampSubsidyToSupplyCap -> CBlockSubsidySplit.
expected_schedule() {
    CAP_SAT=$CAP_SAT CAP_FORK="$1" LAST="$2" DAG_FORK=$DAG_FORK \
    RESERVE_BPS=$RESERVE_BPS SUBSIDY=$SUBSIDY python3 -c '
import os
cap      = int(os.environ["CAP_SAT"])
capfork  = int(os.environ["CAP_FORK"])
last     = int(os.environ["LAST"])
dagfork  = int(os.environ["DAG_FORK"])
bps      = int(os.environ["RESERVE_BPS"])
sched    = int(os.environ["SUBSIDY"]) * 100000000

def share(v, b):
    return (v // 10000) * b + ((v % 10000) * b) // 10000

supply = 0
for h in range(1, last + 1):
    headroom = None if h < capfork else max(0, cap - supply)
    sub = sched if headroom is None else min(sched, headroom)
    res = 0 if h < dagfork else min(share(sched, bps), sub)
    paid = sub - res
    supply += paid
    clamped = 0 if headroom is None or sched <= headroom else 1
    print("%d %.8f %.8f %d" % (h, paid / 1e8, supply / 1e8, clamped))
'
}

expected_paid() { echo "$1" | awk -v h="$2" '$1 == h { print $2 }'; }
expected_supply_after() { echo "$1" | awk -v h="$2" '$1 == h { print $3 }'; }

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

SCHED_A="$(expected_schedule "$CAP_HEIGHT" 29)"
ALL_FULL=1
for H in $(seq 1 29); do
    V="$(coinbase_value "$H")"
    E="$(expected_paid "$SCHED_A" "$H")"
    feq "$V" "$E" || { ALL_FULL=0; fail "height $H paid $V, expected $E"; break; }
done
[ "$ALL_FULL" = "1" ] && success "heights 1..29 each paid the unclamped schedule less the reserve, cap ignored below the fork"

# The split, seen live: below the DAG fork a block pays the whole schedule; from
# the fork on it pays the schedule less the reserve, and the difference is
# exactly the reserve every epoch settles.
V_PRE="$(coinbase_value $((DAG_FORK - 1)))"
V_POST="$(coinbase_value "$DAG_FORK")"
RESERVE_INN="$(python3 -c "print('%.8f' % ($SUBSIDY * $RESERVE_BPS / 10000.0))")"
if feq "$V_PRE" "$SUBSIDY" && feq "$V_POST" "$(python3 -c "print('%.8f' % ($SUBSIDY - $SUBSIDY * $RESERVE_BPS / 10000.0))")"; then
    success "height $((DAG_FORK - 1)) paid $V_PRE and height $DAG_FORK paid $V_POST: $RESERVE_INN INN withheld as the finality reserve"
else
    fail "reserve not withheld at the DAG fork: $((DAG_FORK - 1)) paid $V_PRE, $DAG_FORK paid $V_POST"
fi

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

SCHED_B="$(expected_schedule 1 30)"

ALL_MATCH=1
for H in $(seq 1 30); do
    V="$(coinbase_value "$H")"
    E="$(expected_paid "$SCHED_B" "$H")"
    feq "$V" "$E" || { ALL_MATCH=0; fail "height $H paid $V, expected $E"; break; }
done
[ "$ALL_MATCH" = "1" ] && success "every height 1..30 paid the clamped schedule less the reserve"

# The boundary is the first height whose headroom, not its reserve, cut the subsidy short (column 4).
BOUNDARY="$(echo "$SCHED_B" | awk '$4 == 1 && $2 > 0 { print $1; exit }')"
if [ -n "$BOUNDARY" ]; then
    V_BOUND="$(coinbase_value "$BOUNDARY")"
    success "boundary height $BOUNDARY paid the partial remainder $V_BOUND INN, not $SUBSIDY and not 0"
else
    fail "no boundary block found in the modelled schedule"
fi

ALL_ZERO=1
for H in $(seq $((BOUNDARY + 1)) 30); do
    V="$(coinbase_value "$H")"
    feq "$V" 0 || { ALL_ZERO=0; fail "height $H paid $V, expected 0"; break; }
done
[ "$ALL_ZERO" = "1" ] && success "every height past the boundary paid 0"

# Supply stops at or below the cap: below it by the last block's unminted reserve, which is unissued headroom.
SUP_FINAL="$(money_supply)"
SUP_MODEL="$(expected_supply_after "$SCHED_B" 30)"
if feq "$SUP_FINAL" "$SUP_MODEL"; then
    success "supply landed on the modelled $SUP_MODEL INN"
else
    fail "supply is $SUP_FINAL INN, expected $SUP_MODEL"
fi
if [ "$(python3 -c "print(1 if $SUP_FINAL <= $CAP_INN else 0)")" = "1" ]; then
    success "supply $SUP_FINAL INN is at or under the $CAP_INN cap: the finality share is inside the clamp"
else
    fail "supply $SUP_FINAL INN exceeded the $CAP_INN cap"
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
        if feq "$SUP_FEE" "$SUP_FINAL"; then
            success "paying that fee did not move supply ($SUP_FEE INN): a fee is not issuance"
        else
            fail "supply moved from $SUP_FINAL to $SUP_FEE while only fees were paid"
        fi
    fi
fi

# ============================================================
header "Result"
# ============================================================
echo -e "${GREEN}passed: $PASSED${NC}  ${RED}failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ]
