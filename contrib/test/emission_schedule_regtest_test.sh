#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Walks the post-DAG proof-of-work emission schedule on a single regtest node: mines past
# the DAG fork (11) and the first stretched tier (311); the 50 -> 25 INN step lands at 312.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${EMIT_TEST_DIR:-$HOME/innova_emission_walk_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${EMIT_PORT:-29500}"
RPC="${EMIT_RPC:-29501}"
IDNS="${EMIT_IDNS:-29502}"
RPCUSER="emitwalk"
RPCPASS="emitwalkpass"

# Regtest ladder. FORK_HEIGHT_DAG is 11; the rungs are 20/40/60 pre-DAG-cadence
# blocks past it, stretched by the 15:1 spacing ratio.
DAG_FORK=11
TIER1_LAST=311      # 50 INN
TIER2_LAST=611      # 25 INN
TARGET_HEIGHT=330

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

# What the producer claimed at this height: vout 0 of the coinbase. Regtest never
# reaches the collateralnode payment height, so vout 0 is the whole subsidy.
coinbase_value() {
    local cb; cb="$(coinbase_txid "$1")"
    [ ${#cb} -eq 64 ] || return 1
    rpc getrawtransaction "$cb" 1 2>/dev/null | python3 -c '
import json, sys
try: print("%.8f" % float(json.load(sys.stdin)["vout"][0]["value"]))
except Exception: pass
'
}

# The expected subsidy at a height, straight off the regtest ladder.
expected_value() {
    local h="$1"
    if   [ "$h" -eq 0 ];              then echo "0.00000000"
    elif [ "$h" -le "$TIER1_LAST" ];  then echo "50.00000000"
    elif [ "$h" -le "$TIER2_LAST" ];  then echo "25.00000000"
    else echo "5.00000000"
    fi
}

check_height() {
    local h="$1" want got
    want="$(expected_value "$h")"
    got="$(coinbase_value "$h")"
    if [ "$got" = "$want" ]; then
        success "height $h pays $got INN"
    else
        fail "height $h pays '$got' INN, expected $want"
    fi
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

mine_to_exact() {
    local target="$1" h last=-1 idle=0
    h="$(height)"
    is_int "$h" || return 1
    [ "$h" -eq "$target" ] && return 0
    [ "$h" -gt "$target" ] && return 1
    rpc setgenerate true $(( target - h )) >/dev/null 2>&1
    for _ in $(seq 1 600); do
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
    [ "${EMIT_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "Post-DAG emission schedule walk (regtest)"

[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }

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
EOF

start_node || { fail "node did not start"; exit 1; }
success "node started"

# ============================================================
header "1. Mine across the DAG fork and the first tier boundary"
# ============================================================

mine_to_exact "$TARGET_HEIGHT" || { fail "could not mine to $TARGET_HEIGHT"; exit 1; }
success "mined to height $(height)"

# ============================================================
header "2. Pre-DAG heights pay the unchanged flat regtest reward"
# ============================================================

for h in 1 5 $(( DAG_FORK - 1 )); do
    check_height "$h"
done

# ============================================================
header "3. The fork block and the first rung above it"
# ============================================================

check_height "$DAG_FORK"
check_height $(( DAG_FORK + 1 ))
check_height 100

# ============================================================
header "4. The stretched tier boundary steps exactly at 311"
# ============================================================

check_height $(( TIER1_LAST - 1 ))
check_height "$TIER1_LAST"
check_height $(( TIER1_LAST + 1 ))
check_height $(( TIER1_LAST + 2 ))

# 25 INN is unreachable without the post-DAG ladder and its divisor.
BEFORE="$(coinbase_value "$TIER1_LAST")"
AFTER="$(coinbase_value $(( TIER1_LAST + 1 )))"
if [ "$BEFORE" = "50.00000000" ] && [ "$AFTER" = "25.00000000" ]; then
    success "the post-DAG ladder stepped 50 -> 25 INN at the stretched boundary"
else
    fail "no ladder step at $TIER1_LAST: $BEFORE -> $AFTER"
fi

# ============================================================
header "5. Every mined height matches the ladder"
# ============================================================

MISMATCH=0
FIRST_BAD=""
for h in $(seq 1 "$TARGET_HEIGHT"); do
    want="$(expected_value "$h")"
    got="$(coinbase_value "$h")"
    if [ "$got" != "$want" ]; then
        MISMATCH=$(( MISMATCH + 1 ))
        [ -z "$FIRST_BAD" ] && FIRST_BAD="height $h paid '$got', expected $want"
    fi
done
if [ "$MISMATCH" -eq 0 ]; then
    success "all $TARGET_HEIGHT mined blocks match the schedule"
else
    fail "$MISMATCH of $TARGET_HEIGHT blocks off the schedule ($FIRST_BAD)"
fi

header "Result: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
