#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 leaf-index catch-up: notes received while assignment was held off
# (-regtestiv5holdleafindex) must still be placed once it is released.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_leaf_index_catchup_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_LEAF_TEST_DIR:-/tmp/innova_iv5_leaf_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${IV5_LEAF_PORT:-$(iv5_port 0 28950)}"
RPC="${IV5_LEAF_RPC:-$(iv5_port 1 29000)}"
IDNS="${IV5_LEAF_IDNS:-$(iv5_port 2 9060)}"
RPCUSER="iv5leaf"
RPCPASS="iv5leafpass"
WALLETPASS="iv5leafwallet"

BOUNDARY_B=311
SEED_HEIGHT=250
# Epoch 2 is [311, 610], epoch 3 is [611, 910], epoch 4 is [911, 1210]. One shield
# lands in each of epochs 2 and 3 so the release has to reach back over both.
SHIELD_E2_HEIGHT=330
SHIELD_E2_CONFIRM=350
SHIELD_E3_HEIGHT=700
SHIELD_E3_CONFIRM=720
# Two boundaries past the epoch-2 note, and far enough past the epoch-3 one that
# only the missing position can keep either out of the spendable balance.
HOLD_END_HEIGHT=950
# One node with voting off, so notes spend only by anchor depth
# (EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH = 600); the later epoch closes at 910.
SPENDABLE_HEIGHT=1520

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
is_int() { echo "$1" | grep -qE '^-?[0-9]+$'; }
feq()    { [ "$(python3 -c "print(1 if abs($1 - $2) < 1e-8 else 0)" 2>/dev/null)" = "1" ]; }
fgt()    { [ "$(python3 -c "print(1 if ($1) > ($2) else 0)" 2>/dev/null)" = "1" ]; }

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

# The daemon's exact argv: a bare datadir match also catches this harness's own
# short-lived rpc client processes, so the node would never look stopped.
wait_rpc_down() {
    for _ in $(seq 1 180); do
        pgrep -f -- "-datadir=$NODE_DIR -regtest -daemon" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    wait_rpc_down
}

start_node() {
    "$INNOVAD" -datadir="$NODE_DIR" -regtest -daemon >/dev/null 2>&1
    for _ in $(seq 1 90); do
        rpc getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

# Rewritten between phases: the hold is a startup switch, so releasing it is a
# restart, which is the situation the defect came from in the first place.
write_conf() {
    local hold="$1"
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
EOF
    [ "$hold" = "1" ] && echo "regtestiv5holdleafindex=1" >> "$NODE_DIR/innova.conf"
    return 0
}

# Mine until TARGET. Re-arms the miner if height stalls: setgenerate takes a block
# count, and a template that loses a race consumes one.
mine_to() {
    local target="$1" h last stall=0
    h="$(height)"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc setgenerate true $((target - h)) >/dev/null 2>&1
    for ((i=0; i<2400; i++)); do
        h="$(height)"
        if is_int "$h" && [ "$h" -ge "$target" ]; then
            rpc setgenerate false 0 >/dev/null 2>&1
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
            rpc setgenerate true $((target - h)) >/dev/null 2>&1
            stall=0
        fi
        sleep 1
    done
    rpc setgenerate false 0 >/dev/null 2>&1
    return 1
}

# Sweeps one transparent address into the pool and confirms it. Coin selection can
# pick the tip's own coinbase, which ConnectInputs still refuses, so a failed build
# is retried a block later.
shield_once() {
    local confirm_height="$1" out txid
    for _ in 1 2 3 4; do
        out="$(rpc z_shieldall 2>&1)"
        txid="$(jget "$out" txid)"
        if [ ${#txid} -eq 64 ]; then
            SHIELD_TXID="$txid"
            SHIELD_AMOUNT="$(jget "$out" shielded)"
            mine_to "$confirm_height" || return 1
            [ -n "$(jget "$(rpc gettransaction "$txid" 2>&1)" blockhash)" ] && return 0
            mine_to $(( $(height) + 5 )) || return 1
            [ -n "$(jget "$(rpc gettransaction "$txid" 2>&1)" blockhash)" ] || return 1
            return 0
        fi
        mine_to $(( $(height) + 1 )) || return 1
    done
    SHIELD_ERROR="$out"
    return 1
}

cleanup() {
    stop_node || true
    [ "${IV5_LEAF_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 leaf-index catch-up across epochs"

rm -rf "$TEST_DIR"; mkdir -p "$NODE_DIR"
write_conf 1
start_node || { fail "node did not start"; exit 1; }
success "node started with Boundary B at $BOUNDARY_B and leaf-index assignment held"

# ============================================================
header "1. A wallet with spendable coins and an IV5 seed"
# ============================================================

mine_to "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }

# The IV5 seed is spend authority for every note the wallet will own, so it only
# exists inside an encrypted wallet. Encrypting stops the daemon.
rpc encryptwallet "$WALLETPASS" >/dev/null 2>&1
wait_rpc_down || { fail "node did not stop after encrypting the wallet"; exit 1; }
start_node || { fail "node did not restart after encrypting the wallet"; exit 1; }
rpc walletpassphrase "$WALLETPASS" 36000 >/dev/null 2>&1
SEED="$(rpc z_createiv5seed 2>&1)"
if echo "$SEED" | grep -q '"created"'; then
    success "wallet encrypted, unlocked and seeded below Boundary B"
else
    fail "z_createiv5seed failed: $(echo "$SEED" | head -2)"
    exit 1
fi

# ============================================================
header "2. Value enters the pool in epoch 2 and again in epoch 3"
# ============================================================

mine_to "$SHIELD_E2_HEIGHT" || { fail "could not mine to $SHIELD_E2_HEIGHT"; exit 1; }
shield_once "$SHIELD_E2_CONFIRM" || { fail "epoch-2 shield failed: $(echo "$SHIELD_ERROR" | head -3)"; exit 1; }
E2_TXID="$SHIELD_TXID"
E2_AMOUNT="$SHIELD_AMOUNT"
success "epoch-2 shield confirmed: $E2_AMOUNT INN, txid ${E2_TXID:0:16}"

mine_to "$SHIELD_E3_HEIGHT" || { fail "could not mine to $SHIELD_E3_HEIGHT"; exit 1; }
shield_once "$SHIELD_E3_CONFIRM" || { fail "epoch-3 shield failed: $(echo "$SHIELD_ERROR" | head -3)"; exit 1; }
E3_TXID="$SHIELD_TXID"
E3_AMOUNT="$SHIELD_AMOUNT"
success "epoch-3 shield confirmed: $E3_AMOUNT INN, txid ${E3_TXID:0:16}"

SHIELDED_TOTAL="$(python3 -c "print('%.8f' % ($E2_AMOUNT + $E3_AMOUNT))")"

# ============================================================
header "3. Two epoch boundaries pass with nothing assigning positions"
# ============================================================

mine_to "$HOLD_END_HEIGHT" || { fail "could not mine to $HOLD_END_HEIGHT"; exit 1; }

INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
HELD_BAL="$(jget "$INFO" privacy_vnext_balance)"
HELD_UNCONF="$(jget "$INFO" privacy_vnext_unconfirmed_balance)"
HELD_NOTES="$(jget "$INFO" privacy_vnext_note_count)"
HELD_TREE="$(jget "$INFO" privacy_vnext_tree_size)"

# Both notes must have been detected: the defect was never about discovery, and a
# test that lost the notes here would prove nothing about assignment.
if is_int "$HELD_NOTES" && [ "$HELD_NOTES" -ge 2 ]; then
    success "the wallet holds $HELD_NOTES unspent note(s) across the two epochs"
else
    fail "the wallet detected $HELD_NOTES note(s), expected at least 2"
    exit 1
fi

# Everything shielded is present and none of it is spendable, which also proves the
# hold is in force.
if feq "${HELD_BAL:-0}" 0 && feq "${HELD_UNCONF:-0}" "$SHIELDED_TOTAL"; then
    success "held: $HELD_UNCONF INN detected, 0 spendable, tree=$HELD_TREE"
else
    fail "hold did not produce the stranded state (balance=$HELD_BAL unconfirmed=$HELD_UNCONF expected unconfirmed=$SHIELDED_TOTAL)"
    exit 1
fi

if fgt "$SHIELDED_TOTAL" 0; then
    success "the stranded value is $SHIELDED_TOTAL INN, not an empty pool"
else
    fail "nothing was shielded, so there is nothing to strand"
    exit 1
fi

# ============================================================
header "4. Releasing the hold places both notes within one block"
# ============================================================

stop_node || { fail "node did not stop"; exit 1; }
write_conf 0
start_node || { fail "node did not restart without the hold"; exit 1; }
rpc walletpassphrase "$WALLETPASS" 36000 >/dev/null 2>&1
if [ "$(height)" != "$HOLD_END_HEIGHT" ]; then
    fail "tip is at $(height) after the restart, expected $HOLD_END_HEIGHT"
    exit 1
fi

# Nothing has rescanned: the notes are loaded from the wallet exactly as the hold
# left them, so whatever places them is the connected-block assignment alone.
INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
RESTART_BAL="$(jget "$INFO" privacy_vnext_balance)"
if feq "${RESTART_BAL:-0}" 0; then
    success "the restart alone left the notes unplaced"
else
    fail "balance is $RESTART_BAL after a bare restart; the release below would not be what placed the notes"
    exit 1
fi

mine_to $(( HOLD_END_HEIGHT + 1 )) || { fail "could not mine the release block"; exit 1; }

INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
FREED_BAL="$(jget "$INFO" privacy_vnext_balance)"
FREED_UNCONF="$(jget "$INFO" privacy_vnext_unconfirmed_balance)"
FREED_NOTES="$(jget "$INFO" privacy_vnext_note_count)"
FREED_UNPLACED="$(jget "$INFO" privacy_vnext_unplaced_balance)"

# Assignment driven from the tip would stop at epoch 3 and leave the epoch-2 note
# unplaced. Placement is read directly, not inferred from spendability.
if feq "${FREED_UNPLACED:-1}" 0; then
    success "every note holds a tree position one block after the release: both epochs were walked"
else
    fail "$FREED_UNPLACED INN is still without a tree position; the epoch-2 note is the one a tip-driven walk cannot reach"
fi

if feq "$(echo "${FREED_BAL:-0} + ${FREED_UNCONF:-0}" | bc -l)" "$HELD_UNCONF"; then
    success "all $HELD_UNCONF INN is still owned across $FREED_NOTES note(s): spendable $FREED_BAL, pending $FREED_UNCONF"
else
    fail "owned value $(echo "${FREED_BAL:-0} + ${FREED_UNCONF:-0}" | bc -l) INN does not match the $HELD_UNCONF INN held"
fi

# Placed notes spend once their epochs are deep enough. Carry the chain past the
# later one and require all of it.
mine_to "$SPENDABLE_HEIGHT" || { fail "could not mine to $SPENDABLE_HEIGHT"; exit 1; }
INFO_DEEP="$(rpc z_getshieldedinfo 2>/dev/null)"
DEEP_BAL="$(jget "$INFO_DEEP" privacy_vnext_balance)"
if feq "${DEEP_BAL:-0}" "$HELD_UNCONF"; then
    success "all $DEEP_BAL INN is spendable once the depth anchor reaches both epochs"
else
    fail "only $DEEP_BAL INN of $HELD_UNCONF is spendable at height $SPENDABLE_HEIGHT"
fi

# A scan gap would mean the wallet knows it missed payload data, which is a
# different failure and would make the balances above unreliable.
GAP="$(jget "$INFO" privacy_vnext_scan_gap_height)"
if [ "$GAP" = "-1" ]; then
    success "no scan gap recorded"
else
    fail "a scan gap is recorded at height $GAP"
fi

ERRORS="$(jget "$(rpc getinfo 2>/dev/null)" errors)"
if [ -z "$ERRORS" ]; then
    success "getinfo reports no errors"
else
    fail "getinfo reports: $ERRORS"
fi

header "Results"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ]
