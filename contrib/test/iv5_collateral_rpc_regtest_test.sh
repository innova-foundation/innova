#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Private collateralnode registration pre-candidate paths: preflight, refusal and the
# held-note lock. The full lifecycle needs a multi-node fast-epoch fleet.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_collateral_rpc_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_CN_TEST_DIR:-/tmp/innova_iv5_cnrpc_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${IV5_CN_PORT:-$(iv5_port 0 29700)}"
RPC="${IV5_CN_RPC:-$(iv5_port 1 29701)}"
IDNS="${IV5_CN_IDNS:-$(iv5_port 2 9702)}"
RPCUSER="iv5cn"
RPCPASS="iv5cnpass"
WALLETPASS="iv5cnwallet"

BOUNDARY_B=311
SEED_HEIGHT=320

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
jstr()   { echo "$1" | sed -n "s/.*\"$2\" *: *\"\([^\"]*\)\".*/\1/p" | head -1; }
is_int() { echo "$1" | grep -qE '^[0-9]+$'; }

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    # Match the daemon's exact argv: a bare datadir match also catches the
    # short-lived rpc helpers, so the node would never look gone.
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
    [ "$h" -ge "$target" ] && return 0
    rpc setgenerate true $(( target - h )) >/dev/null 2>&1
    for _ in $(seq 1 1200); do
        sleep 2
        h="$(height)"
        is_int "$h" || continue
        [ "$h" -ge "$target" ] && break
        if [ "$h" = "$last" ]; then
            idle=$(( idle + 1 ))
            if [ "$idle" -ge 5 ]; then
                rpc setgenerate true $(( target - h )) >/dev/null 2>&1
                idle=0
            fi
        else
            idle=0
            last="$h"
        fi
    done
    [ "$(height)" -ge "$target" ]
}

cleanup() {
    stop_node || true
    [ "${IV5_CN_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 private collateralnode registration: preflight and refusal"

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
EOF

start_node || { fail "node did not start"; exit 1; }
success "node started with Boundary B at $BOUNDARY_B"

mine_to_exact "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }

rpc encryptwallet "$WALLETPASS" >/dev/null 2>&1
for _ in $(seq 1 60); do
    pgrep -f -- "-datadir=$NODE_DIR -regtest -daemon" >/dev/null 2>&1 || break
    sleep 1
done
start_node || { fail "node did not restart after encrypting the wallet"; exit 1; }
rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
rpc z_createiv5seed >/dev/null 2>&1
PAYOUT="$(jstr "$(rpc z_getnewiv5address 2>/dev/null)" address)"
if [ -z "$PAYOUT" ]; then
    fail "could not issue an IV5 payout address"
    exit 1
fi
success "wallet seeded; payout address issued"

# ============================================================
header "1. The commands are dispatched"
# ============================================================

for CMD in collateral-notes statusprivate; do
    OUT="$(rpc collateralnode $CMD 2>&1)"
    if echo "$OUT" | grep -qi "Set of commands to execute"; then
        fail "'collateralnode $CMD' is not dispatched"
    else
        success "'collateralnode $CMD' is dispatched"
    fi
done

# ============================================================
header "2. No candidate: the refusal names the safe path"
# ============================================================

NOTES="$(rpc collateralnode collateral-notes 2>&1)"
if echo "$NOTES" | grep -q "z_iv5transfer"; then
    success "collateral-notes names the exact command that carves a note"
else
    fail "collateral-notes did not name z_iv5transfer: $(echo "$NOTES" | head -3)"
fi
if echo "$NOTES" | grep -qi "Do NOT shield exactly 25000"; then
    success "collateral-notes warns against shielding exactly 25000 in one step"
else
    fail "collateral-notes did not warn against the shield flow"
fi

# ============================================================
header "3. Preflight rejects a bound tuple that can never be corrected"
# ============================================================

# collateralnodeprivkey is unset in this config, so the identity half of the
# context cannot be formed and nothing may be built.
REG="$(rpc collateralnode registerprivate 127.0.0.1:14539 "$PAYOUT" 2>&1)"
if echo "$REG" | grep -qi "collateralnodeprivkey is not set"; then
    success "registerprivate refuses without collateralnodeprivkey"
else
    fail "registerprivate did not require collateralnodeprivkey: $(echo "$REG" | head -3)"
fi

KEY="$(rpc collateralnode genkey 2>/dev/null | tr -d '"[:space:]')"
if [ -z "$KEY" ]; then
    fail "could not generate a collateralnodeprivkey"
    exit 1
fi
stop_node || { fail "node did not stop"; exit 1; }
printf 'collateralnodeprivkey=%s\n' "$KEY" >> "$NODE_DIR/innova.conf"
start_node || { fail "node did not restart with a collateralnodeprivkey"; exit 1; }
rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
success "collateralnodeprivkey configured"

# Peers drop any announcement whose endpoint is not on the pinned port, so a
# node bound to another port would be invisible with nothing to show for it.
BADPORT="$(rpc collateralnode registerprivate 127.0.0.1:14540 "$PAYOUT" 2>&1)"
if echo "$BADPORT" | grep -qi "pinned to port"; then
    success "registerprivate pins the announcement port"
else
    fail "registerprivate accepted an off-port endpoint: $(echo "$BADPORT" | head -3)"
fi

BADPAYOUT="$(rpc collateralnode registerprivate 127.0.0.1:14539 not-an-iv5-address 2>&1)"
if echo "$BADPAYOUT" | grep -qi "not an IV5 address"; then
    success "registerprivate validates the pool payout address"
else
    fail "registerprivate accepted a non-IV5 payout: $(echo "$BADPAYOUT" | head -3)"
fi

NOCAND="$(rpc collateralnode registerprivate 127.0.0.1:14539 "$PAYOUT" 2>&1)"
if echo "$NOCAND" | grep -q "z_iv5transfer" && \
   echo "$NOCAND" | grep -qi "Do NOT shield exactly 25000"; then
    success "registerprivate refuses with the remedy and the shield warning"
else
    fail "registerprivate refusal did not name the remedy: $(echo "$NOCAND" | head -5)"
fi
if echo "$NOCAND" | grep -qi "attestation_txid"; then
    fail "registerprivate broadcast something with no candidate note"
else
    success "registerprivate broadcast nothing"
fi

# ============================================================
header "4. Status and release with nothing held"
# ============================================================

STATUS="$(rpc collateralnode statusprivate 2>&1)"
if echo "$STATUS" | grep -q '"registrations"' && \
   echo "$STATUS" | grep -q '"held_balance"'; then
    success "statusprivate reports its layers with nothing held"
else
    fail "statusprivate output is malformed: $(echo "$STATUS" | head -5)"
fi

REL="$(rpc collateralnode releaseprivate 0000000000000000000000000000000000000000000000000000000000000001 2>&1)"
if echo "$REL" | grep -qi "no collateral registration is held"; then
    success "releaseprivate refuses a key image this wallet does not hold"
else
    fail "releaseprivate did not refuse an unknown key image: $(echo "$REL" | head -3)"
fi

RELHELP="$(rpc collateralnode releaseprivate 2>&1)"
if echo "$RELHELP" | grep -qi "can never be registered"; then
    success "releaseprivate help states the permanence of the spend"
else
    fail "releaseprivate help does not state permanence: $(echo "$RELHELP" | head -3)"
fi

ANN="$(rpc collateralnode announceprivate 2>&1)"
if echo "$ANN" | grep -qi "holds no private collateral registration"; then
    success "announceprivate refuses with nothing registered"
else
    fail "announceprivate did not refuse: $(echo "$ANN" | head -3)"
fi

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ]
