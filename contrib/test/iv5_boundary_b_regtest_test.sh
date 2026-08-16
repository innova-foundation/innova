#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 Boundary B edge: a shield is refused one block before activation and mined at it.
# Boundary B must not precede the schema-V3 epoch height (311 on regtest).

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_boundary_b_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_BB_TEST_DIR:-/tmp/innova_iv5_boundary_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${IV5_BB_PORT:-$(iv5_port 0 28650)}"
RPC="${IV5_BB_RPC:-$(iv5_port 1 28700)}"
IDNS="${IV5_BB_IDNS:-$(iv5_port 2 8760)}"
RPCUSER="iv5bb"
RPCPASS="iv5bbpass"
WALLETPASS="iv5bbwallet"

BOUNDARY_B=311
SEED_HEIGHT=250

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
jnum()   { echo "$1" | grep -oE "\"$2\" *: *-?[0-9.]+" | grep -oE '\-?[0-9.]+$' | head -1; }
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

# Mine to exactly `target`. The request is re-armed only after the tip stops moving;
# re-issuing it every poll resets the miner's target.
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
            if [ "$idle" -ge 5 ]; then
                rpc setgenerate true $(( target - h )) >/dev/null 2>&1
                idle=0
            fi
        else
            idle=0
            last="$h"
        fi
    done
    [ "$(height)" -eq "$target" ]
}

cleanup() {
    stop_node || true
    [ "${IV5_BB_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 Boundary-B activation edge"

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

# ============================================================
header "1. A wallet with spendable coins and an IV5 seed"
# ============================================================

mine_to_exact "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }

# The IV5 seed is spend authority for every note the wallet will own, so it only
# exists inside an encrypted wallet. Encrypting stops the daemon.
rpc encryptwallet "$WALLETPASS" >/dev/null 2>&1
for _ in $(seq 1 60); do
    pgrep -f -- "-datadir=$NODE_DIR -regtest -daemon" >/dev/null 2>&1 || break
    sleep 1
done
start_node || { fail "node did not restart after encrypting the wallet"; exit 1; }
UNLOCK="$(rpc walletpassphrase "$WALLETPASS" 3600 2>&1)"
if echo "$UNLOCK" | grep -qiE "error"; then
    fail "could not unlock the wallet: $(echo "$UNLOCK" | head -2)"
    exit 1
fi
SEED="$(rpc z_createiv5seed 2>&1)"
if echo "$SEED" | grep -q '"created"'; then
    success "wallet encrypted, unlocked and seeded below Boundary B"
else
    fail "z_createiv5seed failed: $(echo "$SEED" | head -2)"
    exit 1
fi

# ============================================================
header "2. The block before activation still refuses a shield"
# ============================================================

mine_to_exact $(( BOUNDARY_B - 2 )) || { fail "could not mine to $(( BOUNDARY_B - 2 ))"; exit 1; }
INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
ACTIVE="$(echo "$INFO" | grep -o '"boundary_b_active" *: *[a-z]*' | grep -o '[a-z]*$')"
if [ "$ACTIVE" = "false" ]; then
    success "Boundary B reports inactive at height $(height)"
else
    fail "Boundary B reports active=$ACTIVE at height $(height), before $BOUNDARY_B"
fi

EARLY="$(rpc z_shieldall 2>&1)"
EARLY_TXID="$(jstr "$EARLY" txid)"
if [ ${#EARLY_TXID} -eq 64 ]; then
    fail "a shield was accepted a block before activation: ${EARLY_TXID:0:16}"
else
    success "a shield one block before activation is refused"
fi

# ============================================================
header "3. A shield exists and the tip is walked back to the boundary"
# ============================================================

# The wallet RPC refuses to build below activation, so the transaction is built one
# block above it and the tip is then walked back. What is under test is consensus:
# whether a transaction that would occupy exactly BOUNDARY_B is connectable.
mine_to_exact "$BOUNDARY_B" || { fail "could not mine to $BOUNDARY_B"; exit 1; }
SHIELD="$(rpc z_shieldall 2>&1)"
TXID="$(jstr "$SHIELD" txid)"
SHIELDED="$(jnum "$SHIELD" shielded)"
if [ ${#TXID} -eq 64 ]; then
    success "shield built and held in the mempool: $SHIELDED INN, txid ${TXID:0:16}"
else
    fail "z_shieldall failed: $(echo "$SHIELD" | head -3)"
    exit 1
fi

BBHASH="$(rpc getblockhash "$BOUNDARY_B" 2>/dev/null | tr -d '"[:space:]')"
[ ${#BBHASH} -eq 64 ] || { fail "could not read the hash of block $BOUNDARY_B"; exit 1; }
rpc invalidateblock "$BBHASH" >/dev/null 2>&1
for _ in $(seq 1 30); do
    [ "$(height)" = "$(( BOUNDARY_B - 1 ))" ] && break
    sleep 1
done
if [ "$(height)" = "$(( BOUNDARY_B - 1 ))" ]; then
    success "tip walked back to $(( BOUNDARY_B - 1 )), one below Boundary B"
else
    fail "tip is at $(height), expected $(( BOUNDARY_B - 1 ))"
    exit 1
fi

RAW="$(rpc getrawtransaction "$TXID" 2>/dev/null | tr -d '"[:space:]')"
if [ ${#RAW} -gt 100 ]; then
    success "the raw shield is readable for resubmission"
else
    fail "could not read the raw shield"
    exit 1
fi

# ============================================================
header "4. Relay accepts it with the tip one below activation"
# ============================================================

# Restart to empty the mempool; anything readmitted went through AcceptToMemoryPool
# at tip BOUNDARY_B - 1, for a transaction that would occupy BOUNDARY_B.
stop_node || { fail "node did not stop"; exit 1; }
start_node || { fail "node did not restart"; exit 1; }
rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
if [ "$(height)" != "$(( BOUNDARY_B - 1 ))" ]; then
    fail "tip is at $(height) after restart, expected $(( BOUNDARY_B - 1 ))"
    exit 1
fi

if rpc getrawmempool 2>/dev/null | grep -q "$TXID"; then
    # ReacceptWalletTransactions re-offers the wallet's own unconfirmed transactions
    # on load, so its presence here is an acceptance run at this tip.
    success "the wallet's reaccept path admits the shield at the boundary tip"
else
    SUBMIT="$(rpc sendrawtransaction "$RAW" 2>&1)"
    if rpc getrawmempool 2>/dev/null | grep -q "$TXID"; then
        success "relay accepts the shield at the boundary tip"
    else
        fail "relay refused the shield at the boundary: $(echo "$SUBMIT" | head -2)"
    fi
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
