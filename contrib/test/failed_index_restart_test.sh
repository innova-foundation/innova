#!/usr/bin/env bash
# Restart behaviour of a flagged block and of an index whose DAG vertex is missing:
# invalidate/reconsider across restarts, reconsider refused until a restart rebuilds an
# erased vertex, and a rebuilt main-chain vertex lowering the order-rebuild floor.
set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="${FIR_TEST_DIR:-/tmp/innova_failed_index_restart_$$}"
KEEP_DIR="${KEEP_DIR:-0}"
PORT="${FIR_PORT:-28870}"
RPCPORT="${FIR_RPC_PORT:-28880}"
RPCUSER="firtest"; RPCPASS="firtestpass"

# Regtest: DAG fork 11, epoch-state V3 at 311. Everything here happens above 311.
H_START=330
BOUNDARY_B=311

PASSED=0; FAILED=0
log()     { echo -e "${YELLOW}[....]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }

D="$TEST_DIR/node0"
rpc() { "$INNOVAD" -datadir="$D" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT "$@" 2>&1; }
height()   { rpc getblockcount 2>/dev/null | tr -d '"[:space:]'; }
besthash() { rpc getbestblockhash 2>/dev/null | tr -d '"[:space:]'; }
is_int()   { echo "${1:-}" | grep -qE '^[0-9]+$'; }
jval()     { echo "$1" | sed -n "s/.*\"$2\" *: *\([^,}\"]*\).*/\1/p" | tr -d '[:space:]' | head -1; }
logfile()  { echo "$D/regtest/debug.log"; }
count_log(){ local n; n="$(grep -c -- "$1" "$(logfile)" 2>/dev/null)"; echo "${n:-0}"; }
daemon_pids() { pgrep -f -- "-datadir=$D -regtest -daemon" 2>/dev/null; }

write_conf() {
    mkdir -p "$D"
    cat > "$D/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPCPORT
port=$PORT
listen=0
dnsseed=0
stakingmode=0
nofinalityvoting=1
regtestboundaryb=$BOUNDARY_B
regtestiv5rehearsal=1
EOF
}

start_node() {
    "$INNOVAD" -datadir="$D" -regtest -daemon >/dev/null 2>&1
    local i
    for i in $(seq 1 120); do
        rpc getinfo >/dev/null 2>&1 && return 0
        daemon_pids >/dev/null 2>&1 || { sleep 2; daemon_pids >/dev/null 2>&1 || return 1; }
        sleep 1
    done
    return 1
}

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    local i
    for i in $(seq 1 120); do
        daemon_pids >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

mine_to() {
    local target="$1" i h
    for i in $(seq 1 120); do
        h="$(height)"
        is_int "$h" || { sleep 2; continue; }
        [ "$h" -ge "$target" ] && return 0
        rpc setgenerate true $(( target - h )) >/dev/null 2>&1
        sleep 2
    done
    return 1
}

# The start must not be a refusal: the loader's fatal lines name the condition.
assert_clean_start() {
    local what="$1"
    if [ "$(count_log 'LoadDAGLinks: FATAL')" -ne "${FATAL_BASE:-0}" ]; then
        fail "$what: the loader refused the datadir"; grep -- 'LoadDAGLinks: FATAL' "$(logfile)" | tail -2
        return 1
    fi
    return 0
}

cleanup() {
    stop_node || pkill -9 -f -- "-datadir=$D -regtest -daemon" 2>/dev/null || true
    if [ "$KEEP_DIR" = "1" ]; then echo "kept $TEST_DIR"; else rm -rf "$TEST_DIR"; fi
}
trap cleanup EXIT

[ -x "$INNOVAD" ] || { echo "no innovad at $INNOVAD"; exit 1; }
write_conf
start_node || { fail "node did not start"; exit 1; }
mine_to "$H_START" || { fail "could not mine to $H_START"; exit 1; }
TIP_H="$(height)"; TIP_HASH="$(besthash)"
TARGET=$(( TIP_H - 3 ))
TARGET_HASH="$(rpc getblockhash "$TARGET" | tr -d '"[:space:]')"
log "tip $TIP_H ($TIP_HASH); invalidating $TARGET ($TARGET_HASH)"

# ---- 1. flag persists with the vertex; reconsider reports and restores; restart-stable
rpc invalidateblock "$TARGET_HASH" >/dev/null 2>&1
[ "$(height)" -eq $(( TARGET - 1 )) ] && success "invalidateblock rolled the tip back to $((TARGET - 1))" || fail "tip after invalidateblock is $(height), expected $((TARGET - 1))"
stop_node || fail "stop 1"
FATAL_BASE="$(count_log 'LoadDAGLinks: FATAL')"
start_node || fail "restart 1"
assert_clean_start "restart with a flagged block" && success "restart with a flagged block loads"
[ "$(height)" -eq $(( TARGET - 1 )) ] && success "the flag survived the restart" || fail "tip after restart is $(height), expected $((TARGET - 1))"

R="$(rpc reconsiderblock "$TARGET_HASH")"
[ "$(jval "$R" flags_cleared)" = "true" ] && success "reconsiderblock reports flags_cleared" || fail "reconsiderblock result: $R"
[ "$(jval "$R" tip_moved)" = "true" ] && success "reconsiderblock reports tip_moved" || fail "reconsiderblock result: $R"
[ "$(besthash)" = "$TIP_HASH" ] && success "the tip is back at $TIP_H" || fail "tip after reconsider is $(height) $(besthash)"
stop_node || fail "stop 2"
start_node || fail "restart 2"
assert_clean_start "restart after reconsider" && [ "$(besthash)" = "$TIP_HASH" ] && success "the restored tip survived a restart" || fail "tip after restart 2 is $(height)"

# ---- 2. flagged + vertex erased: refused with the flag intact; rebuilt at the next start
rpc invalidateblock "$TARGET_HASH" >/dev/null 2>&1
rpc erasedagvertex "$TARGET_HASH" >/dev/null 2>&1
R="$(rpc reconsiderblock "$TARGET_HASH")"
echo "$R" | grep -q "no DAG vertex" && success "reconsiderblock refuses the vertex-less flagged block" || fail "reconsiderblock did not refuse: $R"
[ "$(height)" -eq $(( TARGET - 1 )) ] && success "the refused reconsider changed nothing" || fail "tip moved to $(height) on a refused reconsider"
REBUILT_BASE="$(count_log 'rebuilt DAG vertex')"
stop_node || fail "stop 3"
start_node || fail "restart 3"
assert_clean_start "restart with a flagged, vertex-less block" && success "restart with a flagged, vertex-less block loads"
[ "$(count_log 'rebuilt DAG vertex')" -gt "$REBUILT_BASE" ] && success "the loader rebuilt the missing vertex" || fail "no 'rebuilt DAG vertex' line after restart 3"
R="$(rpc reconsiderblock "$TARGET_HASH")"
[ "$(jval "$R" flags_cleared)" = "true" ] && [ "$(besthash)" = "$TIP_HASH" ] && success "reconsiderblock succeeds after the rebuild; tip back at $TIP_H" || fail "reconsider after rebuild: $R (tip $(height))"

# ---- 3. a main-chain block below the tip loses its vertex: rebuilt, floor lowered, persisted once
MID=$(( TIP_H - 10 ))
MID_HASH="$(rpc getblockhash "$MID" | tr -d '"[:space:]')"
rpc erasedagvertex "$MID_HASH" >/dev/null 2>&1
REBUILT_BASE="$(count_log 'rebuilt DAG vertex')"
stop_node || fail "stop 4"
start_node || fail "restart 4"
assert_clean_start "restart with a main-chain vertex missing" && success "restart with a main-chain vertex missing loads"
grep -q -- "rebuilt DAG vertex ${MID_HASH:0:20} at height $MID" "$(logfile)" && success "the vertex at $MID was rebuilt from disk" || fail "no rebuild line for $MID"
grep -q -- "Found DAG clean height $(( MID - 1 ))" "$(logfile)" && success "the order rebuild started below the rebuilt vertex ($((MID - 1)))" || { fail "the order-rebuild floor was not lowered to $((MID - 1))"; grep -- 'IDAG: Found DAG clean height' "$(logfile)" | tail -1; }
grep -q -- "persisted 1 rebuilt DAG vertices" "$(logfile)" && success "the rebuilt vertex was persisted with its order fields" || fail "no persist line for the rebuilt vertex"
[ "$(besthash)" = "$TIP_HASH" ] && success "the tip is unchanged at $TIP_H" || fail "tip after restart 4 is $(height)"
REBUILT_AFTER="$(count_log 'rebuilt DAG vertex')"
stop_node || fail "stop 5"
start_node || fail "restart 5"
assert_clean_start "restart after the rebuild" >/dev/null
[ "$(count_log 'rebuilt DAG vertex')" -eq "$REBUILT_AFTER" ] && success "the following start had nothing to rebuild" || fail "the vertex was rebuilt again on restart 5"
mine_to $(( TIP_H + 5 )) && success "the node mines on the rebuilt state ($(height))" || fail "the node could not mine after the rebuild"

echo
echo "passed=$PASSED failed=$FAILED"
[ "$FAILED" -eq 0 ]
