#!/usr/bin/env bash
# Periodic collateralnode-list refresh on a single-peer node: node0 announces,
# node1 relays, leaf node2 must list 127.0.0.1:14539 via its own periodic iseg refresh.
# The funded chain is cached under CN2HOP_FIXTURE; CN2HOP_USE_FIXTURE=0 always rebuilds.
set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="${CN2HOP_TEST_DIR:-/Volumes/rom/iv5tn-repro/cn2hop/run_$$}"
FIXTURE_DIR="${CN2HOP_FIXTURE:-/Volumes/rom/iv5tn-repro/cn2hop/fixture}"
USE_FIXTURE="${CN2HOP_USE_FIXTURE:-1}"
KEEP_DIR="${KEEP_DIR:-1}"
BASE_PORT="${CN2HOP_PORT_BASE:-27400}"; BASE_RPC="${CN2HOP_RPC_BASE:-27410}"; BASE_IDNS="${CN2HOP_IDNS_BASE:-27420}"
RPCUSER="cn2hoptest"; RPCPASS="cn2hoptestpass"
CN_PORT=14539                      # isee is refused off testnet unless the endpoint carries this port
CN_ENDPOINT="127.0.0.1:$CN_PORT"
# The regtest ladder pays 500 INN a block past 1811; a 25,000 INN send funded
# from the earlier 5-50 INN rungs alone needs ~900 inputs and fails the
# MAX_BLOCK_SIZE_GEN/5 limit in CreateTransaction.
FUND_HEIGHT="${CN2HOP_FUND_HEIGHT:-1900}"
COLLATERAL=25000
CONF_BLOCKS=18                     # >= COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY (15)
QUIET_SECS=65                      # clears node0's 60 s per-IP iseg slot before the reconnect
WINDOW_SECS="${CN2HOP_WINDOW:-240}"
MINE_THREADS="${CN2HOP_MINE_THREADS:-1}"

PASSED=0; FAILED=0
log()     { echo -e "${YELLOW}[....]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
header()  { echo; echo -e "${YELLOW}== $* ==${NC}"; }

node_dir()  { echo "$TEST_DIR/node$1"; }
node_port() { if [ "$1" = "0" ]; then echo "$CN_PORT"; else echo $((BASE_PORT + $1)); fi; }
node_rpc()  { echo $((BASE_RPC + $1)); }
logfile()   { echo "$(node_dir "$1")/regtest/debug.log"; }
is_int()    { echo "${1:-}" | grep -qE '^-?[0-9]+$'; }
is_hash()   { echo "${1:-}" | grep -qE '^[0-9a-f]{64}$'; }
rpc() { local n="$1"; shift; "$INNOVAD" -datadir="$(node_dir "$n")" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport="$(node_rpc "$n")" "$@" 2>&1; }
height() {
    local h i
    for i in 1 2 3 4 5; do
        h="$(rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]')"
        is_int "$h" && { echo "$h"; return 0; }
        sleep 1
    done
    echo ""
}
count_log()   { local n; n="$(grep -a -c -- "$2" "$(logfile "$1")" 2>/dev/null)"; echo "${n:-0}"; }
daemon_pids() { pgrep -f -- "-datadir=$(node_dir "$1") -regtest -daemon" 2>/dev/null; }
peer_count()  { rpc "$1" getpeerinfo 2>/dev/null | python3 -c '
import json, sys
try:
    p = json.load(sys.stdin); print(len(p) if isinstance(p, list) else -1)
except Exception:
    print(-1)'; }
# 1 when the node lists the announced endpoint, else 0.
cn_listed() { CN_EP="$CN_ENDPOINT" python3 -c '
import json, os, sys
try:
    d = json.load(sys.stdin); print(1 if isinstance(d, dict) and os.environ["CN_EP"] in d else 0)
except Exception:
    print(0)' <<< "$(rpc "$1" collateralnode list 2>/dev/null)"; }

# PEERS: node numbers to keep as persistent addnode peers. EXTRA: raw conf lines.
write_conf() {
    local n="$1" peers="$2" extra="${3:-}" d p
    d="$(node_dir "$n")"; mkdir -p "$d"
    {
        echo "regtest=1"; echo "server=1"; echo "rpcuser=$RPCUSER"; echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$n")"; echo "port=$(node_port "$n")"; echo "bind=127.0.0.1"
        echo "listen=1"; echo "dnsseed=0"; echo "nobootstrap=1"; echo "nosmsg=1"; echo "upnp=0"
        echo "listenonion=0"; echo "idnsport=$((BASE_IDNS + n))"; echo "maxconnections=32"
        echo "staking=0"; echo "debug=1"; echo "debugfs=1"
        for p in $peers; do echo "addnode=127.0.0.1:$(node_port "$p")"; done
        [ -n "$extra" ] && printf '%s\n' "$extra"
    } > "$d/innova.conf"
}
# node0 must announce an explicit port: ManageStatus would otherwise fill
# GetDefaultPort() and every receiver drops an endpoint that is not on 14539.
conf0_extra() { printf 'collateralnode=1\ncollateralnodeprivkey=%s\ncollateralnodeaddr=%s\n' "$CNKEY" "$CN_ENDPOINT"; }
launch_node() { "$INNOVAD" -datadir="$(node_dir "$1")" -regtest -daemon >/dev/null 2>&1; }
start_node() {
    local n="$1" i; launch_node "$n"
    for i in $(seq 1 300); do
        rpc "$n" getinfo >/dev/null 2>&1 && return 0
        if [ "$i" -gt 5 ] && ! daemon_pids "$n" >/dev/null 2>&1; then break; fi
        sleep 1
    done
    echo "  node$n did not answer after ${i}s; daemon $(daemon_pids "$n" >/dev/null 2>&1 && echo alive || echo gone); last log lines:"
    tail -12 "$(logfile "$n")" 2>/dev/null | cut -c1-160 | sed 's/^/    | /'
    return 1
}
stop_node() {
    local n="$1" i; rpc "$n" stop >/dev/null 2>&1 || true
    for i in $(seq 1 180); do daemon_pids "$n" >/dev/null 2>&1 || return 0; sleep 1; done
    return 1
}
kill_node() {
    local n="$1" pids i; pids="$(daemon_pids "$n")"; [ -n "$pids" ] || return 1
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null
    for i in $(seq 1 60); do daemon_pids "$n" >/dev/null 2>&1 || break; sleep 1; done
    rm -f "$(node_dir "$n")/regtest/innovad.pid" "$(node_dir "$n")/innovad.pid" 2>/dev/null
    return 0
}
wait_sync() {
    local target="$1" list="$2" limit="${3:-600}" i n h ok
    for i in $(seq 1 "$limit"); do
        ok=1; for n in $list; do h="$(height "$n")"; if ! is_int "$h" || [ "$h" -lt "$target" ]; then ok=0; break; fi; done
        [ "$ok" -eq 1 ] && return 0; sleep 1
    done
    return 1
}
# Mine on NODE to TARGET, re-arming a stalled miner.
mine_to() {
    local n="$1" target="$2" threads="${3:-$MINE_THREADS}" i h last stall=0
    h="$(height "$n")"; is_int "$h" || return 1; [ "$h" -ge "$target" ] && return 0
    last="$h"; rpc "$n" setgenerate true $((target - h)) "$threads" >/dev/null 2>&1
    for i in $(seq 1 4000); do
        h="$(height "$n")"
        is_int "$h" || { sleep 1; continue; }
        if [ "$h" -ge "$target" ]; then rpc "$n" setgenerate false 0 >/dev/null 2>&1; return 0; fi
        if [ "$h" = "$last" ]; then stall=$((stall + 1)); else stall=0; last="$h"; [ $((h % 250)) -lt 3 ] && log "  ...height $h/$target"; fi
        if [ "$stall" -ge 20 ]; then rpc "$n" setgenerate true $((target - h)) "$threads" >/dev/null 2>&1; stall=0; fi
        sleep 1
    done
    rpc "$n" setgenerate false 0 >/dev/null 2>&1; return 1
}
scrub_datadir() {
    local d="$1/regtest"
    rm -f "$d/debug.log" "$d/innovad.pid" "$d/.lock" "$1/innovad.pid" 2>/dev/null
    rm -f "$d"/database/__db.* 2>/dev/null
    rm -f "$1/innova.conf" 2>/dev/null
    return 0
}
save_fixture() {
    local n
    rm -rf "$FIXTURE_DIR"; mkdir -p "$FIXTURE_DIR"
    for n in 0 1 2; do
        cp -R "$(node_dir "$n")" "$FIXTURE_DIR/node$n" || return 1
        scrub_datadir "$FIXTURE_DIR/node$n"
    done
    echo "$CNKEY" > "$FIXTURE_DIR/cnkey"
    date +%s > "$FIXTURE_DIR/ready"
}
restore_fixture() {
    local n
    mkdir -p "$TEST_DIR"
    for n in 0 1 2; do
        cp -R "$FIXTURE_DIR/node$n" "$(node_dir "$n")" || return 1
        scrub_datadir "$(node_dir "$n")"
    done
    CNKEY="$(cat "$FIXTURE_DIR/cnkey")"
}
# node1 first (node2 dials it), node0 last (it dials node1 by onetry).
start_line() {
    local i
    start_node 1 || return 1
    start_node 2 || return 1
    T_NODE2_UP="$(date +%s)"
    start_node 0 || return 1
    rpc 0 addnode "127.0.0.1:$(node_port 1)" onetry >/dev/null 2>&1
    for i in $(seq 1 90); do
        [ "$(peer_count 0)" = "1" ] && [ "$(peer_count 1)" = "2" ] && [ "$(peer_count 2)" = "1" ] && return 0
        sleep 1
    done
    return 1
}

cleanup() {
    local n
    for n in 0 1 2; do rpc "$n" setgenerate false 0 >/dev/null 2>&1 || true; done
    for n in 0 1 2; do stop_node "$n" >/dev/null 2>&1 || kill_node "$n" >/dev/null 2>&1 || true; done
    if [ "$KEEP_DIR" = "1" ]; then echo "kept $TEST_DIR"; else rm -rf "$TEST_DIR"; fi
}
trap cleanup EXIT

[ -x "$INNOVAD" ] || { echo "no innovad at $INNOVAD"; exit 1; }
# A daemon left by an interrupted run still listens on these ports and would
# share its chain; refuse to run against it.
for n in 0 1 2; do
    for port in "$(node_port "$n")" "$(node_rpc "$n")"; do
        if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
            echo "port $port is in use by pid $(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t | head -1); stop it or move CN2HOP_PORT_BASE/CN2HOP_RPC_BASE"; exit 2
        fi
    done
done
mkdir -p "$TEST_DIR"
echo "innovad: $INNOVAD"
echo "sha256:  $(shasum -a 256 "$INNOVAD" | cut -d' ' -f1)"
echo "testdir: $TEST_DIR"

CNKEY=""
FROM_FIXTURE=0
[ "$USE_FIXTURE" = "1" ] && [ -f "$FIXTURE_DIR/ready" ] && FROM_FIXTURE=1

header "1. The line: node2 -> node1, node0 dialled in"
if [ "$FROM_FIXTURE" = "1" ]; then
    restore_fixture || { fail "could not restore the fixture from $FIXTURE_DIR"; exit 1; }
    log "restored the funded chain from $FIXTURE_DIR"
    write_conf 1 ""; write_conf 2 "1"; write_conf 0 "" "$(conf0_extra)"
    start_line || { fail "the line did not come up: node0=$(peer_count 0) node1=$(peer_count 1) node2=$(peer_count 2)"; exit 1; }
else
    write_conf 1 ""; write_conf 2 "1"
    start_node 1 || { fail "node1 did not start"; exit 1; }
    start_node 2 || { fail "node2 did not start"; exit 1; }
    CNKEY="$(rpc 1 collateralnode genkey 2>/dev/null | tr -d '"[:space:]')"
    [ "${#CNKEY}" -ge 50 ] || { fail "collateralnode genkey returned '$CNKEY'"; exit 1; }
    stop_node 1 >/dev/null 2>&1 || kill_node 1 >/dev/null 2>&1
    stop_node 2 >/dev/null 2>&1 || kill_node 2 >/dev/null 2>&1
    write_conf 0 "" "$(conf0_extra)"
    start_line || { fail "the line did not come up: node0=$(peer_count 0) node1=$(peer_count 1) node2=$(peer_count 2)"; exit 1; }
fi
success "node0 -> node1 <- node2, peers 1/2/1"

header "2. A $COLLATERAL INN collateral output on node0"
if [ "$FROM_FIXTURE" = "1" ]; then
    # One fresh block: every receiver drops an isee whose sigTime is more than
    # 120 s past its own tip's block time.
    mine_to 0 $(( $(height 0) + 1 )) || { fail "could not mine the freshening block"; exit 1; }
    wait_sync "$(height 0)" "0 1 2" || { fail "the line did not sync the freshening block"; exit 1; }
    success "chain at $(height 0), tip freshened"
else
    mine_to 0 "$FUND_HEIGHT" || { fail "could not mine to $FUND_HEIGHT"; exit 1; }
    wait_sync "$FUND_HEIGHT" "0 1 2" || { fail "the line did not sync to $FUND_HEIGHT"; exit 1; }
    ADDR0="$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    [ -n "$ADDR0" ] || { fail "node0 has no address"; exit 1; }
    TXID=""
    for attempt in 1 2 3 4; do
        TXID="$(rpc 0 sendtoaddress "$ADDR0" "$COLLATERAL" 2>/dev/null | tr -d '"[:space:]')"
        is_hash "$TXID" && break
        mine_to 0 $(( $(height 0) + 25 )) >/dev/null
    done
    is_hash "$TXID" || { fail "could not fund $COLLATERAL INN: $TXID"; exit 1; }
    mine_to 0 $(( $(height 0) + CONF_BLOCKS )) || { fail "could not confirm the collateral"; exit 1; }
    wait_sync "$(height 0)" "0 1 2" || { fail "the line did not sync the confirmation blocks"; exit 1; }
    success "collateral $TXID confirmed, line synced at $(height 0)"
    if [ "$USE_FIXTURE" = "1" ]; then
        for n in 0 1 2; do stop_node "$n" >/dev/null 2>&1 || kill_node "$n" >/dev/null 2>&1; done
        save_fixture || { fail "could not save the fixture"; exit 1; }
        log "saved the funded chain to $FIXTURE_DIR"
        write_conf 1 ""; write_conf 2 "1"; write_conf 0 "" "$(conf0_extra)"
        start_line || { fail "the line did not come back up after saving the fixture"; exit 1; }
    fi
fi

header "3. Isolate node0, announce, reconnect"
# The leaf can only be starved when its peer holds the entry with count != -1, so
# node1 must learn it from its own handshake iseg, not from a count=-1 relay.
ELAPSED=$(( $(date +%s) - T_NODE2_UP ))
[ "$ELAPSED" -lt 60 ] && sleep $(( 60 - ELAPSED ))
rpc 0 disconnectnode "127.0.0.1:$(node_port 1)" >/dev/null 2>&1
for i in $(seq 1 60); do [ "$(peer_count 0)" = "0" ] && [ "$(peer_count 1)" = "1" ] && break; sleep 1; done
[ "$(peer_count 0)" = "0" ] && [ "$(peer_count 1)" = "1" ] && success "node0 isolated from node1" \
    || { fail "isolation failed: node0=$(peer_count 0) node1=$(peer_count 1)"; exit 1; }
START_OUT="$(rpc 0 collateralnode start 2>&1 | tr -d '"')"
T_ANNOUNCE="$(date +%s)"
echo "$START_OUT" | grep -q "successfully started collateralnode" && success "node0 announced: $START_OUT" \
    || { fail "collateralnode start said: $START_OUT"; exit 1; }
[ "$(cn_listed 0)" = "1" ] && success "node0 holds its own entry $CN_ENDPOINT" || fail "node0 does not list $CN_ENDPOINT"
[ "$(cn_listed 1)" = "0" ] && [ "$(cn_listed 2)" = "0" ] && success "neither node1 nor node2 has the entry yet" \
    || fail "the entry leaked before the reconnect: node1=$(cn_listed 1) node2=$(cn_listed 2)"
# The iseg handler rate-limits per CNetAddr, so every loopback peer of node0
# shares one 60 s slot; let node1's pre-disconnect refresh slot expire.
sleep "$QUIET_SECS"
ASK2_BEFORE="$(count_log 2 'Asking for Collateralnode list from')"
MISB2_BEFORE="$(count_log 2 'Misbehaving:')"
rpc 0 addnode "127.0.0.1:$(node_port 1)" onetry >/dev/null 2>&1
T_RECONNECT="$(date +%s)"
log "reconnected at T+0 (announced $(( T_RECONNECT - T_ANNOUNCE ))s earlier)"

header "4. The leaf's own refresh is its only route"
N1_FIRST=-1; N2_FIRST=-1; LEAF_PEERS_OK=1; LEAF_PEERS_SEEN=""
for i in $(seq 1 $(( WINDOW_SECS / 2 ))); do
    NOW=$(( $(date +%s) - T_RECONNECT ))
    if [ "$N1_FIRST" -lt 0 ] && [ "$(cn_listed 1)" = "1" ]; then N1_FIRST="$NOW"; log "node1 lists the entry at T+${N1_FIRST}s"; fi
    PC2="$(peer_count 2)"
    case " $LEAF_PEERS_SEEN " in *" $PC2 "*) ;; *) LEAF_PEERS_SEEN="$LEAF_PEERS_SEEN $PC2";; esac
    [ "$PC2" = "1" ] || LEAF_PEERS_OK=0
    if [ "$(cn_listed 2)" = "1" ]; then N2_FIRST="$NOW"; log "node2 lists the entry at T+${N2_FIRST}s"; break; fi
    sleep 2
done
ASK2_AFTER="$(count_log 2 'Asking for Collateralnode list from')"
ASK2_N1="$(count_log 2 "Asking for Collateralnode list from 127.0.0.1:$(node_port 1)")"

[ "$N2_FIRST" -ge 0 ] && success "node2 learned $CN_ENDPOINT at T+${N2_FIRST}s (budget ${WINDOW_SECS}s)" \
    || fail "node2 never learned $CN_ENDPOINT within ${WINDOW_SECS}s of the reconnect"
[ "$N1_FIRST" -ge 0 ] && success "node1 learned the entry at T+${N1_FIRST}s" || fail "node1 never learned the entry"
if [ "$N1_FIRST" -ge 0 ] && [ "$N2_FIRST" -ge 0 ] && [ "$N1_FIRST" -le "$N2_FIRST" ]; then
    success "node1 held the entry before node2 (two hops, not a direct relay)"
else
    fail "ordering wrong: node1 T+$N1_FIRST, node2 T+$N2_FIRST"
fi
[ "$LEAF_PEERS_OK" = "1" ] && success "node2 had exactly one peer at every poll" \
    || fail "node2's peer count varied:$LEAF_PEERS_SEEN"
[ "$ASK2_AFTER" -gt "$ASK2_BEFORE" ] && success "node2 asked for the list $(( ASK2_AFTER - ASK2_BEFORE )) time(s) after the reconnect ($ASK2_N1 total to 127.0.0.1:$(node_port 1))" \
    || fail "node2 never asked for the list after the reconnect (single-peer refresh did not run)"
[ "$(count_log 2 'Misbehaving:')" -eq "$MISB2_BEFORE" ] && success "node2 scored nobody" \
    || fail "node2 scored a peer: $(( $(count_log 2 'Misbehaving:') - MISB2_BEFORE ))"

if [ "$N2_FIRST" -lt 0 ]; then
    header "diagnostics"
    echo "  node2 isee accepted:        $(count_log 2 'isee - Got NEW collateralnode entry')"
    echo "  node2 isee rejected:        $(count_log 2 'isee - Rejected collateralnode entry')"
    echo "  node2 isee seen at all:     $(count_log 2 'DEBUG-ISEE start')"
    echo "  node2 asked for list total: $ASK2_AFTER (before reconnect $ASK2_BEFORE)"
    echo "  node1 iseg served:          $(count_log 1 'iseg - Sent')"
    echo "  node1 iseg rate-limited:    $(count_log 1 'iseg - peer already asked me for the list')"
    echo "  node1 isee accepted:        $(count_log 1 'isee - Got NEW collateralnode entry')"
    echo "  node0 iseg served:          $(count_log 0 'iseg - Sent')"
    echo "  node0 registered:           $(count_log 0 'Adding to collateralnode list service')"
    echo "  node2 peer counts seen:    $LEAF_PEERS_SEEN"
fi

echo
echo "T_announce -> T_reconnect: $(( T_RECONNECT - T_ANNOUNCE ))s"
echo "node1 first-seen: T+${N1_FIRST}s   node2 first-seen: T+${N2_FIRST}s"
echo "passed=$PASSED failed=$FAILED"
exit "$FAILED"
