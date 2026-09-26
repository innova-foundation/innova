#!/usr/bin/env bash
# Copyright (c) 2026 The Innova developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# One NullSend v2008 round on three regtest nodes (node0 coordinates, node1/node2 seat) over
# the SOCKS stub, or real Tor with IV5_NULLSEND_TOR=<tor binary>. Takes 30-45 minutes.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
STUB="$INNOVA_ROOT/contrib/test/mix_socks_stub.py"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_nullsend_regtest_test || exit 1
TEST_DIR="${IV5_NULLSEND_TEST_DIR:-$(iv5_test_dir /tmp/innova_iv5_nullsend_$$)}"
NUM_NODES=3
BASE_PORT="${IV5_NULLSEND_BASE_PORT:-$(iv5_port 0 27650)}"
BASE_RPC="${IV5_NULLSEND_BASE_RPC:-$(iv5_port 10 27700)}"
STUB_PORT="$(iv5_port 20 27790)"
COORD_PORT="$(iv5_port 21 27791)"
DIR_PORT="$(iv5_port 22 27792)"
# Nothing ever listens here: the proxy and directory a seat must report as unreachable.
DEAD_PORT="$(iv5_port 24 27794)"
DEAD_ONION="deadaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
COORD_ONION="coordaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
DIR_ONION="directoryaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
TOR_BIN="${IV5_NULLSEND_TOR:-}"
TOR_SOCKS_PORT="$(iv5_port 23 27793)"
RPCUSER=nullsend
RPCPASS=nullsendpass
WALLETPASS=nullsendwallet
BOUNDARY_B=311
DENOMINATION=1
SEATS=2
ROUND_DEADLINE_SECS="${IV5_NULLSEND_ROUND_SECS:-3000}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
PASSED=0; FAILED=0
log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
header()  { echo -e "\n${CYAN}== $* ==${NC}"; }

epoch_start() { echo $(( 11 + ($1 - 1) * 300 )); }

node_dir()  { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc()  { echo $((BASE_RPC + $1)); }

rpc() {
    local node="$1"; shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser="$RPCUSER" \
        -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@"
}
jget() { python3 -c 'import json,sys
try:
    d=json.loads(sys.argv[1]); v=d
    for k in sys.argv[2].split("."):
        v=v[int(k)] if isinstance(v,list) else v[k]
    print(v)
except Exception:
    print("")' "$1" "$2"; }
# A Python expression over the parsed reply d.
jpy() { python3 -c 'import json,sys
try:
    d=json.loads(sys.argv[1])
    print(eval(sys.argv[2]))
except Exception:
    print("")' "$1" "$2"; }
height() { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
is_int() { echo "$1" | grep -qE '^-?[0-9]+$'; }


write_conf() {
    local node="$1" dir; dir="$(node_dir "$node")"
    mkdir -p "$dir"
    {
        echo "regtest=1"
        echo "rpcuser=$RPCUSER"
        echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$node")"
        echo "port=$(node_port "$node")"
        echo "listen=1"
        echo "dnsseed=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "staking=0"
        echo "nofinalityvoting=0"
        echo "finalityvotemode=transparent"
        echo "regtestboundaryb=$BOUNDARY_B"
        echo "regtestiv5rehearsal=1"
        echo "debug=1"
        # A -nativetor node dials through its bundled tor and names its coordinator onion from
        # the service's hostname file.
        if [ -n "$TOR_BIN" ] && [ "$node" -eq 0 ]; then
            echo "nativetor=1"
            echo "onionseed=0"
        elif [ -n "$TOR_BIN" ]; then
            echo "mixproxy=127.0.0.1:$TOR_SOCKS_PORT"
        else
            echo "mixproxy=127.0.0.1:$STUB_PORT"
        fi
        [ -n "$DIR_ONION" ] && echo "mixdir=$DIR_ONION:$DIR_PORT"
        if [ "$node" -eq 0 ]; then
            echo "mixcoordinatorport=$COORD_PORT"
            echo "mixdirectoryport=$DIR_PORT"
            [ -z "$TOR_BIN" ] && echo "mixonion=$COORD_ONION"
        fi
        for ((peer=0; peer<NUM_NODES; peer++)); do
            [ "$peer" -eq "$node" ] && continue
            echo "addnode=127.0.0.1:$(node_port "$peer")"
        done
    } > "$dir/innova.conf"
}

wait_rpc() {
    for _ in $(seq 1 120); do
        rpc "$1" getblockcount >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

start_node() {
    # Retried: a node that has just stopped can still hold its datadir lock for a moment.
    for _ in 1 2 3 4 5 6; do
        "$INNOVAD" -datadir="$(node_dir "$1")" -regtest -daemon >/dev/null 2>&1
        wait_rpc "$1" && return 0
        sleep 5
    done
    return 1
}

wait_rpc_down() {
    for _ in $(seq 1 90); do
        rpc "$1" getblockcount >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

stop_node() {
    rpc "$1" setgenerate false 0 >/dev/null 2>&1 || true
    rpc "$1" stop >/dev/null 2>&1 || true
    wait_rpc_down "$1"
}

STUB_PID=""
TOR_PID=""
MINER_PID=""
cleanup() {
    [ -n "$MINER_PID" ] && kill "$MINER_PID" 2>/dev/null
    for ((n=0; n<NUM_NODES; n++)); do stop_node "$n"; done
    [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
    [ -n "$TOR_PID" ] && kill "$TOR_PID" 2>/dev/null
    iv5_ports_release
    echo
    echo "passed: $PASSED  failed: $FAILED"
    if [ "$FAILED" -eq 0 ] && [ "${KEEP_DIR:-0}" != "1" ]; then
        rm -rf "$TEST_DIR"
    else
        echo "kept $TEST_DIR"
    fi
}
trap cleanup EXIT

wait_sync() {
    local target="$1"
    for _ in $(seq 1 600); do
        local ok=1 h
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
    local target="$1" h
    while :; do
        h="$(height 0)"
        is_int "$h" || return 1
        [ "$h" -ge "$target" ] && break
        local step=$(( target - h )); [ "$step" -gt 50 ] && step=50
        rpc 0 setgenerate true "$step" 1 >/dev/null 2>&1
        for _ in $(seq 1 300); do
            h="$(height 0)"
            is_int "$h" && [ "$h" -ge $(( target < h + step ? target : h )) ] && break
            sleep 1
        done
        rpc 0 setgenerate false 0 >/dev/null 2>&1
        wait_sync "$(height 0)" || true
    done
    wait_sync "$target"
}

# Stop at each epoch boundary long enough for the voters' five-second cycle to land their
# votes inside the inclusion window, which is what keeps epochs HARD.
advance_epochs() {
    local from="$1" to="$2" e b
    for ((e=from; e<=to; e++)); do
        b="$(epoch_start "$e")"
        mine_to "$b" || return 1
        sleep 18
        mine_to $(( b + 3 )) || return 1
    done
}

header "NullSend v2008 regtest round"
[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }
iv5_require_free_ports $(for ((n=0; n<NUM_NODES; n++)); do echo "$(node_port "$n") $(node_rpc "$n")"; done) \
    "$STUB_PORT" "$COORD_PORT" "$DIR_PORT" "$DEAD_PORT" || exit 1
rm -rf "$TEST_DIR"; mkdir -p "$TEST_DIR"
HELP="$("$INNOVAD" -? 2>&1)"
missing=""
for opt in -mixdir= -mixproxy= -mixcoordinatorport= -mixdirectoryport= -mixonion=; do
    echo "$HELP" | grep -q -- "$opt" || missing="$missing $opt"
done
[ -z "$missing" ] && success "-help documents every mix setting" || fail "-help does not document:$missing"

if [ -n "$TOR_BIN" ]; then
    [ -x "$TOR_BIN" ] || { fail "tor not found at $TOR_BIN"; exit 1; }
    mkdir -p "$TEST_DIR/torclient"; chmod 700 "$TEST_DIR/torclient"
    "$TOR_BIN" --SocksPort "$TOR_SOCKS_PORT" --DataDirectory "$TEST_DIR/torclient" \
        --Log "notice file $TEST_DIR/torclient/tor.log" --ignore-missing-torrc -f /dev/null \
        >/dev/null 2>&1 &
    TOR_PID=$!
    # The directory's onion name exists once node0's tor has made its service key.
    DIR_ONION=""
    write_conf 0
    start_node 0 || { fail "node0 did not start"; exit 1; }
    for _ in $(seq 1 180); do
        DIR_ONION="$(cat "$(node_dir 0)/onion-mix-directory/hostname" 2>/dev/null)"
        [ -n "$DIR_ONION" ] && [ -s "$(node_dir 0)/onion-mix-coordinator/hostname" ] && break
        sleep 1
    done
    [ -n "$DIR_ONION" ] || { fail "node0's tor made no mix onion services"; exit 1; }
    for _ in $(seq 1 180); do
        grep -q "Bootstrapped 100%" "$TEST_DIR/torclient/tor.log" 2>/dev/null && break
        sleep 1
    done
    grep -q "Bootstrapped 100%" "$TEST_DIR/torclient/tor.log" || { fail "the seats' tor did not bootstrap"; exit 1; }
    # node0 reads -mixdir when it restarts after encrypting its wallet.
    for ((n=0; n<NUM_NODES; n++)); do write_conf "$n"; done
    for n in 1 2; do start_node "$n" || { fail "node$n did not start"; exit 1; }; done
    success "three nodes up over Tor; directory $DIR_ONION:$DIR_PORT, coordinator $(cat "$(node_dir 0)/onion-mix-coordinator/hostname")"
else
    python3 "$STUB" --port "$STUB_PORT" > "$TEST_DIR/stub.log" 2>&1 &
    STUB_PID=$!
    for ((n=0; n<NUM_NODES; n++)); do write_conf "$n"; start_node "$n" || { fail "node$n did not start"; exit 1; }; done
    success "three nodes up; node0 runs the directory on $DIR_PORT and a coordinator on $COORD_PORT"
fi

header "1. A chain past Boundary B, and a shielded note for each seat"
# z_shieldall sweeps every transparent output, so a seat gets only what it shields first and
# its voting stake after: the transparent finality lane needs two voters above the floor.
mine_to $(( BOUNDARY_B + 9 )) || { fail "could not mine past Boundary B"; exit 1; }
# An IV5 seed lives in an encrypted wallet; encrypting stops the node.
for ((n=0; n<NUM_NODES; n++)); do
    rpc "$n" encryptwallet "$WALLETPASS" >/dev/null 2>&1
    wait_rpc_down "$n" || { fail "node$n did not stop after encrypting"; exit 1; }
    sleep 3
    start_node "$n" || { fail "node$n did not restart after encrypting"; exit 1; }
    rpc "$n" walletpassphrase "$WALLETPASS" 1000000 >/dev/null 2>&1
    SEED="$(rpc "$n" z_createiv5seed 2>&1)"
    echo "$SEED" | grep -q '"created"' || { fail "node$n z_createiv5seed: $SEED"; exit 1; }
done
wait_sync "$(height 0)" || { fail "the fleet did not rejoin"; exit 1; }
success "every wallet is encrypted, unlocked and holds an IV5 seed"
for n in 1 2; do
    ADDR="$(rpc "$n" getnewaddress | tr -d '"[:space:]')"
    rpc 0 sendtoaddress "$ADDR" 5 >/dev/null || { fail "could not fund node$n for shielding"; exit 1; }
done
mine_to $(( $(height 0) + 3 ))
for n in 1 2; do
    SH="$(rpc "$n" z_shieldall 2>&1)"
    [ -n "$(jget "$SH" txid)" ] && success "node$n shielded $(jget "$SH" shielded) INN" || { fail "node$n could not shield: $SH"; exit 1; }
done
mine_to $(( $(height 0) + 3 ))
for n in 1 2; do
    ADDR="$(rpc "$n" getnewaddress | tr -d '"[:space:]')"
    rpc 0 sendtoaddress "$ADDR" 600 >/dev/null || { fail "could not fund node$n with stake"; exit 1; }
done
mine_to $(( $(height 0) + 3 ))
# The coordinator pays for its record from the pool.
SH="$(rpc 0 z_shieldall 2>&1)"
[ -n "$(jget "$SH" txid)" ] && success "node0 shielded $(jget "$SH" shielded) INN to pay for records" || { fail "node0 could not shield: $SH"; exit 1; }
mine_to $(( $(height 0) + 3 ))

header "2. Finality moving, and a note prepared for the tier"
advance_epochs 3 5 || { fail "the fleet stalled while finality started"; exit 1; }
log "finality: $(rpc 0 getfinalityinfo 2>/dev/null | tr -d '\n' | cut -c1-200)"
for n in 1 2; do
    PREP="$(rpc "$n" mixprepare "$DENOMINATION" 2>&1 | tr -d '"[:space:]')"
    [ ${#PREP} -eq 64 ] && success "node$n prepared a $DENOMINATION INN note: $PREP" || { fail "node$n mixprepare: $PREP"; exit 1; }
done
mine_to $(( $(height 0) + 3 ))
advance_epochs 6 8 || { fail "the fleet stalled after preparing notes"; exit 1; }
for n in 1 2; do
    log "node$n: $(rpc "$n" z_getshieldedinfo | python3 -c 'import json,sys; d=json.load(sys.stdin); print("balance", d.get("privacy_vnext_balance"), "held", d.get("privacy_vnext_held_balance"))')"
done

header "2b. Settings, proxy readiness, notes and cancel from RPC"
S="$(rpc 1 mixsettings 2>&1)"
[ "$(jpy "$S" 'd["current"]["directories"] == ["'"$DIR_ONION:$DIR_PORT"'"]')" = "True" ] && \
    [ "$(jget "$S" current.proxy_source)" = "config" ] && [ "$(jget "$S" running)" = "True" ] && \
    success "mixsettings: the running service reads its directory and proxy from innova.conf" || \
    fail "mixsettings: $S"
PS="$(rpc 2 mixproxystatus 2>&1)"
[ "$(jget "$PS" ready)" = "True" ] && [ "$(jget "$PS" isolation)" = "True" ] && \
    success "mixproxystatus: the configured proxy is ready ($(jget "$PS" proxy), $(jget "$PS" latency_ms) ms)" || \
    fail "mixproxystatus on the live proxy: $PS"
SET="$(rpc 2 mixsetsetting mixproxy "127.0.0.1:$DEAD_PORT" 2>&1)"
PS="$(rpc 2 mixproxystatus 2>&1)"
[ "$(jget "$SET" applied)" = "now" ] && [ "$(jget "$PS" reachable)" = "False" ] && \
    [ "$(jget "$PS" ready)" = "False" ] && [ "$(jget "$PS" proxy)" = "127.0.0.1:$DEAD_PORT" ] && \
    [ "$(jget "$PS" source)" = "settings file" ] && \
    success "mixsetsetting moves the proxy at once and mixproxystatus reports the dead one: $(jget "$PS" error)" || \
    fail "a dead proxy: set $SET status $PS"
SETFILE="$(jget "$(rpc 2 mixsettings)" settings_file)"
grep -q "mixproxy=127.0.0.1:$DEAD_PORT" "$SETFILE" 2>/dev/null && \
    success "the proxy change is kept in $SETFILE" || fail "mixsettings.conf: $SETFILE: $(cat "$SETFILE" 2>&1)"
rpc 2 mixsetsetting mixproxy "" >/dev/null 2>&1
PS="$(rpc 2 mixproxystatus 2>&1)"
[ "$(jget "$PS" ready)" = "True" ] && [ "$(jget "$PS" source)" = "config" ] && \
    success "an empty value returns the proxy to innova.conf" || fail "proxy restore: $PS"
BAD="$(rpc 2 mixsetsetting mixdir "example.com:80" 2>&1)"
echo "$BAD" | grep -q "onion" && success "mixsetsetting refuses a directory that is not an onion" || fail "bad mixdir accepted: $BAD"
SET="$(rpc 1 mixsetsetting mixcoordinatorport 4444 2>&1)"
[ "$(jget "$SET" restart_required)" = "True" ] && [ "$(jget "$(rpc 1 mixsettings)" restart_required)" = "True" ] && \
    success "a port change is kept for the next start and says so" || fail "port change: $SET"
rpc 1 mixsetsetting mixcoordinatorport "" >/dev/null 2>&1
[ "$(jget "$(rpc 1 mixsettings)" restart_required)" = "False" ] && success "removing it clears the restart" || fail "restart flag stuck: $(rpc 1 mixsettings)"
for n in 1 2; do
    N="$(rpc "$n" mixnotes 2>&1)"
    [ "$(jpy "$N" 'sum(1 for x in d["notes"] if x["prepared"] and x["usable"] and x["eligible_height"] > 0)')" -ge 1 ] 2>/dev/null && \
        success "node$n mixnotes: a prepared, usable note, a round's anchor covers it from height $(jpy "$N" 'min(x["eligible_height"] for x in d["notes"] if x["prepared"])') (tip $(jget "$N" tip))" || \
        fail "node$n mixnotes: $N"
done

header "3. A round on the clock"
# About one block a second from here on; the voters keep finality current on their own.
( while :; do rpc 0 setgenerate true 1 1 >/dev/null 2>&1; sleep 1; done ) &
MINER_PID=$!

COORD_ADDR="$(rpc 0 getnewaddress | tr -d '"[:space:]')"
CO=""
for _ in $(seq 1 3); do
    CO="$(rpc 0 mixcoordinate "$COORD_ADDR" "$DENOMINATION" "$SEATS" 2>&1)" && break
    sleep 5
done
PUBKEY="$(jget "$CO" coordinator)"
[ ${#PUBKEY} -eq 66 ] && success "coordinator $PUBKEY" || { fail "mixcoordinate: $CO"; exit 1; }
# The record slot is fixed only once the coordinator's plan succeeds in a publishing window.
SLOT=0
for _ in $(seq 1 90); do
    SLOT="$(jget "$(rpc 0 mixstatus)" jobs.0.recordslot)"
    is_int "$SLOT" && [ "$SLOT" -gt 0 ] && break
    sleep 10
done
is_int "$SLOT" && [ "$SLOT" -gt 0 ] && success "the coordinator planned its round for record slot $SLOT" || { fail "the coordinator never planned: $(jget "$(rpc 0 mixstatus)" jobs.0.status)"; exit 1; }
# A seat for a slot far ahead waits to find its round; cancelling it costs nothing.
J="$(rpc 1 mixjoin "$PUBKEY" $(( SLOT + 50 )) 2>&1)"
DECOY="$(jget "$J" id)"
if is_int "$DECOY"; then
    C="$(rpc 1 mixcancel "$DECOY" 2>&1)"
    M="$(rpc 1 mixstatus 2>&1)"
    [ "$(jget "$C" cancelled)" = "True" ] && [ "$(jget "$M" jobs.0.cancelled)" = "True" ] && \
        [ "$(jget "$M" jobs.0.finished)" = "True" ] && is_int "$(jget "$M" jobs.0.started)" && \
        [ "$(jget "$M" jobs.0.updated)" -ge "$(jget "$M" jobs.0.started)" ] && \
        success "mixcancel stops a seat still finding its round: $(jget "$M" jobs.0.status)" || \
        fail "mixcancel on a finding seat: $C / $M"
    AGAIN="$(rpc 1 mixcancel "$DECOY" 2>&1)"
    echo "$AGAIN" | grep -q "ended" && success "a finished seat cannot be cancelled again" || fail "second cancel: $AGAIN"
    CL="$(rpc 1 mixclear 2>&1)"
    [ "$(jget "$CL" cleared)" = "1" ] && [ "$(jpy "$(rpc 1 mixstatus)" 'len(d["jobs"])')" = "0" ] && \
        success "mixclear removes the cancelled seat" || fail "mixclear: $CL / $(rpc 1 mixstatus)"
else
    fail "decoy mixjoin: $J"
fi

# The round, found through the directory rather than handed over.
ROUND=""
for _ in $(seq 1 36); do
    L="$(rpc 1 mixlistrounds 2>&1)"
    ROUND="$(jpy "$L" '[r["round"] for r in d["rounds"] if r["coordinator"] == "'"$PUBKEY"'" and r["recordslot"] == '"$SLOT"'][0]')"
    [ -n "$ROUND" ] && break
    sleep 10
done
if [ -n "$ROUND" ]; then
    ROW="$(jpy "$L" '[r for r in d["rounds"] if r["round"] == "'"$ROUND"'"][0]')"
    success "mixlistrounds finds the round through the directory: $ROW"
    [ "$(jpy "$L" '[r for r in d["rounds"] if r["round"] == "'"$ROUND"'"][0]["seats"]')" = "$SEATS" ] && \
        [ "$(jpy "$L" '[r for r in d["rounds"] if r["round"] == "'"$ROUND"'"][0]["record"] in ("pending", "settled")')" = "True" ] && \
        [ "$(jpy "$L" 'len(d["failed"])')" = "0" ] && \
        success "the listed round names its seats and this chain's record for it is pending or settled" || \
        fail "listed round fields: $ROW / failed $(jpy "$L" 'd["failed"]')"
    for n in 1 2; do
        rpc "$n" mixlistrounds >/dev/null 2>&1
        N="$(rpc "$n" mixnotes "$ROUND" 2>&1)"
        [ "$(jpy "$N" 'any(x.get("eligible") for x in d["notes"])')" = "True" ] && \
            success "node$n mixnotes: a note can take a seat in the listed round" || \
            fail "node$n has no note eligible for the round: $N"
    done
else
    fail "mixlistrounds never listed the round: $L"
fi
# A directory that does not answer is reported, not fatal; the live list follows the setting.
rpc 2 mixsetsetting mixdir "$DEAD_ONION:$DEAD_PORT" >/dev/null 2>&1
L2="$(rpc 2 mixlistrounds 2>&1)"
echo "$L2" | grep -q "$DEAD_ONION" && success "mixlistrounds reports a directory that does not answer" || fail "dead directory: $L2"
rpc 2 mixsetsetting mixdir "" >/dev/null 2>&1
[ "$(jpy "$(rpc 2 mixsettings)" 'd["current"]["directories"] == ["'"$DIR_ONION:$DIR_PORT"'"]')" = "True" ] && \
    success "the directory list returns to innova.conf at once" || fail "mixdir restore: $(rpc 2 mixsettings)"
for n in 1 2; do
    J="$(rpc "$n" mixjoin "$PUBKEY" "$SLOT" 2>&1)"
    [ -n "$(jget "$J" runs)" ] && success "node$n joins the round that runs at $(jget "$J" runs)" || { fail "node$n mixjoin: $J"; exit 1; }
done

START=$(date +%s)
COORD_STATE=""; S1=""; S2=""
while [ $(( $(date +%s) - START )) -lt "$ROUND_DEADLINE_SECS" ]; do
    C="$(rpc 0 mixstatus 2>/dev/null)"
    COORD_STATE="$(jget "$C" jobs.0.state)"
    S1="$(jget "$(rpc 1 mixstatus 2>/dev/null)" jobs.0.state)"
    S2="$(jget "$(rpc 2 mixstatus 2>/dev/null)" jobs.0.state)"
    log "t+$(( $(date +%s) - START ))s tip $(height 0) coordinator[$COORD_STATE] $(jget "$C" jobs.0.status) | seat1[$S1] $(jget "$(rpc 1 mixstatus)" jobs.0.status) | seat2[$S2] $(jget "$(rpc 2 mixstatus)" jobs.0.status)"
    if { [ "$COORD_STATE" = "3" ] || [ "$COORD_STATE" = "4" ]; } && \
       { [ "$S1" = "12" ] || [ "$S1" = "13" ]; } && { [ "$S2" = "12" ] || [ "$S2" = "13" ]; }; then
        break
    fi
    sleep 20
done

header "4. The round's outcome"
[ "$COORD_STATE" = "3" ] && success "the coordinator's round ran to its end" || fail "coordinator ended in state $COORD_STATE: $(jget "$(rpc 0 mixstatus)" jobs.0.status)"
case "$(jget "$(rpc 0 mixstatus)" jobs.0.status)" in
    "transaction broadcast") success "the mix transaction was broadcast" ;;
    *) fail "no mix transaction: $(jget "$(rpc 0 mixstatus)" jobs.0.status)" ;;
esac
[ "$S1" = "12" ] && success "seat 1 completed the round" || fail "seat 1 ended in state $S1: $(jget "$(rpc 1 mixstatus)" jobs.0.status)"
[ "$S2" = "12" ] && success "seat 2 completed the round" || fail "seat 2 ended in state $S2: $(jget "$(rpc 2 mixstatus)" jobs.0.status)"

header "5. Finished seats"
M="$(rpc 1 mixstatus 2>&1)"
[ "$(jget "$M" jobs.0.finished)" = "True" ] && [ "$(jget "$M" jobs.0.updated)" -ge "$(jget "$M" jobs.0.started)" ] 2>/dev/null && \
    success "mixstatus: the seat finished, started $(jget "$M" jobs.0.started), updated $(jget "$M" jobs.0.updated)" || fail "mixstatus timestamps: $M"
C="$(rpc 1 mixcancel "$(jget "$M" jobs.0.id)" 2>&1)"
echo "$C" | grep -q "ended" && success "a finished seat is not cancelled" || fail "cancel after the round: $C"
for n in 1 2; do
    CL="$(rpc "$n" mixclear 2>&1)"
    [ "$(jget "$CL" cleared)" = "1" ] && [ "$(jpy "$(rpc "$n" mixstatus)" 'len(d["jobs"])')" = "0" ] && \
        success "node$n mixclear removes its finished seat" || fail "node$n mixclear: $CL"
done

sleep 30
for n in 1 2; do
    log "node$n after: $(rpc "$n" z_getshieldedinfo | python3 -c 'import json,sys; d=json.load(sys.stdin); print("balance", d.get("privacy_vnext_balance"), "held", d.get("privacy_vnext_held_balance"))')"
done
exit $(( FAILED > 0 ? 1 : 0 ))
