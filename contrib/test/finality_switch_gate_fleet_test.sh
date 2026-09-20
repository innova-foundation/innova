#!/usr/bin/env bash
# A heavier private branch below the finality anchor on a regtest fleet (T-H2-4): nodes keep
# their tip, index the branch as side blocks, score no peer and do not re-download it; a late
# syncer killed mid-catch-up and the branch's own miner both converge on the fleet tip.
set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="${FSG_TEST_DIR:-/tmp/innova_finality_switch_gate_$$}"
KEEP_DIR="${KEEP_DIR:-0}"
BASE_PORT="${FSG_PORT_BASE:-28990}"; BASE_RPC="${FSG_RPC_BASE:-29000}"; BASE_IDNS="${FSG_IDNS_BASE:-29010}"
RPCUSER="fsgtest"; RPCPASS="fsgtestpass"
NUM_FLEET=3        # node0..node2 stay up throughout
PARK_HEIGHT=610    # end of epoch 2 (regtest: DAG fork 11, 300-block epochs)
FUND_HEIGHT=30
VOTER_FUND=1000
MINE_THREADS="${FSG_MINE_THREADS:-1}"
BRANCH_THREADS="${FSG_BRANCH_THREADS:-4}"

PASSED=0; FAILED=0
log()     { echo -e "${YELLOW}[....]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
header()  { echo; echo -e "${YELLOW}== $* ==${NC}"; }

node_dir()  { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc()  { echo $((BASE_RPC + $1)); }
logfile()   { echo "$(node_dir "$1")/regtest/debug.log"; }
is_int()    { echo "${1:-}" | grep -qE '^-?[0-9]+$'; }
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
besthash() { rpc "$1" getbestblockhash 2>/dev/null | tr -d '"[:space:]'; }
is_hash()  { echo "${1:-}" | grep -qE '^[0-9a-f]{64}$'; }
jget() { FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"], None)
    if isinstance(v, bool): print(str(v).lower())
    elif v is None: print("")
    else: print(v)
except Exception:
    print("__jget_error__")' <<< "$1" 2>/dev/null; }
count_log() { local n; n="$(grep -a -c -- "$2" "$(logfile "$1")" 2>/dev/null)"; echo "${n:-0}"; }
daemon_pids() { pgrep -f -- "-datadir=$(node_dir "$1") -regtest -daemon" 2>/dev/null; }
finalized() { jget "$(rpc "$1" getfinalityinfo 2>/dev/null)" deterministic_finalized_height; }
epoch_start() { echo $(( 11 + ($1 - 1) * 300 )); }

# PEERS: space-separated node numbers to keep as persistent peers.
write_conf() {
    local n="$1" peers="$2" extra="${3:-}" d p
    d="$(node_dir "$n")"; mkdir -p "$d"
    {
        echo "regtest=1"; echo "server=1"; echo "rpcuser=$RPCUSER"; echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$n")"; echo "port=$(node_port "$n")"; echo "bind=127.0.0.1"
        echo "listen=1"; echo "dnsseed=0"; echo "nobootstrap=1"; echo "nosmsg=1"; echo "upnp=0"
        echo "listenonion=0"; echo "idnsport=$((BASE_IDNS + n))"; echo "maxconnections=32"
        echo "staking=0"; echo "nofinalityvoting=0"; echo "finalityvotemode=transparent"
        echo "regtestboundaryb=311"; echo "regtestiv5rehearsal=1"
        echo "debug=1"
        for p in $peers; do echo "addnode=127.0.0.1:$(node_port "$p")"; done
        echo "$extra"
    } > "$d/innova.conf"
}
launch_node() { "$INNOVAD" -datadir="$(node_dir "$1")" -regtest -daemon >/dev/null 2>&1; }
start_node() {
    local n="$1" i attempt
    for attempt in 1 2 3 4 5; do
        launch_node "$n"
        for i in $(seq 1 300); do
            rpc "$n" getinfo >/dev/null 2>&1 && return 0
            if [ "$i" -gt 5 ] && ! daemon_pids "$n" >/dev/null 2>&1; then break; fi
            sleep 1
        done
        # A daemon killed a moment ago can still hold the datadir lock while the kernel
        # tears it down; its argv is already unreadable, so pgrep no longer lists it.
        tail -12 "$(logfile "$n")" 2>/dev/null | grep -q "Cannot obtain a lock" || break
        sleep 2
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
    # kill -0 keeps answering for a process in teardown after pgrep has stopped matching
    # its argv; wait for the pids themselves so the datadir lock is really released.
    for i in $(seq 1 600); do
        local alive=0 p
        for p in $pids; do kill -0 "$p" 2>/dev/null && alive=1; done
        [ "$alive" -eq 0 ] && ! daemon_pids "$n" >/dev/null 2>&1 && break
        sleep 0.1
    done
    rm -f "$(node_dir "$n")/regtest/innovad.pid" "$(node_dir "$n")/innovad.pid" 2>/dev/null
    return 0
}
hex_gt() { local a="${1#0}" b="${2#0}"; [ ${#a} -gt ${#b} ] || { [ ${#a} -eq ${#b} ] && [[ "$a" > "$b" ]]; }; }
# A branch mined on several threads merges its own siblings, and each merged sibling adds
# a block of trust, so a linear fleet chain must outgrow the branch by trust, not height.
outgrow() {
    local branch="$1" i ft bt
    for i in $(seq 1 20); do
        ft="$(jget "$(rpc 0 getblock "$(besthash 0)")" chaintrust)"; bt="$(jget "$(rpc 0 getblock "$branch")" chaintrust)"
        [ -n "$ft" ] && [ -n "$bt" ] && hex_gt "$ft" "$bt" && { log "  fleet trust $ft > branch trust $bt at $(height 0)"; return 0; }
        mine_to 0 $(( $(height 0) + 5 )) || return 1
    done
    return 1
}
wait_height() {
    local n="$1" target="$2" limit="${3:-600}" i h
    for i in $(seq 1 "$limit"); do h="$(height "$n")"; is_int "$h" && [ "$h" -ge "$target" ] && return 0; sleep 1; done
    return 1
}
# Every node in LIST at or past TARGET.
wait_sync() {
    local target="$1" list="$2" limit="${3:-600}" i n h ok
    for i in $(seq 1 "$limit"); do
        ok=1; for n in $list; do h="$(height "$n")"; if ! is_int "$h" || [ "$h" -lt "$target" ]; then ok=0; break; fi; done
        [ "$ok" -eq 1 ] && return 0; sleep 1
    done
    return 1
}
wait_hash() {
    local n="$1" want="$2" limit="${3:-600}" i
    for i in $(seq 1 "$limit"); do [ "$(besthash "$n")" = "$want" ] && return 0; sleep 1; done
    return 1
}
# Mine on NODE to TARGET, re-arming a stalled miner; THREADS optional.
mine_to() {
    local n="$1" target="$2" threads="${3:-$MINE_THREADS}" i h last stall=0
    h="$(height "$n")"; is_int "$h" || return 1; [ "$h" -ge "$target" ] && return 0
    last="$h"; rpc "$n" setgenerate true $((target - h)) "$threads" >/dev/null 2>&1
    for i in $(seq 1 3000); do
        h="$(height "$n")"
        is_int "$h" || { sleep 1; continue; }
        if [ "$h" -ge "$target" ]; then rpc "$n" setgenerate false 0 >/dev/null 2>&1; return 0; fi
        if [ "$h" = "$last" ]; then stall=$((stall + 1)); else stall=0; last="$h"; [ $((h % 100)) -eq 0 ] && log "  ...height $h/$target"; fi
        if [ "$stall" -ge 20 ]; then rpc "$n" setgenerate true $((target - h)) "$threads" >/dev/null 2>&1; stall=0; fi
        sleep 1
    done
    rpc "$n" setgenerate false 0 >/dev/null 2>&1; return 1
}
# A transparent vote round at BOUNDARY: mine to it, let the voters cast, carry the votes.
vote_round() {
    local boundary="$1" list="$2"
    mine_to 0 "$boundary" || return 1
    wait_sync "$boundary" "$list" || return 1
    sleep 18
    mine_to 0 $((boundary + 3)) || return 1
    wait_sync $((boundary + 3)) "$list" || return 1
}
# Portable, and it has to be: `stat -f` is a size on macOS and a FILESYSTEM report on
# Linux, where it succeeds and hands the comparison a paragraph.
blkfile_size() { wc -c < "$(node_dir "$1")/regtest/blk0001.dat" 2>/dev/null | tr -d ' ' || echo 0; }

cleanup() {
    local n
    for n in 0 1 2 3 4 5; do rpc "$n" setgenerate false 0 >/dev/null 2>&1 || true; done
    for n in 0 1 2 3 4 5; do stop_node "$n" >/dev/null 2>&1 || kill_node "$n" >/dev/null 2>&1 || true; done
    if [ "$KEEP_DIR" = "1" ]; then echo "kept $TEST_DIR"; else rm -rf "$TEST_DIR"; fi
}
trap cleanup EXIT

[ -x "$INNOVAD" ] || { echo "no innovad at $INNOVAD"; exit 1; }
# A daemon left behind by an interrupted run still listens on our ports; a fresh fleet
# would peer with it and inherit its chain (seen: node0 pulled 1835 headers from a
# ghost node1). Refuse to start on occupied ports rather than run against a ghost.
for n in 0 1 2 3 4 5; do
    for port in "$(node_port "$n")" "$(node_rpc "$n")"; do
        if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
            echo "port $port is in use by pid $(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t | head -1); stop it or set FSG_PORT_BASE/FSG_RPC_BASE"; exit 2
        fi
    done
done
mkdir -p "$TEST_DIR"

header "1. Fleet, voters, parked nodes"
for n in 0 1 2; do write_conf "$n" "0 1 2"; done
write_conf 3 "0"; write_conf 4 "0"; write_conf 5 "0"
for n in 0 1 2 3 4 5; do start_node "$n" || { fail "node$n did not start"; exit 1; }; done
mine_to 0 "$FUND_HEIGHT" || { fail "could not mine to $FUND_HEIGHT"; exit 1; }
ADDR1="$(rpc 1 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
TXID=""
for attempt in 1 2 3 4; do
    TXID="$(rpc 0 sendtoaddress "$ADDR1" "$VOTER_FUND" 2>/dev/null | tr -d '"[:space:]')"
    is_hash "$TXID" && break
    mine_to 0 $(( $(height 0) + 1 )) >/dev/null
done
is_hash "$TXID" && success "node1 funded with $VOTER_FUND INN" || { fail "could not fund node1"; exit 1; }
mine_to 0 $(( $(height 0) + 2 )) >/dev/null
wait_sync "$(height 0)" "0 1 2 3 4 5" || { fail "fleet did not sync the funding blocks"; exit 1; }

# Epoch 2 is the first with votes; its round happens before parking.
vote_round "$(epoch_start 2)" "0 1 2 3 4 5" || { fail "vote round at epoch 2 failed"; exit 1; }
mine_to 0 "$PARK_HEIGHT" || { fail "could not mine to the parking height"; exit 1; }
wait_sync "$PARK_HEIGHT" "0 1 2 3 4 5" || { fail "nodes did not reach $PARK_HEIGHT"; exit 1; }
[ "$(height 0)" -eq "$PARK_HEIGHT" ] && success "fleet at the parking height $PARK_HEIGHT (end of epoch 2)" || fail "node0 overshot the parking height: $(height 0)"
PARK_HASH="$(besthash 0)"
stop_node 3 || fail "node3 did not stop"; stop_node 4 || fail "node4 did not stop"
success "node3 and node4 parked at $PARK_HEIGHT"

header "2. Three HARD epochs raise the deterministic anchor above the parked height"
vote_round "$(epoch_start 3)" "0 1 2 5" || { fail "vote round at epoch 3 failed"; exit 1; }
# node5 parks at the end of epoch 3: two epochs below where the latch anchor will sit
# once epochs 6 and 7 are HARD as well, so its branch draws the permanent verdict.
PARK2_HEIGHT=$(( $(epoch_start 4) - 1 ))
mine_to 0 "$PARK2_HEIGHT" || { fail "could not mine to $PARK2_HEIGHT"; exit 1; }
wait_sync "$PARK2_HEIGHT" "0 1 2 5" || { fail "node5 did not reach $PARK2_HEIGHT"; exit 1; }
PARK2_HASH="$(besthash 0)"; stop_node 5 || fail "node5 did not stop"
success "node5 parked at $PARK2_HEIGHT (end of epoch 3)"
for e in 4 5; do vote_round "$(epoch_start "$e")" "0 1 2" || { fail "vote round at epoch $e failed"; exit 1; }; done
FIN="$(finalized 0)"
if is_int "$FIN" && [ "$FIN" -gt "$PARK_HEIGHT" ]; then
    success "deterministic finalized height $FIN > $PARK_HEIGHT on node0"
else
    fail "finality did not rise above the parked height (deterministic_finalized_height=$FIN); $(rpc 0 getfinalityinfo | grep -oE '"(current_epoch_voters|consecutive_hard_epochs)" : [0-9]+' | tr '\n' ' ')"
    exit 1
fi
[ "$(finalized 1)" = "$FIN" ] && [ "$(finalized 2)" = "$FIN" ] && success "node1 and node2 agree on $FIN" || fail "anchors differ: node1=$(finalized 1) node2=$(finalized 2)"
FLEET_TIP_H="$(height 0)"; FLEET_TIP="$(besthash 0)"
wait_sync "$FLEET_TIP_H" "0 1 2" >/dev/null
log "fleet tip $FLEET_TIP_H ($FLEET_TIP); fleet mining paused"

header "3. node3 mines a heavier private branch on $PARK_HEIGHT in isolation"
write_conf 3 "" "listen=0"
start_node 3 || { fail "node3 did not restart"; exit 1; }
[ "$(besthash 3)" = "$PARK_HASH" ] && success "node3 restarted on $PARK_HEIGHT with no peers" || fail "node3 tip is $(height 3), expected $PARK_HEIGHT"
BRANCH_TARGET=$(( FLEET_TIP_H + 15 ))
mine_to 3 "$BRANCH_TARGET" "$BRANCH_THREADS" || { fail "node3 could not mine the private branch"; exit 1; }
BRANCH_H="$(height 3)"; BRANCH_TIP="$(besthash 3)"
[ "$BRANCH_H" -gt "$FLEET_TIP_H" ] && success "private branch reaches $BRANCH_H (> fleet $FLEET_TIP_H), forking at $PARK_HEIGHT below the anchor $FIN" || fail "branch height $BRANCH_H is not above the fleet tip"
BRANCH_FORK_CHILD="$(rpc 3 getblockhash $((PARK_HEIGHT + 1)) | tr -d '"[:space:]')"

header "4. The fleet is fed the heavier branch"
BLK0_BEFORE="$(blkfile_size 0)"
MISB0_BEFORE="$(count_log 0 'Misbehaving')"; MISB1_BEFORE="$(count_log 1 'Misbehaving')"
rpc 3 addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1
rpc 3 addnode "127.0.0.1:$(node_port 1)" onetry >/dev/null 2>&1
got=0
for i in $(seq 1 300); do
    rpc 0 getblock "$BRANCH_TIP" >/dev/null 2>&1 && rpc 1 getblock "$BRANCH_TIP" >/dev/null 2>&1 && { got=1; break; }
    sleep 1
done
[ "$got" -eq 1 ] && success "node0 and node1 hold the branch tip ($i s)" || fail "the branch tip never reached node0/node1 (node0 has fork child: $(rpc 0 getblock "$BRANCH_FORK_CHILD" >/dev/null 2>&1 && echo yes || echo no))"
sleep 10
[ "$(besthash 0)" = "$FLEET_TIP" ] && success "node0 kept its tip" || fail "node0 moved to $(height 0) $(besthash 0)"
[ "$(besthash 1)" = "$FLEET_TIP" ] && success "node1 kept its tip" || fail "node1 moved to $(height 1) $(besthash 1)"
[ "$(besthash 2)" = "$FLEET_TIP" ] && success "node2 kept its tip" || fail "node2 moved to $(height 2)"
# One gate decision per branch block whose DAG score beats the tip: at least
# BRANCH_H - FLEET_TIP_H, each naming the parked fork height.
KEPT_MIN=$(( BRANCH_H - FLEET_TIP_H ))
for n in 0 1; do
    KEPT="$(count_log "$n" 'kept as a side block')"
    AT_FORK="$(grep -a -c "finalized at height $FIN (fork point $PARK_HEIGHT, .*kept as a side block" "$(logfile "$n")")"
    [ "$KEPT" -ge "$KEPT_MIN" ] && [ "$AT_FORK" -eq "$KEPT" ] && success "node$n side-indexed the heavier ineligible blocks ($KEPT gate decisions, all at fork $PARK_HEIGHT under anchor $FIN; >= $KEPT_MIN expected)" || fail "node$n gate decisions: $KEPT (>= $KEPT_MIN expected), $AT_FORK naming fork $PARK_HEIGHT"
done
[ "$(count_log 0 'kept as a side block')" -eq "$(grep -a -c 'finalized at height .* (fork point .*, latch anchor .*, retryable); kept as a side block' "$(logfile 0)")" ] && success "every decision on node0 was the retryable verdict" || fail "node0 logged a non-retryable verdict in this phase"
[ "$(count_log 0 'SetBestChain() : rejected reorg')" -eq 0 ] && success "no reorg attempt reached the guard on node0" || fail "node0 still attempted a below-anchor reorg: $(grep -a 'SetBestChain() : rejected reorg' "$(logfile 0)" | tail -1 | cut -c1-140)"
[ "$(count_log 0 'Misbehaving')" -eq "$MISB0_BEFORE" ] && [ "$(count_log 1 'Misbehaving')" -eq "$MISB1_BEFORE" ] && success "no peer was scored for relaying the branch" || fail "a peer was scored: node0 +$(( $(count_log 0 Misbehaving) - MISB0_BEFORE )) node1 +$(( $(count_log 1 Misbehaving) - MISB1_BEFORE ))"
[ "$(count_log 0 'marked failed/invalid')" -eq 0 ] && success "no child of the branch was refused as failed on node0" || fail "node0 refused children of a flagged block"
GB="$(rpc 0 getblock "$BRANCH_TIP" 2>/dev/null)"
[ -z "$(jget "$GB" failreason)" ] && success "the branch tip carries no fail reason on node0" || fail "node0 flagged the branch tip: $(jget "$GB" failreason)"
CONF="$(jget "$GB" confirmations)"; log "branch tip on node0: confirmations=$CONF"
sleep 30
BLK0_AFTER="$(blkfile_size 0)"
[ "$BLK0_AFTER" -eq "$BLK0_BEFORE" ] || { sleep 30; BLK0_AFTER2="$(blkfile_size 0)"; [ "$BLK0_AFTER2" -eq "$BLK0_AFTER" ] && success "block file stable after the branch landed (+$(( BLK0_AFTER - BLK0_BEFORE )) bytes once, then flat)" || fail "block file keeps growing: $BLK0_BEFORE -> $BLK0_AFTER -> $BLK0_AFTER2"; }
[ "$BLK0_AFTER" -eq "$BLK0_BEFORE" ] && success "block file did not grow (branch was already on disk)"

header "5. reconsiderblock on the branch tip passes it over; a restart loads"
R="$(rpc 0 reconsiderblock "$BRANCH_TIP")"
[ "$(jget "$R" tip_moved)" = "false" ] && [ "$(besthash 0)" = "$FLEET_TIP" ] && success "reconsiderblock left the tip where it was ($(jget "$R" flags_cleared) flags cleared)" || fail "reconsiderblock: $R (tip $(height 0))"
stop_node 0 || fail "node0 did not stop"
start_node 0 || { fail "node0 did not restart"; exit 1; }
[ "$(count_log 0 'LoadDAGLinks: FATAL')" -eq 0 ] && [ "$(besthash 0)" = "$FLEET_TIP" ] && success "node0 restarted on its tip with the branch retained" || fail "node0 after restart: tip $(height 0), FATAL lines $(count_log 0 'LoadDAGLinks: FATAL')"
rpc 0 getblock "$BRANCH_TIP" >/dev/null 2>&1 && success "the branch tip is still indexed after the restart" || fail "the branch tip is gone after the restart"

header "6. node4 syncs late, fed the branch by node3 before the fleet, killed mid-way"
# node3 still holds its branch as the tip; node4 hears it first and the fleet's chain
# through node0. Its own anchor is still low, so it may follow the branch for a while;
# what matters is that it converges, scores nobody, and refuses nothing.
write_conf 4 "3 0"
start_node 4 || { fail "node4 did not restart"; exit 1; }
MISB3_BEFORE="$(count_log 3 'Misbehaving')"
MISB4_BEFORE="$(count_log 0 'Misbehaving')"
KILL_AT=$(( PARK_HEIGHT + 150 ))
killed=0
for i in $(seq 1 600); do h="$(height 4)"; if is_int "$h" && [ "$h" -ge "$KILL_AT" ]; then kill_node 4 && killed=1; break; fi; sleep 1; done
[ "$killed" -eq 1 ] && success "node4 killed at $h during catch-up" || fail "node4 never reached $KILL_AT ($(height 4))"
start_node 4 || { fail "node4 did not restart after the kill"; exit 1; }
[ "$(count_log 4 'LoadDAGLinks: FATAL')" -eq 0 ] && success "node4 loaded after the kill" || fail "node4 refused its datadir after the kill"
# Its anchor was still low when the branch arrived, so it may have followed the heavier
# branch; either tip is a legitimate resting point until the fleet outgrows the branch
# (phase 7 asserts the convergence).
settled=0
for i in $(seq 1 600); do h4="$(besthash 4)"; { [ "$h4" = "$FLEET_TIP" ] || [ "$h4" = "$BRANCH_TIP" ]; } && { settled=1; break; }; sleep 1; done
[ "$settled" -eq 1 ] && success "node4 caught up to $([ "$h4" = "$FLEET_TIP" ] && echo "the fleet tip $FLEET_TIP_H" || echo "the heavier branch $BRANCH_H (its own anchor was still low)")" || fail "node4 stuck at $(height 4) on neither chain"
[ "$(count_log 4 'Misbehaving')" -eq 0 ] && [ "$(count_log 0 'Misbehaving')" -eq "$MISB4_BEFORE" ] && [ "$(count_log 3 'Misbehaving')" -eq "$MISB3_BEFORE" ] && success "no scores in any direction while node4 caught up" || fail "scores during node4's catch-up: node4 $(count_log 4 Misbehaving), node0 +$(( $(count_log 0 Misbehaving) - MISB4_BEFORE )), node3 +$(( $(count_log 3 Misbehaving) - MISB3_BEFORE ))"
rpc 4 getblock "$BRANCH_TIP" >/dev/null 2>&1 && success "node4 holds the side branch it was fed first" || fail "node4 never indexed the branch node3 fed it"
[ "$(count_log 4 'marked failed/invalid')" -eq 0 ] && [ "$(count_log 4 'LoadDAGLinks: FATAL')" -eq 0 ] && success "node4 flagged nothing and loads" || fail "node4 refused children of a flagged block or failed to load"

header "7. The fleet mines on; everyone converges"
mine_to 0 $(( BRANCH_H + 20 )) || fail "node0 could not resume mining"
outgrow "$BRANCH_TIP" || fail "the fleet chain did not outweigh the branch"
NEW_TIP="$(besthash 0)"; NEW_H="$(height 0)"
[ "$NEW_H" -gt "$BRANCH_H" ] && success "fleet chain outgrew the branch ($NEW_H > $BRANCH_H)" || fail "fleet did not outgrow the branch"
wait_hash 1 "$NEW_TIP" 900 && wait_hash 2 "$NEW_TIP" 900 && wait_hash 4 "$NEW_TIP" 900 && success "node1, node2, node4 follow the fleet tip" || fail "a fleet node lags: node1=$(height 1) node2=$(height 2) node4=$(height 4)"
wait_hash 3 "$NEW_TIP" 900 && success "node3 abandoned its branch and converged" || fail "node3 stuck on its branch at $(height 3) ($(besthash 3))"
[ "$(count_log 0 'LoadDAGLinks: FATAL')" -eq 0 ] && [ "$(count_log 3 'LoadDAGLinks: FATAL')" -eq 0 ] || fail "a node logged a loader FATAL"

header "8. Two more HARD epochs; node5's branch from $PARK2_HEIGHT draws the permanent verdict"
for e in 6 7; do vote_round "$(epoch_start "$e")" "0 1 2 3 4" || { fail "vote round at epoch $e failed"; exit 1; }; done
FIN2="$(finalized 0)"; FLEET2_H="$(height 0)"; FLEET2_TIP="$(besthash 0)"
[ "$FIN2" -gt "$FIN" ] && success "anchor advanced to $FIN2; fleet paused at $FLEET2_H" || fail "the anchor did not advance past $FIN (now $FIN2)"
write_conf 5 "" "listen=0"
start_node 5 || { fail "node5 did not restart"; exit 1; }
[ "$(besthash 5)" = "$PARK2_HASH" ] && success "node5 restarted on $PARK2_HEIGHT with no peers" || fail "node5 tip is $(height 5), expected $PARK2_HEIGHT"
mine_to 5 $(( FLEET2_H + 15 )) "$BRANCH_THREADS" || { fail "node5 could not mine its branch"; exit 1; }
BRANCH2_H="$(height 5)"; BRANCH2_TIP="$(besthash 5)"
MISB0_B="$(count_log 0 'Misbehaving')"; KEPT0_B="$(count_log 0 'kept as a side block')"
rpc 5 addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1
got=0; for i in $(seq 1 300); do rpc 0 getblock "$BRANCH2_TIP" >/dev/null 2>&1 && { got=1; break; }; sleep 1; done
[ "$got" -eq 1 ] && success "node0 holds the second branch tip ($i s)" || fail "the second branch never reached node0"
sleep 10
[ "$(besthash 0)" = "$FLEET2_TIP" ] && success "node0 kept its tip against the permanently refused branch" || fail "node0 moved to $(height 0)"
PERM="$(grep -a -c 'permanent); kept as a side block' "$(logfile 0)")"
[ "$PERM" -ge $(( BRANCH2_H - FLEET2_H )) ] && success "node0 side-indexed the branch under the permanent verdict ($PERM decisions)" || fail "expected >= $(( BRANCH2_H - FLEET2_H )) permanent gate decisions on node0, saw $PERM"
[ "$(count_log 0 'Misbehaving')" -eq "$MISB0_B" ] && [ "$(count_log 0 'marked failed/invalid')" -eq 0 ] && success "no score, no flag for the permanently refused branch" || fail "node0 scored or flagged on the permanent branch"
GB2="$(rpc 0 getblock "$BRANCH2_TIP" 2>/dev/null)"
[ "$(jget "$GB2" hash)" = "$BRANCH2_TIP" ] && [ -z "$(jget "$GB2" failreason)" ] && success "the second branch tip is indexed on node0 with no fail reason" || fail "node0's view of the second branch tip: $(echo "$GB2" | head -c 200)"
mine_to 0 $(( BRANCH2_H + 20 )) || fail "node0 could not resume mining"
outgrow "$BRANCH2_TIP" || fail "the fleet chain did not outweigh the second branch"
NEW2="$(besthash 0)"
wait_hash 1 "$NEW2" 900 && wait_hash 5 "$NEW2" 900 && success "node1 and node5 converge on the fleet tip $(height 0)" || fail "convergence after the permanent branch: node1=$(height 1) node5=$(height 5)"

echo; echo "passed=$PASSED failed=$FAILED"
[ "$FAILED" -eq 0 ]
