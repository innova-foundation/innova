#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 note finality vote regtest: drive the op-10 note vote end to end.
#
# A note vote is an ordinary privacy-vNext transaction, operation 10, that spends the
# voting note and reissues it. Its tag is the spent note's key image, so a second vote
# from one note is a double spend. It anchors to epoch state E-1, relays through the
# mempool, and must be mined in [H_E, H_E + FINALITY_VOTE_INCLUSION_WINDOW). The
# epoch's v4 tally certificate commits the counted set as a root and a count, which
# every node rebuilds at connect. A HARD epoch still needs FINALITY_MIN_VOTERS
# transparent voters, so the fleet is three wallets: node0 holds the IV5 notes and
# votes only in the note lane, node1 and node2 carry the identity lane.
#
# Configuration this harness needs that the spend harness does not:
#   -regtestiv5notevote=<h>  the note-vote fork; init refuses a height below
#                            Boundary B (src/init.cpp)
#   -finalitytallyprivkey    the ONLY committee key a node is configured with.
#                            There is no pinned committee any more: seats are
#                            drawn per term from the IV5 collateral registry, and
#                            a node serves a seat only when the drawn set names
#                            the pubkey of this secret
#   -finalityvotemode=note   node0's lane; the peers run "transparent"
#   -debug -debugnet         the producer's refusal lines are behind fDebug
#
# It also settles where the committee comes from; see
# PRE_TERM_EPOCH below for the check that separates a registry draw from a fixed
# set, and why nothing else here does.
#
# Regtest epoch layout: DAG fork 11, 300-block epochs, so epoch E covers
# [11 + 300*(E-1), 310 + 300*(E-1)]. Boundary B sits at 311 because the IV5 tree
# is only maintained by the schema-V3 epoch build.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init iv5_note_vote_regtest_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_NOTE_VOTE_TEST_DIR:-${TEST_DIR:-/tmp/innova_iv5_notevote_$$}}"
NUM_NODES=3
BASE_PORT="${IV5_NOTE_VOTE_BASE_PORT:-$(iv5_port 0 28650)}"
BASE_RPC="${IV5_NOTE_VOTE_BASE_RPC:-$(iv5_port 16 28700)}"
BASE_IDNS="${IV5_NOTE_VOTE_BASE_IDNS:-$(iv5_port 32 8760)}"
RPCUSER="iv5notevote"
RPCPASS="iv5notevotepass"
WALLETPASS="iv5notevotewallet"

BOUNDARY_B=311
# The note-vote fork. init refuses anything below Boundary B, so this is the
# earliest legal height and every epoch boundary from 2 on is an attempt.
NOTE_VOTE_HEIGHT=311

# Above the 500 INN vote stake floor (GetFinalityMinVoteWeight): a peer holding less
# casts a vote every node refuses as below the minimum weight.
FUND_AMOUNT=600
FUND_HEIGHT=40
FUND_CONFIRM_HEIGHT=45
SHIELD_HEIGHT=330
SHIELD_CONFIRM_HEIGHT=345
SHIELD_SWEEPS=4

# Epochs 2, 3 and 4 are the HARD run. The third consecutive HARD epoch's record
# carries a finalized height of its own start: epoch 4 finalizes 911.
FINALIZED_HEIGHT=911
FINALIZED_EPOCH=4

# CPU miner threads for the long haul. Single-threaded regtest mines ~1.6
# blocks/s on the build host and a seated committee is thousands of blocks away,
# so the run is mining-bound. setgenerate's third argument is the thread count.
#
# N threads overshoot a target by up to N-1 blocks, because each one finishes the
# block it is on. The fleet-setup sections below step between fixed heights only
# a few blocks apart, and an overshoot there skips a confirmation entirely, so
# mining stays single-threaded until those are done and MINE_THREADS_NOW is
# raised. Every target after that is either hundreds of blocks away or an epoch
# boundary with a 24-block inclusion window, both of which absorb the overshoot.
# Default 1. Producing blocks faster than the fleet can follow deadlocks a
# peer's block fetch outright: it ends up holding a header whose parent it never
# requested, reports "waiting for in-flight blocks" with nothing in flight, and
# never recovers no matter how long the run waits. Raise this only to reproduce
# that; the run is long, but a wedged fleet does not finish at all.
MINE_THREADS="${IV5_NOTE_VOTE_MINE_THREADS:-1}"
MINE_THREADS_NOW=1
# Blocks mined before the fleet has to catch up. Left unbounded, node0 outruns
# its peers by hundreds of blocks and their fetch wedges: the peer ends up
# holding a header whose parent it never requested, reporting "waiting for
# in-flight blocks" with nothing in flight, and it does not recover. Keeping the
# gap small never puts them in that state.
MINE_CHUNK="${IV5_NOTE_VOTE_MINE_CHUNK:-50}"

# Epoch E spans [11 + 300*(E-1), 310 + 300*(E-1)].
epoch_start() { echo $(( 11 + ($1 - 1) * 300 )); }
epoch_end()   { echo $(( 310 + ($1 - 1) * 300 )); }

# ---------------------------------------------------------------------------
# The term this run seats a committee for.
#
# Regtest draws 3 seats at M=2 over a 2-epoch term, refuses a registry smaller
# than 2N, and anchors the draw 2 epochs back. So: 6 registrations, all
# confirmed at or below the FIRST height of the anchor epoch; the seed is that
# epoch's END block; the draw is carried by the epoch ending the term's lead-in
# and appears once the chain crosses into the term.
#
# The term is this late because the registrations cost 6 x 25000 INN of real
# collateral, the pool has to be funded well past that (see POOL_SHIELD_TOTAL),
# and node0 is the only miner.
#
# The whole schedule is derived, because it is one schedule: the funding shields
# must be built by the epoch the carve spends against, the carved notes must be
# built AND finalized by the epoch that registers them, every registration must
# confirm at or below the anchor, and the term itself has to sit on the chain's
# own term grid. Written out by hand, a shift left TALLY_EPOCH pointing outside
# NOTE_VOTE_EPOCHS (which silently skipped the certificate stage) and put the term
# on an odd epoch, where GetFinalityCommitteeTermEpoch never resolves to it and
# the committee never seats.
# ---------------------------------------------------------------------------

# Transparent value is shielded here, the collateral notes are carved out of it
# two epochs later, and they are registered two epochs after that. Each step is a
# spend, and a spend anchors to the finalized height the PREDECESSOR epoch's record
# carries: notes the epoch-E build places are spendable from epoch E+2. Funding this
# late because the pool has to hold well over 6 x 25000 INN (see
# POOL_SHIELD_TOTAL) and node0 is the only miner. The regtest ladder's last rung
# ends at 1811, so this height is funded out of the post-ladder tail.
POOL_FUND_EPOCH=14
CARVE_EPOCH=$(( POOL_FUND_EPOCH + 2 ))
REGISTER_EPOCH=$(( CARVE_EPOCH + 2 ))

# A term is GetFinalityCommitteeTermEpochs() epochs long and starts on a multiple
# of that length: (epoch / len) * len. A term epoch off that grid is never the
# current term of any epoch, so its draw is carried and then never resolved.
COMMITTEE_TERM_EPOCHS=2
# The draw anchors FINALITY_COMMITTEE_DRAW_LAG_EPOCHS back and the registrations
# run through the register epoch, so the anchor epoch has to start after that
# epoch ends: the term is at least REGISTER_EPOCH + 3, rounded up onto the grid.
COMMITTEE_TERM_EPOCH=$(( ((REGISTER_EPOCH + 3 + COMMITTEE_TERM_EPOCHS - 1) / COMMITTEE_TERM_EPOCHS) * COMMITTEE_TERM_EPOCHS ))
COMMITTEE_ANCHOR_EPOCH=$(( COMMITTEE_TERM_EPOCH - 2 ))
COMMITTEE_CARRIER_EPOCH=$(( COMMITTEE_TERM_EPOCH - 1 ))
COMMITTEE_ANCHOR_HEIGHT="$(epoch_start "$COMMITTEE_ANCHOR_EPOCH")"
# The carrier epoch's state is built when the chain crosses into the term.
COMMITTEE_SEATED_HEIGHT=$(( $(epoch_end "$COMMITTEE_CARRIER_EPOCH") + 1 ))

# The term immediately before the one this run seats, and the height its draw
# anchors to.
#
# This is the harness's one discriminator between a committee drawn from the
# collateral registry and a committee that came from anywhere else. Every seat this
# run produces is one of the three well-known secp256k1 points 1G/2G/3G, which are
# also the pubkeys of the three configured -finalitytallyprivkey scalars, so an
# implementation that ignored the registry and seated those three every term would
# satisfy every other observation here. It would not satisfy this one: the previous
# term anchors BELOW every registration, section 5c proves the registry is empty at
# that height, and section 5d then requires the chain to seat nothing while it is
# inside that term.
PRE_TERM_EPOCH=$(( COMMITTEE_TERM_EPOCH - COMMITTEE_TERM_EPOCHS ))
PRE_TERM_ANCHOR_EPOCH=$(( PRE_TERM_EPOCH - 2 ))
PRE_TERM_ANCHOR_HEIGHT="$(epoch_start "$PRE_TERM_ANCHOR_EPOCH")"

# The committee shape regtest draws: GetFinalityCommitteeSeats() seats at
# GetFinalityCommitteeThresholdM(). Asserted, not just compared across nodes -- a
# chain that agreed on M=1 or M=3 would otherwise pass.
COMMITTEE_SEAT_COUNT=3
COMMITTEE_THRESHOLD_M=2

# Six rows is the floor: 3 seats x the 2N registry minimum. Two rows per member
# key and one seat per key means the draw seats exactly the three node keys
# whichever rows win.
COLLATERAL_ROWS=$(( COMMITTEE_SEAT_COUNT * 2 ))
COLLATERAL_VALUE=25000

# Funding the pool. A shield never produces one note: it splits its value across
# two notes at a uniformly random point, so no amount shielded in one step can be
# made to land as a single 25000 INN note. The collateral note has to be carved
# by an in-pool transfer, which is also what keeps it off the public link between
# the transparent coins and a +25000 shield.
#
# Every carve is a spend, and a spend's change comes back as a note with no tree
# position until the NEXT epoch build, so within the carve epoch each carve
# strands whatever it over-selected. Selection is largest-first, so the strand is
# bounded by the largest note it touches: six rows of 25500 (12 notes averaging
# 12750) stranded ~7400 per carve and ran out after five. Many smaller shields
# keep the strand small and the total covers 6 x 25000 with room for it.
POOL_SHIELD_ROWS=16
POOL_SHIELD_VALUE=11500
POOL_SHIELD_TOTAL=$(( POOL_SHIELD_ROWS * POOL_SHIELD_VALUE ))

# Inside POOL_FUND_EPOCH, far enough in that node0's MATURE coinbase covers
# POOL_SHIELD_TOTAL -- coinbase only counts once it is nCoinbaseMaturity deep, so
# the balance trails the height by ~200 blocks' worth of subsidy -- and early
# enough that the ~4 blocks per shield row still land in the same epoch.
POOL_FUND_HEIGHT=$(( $(epoch_start "$POOL_FUND_EPOCH") + 140 ))
# The funding epoch's build has put the shielded notes in the tree by here.
CARVE_HEIGHT="$(epoch_start "$CARVE_EPOCH")"
# The carve epoch's build has put the carved notes in the tree by here.
# Every registration must then confirm at or below COMMITTEE_ANCHOR_HEIGHT.
REGISTER_HEIGHT="$(epoch_start "$REGISTER_EPOCH")"

# Boundaries observed for note votes. Both epochs of the term the draw seats.
NOTE_VOTE_EPOCHS="$COMMITTEE_TERM_EPOCH $(( COMMITTEE_TERM_EPOCH + 1 ))"
# The epoch after them, for the carrier-disconnect case in section 15a.
REORG_VOTE_EPOCH=$(( COMMITTEE_TERM_EPOCH + 2 ))
# FINALITY_VOTE_INCLUSION_WINDOW: a vote for boundary B connects only in [B, B+24).
NOTE_VOTE_INCLUSION_WINDOW=24
# FINALITY_VOTE_EMIT_OFFSET_POST_DAG: the producer casts once the tip is 2 blocks past
# the boundary, so a note-vote round holds the chain there, not at the boundary.
NOTE_VOTE_EMIT_OFFSET=2
# Blocks mined past a boundary while the vote is pending. Inside the inclusion
# window, so every one of them may carry the vote.
NOTE_VOTE_WINDOW=10
# Seconds the chain is held at the emit height. ThreadFinalityVoter wakes on a 5s
# cycle and proving takes ~5s.
NOTE_VOTE_SETTLE=30

# One member secret per node. These are NOT a committee: nothing is pinned. A node
# holds a seat only if some IV5 collateral registration published the matching
# pubkey and that registration wins the term's draw, which is what the registration
# section below arranges. Scalars 1/2/3, the well-known secp256k1 test points.
COMMITTEE_PRIVKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
# The same three secrets in wallet-import form (regtest secret prefix 230), so the
# wallet that registers a note can hold the private half of the member key it
# publishes -- collateralnode finality-register refuses a key it cannot decrypt to.
COMMITTEE_WIFS=(
    "b2N2W7suGMid823gCRnQ72m2EwD31FNCScGyhUgmw4LhmdmxgjPn"
    "b2N2W7suGMid823gCRnQ72m2EwD31FNCScGyhUgmw4Lhn8iV52zc"
    "b2N2W7suGMid823gCRnQ72m2EwD31FNCScGyhUgmw4LhndY5atD1"
)
# The matching compressed pubkeys, for asserting which seats the draw produced.
COMMITTEE_PUBKEYS=(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)

# A note vote is an ordinary shielded transaction, operation 10, not a coinbase envelope:
# it spends the note it votes with, so the ledger enforces one vote per note per epoch.
# The coinbase-script lane it replaced was deleted.
NOTE_VOTE_OPERATION=10
# FINALITY_NOTE_CERT_VERSION: the certificate whose note leg is a root and a count.
NOTE_CERT_VERSION=4

# The epoch whose note tally is driven to a certificate. It is the first of
# NOTE_VOTE_EPOCHS and derived from it, because the certificate has to be carried
# by a block of that same epoch: the deterministic tier reads the epoch's OWN
# blocks, so a cert carried a whole epoch later is block-valid and
# tier-irrelevant, and a TALLY_EPOCH outside NOTE_VOTE_EPOCHS is never reached at
# all.
TALLY_EPOCH="${NOTE_VOTE_EPOCHS%% *}"
# H_E + FINALITY_VOTE_INCLUSION_WINDOW is the freeze point: before it the counted
# note-vote set still grows and no certificate can satisfy connect-time coverage.
TALLY_WINDOW_CLOSE=$(( 11 + (TALLY_EPOCH - 1) * 300 + 24 ))
# Blocks mined past the freeze point, inside the same epoch, for the committee to
# converge and for a miner to carry the certificate it assembles.
TALLY_CARRY_HEIGHT=$(( TALLY_WINDOW_CLOSE + 40 ))
# Seconds the chain rests at the freeze point. ThreadFinalityVoter drives
# ProcessFinalityTallyCommittee on a 5s cycle, and the pass and the M-of-N
# signature round each need one.
TALLY_SETTLE=45

PASSED=0
FAILED=0
WARNED=0
WARNINGS=()

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
# Warns are advisory: no check pairs a warn with a PASS, so the pass count is fixed.
# They are re-listed in Results because the run directory is deleted on success.
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; WARNED=$((WARNED + 1)); WARNINGS+=("$*"); }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

RESULTS_PRINTED=0
print_results() {
    RESULTS_PRINTED=1
    header "Results"
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo -e "${YELLOW}Warnings: $WARNED${NC}"
    # The only record of warns once the run directory is deleted.
    if [ "$WARNED" -gt 0 ]; then
        local w
        for w in "${WARNINGS[@]}"; do
            echo -e "${YELLOW}  - $w${NC}"
        done
    fi
}

node_dir()  { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc()  { echo $((BASE_RPC + $1)); }
node_idns() { echo $((BASE_IDNS + $1)); }
node_log()  { echo "$TEST_DIR/node$1/regtest/debug.log"; }

rpc() {
    local node="$1"; shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser="$RPCUSER" \
        -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>&1
}

is_int() { echo "$1" | grep -qE '^-?[0-9]+$'; }

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

# Field of a nested object: jget2 "$json" outer inner.
jget2() {
    OUTER="$2" INNER="$3" python3 -c '
import json, os, sys
try:
    d = json.load(sys.stdin).get(os.environ["OUTER"], None)
    v = d.get(os.environ["INNER"], None) if isinstance(d, dict) else None
    if isinstance(v, bool): print(str(v).lower())
    elif v is None: print("")
    else: print(v)
except Exception:
    pass
' <<< "$1" 2>/dev/null
}

jlen() {
    FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"], [])
    print(len(v) if isinstance(v, (list, dict)) else 0)
except Exception:
    print(-1)
' <<< "$1" 2>/dev/null
}

height()     { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
block_hash() { rpc "$1" getblockhash "$2" 2>/dev/null | tr -d '"[:space:]'; }

block_json() {
    local h; h="$(block_hash "$1" "$2")"
    [ ${#h} -eq 64 ] || return 1
    rpc "$1" getblock "$h" 2>/dev/null
}

feq() { [ "$(python3 -c "print(1 if abs($1 - $2) < 1e-8 else 0)" 2>/dev/null)" = "1" ]; }

# A hex string that is all zeroes, or empty, is "no root".
is_zero_hex() {
    case "$1" in
        ""|*[!0]*) [ -z "$1" ] && return 0 || return 1 ;;
        *) return 0 ;;
    esac
}

# Process and port hygiene: nothing starts until the ports are free, and every exit
# path tears the fleet down by PID.

port_in_use() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null || return 1
    exec 3>&- 2>/dev/null
    return 0
}

# The daemon's exact argv: a bare datadir match also catches this harness's own
# short-lived rpc client processes, so the node never looks stopped.
node_pids() { pgrep -f -- "-datadir=$(node_dir "$1") -regtest -daemon" 2>/dev/null; }

wait_rpc_down() {
    for _ in $(seq 1 180); do
        node_pids "$1" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

force_kill_node() {
    local p
    for p in $(node_pids "$1"); do
        kill -9 "$p" 2>/dev/null || true
    done
}

wait_ports_free() {
    local n port busy
    for _ in $(seq 1 60); do
        busy=""
        for ((n=0; n<=NUM_NODES; n++)); do
            for port in "$(node_port "$n")" "$(node_rpc "$n")" "$(node_idns "$n")"; do
                port_in_use "$port" && busy="$busy $port"
            done
        done
        [ -z "$busy" ] && return 0
        sleep 1
    done
    echo "$busy"
    return 1
}

wait_rpc() {
    for _ in $(seq 1 90); do
        rpc "$1" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

start_node() {
    "$INNOVAD" -datadir="$(node_dir "$1")" -regtest -daemon >/dev/null 2>&1
    wait_rpc "$1"
}

connect_mesh() {
    local n p
    for ((n=0; n<NUM_NODES; n++)); do
        for ((p=0; p<NUM_NODES; p++)); do
            [ "$n" -eq "$p" ] && continue
            rpc "$n" addnode "127.0.0.1:$(node_port "$p")" onetry >/dev/null 2>&1 || true
        done
    done
}

peer_count() {
    rpc "$1" getpeerinfo 2>/dev/null | python3 -c '
import json, sys
try:
    p = json.load(sys.stdin)
    print(len(p) if isinstance(p, list) else 0)
except Exception:
    print(0)
'
}

wait_peers() {
    for _ in $(seq 1 60); do
        local ok=1 n c
        for ((n=0; n<NUM_NODES; n++)); do
            c="$(peer_count "$n")"
            if ! is_int "$c" || [ "$c" -lt 2 ]; then ok=0; break; fi
        done
        [ "$ok" -eq 1 ] && return 0
        connect_mesh
        sleep 2
    done
    return 1
}

wait_sync() {
    local target="$1" max="${2:-900}" n h
    for ((i=0; i<max; i++)); do
        local ok=1
        for ((n=0; n<NUM_NODES; n++)); do
            h="$(height "$n")"
            if ! is_int "$h" || [ "$h" -lt "$target" ]; then ok=0; break; fi
        done
        [ "$ok" -eq 1 ] && return 0
        sleep 1
    done
    return 1
}

# Mine on NODE until TARGET, in chunks, letting the fleet catch up between them.
# Mining far ahead of the peers wedges their block fetch, so the gap is bounded.
mine_to() {
    local node="$1" target="$2" h stop
    h="$(height "$node")"
    is_int "$h" || return 1
    while [ "$h" -lt "$target" ]; do
        stop=$(( h + MINE_CHUNK ))
        [ "$stop" -gt "$target" ] && stop="$target"
        mine_chunk "$node" "$stop" || return 1
        wait_sync "$stop" 180 >/dev/null 2>&1 || \
            warn "the fleet lagged past height $stop; continuing"
        h="$(height "$node")"
        is_int "$h" || return 1
    done
    return 0
}

# Mine on NODE until TARGET. Re-arms the miner if height stalls: setgenerate
# takes a block count, and a template that loses a race consumes one.
mine_chunk() {
    local node="$1" target="$2" h last stall=0
    h="$(height "$node")"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$node" setgenerate true $((target - h)) "$MINE_THREADS_NOW" >/dev/null 2>&1
    for ((i=0; i<3000; i++)); do
        h="$(height "$node")"
        if is_int "$h" && [ "$h" -ge "$target" ]; then
            rpc "$node" setgenerate false 0 >/dev/null 2>&1
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
            rpc "$node" setgenerate true $((target - h)) "$MINE_THREADS_NOW" >/dev/null 2>&1
            stall=0
        fi
        sleep 1
    done
    rpc "$node" setgenerate false 0 >/dev/null 2>&1
    return 1
}

# Transparent finality votes for the epoch starting at BOUNDARY. Each node casts
# on its own 5s cycle and relays; mining is paused at the boundary so every vote
# lands inside the [H_E, H_E+24) inclusion window.
vote_round() {
    local boundary="$1" settle="${2:-18}" carry="${3:-3}"
    mine_to 0 "$boundary" || return 1
    wait_sync "$boundary" || return 1
    sleep "$settle"
    mine_to 0 $((boundary + carry)) || return 1
    wait_sync $((boundary + carry)) || return 1
}

# Coin selection can pick the coinbase of the current tip, which the wallet calls
# mature at regtest depth 1 but ConnectInputs still refuses. Mining one more
# block and retrying moves it out of reach.
fund_peer() {
    local addr="$1" amount="$2" sent
    for _ in 1 2 3 4; do
        sent="$(rpc 0 sendtoaddress "$addr" "$amount" 2>&1 | tr -d '"[:space:]')"
        if [ ${#sent} -eq 64 ]; then
            echo "$sent"
            return 0
        fi
        mine_to 0 $(( $(height 0) + 1 )) || return 1
    done
    return 1
}

# Mine COUNT blocks on node0 and wait for the fleet, so a transaction just
# broadcast is confirmed everywhere before the next one is built on top of it.
confirm_on() {
    local count="${1:-2}" target
    target=$(( $(height 0) + count ))
    mine_to 0 "$target" >/dev/null || return 1
    wait_sync "$target" >/dev/null || return 1
    return 0
}

# Drive the transparent vote round at every epoch boundary in [from, to]. Skipping
# a boundary stalls finalization.
advance_through_epochs() {
    local from="$1" to="$2" e b
    for ((e=from; e<=to; e++)); do
        b="$(epoch_start "$e")"
        log "  epoch $e boundary at height $b"
        vote_round "$b" || return 1
    done
    return 0
}

# "<txhash>:<index>" for each attestable 25000 INN note, one per line. This is
# exactly the identifier finality-register takes.
collateral_note_ids() {
    rpc "$1" collateralnode collateral-notes 2>/dev/null | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for c in doc.get("candidates", []):
    n = c.get("note")
    if n: print(n)
'
}

# The compressed member pubkeys the chain says are seated right now, one per
# line, in seat order.
committee_seats() {
    rpc "$1" getfinalityinfo 2>/dev/null | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for k in ("committee", "committee_seats", "committee_members", "committee_pubkeys"):
    v = doc.get(k)
    if isinstance(v, list):
        for s in v:
            print(s if not isinstance(s, dict)
                  else (s.get("pubkey") or s.get("member_pubkey") or ""))
        break
'
}

# A 64-hex value that is not the all-zero hash. Every fleet-agreement check below
# is guarded with this: an RPC that failed yields an empty field and an epoch with
# no state yields the zero hash, and "all three nodes agree" is true of both.
is_real_hash() { [ ${#1} -eq 64 ] && ! is_zero_hex "$1"; }

# Reorganize() opens with an unconditional printf("REORGANIZE"), so this counts
# actual block disconnections rather than a state a node could also have reached
# by fast-forward.
reorg_count() {
    local c
    c="$(grep -cF "REORGANIZE" "$(node_log "$1")" 2>/dev/null | tr -d '[:space:]')"
    if is_int "$c"; then echo "$c"; else echo 0; fi
}

votes_in_range() {
    local node="$1" from="$2" to="$3" total=0 h c
    for ((h=from; h<=to; h++)); do
        c="$(jlen "$(block_json "$node" "$h")" finality_votes)"
        is_int "$c" && [ "$c" -gt 0 ] && total=$((total + c))
    done
    echo "$total"
}

# ------------------------------------------------------------------
# Note-vote observation
# ------------------------------------------------------------------

# The producer's own account of one epoch, out of node0's log. The success line is
# printed by ProducePrivacyVNextNoteVote after the vote entered node0's mempool; a
# refusal is printed by ProduceFinalityVote behind fDebug.
#   ProducePrivacyVNextNoteVote: epoch=E boundary=B height=H txid=<10 hex>
producer_success()  { grep -aF "ProducePrivacyVNextNoteVote: epoch=$1 " "$(node_log 0)" 2>/dev/null; }
producer_refused()  { grep -aF "no IV5 note vote for epoch $1: the note finality vote was built but could not be committed" "$(node_log 0)" 2>/dev/null; }
producer_all()      { grep -aE "ProducePrivacyVNextNoteVote:|no IV5 note vote for epoch" "$(node_log 0)" 2>/dev/null; }
producer_txid()     { producer_success "$1" | head -1 | sed -n 's/.*txid=\([0-9a-f]*\).*/\1/p'; }
producer_boundary() { producer_success "$1" | head -1 | sed -n 's/.* boundary=\([0-9]*\).*/\1/p'; }

raw_tx() { rpc "$1" getrawtransaction "$2" 2>/dev/null | tr -d '"[:space:]'; }

# The full id of the mempool transaction whose txid starts with PREFIX, if any.
mempool_txid() {
    [ -n "$2" ] || return 0
    rpc "$1" getrawmempool 2>/dev/null | grep -oE '[0-9a-f]{64}' | grep "^$2" | head -1
}

# An operation-10 payload read off the transaction bytes rather than the node's parse:
# "<inputs> <key image> <boundary height> <boundary hash>", hashes in the byte order the
# RPC prints a uint256, so the key image reads as the tag getepochinfo reports.
notevote_fields() {
    local raw; raw="$(raw_tx "$1" "$2")"
    [ -n "$raw" ] || return 1
    RAW="$raw" python3 -c '
import os, sys
b = bytes.fromhex(os.environ["RAW"]); i = 0
def take(n):
    global i
    if i + n > len(b): raise ValueError("short")
    v = b[i:i+n]; i += n; return v
def u(n): return int.from_bytes(take(n), "little")
def cs():
    n = u(1)
    return n if n < 253 else u({253: 2, 254: 4, 255: 8}[n])
try:
    u(4); u(4)
    for _ in range(cs()): take(36); take(cs()); u(4)
    for _ in range(cs()): u(8); take(cs())
    u(4)
    if take(5) != b"\xffIV5P": raise ValueError("no IV5 envelope")
    u(2)
    b, i = take(cs()), 0
    if u(2) != 1: raise ValueError("payload schema")
    if u(1) != 10: raise ValueError("not operation 10")
    take(6)
    # genesis, parameter digest, finalized root, tree size, balance, fee, binding
    take(32 + 32 + 32 + 8 + 8 + 8 + 32)
    n_in = cs(); kis = []
    for _ in range(n_in): take(32); kis.append(take(32))
    for _ in range(cs()):
        take(128); take(cs()); take(cs())
    bh = take(32); bheight = u(4)
    print(n_in, kis[0][::-1].hex() if kis else "-", bheight, bh[::-1].hex())
except Exception:
    sys.exit(1)
'
}

# Every canonical tally certificate a block's coinbase carries, off the script bytes:
# "<cert version> <epoch> <tier> <signers> <note count> <note root>" per IFCC envelope,
# the root in RPC byte order. getblock reports neither note field.
cert_envelopes() {
    local bh cb raw
    bh="$(block_hash "$1" "$2")"
    [ ${#bh} -eq 64 ] || return 1
    cb="$(rpc "$1" getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["tx"][0])
except Exception: pass
')"
    [ ${#cb} -eq 64 ] || return 1
    raw="$(raw_tx "$1" "$cb")"
    [ -n "$raw" ] || return 1
    RAW="$raw" python3 -c '
import os, sys
b = bytes.fromhex(os.environ["RAW"]); i = 0
def take(n):
    global i
    if i + n > len(b): raise ValueError("short")
    v = b[i:i+n]; i += n; return v
def u(n): return int.from_bytes(take(n), "little")
def s(n): return int.from_bytes(take(n), "little", signed=True)
def cs():
    n = u(1)
    return n if n < 253 else u({253: 2, 254: 4, 255: 8}[n])
try:
    u(4); u(4)
    for _ in range(cs()): take(36); take(cs()); u(4)
    scripts = []
    for _ in range(cs()): u(8); scripts.append(take(cs()))
except Exception:
    sys.exit(1)
for sc in scripts:
    if len(sc) < 2 or sc[0] != 0x6a: continue
    op, j = sc[1], 2
    if op <= 75: n = op
    elif op == 0x4c: n = sc[j]; j += 1
    elif op == 0x4d: n = int.from_bytes(sc[j:j+2], "little"); j += 2
    else: continue
    d = sc[j:j+n]
    if d[:4] != b"IFCC": continue
    b, i = d[4:], 0
    try:
        # CCanonicalFinalityTallyCertificateEnvelope, finality.h
        lv = u(4); cv = s(4); ep = s(4); take(32); s(4); tier = s(4); s(4)
        take(96); take(24)
        for _ in range(cs()): take(32)
        signers, cnt, root = 0, 0, bytes(32)
        if lv >= 2:
            signers = cs(); take(2 * signers)
            for _ in range(cs()): take(cs())
            root = take(32); cnt = u(4)
        if i != len(b): raise ValueError("trailing bytes")
        print(cv, ep, tier, signers, cnt, root[::-1].hex())
    except Exception:
        print("undecodable")
'
}

# ComputeNoteVoteSetRoot over RPC-order tags: sorted, domain-separated double-SHA256
# leaves and nodes, an odd tail promoted rather than duplicated.
note_set_root() {
    TAGS="$*" python3 -c '
import hashlib, os
def h(x): return hashlib.sha256(hashlib.sha256(x).digest()).digest()
def ser(s): return bytes([len(s)]) + s
tags = sorted(t for t in os.environ["TAGS"].split() if t)
if not tags:
    print("0" * 64); raise SystemExit
lv = [h(ser(b"Innova/Finality/NoteVoteLeaf/v1") + bytes.fromhex(t)[::-1]) for t in tags]
while len(lv) > 1:
    nx = [h(ser(b"Innova/Finality/NoteVoteNode/v1") + lv[k] + lv[k + 1])
          for k in range(0, len(lv) - 1, 2)]
    if len(lv) % 2: nx.append(lv[-1])
    lv = nx
print(lv[0][::-1].hex())
'
}

# The note_vote_tags array of a getepochinfo result, space separated.
epoch_note_tags() {
    python3 -c '
import json, sys
try: print(" ".join(json.load(sys.stdin).get("note_vote_tags") or []))
except Exception: pass
' <<< "$1" 2>/dev/null
}

# One epoch's counted note-vote set on NODE: "<counted> <equivocated> <tags...>", tags
# sorted. getepochinfo reports only epochs whose state is built; the tip's own epoch is
# read from getfinalityinfo's live note_votes view instead.
epoch_note_view() {
    local ei fi
    ei="$(rpc "$1" getepochinfo "$2" 2>/dev/null)"
    fi="$(rpc "$1" getfinalityinfo 2>/dev/null)"
    EI="$ei" FI="$fi" E="$2" python3 -c '
import json, os
def load(k):
    try: return json.loads(os.environ[k])
    except Exception: return {}
ei, nv = load("EI"), load("FI").get("note_votes") or {}
if "note_votes_counted" in ei:
    c, q, t = ei["note_votes_counted"], ei.get("note_votes_equivocated"), ei.get("note_vote_tags") or []
elif nv.get("epoch") == int(os.environ["E"]):
    c, q, t = nv.get("counted"), nv.get("equivocated"), nv.get("tags") or []
else:
    raise SystemExit
print(" ".join([str(c), str(q)] + sorted(t)))
'
}

# A second vote from one note (same vote, nTime one second earlier) must be refused by
# the spent-key rule alone. Sets PROBE_WHY on failure.
double_vote_probe() {
    local node="$1" txid="$2" expect="$3" raw ki mut mut_id res pat before after
    PROBE_WHY=""
    raw="$(raw_tx "$node" "$txid")"
    ki="$(notevote_fields "$node" "$txid" | awk '{print $2}')"
    [ -n "$raw" ] && [ ${#ki} -eq 64 ] || { PROBE_WHY="node$node cannot read vote ${txid:0:16}"; return 1; }
    read -r mut mut_id < <(RAW="$raw" python3 -c '
import hashlib, os
b = bytearray.fromhex(os.environ["RAW"])
t = int.from_bytes(b[4:8], "little") - 1
b[4:8] = t.to_bytes(4, "little")
print(b.hex(), hashlib.sha256(hashlib.sha256(bytes(b)).digest()).digest()[::-1].hex())
')
    [ ${#mut_id} -eq 64 ] && [ "$mut_id" != "$txid" ] || { PROBE_WHY="could not build the second vote"; return 1; }
    pat="IV5 spent key ${ki:0:10} $expect ${txid:0:10}"
    before="$(grep -acF "$pat" "$(node_log "$node")" 2>/dev/null)"
    res="$(rpc "$node" sendrawtransaction "$mut" 2>&1 | tr -d '"[:space:]')"
    sleep 1
    after="$(grep -acF "$pat" "$(node_log "$node")" 2>/dev/null)"
    is_int "${before:-x}" || before=0
    is_int "${after:-x}" || after=0
    if [ "$res" = "$mut_id" ] || [ -n "$(mempool_txid "$node" "$mut_id")" ]; then
        PROBE_WHY="node$node ACCEPTED a second vote ${mut_id:0:16} spending key image ${ki:0:16}"
        return 1
    fi
    if [ "$after" -le "$before" ]; then
        PROBE_WHY="node$node refused ${mut_id:0:16} but not with '$pat': $(grep -a "CTxMemPool::accept()" "$(node_log "$node")" | tail -1)"
        return 1
    fi
    PROBE_KI="$ki"
    return 0
}

# One note-vote epoch. The chain is held at the emit height, where the vote is cast and
# relayed while nothing can mine it away, and each node's mempool is watched for it.
# Records NV_TXID[E] (full txid, from node0's mempool) and NV_SEEN[E] (nodes whose mempool
# held it). With PROBE=1, a second vote is offered to node1 once node1 holds the first.
NV_TXID=()
NV_SEEN=()
PROBE_MEMPOOL_OK=""
PROBE_MEMPOOL_WHY=""
note_vote_round() {
    local e="$1" b="$2" carry="$3" probe="${4:-0}" hold s n t10 full
    hold=$(( b + NOTE_VOTE_EMIT_OFFSET ))
    mine_to 0 "$hold" || return 1
    wait_sync "$hold" || return 1
    NV_SEEN[$e]=""
    NV_TXID[$e]=""
    for ((s=0; s<NOTE_VOTE_SETTLE; s++)); do
        sleep 1
        t10="$(producer_txid "$e")"
        [ -n "$t10" ] || continue
        for ((n=0; n<NUM_NODES; n++)); do
            case " ${NV_SEEN[$e]} " in *" $n "*) continue ;; esac
            full="$(mempool_txid "$n" "$t10")"
            [ ${#full} -eq 64 ] || continue
            NV_SEEN[$e]="${NV_SEEN[$e]} $n"
            [ "$n" -eq 0 ] && NV_TXID[$e]="$full"
        done
    done
    if [ "$probe" = "1" ]; then
        full="$(mempool_txid 1 "$(producer_txid "$e")")"
        if [ ${#full} -eq 64 ] && double_vote_probe 1 "$full" "is reserved by"; then
            PROBE_MEMPOOL_OK=1
        else
            PROBE_MEMPOOL_OK=0
            PROBE_MEMPOOL_WHY="${PROBE_WHY:-node1 never held the epoch $e vote}"
        fi
    fi
    mine_to 0 $(( b + carry )) || return 1
    wait_sync $(( b + carry )) || return 1
}

# Every note-vote transaction in a block, by txid. A vote declares operation 10 in its
# payload envelope and carries no transparent side at all, which is what the carrier rule
# requires of it.
notevote_txids() {
    local node="$1" h="$2" bh
    bh="$(block_hash "$node" "$h")"
    [ ${#bh} -eq 64 ] || return 1
    local txids
    txids="$(rpc "$node" getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print("\n".join(json.load(sys.stdin).get("tx", [])))
except Exception: pass
')"
    local t
    while read -r t; do
        [ ${#t} -eq 64 ] || continue
        rpc "$node" getrawtransaction "$t" 1 2>/dev/null | \
        TXID="$t" OP="$NOTE_VOTE_OPERATION" python3 -c '
import json, os, sys
try: tx = json.load(sys.stdin)
except Exception: sys.exit(0)
pv = tx.get("privacy_vnext") or {}
if pv.get("operation") == int(os.environ["OP"]):
    print(os.environ["TXID"])
'
    done <<< "$txids"
}

# Every note vote a node sees in [from, to], and the height carrying each.
# Prints "height txid" lines.
notevotes_in_range() {
    local node="$1" from="$2" to="$3" h s
    for ((h=from; h<=to; h++)); do
        while read -r s; do
            [ -n "$s" ] && echo "$h $s"
        done < <(notevote_txids "$node" "$h" 2>/dev/null)
    done
}

write_config() {
    local node="$1" dir peer key
    dir="$(node_dir "$node")"
    mkdir -p "$dir"
    {
        echo "regtest=1"
        echo "server=1"
        echo "rpcuser=$RPCUSER"
        echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$node")"
        echo "port=$(node_port "$node")"
        echo "bind=127.0.0.1"
        echo "listen=1"
        echo "dnsseed=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "idnsport=$(node_idns "$node")"
        echo "maxconnections=32"
        # Only node0 produces blocks; PoS would fork the pre-DAG stretch where
        # every wallet is being funded.
        echo "staking=0"
        echo "nofinalityvoting=0"
        # One lane per node. A node that emitted both an identity vote and an
        # anonymous note vote for an epoch would hand every directly connected peer
        # the link between the tag and the wallet, so node0 -- the only node with
        # IV5 notes -- takes the anonymous lane and casts no transparent vote, and
        # the two peers carry the identity lane the deterministic tally counts.
        # FINALITY_MIN_VOTERS is 2, so those two peers are exactly what keeps the
        # epochs HARD; node0 depends on them, which is the point of the split.
        if [ "$node" -eq 0 ]; then
            echo "finalityvotemode=note"
        else
            echo "finalityvotemode=transparent"
        fi
        echo "regtestboundaryb=$BOUNDARY_B"
        echo "regtestiv5rehearsal=1"
        echo "regtestiv5notevote=$NOTE_VOTE_HEIGHT"
        # No committee is configured anywhere: the canonical set is drawn from the
        # IV5 collateral registry and carried by the chain's own epoch state. The
        # only thing a node is told is the secret it would serve a seat with, and
        # the seat itself has to be won by a registration.
        echo "finalitytallyprivkey=${COMMITTEE_PRIVKEYS[$node]}"
        # Every producer gate log is behind fDebug, and -debug deliberately does
        # NOT imply -debugnet, which carries the peer-side receive line.
        echo "debug=1"
        echo "debugnet=1"
        for ((peer=0; peer<NUM_NODES; peer++)); do
            [ "$peer" -eq "$node" ] && continue
            echo "addnode=127.0.0.1:$(node_port "$peer")"
        done
    } > "$dir/innova.conf"
}

cleanup() {
    # The reorg section starts a fourth node from an empty datadir, so teardown
    # covers one more than the fleet size.
    local n last=$((NUM_NODES))
    for ((n=0; n<=last; n++)); do rpc "$n" setgenerate false 0 >/dev/null 2>&1 || true; done
    for ((n=0; n<=last; n++)); do rpc "$n" stop >/dev/null 2>&1 || true; done
    for ((n=0; n<=last; n++)); do
        if ! wait_rpc_down "$n"; then
            warn "node$n did not stop; killing it by pid"
            force_kill_node "$n"
        fi
    done
    # Anything still holding a datadir under this run's tree, by pid only; a broad
    # pattern can match a shell or ssh command line.
    for ((n=0; n<NUM_NODES; n++)); do force_kill_node "$n"; done
    wait_ports_free >/dev/null 2>&1 || warn "regtest ports were still held at exit"
    if [ "${IV5_NOTE_VOTE_KEEP_DIR:-${KEEP_DIR:-0}}" = "1" ] || [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
    # Early exits still print the tally.
    [ "$RESULTS_PRINTED" = "1" ] || print_results
}
trap cleanup EXIT

header "IV5 note finality vote regtest"

[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }

BUSY="$(wait_ports_free)" || {
    fail "regtest ports still in use before the fleet starts:$BUSY"
    fail "a previous run's daemon is still holding them; stop it before retrying"
    exit 1
}

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done

# ============================================================
header "0. The note-vote fork cannot be scheduled before the pool"
# ============================================================

# init refuses -regtestiv5notevote below Boundary B, because a note has to exist
# before it can vote. Driving the refusal here also proves the flag is parsed.
PREFLIGHT_DIR="$TEST_DIR/preflight"
mkdir -p "$PREFLIGHT_DIR"
# A refusal exits immediately; the timeout only bounds the case where it does not.
PREFLIGHT_TIMEOUT=""
command -v timeout >/dev/null 2>&1 && PREFLIGHT_TIMEOUT="timeout 120"
PREFLIGHT_OUT="$(
    $PREFLIGHT_TIMEOUT "$INNOVAD" -datadir="$PREFLIGHT_DIR" -regtest -listen=0 \
        -dnsseed=0 -nobootstrap=1 -nosmsg=1 -rpcuser=x -rpcpassword=y \
        -rpcport=$((BASE_RPC + 90)) -port=$((BASE_PORT + 90)) \
        -regtestboundaryb="$BOUNDARY_B" \
        -regtestiv5notevote=$((BOUNDARY_B - 1)) 2>&1 | head -20
)"
if echo "$PREFLIGHT_OUT" | grep -qi "below the Boundary-B height"; then
    success "a note-vote fork below Boundary B is refused at startup"
else
    fail "init did not refuse a note-vote fork below Boundary B: $(echo "$PREFLIGHT_OUT" | head -3)"
fi
rm -rf "$PREFLIGHT_DIR"

# ============================================================
header "1. Fleet up with the note-vote fork configured"
# ============================================================

for ((n=0; n<NUM_NODES; n++)); do
    start_node "$n" || { fail "node$n did not start"; exit 1; }
done
wait_peers || { fail "fleet did not mesh"; exit 1; }
success "$NUM_NODES-node fleet up and meshed (Boundary B at $BOUNDARY_B)"

FORK_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    grep -qF "IV5 note-vote fork height: $NOTE_VOTE_HEIGHT (regtest only)" \
        "$(node_log "$n")" 2>/dev/null || FORK_OK=0
done
if [ "$FORK_OK" -eq 1 ]; then
    success "every node accepted the note-vote fork at height $NOTE_VOTE_HEIGHT"
else
    fail "at least one node did not report the note-vote fork height"
    exit 1
fi

# The pinned-committee path is NOT gone from the daemon: GetFinalityTallyConfig
# still parses -finalitytallypubkey and -finalitytallythreshold, and
# CFinalityTallyConfig still computes a configured committeeSetHash from them. What
# is asserted here is the narrower, true thing -- that path is unused in this run.
# Both directions are checked, because the harness writing the configs is not
# evidence about the daemon: no node is GIVEN those inputs, and every node reports
# back that it holds zero configured committee pubkeys, no valid configured
# committee and a zero configured set hash, with only its own member secret loaded.
PINNED=0
for ((n=0; n<NUM_NODES; n++)); do
    grep -qE '^[[:space:]]*(finalitytallypubkey|finalitytallythreshold)[[:space:]]*=' \
        "$(node_dir "$n")/innova.conf" && PINNED=1
done
CONFIG_OK=1
CONFIG_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    [ "$(jget "$FI" tally_pubkey_configured)" = "false" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n reports a configured committee pubkey"; }
    [ "$(jget "$FI" tally_configured_pubkeys)" = "0" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n reports $(jget "$FI" tally_configured_pubkeys) configured pubkeys"; }
    [ "$(jget "$FI" tally_committee_valid)" = "false" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n reports a valid CONFIGURED committee"; }
    [ "$(jget "$FI" tally_threshold_valid)" = "false" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n reports a valid configured threshold"; }
    is_zero_hex "$(jget "$FI" tally_committee_set_hash)" || \
        { CONFIG_OK=0; CONFIG_WHY="node$n has a non-zero CONFIGURED committee set hash"; }
    [ "$(jget "$FI" tally_privkey_valid)" = "true" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n did not load its member secret"; }
done
if [ "$PINNED" -eq 0 ] && [ "$CONFIG_OK" -eq 1 ]; then
    success "the pinned-committee inputs are unused: no node is given one and every node reports 0 configured pubkeys, holding only its own member secret"
else
    fail "the pinned-committee path is in play (config files carry it: $PINNED; $CONFIG_WHY)"
    exit 1
fi

# committee_source is a fixed string in the RPC, so it identifies WHICH resolver
# this build ships, not where a seat came from. Where the seats came from is
# settled in 5c/5d by PRE_TERM_ANCHOR_HEIGHT. committee_seated is false here for a
# structural reason that holds for any implementation -- no epoch state exists yet,
# so GetCommitteeForEpoch has no carrier record to read -- and is recorded as the
# baseline rather than as evidence.
DRAW_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    [ "$(jget "$FI" committee_source)" = "collateral_registry_draw" ] || DRAW_OK=0
    [ "$(jget "$FI" committee_seated)" = "false" ] || DRAW_OK=0
done
if [ "$DRAW_OK" -eq 1 ]; then
    success "every node ships the collateral-registry-draw resolver and starts with nothing seated"
else
    fail "a node did not report an unseated collateral-registry-draw committee"
fi

# The term this run schedules has to be a term the chain recognises. A term epoch
# off the grid is carried and then never resolved, and the seating stage is 5000
# blocks away, so it is checked here rather than found there.
NODE_TERM_LEN="$(jget "$(rpc 0 getfinalityinfo 2>/dev/null)" committee_term_epochs)"
if [ "$NODE_TERM_LEN" = "$COMMITTEE_TERM_EPOCHS" ] && \
   [ $(( COMMITTEE_TERM_EPOCH % COMMITTEE_TERM_EPOCHS )) -eq 0 ] && \
   [ $(( PRE_TERM_EPOCH % COMMITTEE_TERM_EPOCHS )) -eq 0 ] && \
   [ "$PRE_TERM_ANCHOR_HEIGHT" -le "$REGISTER_HEIGHT" ]; then
    success "term $COMMITTEE_TERM_EPOCH is on the chain's $NODE_TERM_LEN-epoch term grid (anchor $COMMITTEE_ANCHOR_EPOCH, carrier $COMMITTEE_CARRIER_EPOCH), and the previous term $PRE_TERM_EPOCH anchors at $PRE_TERM_ANCHOR_HEIGHT, at or below the registration height $REGISTER_HEIGHT"
else
    fail "the committee schedule is off the grid: term $COMMITTEE_TERM_EPOCH / previous term $PRE_TERM_EPOCH against a chain term length of $NODE_TERM_LEN (harness assumed $COMMITTEE_TERM_EPOCHS), previous anchor $PRE_TERM_ANCHOR_HEIGHT vs registration height $REGISTER_HEIGHT"
    exit 1
fi

# The seats are won further down, in sections 5a-5d. Nothing is configured.

# ============================================================
header "2. node0 holds an IV5 seed in an encrypted wallet"
# ============================================================

rpc 0 encryptwallet "$WALLETPASS" >/dev/null 2>&1
wait_rpc_down 0 || { fail "node0 did not stop after encrypting the wallet"; exit 1; }
start_node 0 || { fail "node0 did not restart after encrypting the wallet"; exit 1; }
connect_mesh
wait_peers || { fail "node0 did not rejoin the mesh"; exit 1; }

UNLOCK="$(rpc 0 walletpassphrase "$WALLETPASS" 1000000 2>&1)"
if echo "$UNLOCK" | grep -qiE "error"; then
    fail "could not unlock node0: $(echo "$UNLOCK" | head -2)"
    exit 1
fi
SEED="$(rpc 0 z_createiv5seed 2>&1)"
if echo "$SEED" | grep -q '"created"'; then
    success "IV5 seed created into node0's encrypted wallet"
else
    fail "z_createiv5seed failed: $(echo "$SEED" | head -3)"
    exit 1
fi

# ============================================================
header "3. Three distinct wallets hold votable transparent stake"
# ============================================================

# Negative control first: the peers hold no stake at the epoch-1 boundary and
# node0 is in the anonymous lane, so epoch 1 carries no transparent vote at all
# and stays below FINALITY_MIN_VOTERS. node0 holding stake and still casting
# nothing is the lane split working.
vote_round 11 || { fail "epoch 1 vote round failed"; exit 1; }
E1_VOTES="$(votes_in_range 0 11 14)"
if [ "$E1_VOTES" = "0" ]; then
    success "epoch 1 carried no transparent finality vote: no peer holds stake yet and node0 is note-only"
else
    fail "epoch 1 carried $E1_VOTES finality votes, expected 0"
fi

mine_to 0 "$FUND_HEIGHT" || { fail "mining to the funding height failed"; exit 1; }
wait_sync "$FUND_HEIGHT" || { fail "peers did not sync the funding chain"; exit 1; }

FUND_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    ADDR="$(rpc "$n" getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    if [ ${#ADDR} -lt 20 ]; then FUND_OK=0; break; fi
    SENT="$(fund_peer "$ADDR" "$FUND_AMOUNT")"
    if [ ${#SENT} -ne 64 ]; then
        fail "funding node$n failed"
        FUND_OK=0
        break
    fi
    log "  node$n funded with $FUND_AMOUNT INN (txid ${SENT:0:16})"
done
[ "$FUND_OK" -eq 1 ] || { fail "could not fund the peer wallets"; exit 1; }

mine_to 0 "$FUND_CONFIRM_HEIGHT" || { fail "could not confirm the funding transactions"; exit 1; }
wait_sync "$FUND_CONFIRM_HEIGHT" || { fail "peers did not sync the funding blocks"; exit 1; }

STAKE_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    BAL="$(rpc "$n" getbalance 2>/dev/null | tr -d '"[:space:]')"
    feq "${BAL:-0}" "$FUND_AMOUNT" || STAKE_OK=0
done
if [ "$STAKE_OK" -eq 1 ]; then
    success "each peer wallet holds $FUND_AMOUNT INN under its own key"
else
    fail "peer wallets are not funded"
    exit 1
fi

# ============================================================
header "4. Value enters the IV5 pool inside epoch 2"
# ============================================================

vote_round "$BOUNDARY_B" || { fail "epoch 2 vote round failed"; exit 1; }
E2_VOTES="$(votes_in_range 0 "$BOUNDARY_B" $((BOUNDARY_B + 4)))"
if is_int "$E2_VOTES" && [ "$E2_VOTES" -ge 2 ]; then
    success "epoch 2 carried $E2_VOTES relayed finality votes"
else
    fail "epoch 2 carried $E2_VOTES finality votes, need >= 2"
fi

INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
B_ACTIVE="$(jget "$INFO" boundary_b_active)"
B_ACCEPT="$(jget "$INFO" privacy_vnext_transactions_accepted)"
if [ "$B_ACTIVE" = "true" ] && [ "$B_ACCEPT" = "true" ]; then
    success "Boundary B active and consensus accepts IV5 transactions"
else
    fail "IV5 inactive (boundary_b_active=$B_ACTIVE accepted=$B_ACCEPT)"
    exit 1
fi

mine_to 0 "$SHIELD_HEIGHT" || { fail "could not mine to the shield height"; exit 1; }
wait_sync "$SHIELD_HEIGHT" || { fail "peers did not sync to the shield height"; exit 1; }

# A vote needs ONE note worth at least the stake floor (GetFinalityMinVoteWeight,
# 500 INN), so sweep several addresses: each sweep moves one address's whole value with no
# transparent change. Each is confirmed before the next is built, because a
# shield names the tree it saw.
SHIELDS=0
for ((s=0; s<SHIELD_SWEEPS; s++)); do
    SH="$(rpc 0 z_shieldall 2>&1)"
    SH_TXID="$(jget "$SH" txid)"
    [ ${#SH_TXID} -eq 64 ] || break
    SHIELDS=$((SHIELDS + 1))
    log "  swept $(jget "$SH" shielded) INN from $(jget "$SH" inputs) output(s) into the pool"
    SH_TARGET=$(( $(height 0) + 2 ))
    mine_to 0 "$SH_TARGET" >/dev/null || break
    wait_sync "$SH_TARGET" >/dev/null || break
done
if [ "$SHIELDS" -ge 1 ]; then
    success "$SHIELDS shield sweep(s) confirmed into the IV5 pool"
else
    fail "no value could be shielded into the IV5 pool"
    exit 1
fi

mine_to 0 "$SHIELD_CONFIRM_HEIGHT" || { fail "could not confirm the shields"; exit 1; }
wait_sync "$SHIELD_CONFIRM_HEIGHT" || { fail "peers did not accept the shield blocks"; exit 1; }

INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
POOL_NOTES="$(jget "$INFO" privacy_vnext_note_count)"
POOL_UNCONF="$(jget "$INFO" privacy_vnext_unconfirmed_balance)"
if is_int "$POOL_NOTES" && [ "$POOL_NOTES" -gt 0 ]; then
    success "node0 sees $POOL_NOTES IV5 note(s) worth $POOL_UNCONF INN"
else
    fail "node0 sees no IV5 notes after shielding"
    exit 1
fi

# ============================================================
header "5. Three consecutive HARD epochs produce a finalized height"
# ============================================================

vote_round 611  || { fail "epoch 3 vote round failed"; exit 1; }

# A note is votable once an epoch build has put it in the IV5 tree and assigned its
# leaf index, which happens when the chain crosses into the next epoch. The vote
# anchors to epoch state E-1, not to finality, so spendable balance -- which waits on
# the finalized tree or the depth anchor -- is zero here by design. Placement is the
# owned value less the unplaced part, which also holds value that arrived in the
# current epoch; the floor is 500 INN of placed value.
INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
POOL_OWNED="$(python3 -c "print(float('$(jget "$INFO" privacy_vnext_balance)' or 0) + float('$(jget "$INFO" privacy_vnext_unconfirmed_balance)' or 0))" 2>/dev/null)"
POOL_UNPLACED="$(jget "$INFO" privacy_vnext_unplaced_balance)"
POOL_NOTES="$(jget "$INFO" privacy_vnext_note_count)"
TREE_SIZE="$(jget "$INFO" privacy_vnext_tree_size)"
if [ "$(python3 -c "print(1 if float('${POOL_OWNED:-0}') - float('${POOL_UNPLACED:-0}') >= 500 else 0)" 2>/dev/null)" = "1" ] && \
   is_int "$TREE_SIZE" && [ "$TREE_SIZE" -gt 0 ]; then
    success "node0 owns $POOL_OWNED INN ($POOL_UNPLACED not yet placed) across $POOL_NOTES note(s), tree=$TREE_SIZE"
else
    fail "node0 has no votable IV5 note (owned=${POOL_OWNED:-?} unplaced=${POOL_UNPLACED:-?} notes=$POOL_NOTES tree=$TREE_SIZE)"
    exit 1
fi

vote_round 911  || { fail "epoch 4 vote round failed"; exit 1; }

for e in 2 3; do
    EI="$(rpc 0 getepochinfo "$e" 2>/dev/null)"
    T="$(jget "$EI" finality_tier)"
    H="$(jget "$EI" consecutive_hard_epochs)"
    if [ "$T" = "hard" ] && [ "$H" = "$((e - 1))" ]; then
        success "epoch $e is tier=$T consecutive_hard=$H"
    else
        fail "epoch $e did not reach HARD (tier=$T consecutive_hard=$H)"
        exit 1
    fi
done

# ============================================================
header "5a. node0 holds the private half of every member key"
# ============================================================

# finality-register refuses a key this wallet cannot decrypt to: a seat nobody
# can serve is worse than no seat. Each node keeps its own finalitytallyprivkey,
# so the registering wallet has to hold all three.
IMPORT_OK=1
for ((k=0; k<NUM_NODES; k++)); do
    IMP="$(rpc 0 importprivkey "${COMMITTEE_WIFS[$k]}" "member$k" false 2>&1)"
    if echo "$IMP" | grep -qiE "error|invalid"; then
        fail "importing member key $k failed: $(echo "$IMP" | head -2)"
        IMPORT_OK=0
    fi
done
[ "$IMPORT_OK" -eq 1 ] || exit 1

success "node0 imported the private half of all $NUM_NODES member keys"

# ============================================================
header "5b. Six 25000 INN collateral notes are carved in the pool"
# ============================================================

# Past the fixed-height fleet setup: the rest is thousands of blocks and epoch
# boundaries, so the miner can use every core.
MINE_THREADS_NOW="$MINE_THREADS"
log "raising the miner to $MINE_THREADS_NOW threads for the run to the committee term"

# Everything up to the anchor epoch needs a vote round at each boundary: an
# epoch that misses one is not HARD, the finalized height stops advancing, and
# a note in an unfinalized epoch is not attestable.
advance_through_epochs 5 "$POOL_FUND_EPOCH" || { fail "the epoch 5-$POOL_FUND_EPOCH vote rounds failed"; exit 1; }

log "mining to $POOL_FUND_HEIGHT, where node0's mature coinbase covers $POOL_SHIELD_ROWS x $POOL_SHIELD_VALUE INN"
mine_to 0 "$POOL_FUND_HEIGHT" || { fail "could not mine to the pool-funding height"; exit 1; }
wait_sync "$POOL_FUND_HEIGHT" || { fail "fleet did not sync to the pool-funding height"; exit 1; }

BAL="$(rpc 0 getbalance 2>/dev/null | tr -d '"[:space:]')"
if [ "$(python3 -c "print(1 if float('${BAL:-0}') >= $POOL_SHIELD_TOTAL else 0)")" = "1" ]; then
    success "node0 holds $BAL INN, enough to fund the pool with $POOL_SHIELD_TOTAL"
else
    fail "node0 holds $BAL INN but needs $POOL_SHIELD_TOTAL; raise POOL_FUND_HEIGHT"
    exit 1
fi

# One consolidating send per row, then one sweep per row. z_shieldall moves a
# single address's whole value with no transparent change, so consolidating
# first is what turns ~500 coinbase outputs into one shieldable note.
SHIELDED_ROWS=0
SHIELDED_TOTAL=0
for ((r=0; r<POOL_SHIELD_ROWS; r++)); do
    RADDR="$(rpc 0 getnewaddress "poolfund$r" 2>/dev/null | tr -d '"[:space:]')"
    [ ${#RADDR} -ge 20 ] || { fail "could not create a consolidation address"; break; }
    SENT="$(fund_peer "$RADDR" "$POOL_SHIELD_VALUE")"
    [ ${#SENT} -eq 64 ] || { fail "consolidating row $r failed"; break; }
    confirm_on 2 || { fail "could not confirm consolidation $r"; break; }
    SH="$(rpc 0 z_shieldall "$RADDR" 2>&1)"
    SH_TXID="$(jget "$SH" txid)"
    if [ ${#SH_TXID} -ne 64 ]; then
        fail "shielding row $r failed: $(echo "$SH" | head -2)"
        break
    fi
    confirm_on 2 || { fail "could not confirm shield $r"; break; }
    SHIELDED_ROWS=$((SHIELDED_ROWS + 1))
    SHIELDED_TOTAL="$(python3 -c "print(round($SHIELDED_TOTAL + float('$(jget "$SH" shielded)' or 0), 8))")"
    log "  row $r: $(jget "$SH" shielded) INN into the pool (running total $SHIELDED_TOTAL)"
done
if [ "$SHIELDED_ROWS" -eq "$POOL_SHIELD_ROWS" ] && \
   [ "$(python3 -c "print(1 if $SHIELDED_TOTAL >= $POOL_SHIELD_TOTAL else 0)")" = "1" ]; then
    success "$SHIELDED_ROWS shields put $SHIELDED_TOTAL INN into the pool, over the $POOL_SHIELD_TOTAL the carve needs"
else
    fail "only $SHIELDED_ROWS of $POOL_SHIELD_ROWS rows reached the pool ($SHIELDED_TOTAL of $POOL_SHIELD_TOTAL INN)"
    exit 1
fi

# The funding shields must all be inside POOL_FUND_EPOCH: a shield that lands in
# the carve epoch is not in the tree the carve proves against.
if [ "$(height 0)" -le "$(epoch_end "$POOL_FUND_EPOCH")" ]; then
    success "every funding shield confirmed inside epoch $POOL_FUND_EPOCH, which the carve spends against"
else
    fail "the funding shields ran past epoch $POOL_FUND_EPOCH (tip $(height 0) > $(epoch_end "$POOL_FUND_EPOCH")); the last of them are not in the carve's tree"
    exit 1
fi

# Cross into the carve epoch: the funding epoch's build indexes those notes and,
# because the epoch goes HARD, finalizes them into the anchor a spend proves
# against.
advance_through_epochs $(( POOL_FUND_EPOCH + 1 )) "$CARVE_EPOCH" || { fail "the epoch $(( POOL_FUND_EPOCH + 1 ))-$CARVE_EPOCH vote rounds failed"; exit 1; }
mine_to 0 $((CARVE_HEIGHT + 10)) || { fail "could not mine into epoch $CARVE_EPOCH"; exit 1; }
wait_sync $((CARVE_HEIGHT + 10)) || { fail "fleet did not sync into epoch $CARVE_EPOCH"; exit 1; }

IV5ADDR="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
if [ ${#IV5ADDR} -ge 20 ]; then
    success "node0 holds an IV5 address to carve the collateral notes to"
else
    fail "could not create an IV5 address for the carve: $(rpc 0 z_getnewiv5address 2>&1 | head -2)"
    exit 1
fi

# The carve. A shield cannot produce a 25000 INN note at all -- it splits its
# value across two notes at a random point -- so the attestable note is made by
# an in-pool transfer, which also keeps it off the public link a +25000 shield
# would draw to the transparent coins behind it.
#
# All six carves stay inside this one epoch on purpose. Selection is
# largest-first, and once the carve epoch is built a 25000 INN collateral note is
# the largest note the wallet holds: a seventh carve would spend one of the six
# it just made and the count would never move.
CARVED=0
for ((r=0; r<COLLATERAL_ROWS; r++)); do
    TR="$(rpc 0 z_iv5transfer "$IV5ADDR" "$COLLATERAL_VALUE" 2>&1)"
    TR_TXID="$(jget "$TR" txid)"
    if [ ${#TR_TXID} -ne 64 ]; then
        fail "carving note $r failed: $(echo "$TR" | head -3)"
        INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
        log "  pool=$(jget "$INFO" privacy_vnext_pool_value) spendable=$(jget "$INFO" privacy_vnext_balance) pending=$(jget "$INFO" privacy_vnext_unconfirmed_balance) notes=$(jget "$INFO" privacy_vnext_note_count) anchor_leaves=$(jget "$INFO" privacy_vnext_tree_size)"
        break
    fi
    confirm_on 3 || { fail "could not confirm carve $r"; break; }
    CARVED=$((CARVED + 1))
    log "  carved note $r ($COLLATERAL_VALUE INN, txid ${TR_TXID:0:16})"
done
if [ "$CARVED" -eq "$COLLATERAL_ROWS" ]; then
    success "$CARVED exact-$COLLATERAL_VALUE INN notes carved by in-pool transfer"
else
    fail "only $CARVED of $COLLATERAL_ROWS collateral notes were carved"
    exit 1
fi

if [ "$(height 0)" -le "$(epoch_end "$CARVE_EPOCH")" ]; then
    success "all $CARVED carves confirmed inside epoch $CARVE_EPOCH, before its build makes them selectable"
else
    fail "the carves ran past epoch $CARVE_EPOCH (tip $(height 0) > $(epoch_end "$CARVE_EPOCH")); a later carve can spend an earlier collateral note"
    exit 1
fi

# ============================================================
header "5c. Six finality-member registrations confirm below the anchor height"
# ============================================================

# Cross into the register epoch so the carve epoch is built AND finalized: a note
# is attestable only once its leaf index is inside the finalized spend anchor.
advance_through_epochs $(( CARVE_EPOCH + 1 )) "$REGISTER_EPOCH" || { fail "the epoch $(( CARVE_EPOCH + 1 ))-$REGISTER_EPOCH vote rounds failed"; exit 1; }
mine_to 0 $((REGISTER_HEIGHT + 10)) || { fail "could not mine into epoch $REGISTER_EPOCH"; exit 1; }
wait_sync $((REGISTER_HEIGHT + 10)) || { fail "fleet did not sync into epoch $REGISTER_EPOCH"; exit 1; }

NOTE_IDS=()
while read -r nid; do [ -n "$nid" ] && NOTE_IDS+=("$nid"); done < <(collateral_note_ids 0)
if [ "${#NOTE_IDS[@]}" -ge "$COLLATERAL_ROWS" ]; then
    success "${#NOTE_IDS[@]} attestable $COLLATERAL_VALUE INN note(s) are visible to the wallet"
else
    fail "only ${#NOTE_IDS[@]} attestable note(s); the carve did not finalize into the anchor"
    rpc 0 collateralnode collateral-notes 2>&1 | head -20
    exit 1
fi

# Two rows per member key. Three distinct keys across six rows, and one seat per
# key, means the draw seats exactly these three whichever rows win.
REGISTERED=0
REG_KEYIMAGES=()
for ((r=0; r<COLLATERAL_ROWS; r++)); do
    KEYIDX=$(( r % NUM_NODES ))
    REG="$(rpc 0 collateralnode finality-register "${COMMITTEE_PUBKEYS[$KEYIDX]}" \
              "${NOTE_IDS[$r]}" confirm 2>&1)"
    REG_TXID="$(jget "$REG" registration_txid)"
    if [ ${#REG_TXID} -ne 64 ]; then
        fail "registration $r (key $KEYIDX) failed: $(echo "$REG" | head -4)"
        break
    fi
    KI="$(jget "$REG" key_image)"
    [ -n "$KI" ] && REG_KEYIMAGES+=("$KI")
    confirm_on 3 || { fail "could not confirm registration $r"; break; }
    REGISTERED=$((REGISTERED + 1))
    log "  registered row $r under member key $KEYIDX (txid ${REG_TXID:0:16})"
done
if [ "$REGISTERED" -eq "$COLLATERAL_ROWS" ]; then
    success "$REGISTERED finality-member registrations confirmed"
else
    fail "only $REGISTERED of $COLLATERAL_ROWS registrations confirmed"
    exit 1
fi

REG_TIP="$(height 0)"
if [ "$REG_TIP" -le "$COMMITTEE_ANCHOR_HEIGHT" ]; then
    success "every registration confirmed at height $REG_TIP, at or below the anchor height $COMMITTEE_ANCHOR_HEIGHT"
else
    fail "registrations ran past the anchor height ($REG_TIP > $COMMITTEE_ANCHOR_HEIGHT): they cannot be drawn for term $COMMITTEE_TERM_EPOCH"
    exit 1
fi

# The registry the draw will read, asked for at exactly the height the draw
# anchors to. This is the same snapshot function the consensus draw calls.
REGISTRY="$(rpc 0 collateralnode finality-registry "$COMMITTEE_ANCHOR_HEIGHT" 2>&1)"
REGISTRY_N="$(jget "$REGISTRY" count)"
if is_int "$REGISTRY_N" && [ "$REGISTRY_N" -ge "$COLLATERAL_ROWS" ]; then
    success "the registry holds $REGISTRY_N member rows at the anchor height"
else
    fail "the registry holds $REGISTRY_N rows at height $COMMITTEE_ANCHOR_HEIGHT, expected >= $COLLATERAL_ROWS"
    exit 1
fi

# The same snapshot at the PREVIOUS term's anchor height. Every registration above
# confirmed after this height, so a draw that reads the registry can seat nothing
# for term $PRE_TERM_EPOCH. Section 5d then holds the chain inside that term and
# requires exactly that. Without this row being empty, the unseated assertion there
# would prove nothing, so the run stops here rather than reporting a pass it cannot
# back.
PRE_REGISTRY_N="$(jget "$(rpc 0 collateralnode finality-registry "$PRE_TERM_ANCHOR_HEIGHT" 2>&1)" count)"
if [ "$PRE_REGISTRY_N" = "0" ]; then
    success "the registry is empty at term $PRE_TERM_EPOCH's anchor height $PRE_TERM_ANCHOR_HEIGHT, so a registry-drawn committee cannot seat for that term"
else
    fail "the registry already holds '$PRE_REGISTRY_N' row(s) at height $PRE_TERM_ANCHOR_HEIGHT; term $PRE_TERM_EPOCH could legitimately seat and the discriminator in 5d would be worthless"
    exit 1
fi

# ============================================================
header "5d. The chain draws a committee from that registry"
# ============================================================

# Every boundary from the register epoch to the carrier, not just the anchor's: a
# skipped round leaves an epoch soft, and the finalized height stops advancing.
advance_through_epochs $(( REGISTER_EPOCH + 1 )) "$COMMITTEE_CARRIER_EPOCH" || { fail "the epoch $(( REGISTER_EPOCH + 1 ))-$COMMITTEE_CARRIER_EPOCH vote rounds failed"; exit 1; }

# ---------------------------------------------------------------------------
# THE DISCRIMINATOR.
#
# The chain is now inside term $PRE_TERM_EPOCH. 5c proved the registry is empty at
# that term's anchor height, so a committee drawn from the registry seats nothing
# here. Every other observable this harness makes -- the seat identities, the set
# hash, the fleet agreement, the certificate -- is equally produced by an
# implementation that ignores the registry and seats the three configured member
# keys every term, because those keys ARE 1G/2G/3G. This is the only check that
# separates the two, and it separates them in the direction that matters: the
# real draw MUST report nothing seated here, the fixed set MUST report seats.
# ---------------------------------------------------------------------------
PRE_SEAT_HEIGHT="$(height 0)"
PRE_SEAT_OK=1
PRE_SEAT_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    T="$(jget "$FI" committee_term_epoch)"
    S="$(jget "$FI" committee_seated)"
    C="$(jget "$FI" committee_seat_count)"
    [ "$T" = "$PRE_TERM_EPOCH" ] || { PRE_SEAT_OK=0; PRE_SEAT_WHY="node$n is in term '$T', not $PRE_TERM_EPOCH"; }
    [ "$S" = "false" ]           || { PRE_SEAT_OK=0; PRE_SEAT_WHY="node$n reports committee_seated=$S"; }
    [ "$C" = "0" ]               || { PRE_SEAT_OK=0; PRE_SEAT_WHY="node$n reports $C seat(s)"; }
done
if [ "$PRE_SEAT_OK" -eq 1 ]; then
    success "at height $PRE_SEAT_HEIGHT the chain is in term $PRE_TERM_EPOCH and no node seats a committee, because that term's anchor registry was empty"
else
    fail "the seats do not come from the collateral registry: $PRE_SEAT_WHY, while term $PRE_TERM_EPOCH's anchor height $PRE_TERM_ANCHOR_HEIGHT held $PRE_REGISTRY_N registry rows"
    for ((n=0; n<NUM_NODES; n++)); do
        echo "  node$n: $(rpc "$n" getfinalityinfo 2>/dev/null | grep -E 'committee_(term_epoch|seated|seat_count|source)' | tr -d '\n')"
    done
    exit 1
fi

# The other half of the same claim, from the node's own forward-looking draw: the
# term this run seats reads the registrations, at the anchor height the harness
# computed, and reports it will seat. A resolver that never reads the registry
# cannot produce this row.
FI0="$(rpc 0 getfinalityinfo 2>/dev/null)"
NEXT_TERM="$(jget2 "$FI0" committee_next_term_draw term_epoch)"
NEXT_ANCHOR_H="$(jget2 "$FI0" committee_next_term_draw anchor_height)"
NEXT_ROWS="$(jget2 "$FI0" committee_next_term_draw registry_rows)"
NEXT_SEATED="$(jget2 "$FI0" committee_next_term_draw seated)"
if [ "$NEXT_TERM" = "$COMMITTEE_TERM_EPOCH" ] && \
   [ "$NEXT_ANCHOR_H" = "$COMMITTEE_ANCHOR_HEIGHT" ] && \
   is_int "${NEXT_ROWS:-x}" && [ "${NEXT_ROWS:-0}" -ge "$COLLATERAL_ROWS" ] && \
   [ "$NEXT_SEATED" = "true" ]; then
    success "the term $COMMITTEE_TERM_EPOCH draw reads $NEXT_ROWS registry rows at anchor height $NEXT_ANCHOR_H and will seat"
else
    fail "the term $COMMITTEE_TERM_EPOCH draw does not read the registrations (term=$NEXT_TERM anchor=$NEXT_ANCHOR_H rows=$NEXT_ROWS seated=$NEXT_SEATED, expected $COMMITTEE_TERM_EPOCH/$COMMITTEE_ANCHOR_HEIGHT/>=$COLLATERAL_ROWS/true)"
fi

log "mining to $COMMITTEE_SEATED_HEIGHT, where epoch $COMMITTEE_CARRIER_EPOCH is built and carries the draw"
mine_to 0 "$COMMITTEE_SEATED_HEIGHT" || { fail "could not mine to the seating height"; exit 1; }
wait_sync "$COMMITTEE_SEATED_HEIGHT" || { fail "fleet did not sync to the seating height"; exit 1; }

# M and the seat count are asserted against the values regtest is supposed to draw,
# not merely compared between nodes: a chain that agreed fleet-wide on M=1 or M=3
# would satisfy an equality-only check while certifying under the wrong threshold.
SEAT_OK=1
SEAT_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    S="$(jget "$FI" committee_seated)"
    T="$(jget "$FI" committee_term_epoch)"
    M="$(jget "$FI" committee_threshold_m)"
    C="$(jget "$FI" committee_seat_count)"
    [ "$S" = "true" ]                    || { SEAT_OK=0; SEAT_WHY="node$n committee_seated=$S"; }
    [ "$T" = "$COMMITTEE_TERM_EPOCH" ]   || { SEAT_OK=0; SEAT_WHY="node$n is in term '$T', not $COMMITTEE_TERM_EPOCH"; }
    [ "$M" = "$COMMITTEE_THRESHOLD_M" ]  || { SEAT_OK=0; SEAT_WHY="node$n threshold M='$M', expected $COMMITTEE_THRESHOLD_M"; }
    [ "$C" = "$COMMITTEE_SEAT_COUNT" ]   || { SEAT_OK=0; SEAT_WHY="node$n seat count='$C', expected $COMMITTEE_SEAT_COUNT"; }
done
if [ "$SEAT_OK" -eq 1 ]; then
    success "every node seats term $COMMITTEE_TERM_EPOCH's committee at exactly $COMMITTEE_SEAT_COUNT seats and M=$COMMITTEE_THRESHOLD_M"
else
    fail "the committee did not seat as drawn on every node: $SEAT_WHY"
    for ((n=0; n<NUM_NODES; n++)); do
        echo "  node$n: $(rpc "$n" getfinalityinfo 2>/dev/null | head -40)"
    done
    exit 1
fi

# The seats must be exactly the three registered member keys, and identical on
# every node: the draw is a consensus object, not a local opinion.
SEATS0="$(committee_seats 0 | sort | tr '\n' ' ')"
EXPECTED_SEATS="$(printf '%s\n' "${COMMITTEE_PUBKEYS[@]}" | sort | tr '\n' ' ')"
if [ "$SEATS0" = "$EXPECTED_SEATS" ]; then
    success "the drawn seats are exactly the three registered member keys"
else
    fail "drawn seats [$SEATS0] are not the registered keys [$EXPECTED_SEATS]"
fi

# Ordered seat lists, each required to be a full committee first: three nodes that
# all answered nothing are also three nodes that agree.
SEATS_AGREE=1
SEATS_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    SN="$(committee_seats "$n" | grep -c . || true)"
    is_int "$SN" && [ "$SN" -eq "$COMMITTEE_SEAT_COUNT" ] || \
        { SEATS_AGREE=0; SEATS_WHY="node$n lists $SN seat(s), expected $COMMITTEE_SEAT_COUNT"; }
    [ "$(committee_seats "$n" | tr '\n' ' ')" = "$(committee_seats 0 | tr '\n' ' ')" ] || \
        { SEATS_AGREE=0; SEATS_WHY="node$n resolves a different seat list from node0"; }
done
if [ "$SEATS_AGREE" -eq 1 ]; then
    success "all $NUM_NODES nodes resolve the identical $COMMITTEE_SEAT_COUNT-seat committee in the identical seat order"
else
    fail "the nodes disagree about the drawn committee: $SEATS_WHY"
    exit 1
fi

# Fleet agreement on the two objects the draw produces. Counting distinct values is
# not enough on its own: jget yields an empty string for a failed RPC and
# getepochinfo yields the zero hash for an epoch it has not computed, so three
# failures and three uncomputed epochs both count as one distinct value. Each value
# has to be a real hash before agreement means anything.
CARRIER_DIGEST=()
SET_HASH=()
for ((n=0; n<NUM_NODES; n++)); do
    CARRIER_DIGEST+=("$(jget "$(rpc "$n" getepochinfo "$COMMITTEE_CARRIER_EPOCH" 2>/dev/null)" epoch_state_digest)")
    SET_HASH+=("$(jget "$(rpc "$n" getfinalityinfo 2>/dev/null)" committee_set_hash)")
done
AGREE_OK=1
AGREE_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    is_real_hash "${CARRIER_DIGEST[$n]}" || \
        { AGREE_OK=0; AGREE_WHY="node$n has no carrier epoch digest ('${CARRIER_DIGEST[$n]}')"; }
    is_real_hash "${SET_HASH[$n]}" || \
        { AGREE_OK=0; AGREE_WHY="node$n has no committee set hash ('${SET_HASH[$n]}')"; }
    [ "${CARRIER_DIGEST[$n]}" = "${CARRIER_DIGEST[0]}" ] || \
        { AGREE_OK=0; AGREE_WHY="node$n's carrier epoch digest differs from node0's"; }
    [ "${SET_HASH[$n]}" = "${SET_HASH[0]}" ] || \
        { AGREE_OK=0; AGREE_WHY="node$n's committee set hash differs from node0's"; }
done
if [ "$AGREE_OK" -eq 1 ]; then
    success "the carrier epoch $COMMITTEE_CARRIER_EPOCH has one non-zero state digest (${CARRIER_DIGEST[0]:0:16}) and one non-zero committee set hash (${SET_HASH[0]:0:16}) fleet-wide"
else
    fail "the carrier epoch digest or committee set hash is missing or divergent: $AGREE_WHY"
fi

# ============================================================
header "6. Note-vote rounds over the finalized chain"
# ============================================================

# Each round drives the transparent votes that keep finality advancing and gives
# node0 its one note vote for the epoch. The tally epoch's round also offers node1 a
# second vote from the same note while the first is still in its mempool.
for E in $NOTE_VOTE_EPOCHS; do
    B=$(( 11 + (E - 1) * 300 ))
    log "epoch $E: holding the chain at $((B + NOTE_VOTE_EMIT_OFFSET)) for ${NOTE_VOTE_SETTLE}s"
    PROBE=0
    [ "$E" = "$TALLY_EPOCH" ] && PROBE=1
    note_vote_round "$E" "$B" "$NOTE_VOTE_WINDOW" "$PROBE" || {
        fail "epoch $E vote round failed"
        exit 1
    }
    log "epoch $E: vote ${NV_TXID[$E]:-<none>} held by node(s)${NV_SEEN[$E]:- none}"
    log "epoch $E: window mined to $((B + NOTE_VOTE_WINDOW))"

    # The tally epoch gets two more stops inside its own span: one at the
    # vote-inclusion window close, which is the freeze point the committee needs
    # before any certificate can satisfy connect-time coverage, and one after it
    # so a block of THIS epoch can carry the certificate the committee assembles.
    if [ "$E" = "$TALLY_EPOCH" ]; then
        log "epoch $E: mining to the vote-inclusion window close at $TALLY_WINDOW_CLOSE"
        mine_to 0 "$TALLY_WINDOW_CLOSE" || { fail "epoch $E did not reach the freeze point"; exit 1; }
        wait_sync "$TALLY_WINDOW_CLOSE" || { fail "fleet did not sync to the freeze point"; exit 1; }
        log "epoch $E: resting ${TALLY_SETTLE}s for the note tally committee"
        sleep "$TALLY_SETTLE"
        log "epoch $E: mining to $TALLY_CARRY_HEIGHT so an own-epoch block can carry the certificate"
        mine_to 0 "$TALLY_CARRY_HEIGHT" || { fail "epoch $E did not reach the carry height"; exit 1; }
        wait_sync "$TALLY_CARRY_HEIGHT" || { fail "fleet did not sync to the carry height"; exit 1; }
        # A second short rest and a few more blocks: the first carry may land
        # before the M-of-N signature round completes on every node.
        sleep 20
        mine_to 0 $((TALLY_CARRY_HEIGHT + 20)) || { fail "epoch $E did not extend past the carry height"; exit 1; }
        wait_sync $((TALLY_CARRY_HEIGHT + 20)) || { fail "fleet did not sync past the carry height"; exit 1; }
    fi
done

E4="$(rpc 0 getepochinfo "$FINALIZED_EPOCH" 2>/dev/null)"
E4_TIER="$(jget "$E4" finality_tier)"
E4_HARD="$(jget "$E4" consecutive_hard_epochs)"
E4_FIN="$(jget "$E4" finalized_height_as_of)"
E4_FINALIZED="$(jget "$E4" finalized)"
if [ "$E4_TIER" = "hard" ] && [ "$E4_HARD" = "3" ] && \
   [ "$E4_FIN" = "$FINALIZED_HEIGHT" ] && [ "$E4_FINALIZED" = "true" ]; then
    success "epoch $FINALIZED_EPOCH finalizes height $E4_FIN after $E4_HARD consecutive HARD epochs"
else
    fail "epoch $FINALIZED_EPOCH did not finalize (tier=$E4_TIER consecutive_hard=$E4_HARD finalized_height_as_of=$E4_FIN finalized=$E4_FINALIZED)"
    exit 1
fi

DIFF_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    PEER_FIN="$(jget "$(rpc "$n" getepochinfo "$FINALIZED_EPOCH" 2>/dev/null)" finalized_height_as_of)"
    [ "$PEER_FIN" = "$E4_FIN" ] || DIFF_OK=0
done
if [ "$DIFF_OK" -eq 1 ]; then
    success "every node agrees the finalized height is $E4_FIN"
else
    fail "nodes disagree on the finalized height"
    exit 1
fi

# The finalized epoch carries a populated IV5 tree.
ANCHOR_TREE_ROOT="$(jget "$E4" iv5_tree_root)"
ANCHOR_TREE_SIZE="$(jget "$E4" iv5_tree_size)"
if [ ${#ANCHOR_TREE_ROOT} -ge 64 ] && ! is_zero_hex "$ANCHOR_TREE_ROOT" && \
   is_int "$ANCHOR_TREE_SIZE" && [ "$ANCHOR_TREE_SIZE" -gt 0 ]; then
    success "the finalized epoch carries an IV5 tree ($ANCHOR_TREE_SIZE leaves, root ${ANCHOR_TREE_ROOT:0:12})"
else
    fail "the finalized epoch carries no IV5 tree (root='$ANCHOR_TREE_ROOT' size='$ANCHOR_TREE_SIZE')"
    exit 1
fi

# ============================================================
header "7. (a) node0 builds one note vote per epoch"
# ============================================================

# One producer line per epoch at most, from the first votable epoch on. The note-vote
# epochs are held for the producer, so each must have exactly one, naming its own
# boundary; the earlier epochs are crossed at mining pace and are only bounded.
BUILT_OK=1
BUILT_EPOCHS=""
LAST_NV_EPOCH="${NOTE_VOTE_EPOCHS##* }"
for ((E=3; E<=LAST_NV_EPOCH; E++)); do
    N="$(producer_success "$E" | grep -c . || true)"
    is_int "$N" || N=0
    [ "$N" -le 1 ] || { BUILT_OK=0; fail "node0 built $N note votes in epoch $E"; }
    [ "$N" -eq 1 ] && BUILT_EPOCHS="$BUILT_EPOCHS $E"
done
for E in $NOTE_VOTE_EPOCHS; do
    PB="$(producer_boundary "$E")"
    [ "$PB" = "$(epoch_start "$E")" ] || \
        { BUILT_OK=0; fail "epoch $E: the producer named boundary '$PB', expected $(epoch_start "$E")"; }
done
if [ "$BUILT_OK" -eq 1 ]; then
    success "node0 built exactly one note vote in each of epoch(s)$BUILT_EPOCHS, the held epochs naming their own boundary"
else
    producer_all | tail -12
fi

# ============================================================
header "8. (b) node0's own mempool accepts the vote"
# ============================================================

# The producer commits the vote through the wallet and prints its line only after the
# mempool took it; the old lane's relay check (AddPendingNoteVote) was deleted with it.
OWN_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    case " ${NV_SEEN[$E]} " in
        *" 0 "*) ;;
        *) OWN_OK=0; fail "epoch $E: node0's mempool never held its vote (producer txid '$(producer_txid "$E")')" ;;
    esac
    if [ ${#NV_TXID[$E]} -ne 64 ] || [ "${NV_TXID[$E]:0:10}" != "$(producer_txid "$E")" ]; then
        OWN_OK=0
        fail "epoch $E: node0's mempool vote '${NV_TXID[$E]}' is not the producer's '$(producer_txid "$E")'"
    fi
done
OWN_REFUSED="$(grep -aF "the note finality vote was built but could not be committed" "$(node_log 0)" 2>/dev/null | head -1)"
[ -z "$OWN_REFUSED" ] || { OWN_OK=0; fail "node0 refused its own note vote: $OWN_REFUSED"; }
if [ "$OWN_OK" -eq 1 ]; then
    success "every held epoch's vote entered node0's own mempool and none was refused locally"
fi

# ============================================================
header "9. (c) Peers receive the note vote"
# ============================================================

# A vote relays as an ordinary transaction. The chain is held at the emit height, so a
# peer's mempool holding it is the relay itself, observed before any block carried it.
# The sample stops when the hold ends, and a stem-routed vote can reach the last peer
# after that but before the carrier. Its relay-accept line is the same evidence: the
# tx handler writes it only when AcceptToMemoryPool admits the vote, which fails once
# a connected block has spent the note.
relay_accepted() { grep -aqF "TXRELAY accept tx=${2:0:10} " "$(node_log "$1")" 2>/dev/null; }
RELAY_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    for ((n=1; n<NUM_NODES; n++)); do
        case " ${NV_SEEN[$E]} " in
            *" $n "*) ;;
            *) relay_accepted "$n" "${NV_TXID[$E]}" || {
                   RELAY_OK=0
                   fail "epoch $E: node$n never accepted the vote ${NV_TXID[$E]:0:16} by relay"
               } ;;
        esac
    done
done
if [ "$RELAY_OK" -eq 1 ]; then
    success "both peers accepted each note vote by relay before any block carried it"
fi

# ------------------------------------------------------------
# C6: no node originates both a named and an anonymous vote.
#
# A CFinalityVote names its voter -- pubkey, real staked outpoints, cleartext
# weight and time -- and a note vote carries only a key image. The two originated
# by one node put the name and the tag on the same connection, and no tag
# construction undoes that. Origination is what this reads: relay carries every
# object to every node, so the producer lines are the only place the origin is
# visible.
#   ProduceFinalityVote: epoch=          identity lane, one per epoch cast
#   ProducePrivacyVNextNoteVote: epoch=  anonymous lane, one per epoch cast
# ------------------------------------------------------------
LANE_OK=1
LANE_TOTAL_ANON=0
LANE_TOTAL_IDENT=0
for ((n=0; n<NUM_NODES; n++)); do
    L="$(node_log "$n")"
    N_IDENT="$(grep -acF "ProduceFinalityVote: epoch=" "$L" 2>/dev/null)"
    N_ANON="$(grep -acF "ProducePrivacyVNextNoteVote: epoch=" "$L" 2>/dev/null)"
    is_int "${N_IDENT:-x}" || N_IDENT=0
    is_int "${N_ANON:-x}" || N_ANON=0
    N_LANE="$(grep -aoE "FINALITY vote lane latched: lane=[a-z]+" "$L" 2>/dev/null | \
              sed -n 's/.*lane=//p' | sort -u | tr '\n' ' ' | tr -d '[:space:]')"
    LANE_TOTAL_IDENT=$((LANE_TOTAL_IDENT + N_IDENT))
    LANE_TOTAL_ANON=$((LANE_TOTAL_ANON + N_ANON))
    log "  node$n originated $N_IDENT identity vote(s), $N_ANON note vote(s), lane='$N_LANE'"

    # The invariant, on every node: never both.
    if [ "$N_IDENT" -gt 0 ] && [ "$N_ANON" -gt 0 ]; then
        LANE_OK=0
        fail "node$n originated BOTH an identity vote and a note vote: the tag is linkable to its wallet"
    fi
    # A node latches one lane for the life of the process, and only one.
    case "$N_LANE" in
        identity|anonymous|"") ;;
        *) LANE_OK=0; fail "node$n latched more than one vote lane: '$N_LANE'" ;;
    esac

    if [ "$n" -eq 0 ]; then
        [ "$N_IDENT" -eq 0 ] || { LANE_OK=0; fail "node0 is note-only but originated $N_IDENT transparent vote(s)"; }
        [ "$N_ANON" -gt 0 ]  || { LANE_OK=0; fail "node0 originated no note vote"; }
        [ "$N_LANE" = "anonymous" ] || { LANE_OK=0; fail "node0 latched lane '$N_LANE', expected anonymous"; }
    else
        [ "$N_ANON" -eq 0 ] || { LANE_OK=0; fail "node$n is transparent-only but originated $N_ANON note vote(s)"; }
        [ "$N_IDENT" -gt 0 ] || { LANE_OK=0; fail "node$n originated no transparent vote"; }
        [ "$N_LANE" = "identity" ] || { LANE_OK=0; fail "node$n latched lane '$N_LANE', expected identity"; }
    fi
done
if [ "$LANE_OK" -eq 1 ]; then
    success "no node originated both lanes ($LANE_TOTAL_IDENT identity, $LANE_TOTAL_ANON anonymous, split across nodes)"
fi

# The liveness half of the same property: the split is only safe while the identity
# voters still finalize. This run finalized at $FINALIZED_HEIGHT with node0 silent on
# the identity lane.
FIN_NOW="$(jget "$(rpc 0 getfinalityinfo 2>/dev/null)" finalized_height)"
if is_int "${FIN_NOW:-x}" && [ "${FIN_NOW:-0}" -ge "$FINALIZED_HEIGHT" ]; then
    success "finality still advances with node0 silent on the identity lane (finalized_height=$FIN_NOW)"
else
    fail "finality stalled once node0 left the identity lane (finalized_height=$FIN_NOW, need >= $FINALIZED_HEIGHT)"
fi

# ============================================================
header "10. (d) The vote is mined inside its inclusion window and connects"
# ============================================================

# Exactly one operation-10 transaction per held epoch, the one node0 cast, at a height
# in [B, B+24). Connected on every node: each node's carrier block is the same block
# and each node's transaction index places the vote in it.
CARRIED_OK=1
CARRIED_EPOCHS=""
for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    ROWS="$(notevotes_in_range 0 "$B" $((B + NOTE_VOTE_WINDOW)))"
    N="$(echo "$ROWS" | grep -c . || true)"
    H="$(echo "$ROWS" | awk 'NF{print $1; exit}')"
    T="$(echo "$ROWS" | awk 'NF{print $2; exit}')"
    if [ "$N" != "1" ]; then
        CARRIED_OK=0
        fail "epoch $E: $N operation-10 transaction(s) in [$B, $((B + NOTE_VOTE_WINDOW))], expected 1"
        continue
    fi
    if [ "$T" != "${NV_TXID[$E]}" ]; then
        CARRIED_OK=0
        fail "epoch $E: the carried vote ${T:0:16} is not the one node0 cast (${NV_TXID[$E]:0:16})"
        continue
    fi
    if [ "$H" -lt "$B" ] || [ "$H" -ge $((B + NOTE_VOTE_INCLUSION_WINDOW)) ]; then
        CARRIED_OK=0
        fail "epoch $E: the vote is carried at $H, outside [$B, $((B + NOTE_VOTE_INCLUSION_WINDOW)))"
        continue
    fi
    BH0="$(block_hash 0 "$H")"
    for ((n=0; n<NUM_NODES; n++)); do
        BHN="$(block_hash "$n" "$H")"
        TBN="$(jget "$(rpc "$n" getrawtransaction "$T" 1 2>/dev/null)" blockhash)"
        if [ ${#BH0} -ne 64 ] || [ "$BHN" != "$BH0" ] || [ "$TBN" != "$BH0" ]; then
            CARRIED_OK=0
            fail "epoch $E: node$n holds block '${BHN:0:16}' at $H and places the vote in '${TBN:0:16}', node0 has '${BH0:0:16}'"
        fi
    done
    CARRIED_EPOCHS="$CARRIED_EPOCHS $E@$H"
done
CONNECT_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    R="$(grep -aF "ConnectBlockNoteVotes: rejected vote in block" "$(node_log "$n")" 2>/dev/null | head -1)"
    [ -n "$R" ] && CONNECT_REJECT="node$n: $R"
done
[ -z "$CONNECT_REJECT" ] || { CARRIED_OK=0; fail "a node rejected a note vote at connect: $CONNECT_REJECT"; }
if [ "$CARRIED_OK" -eq 1 ]; then
    success "each vote was mined once inside its inclusion window and connected on all $NUM_NODES nodes (epoch@height:$CARRIED_EPOCHS)"
fi

# ============================================================
header "11. (e) One note, one vote: a second vote from it is a double spend"
# ============================================================

# Read off each vote's own bytes: one spent note, the epoch's boundary height and
# hash. The tag the tally counts is that note's key image, so no key image may repeat
# across epochs -- a vote reissues its note under a fresh one.
NV_KI=()
KI_ALL=""
FIELDS_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    read -r NIN KI BHT BHASH <<< "$(notevote_fields 0 "${NV_TXID[$E]}")"
    if [ "$NIN" = "1" ] && [ ${#KI} -eq 64 ] && [ "$BHT" = "$B" ] && \
       [ "$BHASH" = "$(block_hash 0 "$B")" ]; then
        NV_KI[$E]="$KI"
        KI_ALL="$KI_ALL $KI"
        log "  epoch $E: key image ${KI:0:16}, boundary $BHT ${BHASH:0:16}"
    else
        FIELDS_OK=0
        fail "epoch $E: vote ${NV_TXID[$E]:0:16} reads inputs='$NIN' key_image='${KI:0:16}' boundary='$BHT' '${BHASH:0:16}', expected 1 input naming $B $(block_hash 0 "$B" | cut -c1-16)"
    fi
done
NKI="$(echo "$KI_ALL" | tr ' ' '\n' | grep -c . || true)"
NKI_UNIQ="$(echo "$KI_ALL" | tr ' ' '\n' | grep . | sort -u | grep -c . || true)"
if [ "$FIELDS_OK" -eq 1 ] && [ "$NKI" -gt 0 ] && [ "$NKI" = "$NKI_UNIQ" ]; then
    success "each vote spends one note and names its own boundary; $NKI vote(s), $NKI_UNIQ distinct key image(s)"
elif [ "$FIELDS_OK" -eq 1 ]; then
    fail "a key image repeats across epochs ($NKI votes, $NKI_UNIQ distinct)"
fi

# The same note voting again while its first vote is pending: offered to node1 during
# the tally epoch's hold (section 6).
if [ "$PROBE_MEMPOOL_OK" = "1" ]; then
    success "node1 refused a second epoch-$TALLY_EPOCH vote from the same note while the first was pending: its key image is reserved"
else
    fail "the pending double-vote probe did not refuse on the spent key: ${PROBE_MEMPOOL_WHY:-it never ran}"
fi

# And once the first vote is mined, still inside the window, so only the spent-key
# rule stands between the second vote and the mempool.
if double_vote_probe 1 "${NV_TXID[$LAST_NV_EPOCH]}" "was already consumed by"; then
    success "node1 refused a second epoch-$LAST_NV_EPOCH vote from the same note after the first was mined: key image ${PROBE_KI:0:16} is spent"
else
    fail "the mined double-vote probe: $PROBE_WHY"
fi

# Neither second vote reached a block: every held epoch counts one vote and no tag
# was retired as equivocated.
EQUIV_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    for ((n=0; n<NUM_NODES; n++)); do
        read -r C Q _ <<< "$(epoch_note_view "$n" "$E")"
        [ "$C" = "1" ] && [ "$Q" = "0" ] || \
            { EQUIV_OK=0; fail "node$n epoch $E: counted='$C' equivocated='$Q', expected 1 and 0"; }
    done
done
[ "$EQUIV_OK" -eq 1 ] && success "every node counts exactly one note vote per held epoch, none equivocated"

# ============================================================
header "12. The note tally runs over the counted set"
# ============================================================

# A counted note vote is one voter; nothing is opened. The seat's pass logs how many it
# counted and how many back the winning boundary.
TALLY_LINE=""
TALLY_NODE=""
for ((n=0; n<NUM_NODES; n++)); do
    L="$(grep -aF "ProcessNoteTallyCommitteeEpoch: epoch $TALLY_EPOCH tier=" "$(node_log "$n")" 2>/dev/null | tail -1)"
    if [ -n "$L" ]; then
        TALLY_LINE="$L"
        TALLY_NODE="$n"
        break
    fi
done
if [ -n "$TALLY_LINE" ]; then
    success "node$TALLY_NODE ran the note tally for epoch $TALLY_EPOCH"
    log "  $TALLY_LINE"
else
    fail "no node ran the note tally committee pass for epoch $TALLY_EPOCH"
    for ((n=0; n<NUM_NODES; n++)); do
        grep -aF "ProcessNoteTallyCommitteeEpoch:" "$(node_log "$n")" 2>/dev/null | tail -3
    done
fi

TALLY_COUNTED="$(jget "$(rpc 0 getepochinfo "$TALLY_EPOCH" 2>/dev/null)" note_votes_counted)"
NOTE_VOTES="$(echo "$TALLY_LINE" | sed -n 's/.* note_votes=\([0-9]*\).*/\1/p')"
NOTE_WINNERS="$(echo "$TALLY_LINE" | sed -n 's/.* note_winners=\([0-9]*\).*/\1/p')"
if is_int "${NOTE_VOTES:-x}" && is_int "${NOTE_WINNERS:-x}" && \
   [ "$NOTE_VOTES" = "$TALLY_COUNTED" ] && [ "$NOTE_VOTES" -ge 1 ] && \
   [ "$NOTE_WINNERS" -ge 1 ] && [ "$NOTE_WINNERS" -le "$NOTE_VOTES" ]; then
    success "the tally counted $NOTE_WINNERS of $NOTE_VOTES note vote(s) for the winner, the epoch's whole counted set"
else
    fail "the tally does not match the counted set (note_votes='$NOTE_VOTES' note_winners='$NOTE_WINNERS' counted='$TALLY_COUNTED')"
fi
# Removed: the tally-partial relay check. The Shamir partials, complaints and share
# openings were deleted with the tally shares (43a059c1); nothing is exchanged now.

# ============================================================
header "13. The v4 note certificate commits the counted set"
# ============================================================

# Every certificate the committee assembled. More than one can reach the threshold;
# which one an epoch selects is decided at connect time.
NOTE_CERT_HASHES=""
NOTE_CERT_LINE=""
for ((n=0; n<NUM_NODES; n++)); do
    while read -r L; do
        [ -n "$L" ] || continue
        [ -n "$NOTE_CERT_LINE" ] || NOTE_CERT_LINE="$L"
        H="$(echo "$L" | sed -n 's/.*note certificate \([0-9a-f]\{64\}\).*/\1/p')"
        [ -n "$H" ] && NOTE_CERT_HASHES="$NOTE_CERT_HASHES $H"
    done < <(grep -aF "FinalityNoteTally: epoch $TALLY_EPOCH note certificate " \
                  "$(node_log "$n")" 2>/dev/null)
done
NOTE_CERT_HASHES="$(echo "$NOTE_CERT_HASHES" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
if [ -n "$NOTE_CERT_HASHES" ]; then
    success "the committee assembled $(echo "$NOTE_CERT_HASHES" | wc -w | tr -d ' ') note certificate(s) for epoch $TALLY_EPOCH"
    log "  $NOTE_CERT_LINE"
else
    fail "no M-of-N note certificate was assembled for epoch $TALLY_EPOCH"
fi

# The carried certificate, decoded from the coinbase bytes. It has to be in a block of
# the tally epoch's own span: the tier reads the epoch's own blocks.
CERT_CARRY_HEIGHT=""
CERT_FIELDS=""
for ((h=TALLY_WINDOW_CLOSE; h<=TALLY_CARRY_HEIGHT + 20 && h<=$(epoch_end "$TALLY_EPOCH"); h++)); do
    while read -r L; do
        read -r F_VER F_EPOCH _ <<< "$L"
        if [ "${F_VER:-}" = "$NOTE_CERT_VERSION" ] && [ "${F_EPOCH:-}" = "$TALLY_EPOCH" ]; then
            CERT_CARRY_HEIGHT="$h"
            CERT_FIELDS="$L"
            break
        fi
    done < <(cert_envelopes 0 "$h")
    [ -n "$CERT_CARRY_HEIGHT" ] && break
done
if [ -n "$CERT_CARRY_HEIGHT" ]; then
    success "a v$NOTE_CERT_VERSION certificate for epoch $TALLY_EPOCH is carried at height $CERT_CARRY_HEIGHT, inside the epoch"
else
    fail "no v$NOTE_CERT_VERSION certificate for epoch $TALLY_EPOCH was carried in [$TALLY_WINDOW_CLOSE, $((TALLY_CARRY_HEIGHT + 20))]"
fi

# The commitment: the count and root the certificate carries must be the counted set's,
# rebuilt here twice -- from the tags getepochinfo reports and from the key image read
# off the vote transaction itself.
read -r C_VER C_EPOCH C_TIER C_SIGNERS C_COUNT C_ROOT <<< "$CERT_FIELDS"
TALLY_TAGS="$(epoch_note_tags "$(rpc 0 getepochinfo "$TALLY_EPOCH" 2>/dev/null)")"
ROOT_FROM_RPC="$(note_set_root $TALLY_TAGS)"
ROOT_FROM_TX="$(note_set_root "${NV_KI[$TALLY_EPOCH]}")"
if is_real_hash "$C_ROOT" && [ "$C_COUNT" = "$TALLY_COUNTED" ] && \
   [ "$C_ROOT" = "$ROOT_FROM_RPC" ] && [ "$C_ROOT" = "$ROOT_FROM_TX" ]; then
    success "the certificate commits count=$C_COUNT and root ${C_ROOT:0:16}, the root of the cast vote's key image"
else
    fail "the certificate does not commit the counted set: count='$C_COUNT' root='$C_ROOT', counted=$TALLY_COUNTED rpc_root=$ROOT_FROM_RPC tx_root=$ROOT_FROM_TX"
fi
if is_int "${C_SIGNERS:-x}" && [ "$C_SIGNERS" -ge "$COMMITTEE_THRESHOLD_M" ] && \
   [ "$C_SIGNERS" -le "$COMMITTEE_SEAT_COUNT" ]; then
    success "the certificate carries $C_SIGNERS member signature(s), at least M=$COMMITTEE_THRESHOLD_M of $COMMITTEE_SEAT_COUNT"
else
    fail "the certificate carries '$C_SIGNERS' signature(s), expected $COMMITTEE_THRESHOLD_M..$COMMITTEE_SEAT_COUNT"
fi

# Connect-time CheckNoteVoteSetCommitment rebuilds that root from each node's own
# counted set, so a carrier block every node holds is a commitment every node accepted.
CERT_CONVERGED=1
BH0="$(block_hash 0 "${CERT_CARRY_HEIGHT:-0}")"
[ ${#BH0} -eq 64 ] || CERT_CONVERGED=0
for ((n=1; n<NUM_NODES; n++)); do
    [ "$(block_hash "$n" "${CERT_CARRY_HEIGHT:-0}")" = "$BH0" ] || CERT_CONVERGED=0
done
if [ "$CERT_CONVERGED" -eq 1 ]; then
    success "the certificate's carrier block ${BH0:0:16} connected on all $NUM_NODES nodes"
else
    fail "the certificate's carrier block did not converge across the fleet"
fi

# The logical hash of that certificate, for section 14.
CARRIED_CERT_HASH="$(rpc 0 getblock "$BH0" 2>/dev/null | \
    V="$NOTE_CERT_VERSION" E="$TALLY_EPOCH" python3 -c '
import json, os, sys
try: certs = json.load(sys.stdin).get("finality_tally_certificates") or []
except Exception: certs = []
for c in certs:
    if c.get("version") == int(os.environ["V"]) and c.get("epoch") == int(os.environ["E"]):
        print(c.get("hash", "")); break
')"

# Advisory, not an assertion. A miner legitimately excludes a certificate it cannot
# yet cover, so neither outcome is a verdict -- and a check whose clean side scores
# a PASS would make the maximum attainable count depend on a benign race.
CERT_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    R="$(grep -aF "excluding finality tally certificate" "$(node_log "$n")" 2>/dev/null | tail -1)"
    [ -n "$R" ] && CERT_REJECT="node$n: $R"
done
if [ -z "$CERT_REJECT" ]; then
    log "no node excluded a tally certificate from a block it built"
else
    warn "a node excluded a certificate at some point: $CERT_REJECT"
fi

# ============================================================
header "14. The epoch's tier comes from the note certificate"
# ============================================================

TALLY_EI="$(rpc 0 getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
TALLY_CERT="$(jget "$TALLY_EI" finality_certificate)"
TALLY_TIER="$(jget "$TALLY_EI" finality_tier)"
TALLY_ROOT="$(jget "$TALLY_EI" vote_set_root)"
TALLY_DIGEST="$(jget "$TALLY_EI" epoch_state_digest)"

if is_real_hash "$TALLY_CERT" && [ "$TALLY_CERT" = "$CARRIED_CERT_HASH" ] && \
   echo " $NOTE_CERT_HASHES " | grep -qF " $TALLY_CERT "; then
    success "epoch $TALLY_EPOCH selected the carried note certificate ${TALLY_CERT:0:16} (tier=$TALLY_TIER)"
else
    fail "epoch $TALLY_EPOCH selected '${TALLY_CERT:0:16}', expected the carried v$NOTE_CERT_VERSION certificate '${CARRIED_CERT_HASH:0:16}' (assembled:$NOTE_CERT_HASHES)"
fi

# FinalityTier: HARD is 3.
if [ "$TALLY_TIER" = "hard" ] && [ "$C_TIER" = "3" ]; then
    success "epoch $TALLY_EPOCH is tier=$TALLY_TIER, the tier its note certificate carries"
else
    fail "epoch $TALLY_EPOCH is tier=$TALLY_TIER, certificate tier '$C_TIER'"
fi

# Fleet-wide equality of the certificate, the vote-set root and the whole epoch-state
# digest is the determinism claim. node0's values must be real first: getepochinfo
# answers an uncomputed epoch with the zero hash, and three zero hashes agree.
EPOCH_AGREE=1
EPOCH_WHY=""
is_real_hash "$TALLY_ROOT"   || { EPOCH_AGREE=0; EPOCH_WHY="node0's vote-set root is '$TALLY_ROOT'"; }
is_real_hash "$TALLY_DIGEST" || { EPOCH_AGREE=0; EPOCH_WHY="node0's epoch state digest is '$TALLY_DIGEST'"; }
for ((n=1; n<NUM_NODES; n++)); do
    PEER_EI="$(rpc "$n" getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
    [ "$(jget "$PEER_EI" finality_certificate)" = "$TALLY_CERT" ] || { EPOCH_AGREE=0; EPOCH_WHY="node$n has a different certificate"; }
    [ "$(jget "$PEER_EI" vote_set_root)" = "$TALLY_ROOT" ] || { EPOCH_AGREE=0; EPOCH_WHY="node$n has a different vote-set root"; }
    [ "$(jget "$PEER_EI" epoch_state_digest)" = "$TALLY_DIGEST" ] || { EPOCH_AGREE=0; EPOCH_WHY="node$n has a different epoch state digest"; }
    [ "$(jget "$PEER_EI" finality_tier)" = "$TALLY_TIER" ] || { EPOCH_AGREE=0; EPOCH_WHY="node$n has a different tier"; }
done
if [ "$EPOCH_AGREE" -eq 1 ]; then
    success "every node agrees on epoch $TALLY_EPOCH's certificate, vote-set root (${TALLY_ROOT:0:16}) and state digest (${TALLY_DIGEST:0:16})"
else
    fail "epoch $TALLY_EPOCH's state is missing or divergent: $EPOCH_WHY"
fi

# ============================================================
header "14a. An operator can read the counted note-vote set over RPC"
# ============================================================

# getfinalityinfo answers "is the lane live right now", getepochinfo answers "what did
# epoch E count"; transparent_votes/private_votes count CFinalityVote carriers and read
# zero while the note lane runs.
NV_RPC_OK=1
NV_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    [ "$(jget2 "$FI" note_votes configured)" = "true" ] || {
        NV_RPC_OK=0; NV_WHY="node$n reports the note-vote fork unconfigured"; }
    [ "$(jget2 "$FI" note_votes active)" = "true" ] || {
        NV_RPC_OK=0; NV_WHY="node$n reports the note-vote fork inactive at the tip"; }
    [ "$(jget2 "$FI" note_votes activation_height)" = "$NOTE_VOTE_HEIGHT" ] || {
        NV_RPC_OK=0
        NV_WHY="node$n reports activation_height $(jget2 "$FI" note_votes activation_height), not $NOTE_VOTE_HEIGHT"; }
done
if [ "$NV_RPC_OK" -eq 1 ]; then
    success "every node reports the note-vote fork as configured and active at height $NOTE_VOTE_HEIGHT"
else
    fail "the note-vote lane is not reported as live: $NV_WHY"
fi

# The counted set for the tally epoch. node0's number has to be real before agreement
# means anything.
TALLY_EI_NV="$(rpc 0 getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
NV_COUNTED="$(jget "$TALLY_EI_NV" note_votes_counted)"
NV_EQUIV="$(jget "$TALLY_EI_NV" note_votes_equivocated)"
NV_TAGS="$(jlen "$TALLY_EI_NV" note_vote_tags)"
is_int "$NV_COUNTED" || NV_COUNTED=0
is_int "$NV_EQUIV" || NV_EQUIV=0
is_int "$NV_TAGS" || NV_TAGS=0
if [ "$NV_COUNTED" -ge 1 ] && [ "$NV_TAGS" = "$NV_COUNTED" ] && [ "$NV_EQUIV" = "0" ]; then
    success "getepochinfo $TALLY_EPOCH reports $NV_COUNTED counted note vote(s), $NV_TAGS tag(s), 0 equivocated"
else
    fail "getepochinfo $TALLY_EPOCH reports counted=$NV_COUNTED tags=$NV_TAGS equivocated=$NV_EQUIV"
fi

# First element of a JSON array field.
jfirst() {
    FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"]) or []
except Exception:
    v = []
print(v[0] if isinstance(v, list) and v else "")
' <<< "$1" 2>/dev/null
}

# The tag the RPC publishes is the key image the vote transaction spent, in full.
NV_RPC_TAG="$(jfirst "$TALLY_EI_NV" note_vote_tags)"
if [ ${#NV_RPC_TAG} -eq 64 ] && [ "$NV_RPC_TAG" = "${NV_KI[$TALLY_EPOCH]}" ]; then
    success "the tag getepochinfo publishes is the key image node0's vote spent (${NV_RPC_TAG:0:16})"
else
    fail "getepochinfo tag '$NV_RPC_TAG' is not the vote's key image '${NV_KI[$TALLY_EPOCH]}'"
fi

NV_AGREE=1
for ((n=1; n<NUM_NODES; n++)); do
    PEER_EI="$(rpc "$n" getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
    [ "$(jget "$PEER_EI" note_votes_counted)" = "$NV_COUNTED" ] || NV_AGREE=0
    [ "$(epoch_note_tags "$PEER_EI")" = "$(epoch_note_tags "$TALLY_EI_NV")" ] || NV_AGREE=0
done
if [ "$NV_AGREE" -eq 1 ]; then
    success "every node reports the same counted note-vote set for epoch $TALLY_EPOCH"
else
    fail "nodes disagree on epoch $TALLY_EPOCH's counted note-vote set"
fi

# The live view: the tip is inside the last held epoch, whose one vote is counted.
LIVE_OK=1
LIVE_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    LE="$(jget2 "$FI" note_votes epoch)"
    LC="$(jget2 "$FI" note_votes counted)"
    LT="$(FI="$FI" python3 -c '
import json, os
try: print(" ".join((json.loads(os.environ["FI"]).get("note_votes") or {}).get("tags") or []))
except Exception: pass
')"
    [ "$LE" = "$LAST_NV_EPOCH" ] && [ "$LC" = "1" ] && [ "$LT" = "${NV_KI[$LAST_NV_EPOCH]}" ] || \
        { LIVE_OK=0; LIVE_WHY="node$n: epoch='$LE' counted='$LC' tags='${LT:0:16}'"; }
done
if [ "$LIVE_OK" -eq 1 ]; then
    success "getfinalityinfo reports epoch $LAST_NV_EPOCH's one counted note vote, tag ${NV_KI[$LAST_NV_EPOCH]:0:16}, on every node"
else
    fail "getfinalityinfo's live note-vote view is wrong: $LIVE_WHY (expected epoch $LAST_NV_EPOCH, 1, ${NV_KI[$LAST_NV_EPOCH]:0:16})"
fi

# The lane worked while every pre-existing vote counter read zero. A non-zero value
# here means this run no longer isolates the note lane, so it fails.
BLIND_OK=1
BLIND_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    PV="$(jget "$FI" private_votes)"
    is_int "$PV" || PV=-1
    [ "$PV" = "0" ] || { BLIND_OK=0; BLIND_WHY="node$n reports private_votes=$PV"; }
done
if [ "$BLIND_OK" -eq 1 ]; then
    success "private_votes reads 0 on every node while the note lane carried epoch $TALLY_EPOCH -- which is why note_votes had to exist"
else
    fail "a transparent-carrier private vote appeared, so this run no longer isolates the note lane: $BLIND_WHY"
fi

# ============================================================
header "15. A reorg that releases a seated member does not move the committee"
# ============================================================

# The chain-split case, driven the way two honest nodes actually differ.
#
# Two branches share everything through the anchor epoch and fork INSIDE the
# term's lead-in. On the losing branch a seated member's collateral is released;
# on the winning branch it never is. A node that reorganises from the first to
# the second stages the epoch suffix -- and so redraws the committee -- BEFORE
# it disconnects the losing branch, so its registry handle still holds the
# release. A node that syncs the winning branch from nothing never saw it.
#
# Both are at the same height on the same chain. If the spend filter is not
# bounded by the anchor height, the first drops the released row and promotes
# the next candidate while the second keeps it: two committees, two epoch-state
# digests, and no self-heal, because the draw is stored rather than rederived.
REORG_RUN=1
if [ "${#REG_KEYIMAGES[@]}" -lt 1 ]; then
    fail "no registration key image was captured, so the reorg divergence test cannot run"
    REORG_RUN=0
fi

if [ "$REORG_RUN" -eq 1 ]; then
    FORK_HEIGHT="$(height 0)"
    FORK_HASH="$(block_hash 0 "$FORK_HEIGHT")"
    # Reorganize() prints unconditionally, so the count before the partition is the
    # baseline the reorg has to beat. Anything already in the log -- a mining race
    # earlier in the run -- would otherwise satisfy a bare grep.
    REORG_BEFORE="$(reorg_count 0)"
    log "forking the fleet at height $FORK_HEIGHT (${FORK_HASH:0:16}), anchor height is $COMMITTEE_ANCHOR_HEIGHT, node0 has logged $REORG_BEFORE REORGANIZE line(s) so far"

    # node2 leaves the mesh and becomes the branch that never sees the release.
    # Every node carries the others as addnode, so a single disconnect round races
    # the reconnect timer; retry until node2 is provably alone. A leaked partition
    # produces no divergence at all, so this is an assertion, not an observation.
    PARTITIONED=0
    P2=""
    for _ in $(seq 1 10); do
        for ((p=0; p<NUM_NODES; p++)); do
            [ "$p" -eq 2 ] && continue
            rpc 2 disconnectnode "127.0.0.1:$(node_port "$p")" >/dev/null 2>&1 || true
            rpc "$p" disconnectnode "127.0.0.1:$(node_port 2)" >/dev/null 2>&1 || true
        done
        sleep 3
        P2="$(peer_count 2)"
        [ "$P2" = "0" ] && { PARTITIONED=1; break; }
    done
    if [ "$PARTITIONED" -eq 1 ]; then
        success "node2 is partitioned from the fleet at height $FORK_HEIGHT"
    else
        fail "node2 still reports $P2 peer(s) after 10 disconnect rounds; the branches cannot diverge"
    fi

    # Branch X (node0/node1): release a seated member's collateral and spend it.
    RELEASED_KI="${REG_KEYIMAGES[0]}"
    REL="$(rpc 0 collateralnode releaseprivate "$RELEASED_KI" 2>&1)"
    if echo "$REL" | grep -q '"released"'; then
        success "node0 released the hold on collateral note ${RELEASED_KI:0:16}"
    else
        fail "releaseprivate did not report a release, so there is no divergence to drive: $(echo "$REL" | head -2)"
    fi

    # Spend it. 20000 INN is chosen so the released note is the only unlocked
    # note that can cover it: the other five collateral notes are still held by
    # their own registrations, and everything else in this wallet's pool is
    # carve change or a section-4 sweep.
    SPEND="$(rpc 0 z_iv5transfer "$IV5ADDR" 20000 2>&1)"
    SPEND_TXID="$(jget "$SPEND" txid)"
    if [ ${#SPEND_TXID} -eq 64 ]; then
        success "node0 spent the released collateral on branch X (txid ${SPEND_TXID:0:16})"
    else
        fail "the branch-X release spend failed, so branch X does not carry the release: $(echo "$SPEND" | head -3)"
    fi

    # mine_chunk, not mine_to: mine_to waits for the fleet to catch up, and the
    # node it would wait for is the one this section has just partitioned off.
    mine_chunk 0 $((FORK_HEIGHT + 12)) || fail "branch X did not extend"
    X_TIP="$(height 0)"

    # The driver has to actually fire, or the rest of this section proves
    # nothing. On branch X the release is committed and sits ABOVE the anchor
    # height, so the registry read at the tip must have lost a row while the
    # registry read at the anchor height must not have.
    REG_X_TIP="$(jget "$(rpc 0 collateralnode finality-registry "$X_TIP" 2>&1)" count)"
    REG_X_ANCHOR="$(jget "$(rpc 0 collateralnode finality-registry "$COMMITTEE_ANCHOR_HEIGHT" 2>&1)" count)"
    log "  branch X registry: $REG_X_TIP rows at the tip $X_TIP, $REG_X_ANCHOR rows at the anchor $COMMITTEE_ANCHOR_HEIGHT"
    DRIVER_FIRED=0
    if is_int "$REG_X_TIP" && is_int "$REG_X_ANCHOR" && [ "$REG_X_TIP" -lt "$REG_X_ANCHOR" ]; then
        DRIVER_FIRED=1
        success "the release deregistered a row on branch X ($REG_X_TIP at the tip vs $REG_X_ANCHOR at the anchor)"
    else
        fail "the branch-X spend did not consume a registered note ($REG_X_TIP at the tip vs $REG_X_ANCHOR at the anchor); nothing in this section would then be driven by a release"
    fi
    if is_int "$REG_X_ANCHOR" && [ "$REG_X_ANCHOR" -ge "$COLLATERAL_ROWS" ]; then
        success "the anchored registry is unmoved by a release above the anchor height ($REG_X_ANCHOR rows)"
    else
        fail "a release above the anchor height changed the ANCHORED registry ($REG_X_ANCHOR < $COLLATERAL_ROWS)"
    fi

    # Branch Y (node2): longer, and it never carried the release.
    rpc 2 setgenerate true 30 "$MINE_THREADS_NOW" >/dev/null 2>&1
    for _ in $(seq 1 300); do
        Y="$(height 2)"
        is_int "$Y" && [ "$Y" -ge $((X_TIP + 8)) ] && break
        sleep 1
    done
    rpc 2 setgenerate false 0 >/dev/null 2>&1
    Y_TIP="$(height 2)"
    log "branch X tip=$X_TIP  branch Y tip=$Y_TIP"

    if is_int "$Y_TIP" && is_int "$X_TIP" && [ "$Y_TIP" -gt "$X_TIP" ]; then
        success "branch Y ($Y_TIP) outruns branch X ($X_TIP), so the fleet must reorganise onto it"
    else
        fail "branch Y ($Y_TIP) did not outrun branch X ($X_TIP); node0 would have nothing to reorganise onto"
    fi

    # The two branches, identified by the block each holds at the first height above
    # the fork. These are what the convergence check below compares -- heights are
    # equal whether node0 reorganised onto Y or node2 abandoned Y for X, and only
    # the hashes tell those apart.
    X_FORK1="$(block_hash 0 $((FORK_HEIGHT + 1)))"
    Y_FORK1="$(block_hash 2 $((FORK_HEIGHT + 1)))"
    if [ ${#X_FORK1} -eq 64 ] && [ ${#Y_FORK1} -eq 64 ] && [ "$X_FORK1" != "$Y_FORK1" ]; then
        success "the branches really diverged at $((FORK_HEIGHT + 1)): X holds ${X_FORK1:0:16}, Y holds ${Y_FORK1:0:16}"
    else
        fail "the branches did not diverge at $((FORK_HEIGHT + 1)) (X='$X_FORK1' Y='$Y_FORK1'); there is no reorg to observe"
    fi

    # Rejoin. node0 reorganises X -> Y with the release still in its database.
    connect_mesh
    # Advisory: a peer slot that has not re-formed yet is a benign race, and the tip
    # hash convergence below is the thing that actually has to happen.
    wait_peers >/dev/null 2>&1 || warn "the mesh did not fully re-form"
    REORG_OK=0
    BH0=""
    for _ in $(seq 1 240); do
        H0="$(height 0)"; H2="$(height 2)"
        if is_int "$H0" && is_int "$H2" && [ "$H0" = "$H2" ]; then
            BH0="$(block_hash 0 "$H0")"
            BH2="$(block_hash 2 "$H2")"
            if [ ${#BH0} -eq 64 ] && [ "$BH0" = "$BH2" ]; then REORG_OK=1; break; fi
        fi
        sleep 1
    done
    if [ "$REORG_OK" -eq 1 ]; then
        success "the fleet converged on one tip: height $(height 0), hash ${BH0:0:16}"
    else
        fail "the fleet did not converge on one tip after the partition (node0=$(height 0)/$(block_hash 0 "$(height 0)") node2=$(height 2)/$(block_hash 2 "$(height 2)"))"
    fi

    # Which branch it converged ON. node0 has to be holding branch Y's block at the
    # first height above the fork, which means it disconnected its own.
    NOW_FORK1="$(block_hash 0 $((FORK_HEIGHT + 1)))"
    if [ ${#Y_FORK1} -eq 64 ] && [ "$NOW_FORK1" = "$Y_FORK1" ] && [ "$Y_FORK1" != "$X_FORK1" ]; then
        success "node0 replaced its own block at $((FORK_HEIGHT + 1)) (${X_FORK1:0:16}) with branch Y's (${Y_FORK1:0:16})"
    else
        fail "node0 did not adopt branch Y at $((FORK_HEIGHT + 1)): it holds ${NOW_FORK1:0:16}, branch X had ${X_FORK1:0:16} and branch Y ${Y_FORK1:0:16}"
    fi

    # And that it got there by disconnecting blocks rather than by fast-forward.
    # Reorganize() prints REORGANIZE unconditionally, so a count that has not moved
    # means no disconnect happened on this node.
    REORG_AFTER="$(reorg_count 0)"
    if [ "$REORG_AFTER" -gt "$REORG_BEFORE" ]; then
        success "node0 logged a reorganisation ($REORG_BEFORE -> $REORG_AFTER REORGANIZE lines)"
    else
        fail "node0 logged no new reorganisation ($REORG_BEFORE -> $REORG_AFTER): it disconnected nothing"
    fi

    # A fourth node, started from an empty datadir, syncs branch Y from nothing.
    # This is the other half of the claim: same chain, no history of the release.
    FRESH=3
    rm -rf "$(node_dir "$FRESH")"
    NUM_NODES=$((NUM_NODES + 1))
    write_config "$FRESH"
    NUM_NODES=$((NUM_NODES - 1))
    # A fresh node holds no member secret and needs none: it only has to derive
    # the same committee from the same chain.
    # -i.bak, not -i: BSD sed reads the argument after -i as the backup suffix, so
    # the bare form silently edits nothing and leaves the line in place.
    sed -i.bak "/^finalitytallyprivkey=/d" "$(node_dir "$FRESH")/innova.conf"
    rm -f "$(node_dir "$FRESH")/innova.conf.bak"
    "$INNOVAD" -datadir="$(node_dir "$FRESH")" -regtest -daemon >/dev/null 2>&1
    if wait_rpc "$FRESH"; then
        for ((p=0; p<NUM_NODES; p++)); do
            rpc "$FRESH" addnode "127.0.0.1:$(node_port "$p")" onetry >/dev/null 2>&1 || true
        done
        TARGET="$(height 0)"
        SYNCED=0
        for _ in $(seq 1 1200); do
            HF="$(height "$FRESH")"
            if is_int "$HF" && [ "$HF" -ge "$TARGET" ]; then SYNCED=1; break; fi
            sleep 1
        done
        if [ "$SYNCED" -eq 1 ]; then
            success "a fresh node synced branch Y from nothing to height $(height "$FRESH")"
        else
            fail "the fresh node did not sync (height=$(height "$FRESH") target=$TARGET)"
        fi

        # THE ASSERTION. The reorganised node and the fresh node must hold the
        # same committee and the same carrier-epoch digest.
        R_SEATS="$(committee_seats 0 | tr '\n' ' ')"
        F_SEATS="$(committee_seats "$FRESH" | tr '\n' ' ')"
        R_SET="$(jget "$(rpc 0 getfinalityinfo 2>/dev/null)" committee_set_hash)"
        F_SET="$(jget "$(rpc "$FRESH" getfinalityinfo 2>/dev/null)" committee_set_hash)"
        R_DIG="$(jget "$(rpc 0 getepochinfo "$COMMITTEE_CARRIER_EPOCH" 2>/dev/null)" epoch_state_digest)"
        F_DIG="$(jget "$(rpc "$FRESH" getepochinfo "$COMMITTEE_CARRIER_EPOCH" 2>/dev/null)" epoch_state_digest)"

        # Each value has to be a real committee / real hash before equality means
        # anything: two nodes that both answered nothing are also two nodes that
        # agree.
        R_SEAT_N="$(committee_seats 0 | grep -c . || true)"
        if is_int "$R_SEAT_N" && [ "$R_SEAT_N" -eq "$COMMITTEE_SEAT_COUNT" ] && \
           [ "$R_SEATS" = "$F_SEATS" ]; then
            success "the reorganised node and the fresh node draw the identical $COMMITTEE_SEAT_COUNT-seat committee"
            log "  seats: $R_SEATS"
        else
            fail "COMMITTEE SPLIT or empty: reorganised [$R_SEATS] vs fresh-synced [$F_SEATS]"
        fi
        if is_real_hash "$R_SET" && [ "$R_SET" = "$F_SET" ]; then
            success "both nodes report the same committee set hash ${R_SET:0:16}"
        else
            fail "COMMITTEE SET HASH SPLIT or empty: reorganised '$R_SET' vs fresh-synced '$F_SET'"
        fi
        if is_real_hash "$R_DIG" && [ "$R_DIG" = "$F_DIG" ]; then
            success "the carrier epoch $COMMITTEE_CARRIER_EPOCH digest is identical on both (${R_DIG:0:16})"
        else
            fail "EPOCH STATE DIGEST SPLIT or empty: reorganised '$R_DIG' vs fresh-synced '$F_DIG'"
        fi

        # What the whole section rests on, restated rather than re-asserted: the
        # reorganising node held the losing branch's release in its database while
        # it restaged the epoch suffix, and the fresh node never had it. That the
        # release fired is already a hard assertion above (DRIVER_FIRED).
        log "the agreement above was driven by a real release: branch X read $REG_X_TIP registry rows at its tip and $REG_X_ANCHOR at the anchor"
        R_ANCHOR="$(jget "$(rpc 0 collateralnode finality-registry "$COMMITTEE_ANCHOR_HEIGHT" 2>&1)" count)"
        F_ANCHOR="$(jget "$(rpc "$FRESH" collateralnode finality-registry "$COMMITTEE_ANCHOR_HEIGHT" 2>&1)" count)"
        if is_int "${R_ANCHOR:-x}" && [ "${R_ANCHOR:-0}" -ge "$COLLATERAL_ROWS" ] && \
           [ "$R_ANCHOR" = "$F_ANCHOR" ]; then
            success "both nodes read the identical anchored registry ($R_ANCHOR rows at height $COMMITTEE_ANCHOR_HEIGHT)"
        else
            fail "ANCHORED REGISTRY SPLIT or empty: reorganised '$R_ANCHOR' rows vs fresh-synced '$F_ANCHOR' rows, expected >= $COLLATERAL_ROWS on both"
        fi

        rpc "$FRESH" stop >/dev/null 2>&1 || true
    else
        fail "the fresh node did not start"
    fi
fi

# ============================================================
header "15a. A reorg that disconnects a note vote's carrier takes it out of the counted set"
# ============================================================

# Connect records a block's votes in the carrier index and disconnect owes their
# removal whether or not the vote comes back. node0 invalidates the block carrying its
# own vote, then outruns the fleet so every peer reorganises off that block too.
# Throughout, a node's counted set must be exactly the operation-10 votes its active
# chain carries in the epoch's window.
RV_E="$REORG_VOTE_EPOCH"
RV_B="$(epoch_start "$RV_E")"
# Short on purpose: node0 drops below the carrier, and a peer chain far ahead of an
# invalidated tip is a large-work fork warning rather than a reorg.
RV_CARRY=5
log "epoch $RV_E: holding the chain at $((RV_B + NOTE_VOTE_EMIT_OFFSET)) for ${NOTE_VOTE_SETTLE}s"
note_vote_round "$RV_E" "$RV_B" "$RV_CARRY" || { fail "epoch $RV_E vote round failed"; exit 1; }

RV_ROWS="$(notevotes_in_range 0 "$RV_B" $((RV_B + RV_CARRY)))"
RV_N="$(echo "$RV_ROWS" | grep -c . || true)"
RV_H="$(echo "$RV_ROWS" | awk 'NF{print $1; exit}')"
RV_TXID="$(echo "$RV_ROWS" | awk 'NF{print $2; exit}')"
RV_RUN=1
if [ "$RV_N" = "1" ] && [ ${#RV_TXID} -eq 64 ] && [ "$RV_TXID" = "${NV_TXID[$RV_E]}" ]; then
    success "node0's epoch $RV_E vote ${RV_TXID:0:16} is carried at height $RV_H"
else
    fail "epoch $RV_E carries $RV_N vote(s) ('${RV_TXID:0:16}' vs cast '${NV_TXID[$RV_E]:0:16}'); nothing to disconnect"
    RV_RUN=0
fi

if [ "$RV_RUN" -eq 1 ]; then
    RV_KI="$(notevote_fields 0 "$RV_TXID" | awk '{print $2}')"
    PRE_OK=1
    for ((n=0; n<NUM_NODES; n++)); do
        V="$(epoch_note_view "$n" "$RV_E")"
        [ "$V" = "1 0 $RV_KI" ] || \
            { PRE_OK=0; fail "node$n does not count the carried vote before the disconnect (view '${V:0:40}')"; }
    done
    [ "$PRE_OK" -eq 1 ] && [ ${#RV_KI} -eq 64 ] && \
        success "every node counts the vote (tag ${RV_KI:0:16}) before the disconnect"

    RV_HASH="$(block_hash 0 "$RV_H")"
    RV_RAW="$(raw_tx 0 "$RV_TXID")"
    R1_BEFORE="$(reorg_count 1)"
    R2_BEFORE="$(reorg_count 2)"
    INV="$(rpc 0 invalidateblock "$RV_HASH" 2>&1)"
    for _ in $(seq 1 30); do
        [ "$(height 0)" = "$((RV_H - 1))" ] && break
        sleep 1
    done
    V0="$(epoch_note_view 0 "$RV_E")"
    if [ "$(height 0)" = "$((RV_H - 1))" ] && [ "$V0" = "0 0" ]; then
        success "with its carrier ${RV_HASH:0:16} disconnected, node0 counts no note vote for epoch $RV_E"
    else
        fail "after invalidating the carrier node0 is at $(height 0) (expected $((RV_H - 1))) and reports '${V0:0:40}' for the epoch ($INV)"
    fi
    # Reorganize() resurrects a disconnected transaction only above
    # Checkpoints::GetTotalBlocksEstimate(), which reads the mainnet checkpoint map on
    # regtest, so no regtest reorg returns anything to the mempool. The vote is offered
    # again by hand: with its carrier gone its key image is unspent, so it must be taken.
    if [ -n "$(mempool_txid 0 "$RV_TXID")" ]; then
        log "  the disconnected vote is back in node0's mempool"
    else
        RS="$(rpc 0 sendrawtransaction "$RV_RAW" 2>&1 | tr -d '"[:space:]')"
        if [ "$RS" = "$RV_TXID" ] && [ -n "$(mempool_txid 0 "$RV_TXID")" ]; then
            success "with its carrier disconnected the vote's key image is unspent again: node0 re-admits the same vote"
        else
            fail "node0 refused the disconnected vote ($RS): $(grep -a "CTxMemPool::accept()" "$(node_log 0)" | tail -1)"
        fi
    fi

    # node0 outruns the peers, still inside the vote's inclusion window.
    PEER_TIP="$(height 1)"
    RV_TARGET=$(( PEER_TIP + 2 ))
    if [ "$RV_TARGET" -ge $((RV_B + NOTE_VOTE_INCLUSION_WINDOW)) ]; then
        fail "the peers' tip $PEER_TIP leaves no room inside the window ending $((RV_B + NOTE_VOTE_INCLUSION_WINDOW - 1))"
    fi
    mine_chunk 0 "$RV_TARGET" || fail "node0 did not extend its branch to $RV_TARGET"
    RV_CONV=0
    for _ in $(seq 1 240); do
        T0="$(block_hash 0 "$RV_TARGET")"
        OK=1
        for ((n=1; n<NUM_NODES; n++)); do
            [ ${#T0} -eq 64 ] && [ "$(block_hash "$n" "$RV_TARGET")" = "$T0" ] || OK=0
        done
        [ "$OK" -eq 1 ] && { RV_CONV=1; break; }
        sleep 1
    done
    R1_AFTER="$(reorg_count 1)"
    R2_AFTER="$(reorg_count 2)"
    SWAP_OK=1
    for ((n=0; n<NUM_NODES; n++)); do
        [ "$(block_hash "$n" "$RV_H")" != "$RV_HASH" ] || SWAP_OK=0
    done
    if [ "$RV_CONV" -eq 1 ] && [ "$SWAP_OK" -eq 1 ] && \
       [ "$R1_AFTER" -gt "$R1_BEFORE" ] && [ "$R2_AFTER" -gt "$R2_BEFORE" ]; then
        success "both peers reorganised onto node0's branch (height $RV_TARGET) and no node holds the old carrier at $RV_H"
    else
        fail "the fleet did not reorganise off the carrier: converged=$RV_CONV replaced=$SWAP_OK node1 $R1_BEFORE->$R1_AFTER node2 $R2_BEFORE->$R2_AFTER"
    fi

    # The invariant, against the reorganised chain.
    NEW_ROWS="$(notevotes_in_range 0 "$RV_B" "$RV_TARGET")"
    NEW_KIS=""
    while read -r _ T; do
        [ ${#T} -eq 64 ] && NEW_KIS="$NEW_KIS $(notevote_fields 0 "$T" | awk '{print $2}')"
    done <<< "$NEW_ROWS"
    NEW_KIS="$(echo "$NEW_KIS" | tr ' ' '\n' | grep . | sort | tr '\n' ' ' | sed 's/ $//')"
    NEW_N="$(echo "$NEW_KIS" | wc -w | tr -d ' ')"
    SET_OK=1
    for ((n=0; n<NUM_NODES; n++)); do
        V="$(epoch_note_view "$n" "$RV_E")"
        [ "$V" = "$(echo "$NEW_N 0 $NEW_KIS" | sed 's/ $//')" ] || \
            { SET_OK=0; fail "node$n reports '${V:0:40}' for epoch $RV_E; its chain carries $NEW_N [${NEW_KIS:0:16}]"; }
    done
    [ "$SET_OK" -eq 1 ] && \
        success "every node's epoch $RV_E counted set equals the $NEW_N vote(s) its reorganised chain carries"

    # The vote is carried again, once, inside its window.
    RE_H="$(echo "$NEW_ROWS" | awk -v t="$RV_TXID" '$2 == t {print $1}')"
    if [ "$NEW_N" = "1" ] && [ "$NEW_KIS" = "$RV_KI" ] && is_int "${RE_H:-x}" && \
       [ "$RE_H" -lt $((RV_B + NOTE_VOTE_INCLUSION_WINDOW)) ]; then
        success "the disconnected vote was carried again at height $RE_H, inside its window, under the same tag"
    else
        fail "the disconnected vote was not re-carried once (carried $NEW_N vote(s), txid at '${RE_H:-none}')"
    fi

    # Clear the mark; the old carrier is on the shorter branch, so the tip stays.
    RC="$(rpc 0 reconsiderblock "$RV_HASH" 2>&1)"
    log "  reconsiderblock: tip_moved=$(jget "$RC" tip_moved) tip_height=$(jget "$RC" tip_height)"
fi

# ============================================================
header "16. The fleet reports no errors"
# ============================================================

ERR_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    E="$(jget "$(rpc "$n" getinfo 2>/dev/null)" errors)"
    [ -z "$E" ] || { fail "node$n reports errors: $E"; ERR_OK=0; }
    if grep -qiE "IV5 pool balance|takes more from the pool|does not validate|IV5 finalized context rejected" \
            "$(node_log "$n")" 2>/dev/null; then
        fail "node$n log carries an IV5 pool or validation complaint"
        grep -iE "IV5 pool balance|takes more from the pool|does not validate|IV5 finalized context rejected" \
            "$(node_log "$n")" | tail -3
        ERR_OK=0
    fi
done
[ "$ERR_OK" -eq 1 ] && success "no node reports errors or IV5 validation complaints"

# ============================================================
print_results
[ "$FAILED" -eq 0 ] || exit 1
exit 0
