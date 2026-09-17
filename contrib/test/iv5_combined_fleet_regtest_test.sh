#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Every v5 feature live on one regtest fleet at the same time.
#
# Nothing else in contrib/test runs more than two of the regtest feature switches
# at once. This runs all of them on one chain and requires the features to
# compose: IDAG ordering with DAGKnight, the FCMP++ pool at Boundary B, every
# disclosure mask, IV5 note finality voting, the IDNS name reset, the IV5 coinbase
# fee note, the total-supply cap, and private collateralnode registration -- plus
# a proof-of-data stamp, which is reachable on regtest and cheap to carry along.
#
# What a combined run can settle that the single-feature harnesses cannot:
#   - one coinbase carrying an IDAG parent commitment, a note-vote envelope and an
#     IV5 fee-note payload has to be built, connected and accepted fleet-wide.
#     The miner builds the fee-note payload over the FINAL coinbase output vector,
#     which the vote envelopes have already been appended to, so the two features
#     share one object and either binding could be computed over the wrong bytes
#   - a masked transfer's fee under the fee-note fork must leave the pool balance
#     unchanged: the fee comes out of the spent note and comes back as the
#     coinbase note. Pre-fork the same transfer moves it to the miner
#   - the supply cap has to clamp issuance while the finality settlement, the fee
#     note and the collateralnode split are all live in the same coinbase
#   - the IDNS reset guard and the pool have to coexist: they share a wallet
#
# Layout. Regtest activates the DAG at 11 and DAGKnight at 13, epochs are 300
# blocks, so epoch E covers [11 + 300*(E-1), 310 + 300*(E-1)] and Boundary B sits
# at 311, the epoch-state V3 height. The committee schedule below is derived, not
# written out: registrations have to confirm at or below the term's draw anchor
# and the term has to sit on the chain's own term grid.
#
# The negative phase runs FIRST and on its own datadir. It builds the same pool
# state with -regtestiv5holdleafindex, which leaves received notes without a tree
# position and so unspendable, and then runs the SAME predicate the positive path
# asserts with. A harness whose detector cannot report a failure is not measuring
# anything, so that predicate returning "spendable" there is a hard failure here.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_COMBINED_TEST_DIR:-${TEST_DIR:-/tmp/innova_iv5_combined_$$}}"
NUM_NODES=3
BASE_PORT="${IV5_COMBINED_BASE_PORT:-26650}"
BASE_RPC="${IV5_COMBINED_BASE_RPC:-26700}"
BASE_IDNS="${IV5_COMBINED_BASE_IDNS:-6650}"
RPCUSER="iv5combined"
RPCPASS="iv5combinedpass"
WALLETPASS="iv5combinedwallet"

# The fault-injection node of the negative phase. Its own index so it gets its own
# datadir and its own three ports, and so the fleet teardown covers it.
NEG_NODE=8

# ---------------------------------------------------------------------------
# The switches. Every one of these is passed to every node for the whole run.
# ---------------------------------------------------------------------------
BOUNDARY_B=311
# init refuses a note-vote fork below Boundary B, so this is the earliest legal
# height and every epoch boundary from 2 on is an attempt.
NOTE_VOTE_HEIGHT=311
# Above Boundary B with value already pooled, and clear of epoch 2's
# vote-inclusion window [311, 335) and settlement height 335, which add coinbase
# outputs.
FEE_NOTE_HEIGHT=400
# Inside epoch 3 [611, 910]. Below it the wallet must refuse a name whose term the
# reset would wipe; at and above it registration works again.
IDNS_RESET_HEIGHT=800
# The clamp applies from the DAG fork. This amount is unreachable; the final
# section restarts the fleet with a cap just above issued supply.
SUPPLY_CAP_HEIGHT=11
SUPPLY_CAP=500000000000000
SUPPLY_CAP_INN=5000000
# Headroom above issued supply when the cap is retightened; under half a
# block's issuance.
SUPPLY_CAP_TIGHTEN_INN=200
# Blocks mined after retightening before issuance must have stopped. Payout is
# nine tenths of remaining headroom per block; 200 INN truncates to zero in ~12.
CAP_DRAIN_BLOCKS=25

# Fee every IV5 transaction declares.
SHIELD_FEE="0.00100000"

# ---------------------------------------------------------------------------
# Fixed heights. Each peer's stake must clear the 500 INN vote floor from NOTE_VOTE_HEIGHT.
# ---------------------------------------------------------------------------
FUND_AMOUNT=600
FUND_HEIGHT=40
FUND_CONFIRM_HEIGHT=45
SHIELD_HEIGHT=330
SHIELD_CONFIRM_HEIGHT=345
SHIELD_SWEEPS=4

# Epochs 2-4 are the HARD run; an epoch-E vote names E's boundary, so epoch 4's
# record carries finalized height 911.
FINALIZED_HEIGHT=911
FINALIZED_EPOCH=4

# Negative phase: one node, same switches plus the leaf-index hold. Shield in
# epoch 2, tip carried into epoch 3, so only the hold keeps the note unspendable.
NEG_SEED_HEIGHT=250
NEG_SHIELD_HEIGHT=330
NEG_SHIELD_CONFIRM=350
NEG_END_HEIGHT=620

# Single-threaded: setgenerate with N threads overshoots a target by up to N-1,
# and mining faster than the fleet follows wedges a peer's block fetch.
MINE_THREADS=1
MINE_THREADS_NOW=1
MINE_CHUNK="${IV5_COMBINED_MINE_CHUNK:-50}"

# Epoch E spans [11 + 300*(E-1), 310 + 300*(E-1)].
epoch_start() { echo $(( 11 + ($1 - 1) * 300 )); }
epoch_end()   { echo $(( 310 + ($1 - 1) * 300 )); }

# ---------------------------------------------------------------------------
# The committee schedule.
#
# Regtest draws 3 seats at M=2 over a 2-epoch term, refuses a registry smaller
# than 2N, and anchors the draw 2 epochs back. Transparent value is shielded in
# the funding epoch, the collateral notes are carved out of it, and they are
# registered; every registration must confirm at or below the term's anchor height,
# and the term itself has to sit on the chain's own term grid.
#
# A note made in epoch E is first spendable in E+2. At a height in E+1 the spend
# anchor is the newest epoch the E record calls finalized, which is at most E-1, and
# E itself is under EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH deep. Only the E+1
# record, written as E+2 opens, carries a finalized height that covers E.
# ---------------------------------------------------------------------------
POOL_FUND_EPOCH=9
CARVE_EPOCH=$(( POOL_FUND_EPOCH + 2 ))
REGISTER_EPOCH=$(( CARVE_EPOCH + 2 ))
# Above the anchor, so nothing here moves the registry the draw reads.
MASK_EPOCH=$(( REGISTER_EPOCH + 1 ))

COMMITTEE_TERM_EPOCHS=2
COMMITTEE_TERM_EPOCH=$(( ((REGISTER_EPOCH + 3 + COMMITTEE_TERM_EPOCHS - 1) / COMMITTEE_TERM_EPOCHS) * COMMITTEE_TERM_EPOCHS ))
COMMITTEE_ANCHOR_EPOCH=$(( COMMITTEE_TERM_EPOCH - 2 ))
COMMITTEE_CARRIER_EPOCH=$(( COMMITTEE_TERM_EPOCH - 1 ))
COMMITTEE_ANCHOR_HEIGHT="$(epoch_start "$COMMITTEE_ANCHOR_EPOCH")"
COMMITTEE_SEATED_HEIGHT=$(( $(epoch_end "$COMMITTEE_CARRIER_EPOCH") + 1 ))

# The term before the one this run seats. Its anchor sits below every
# registration, which is the harness's only discriminator between a committee
# drawn from the collateral registry and a fixed set: the three member keys are
# 1G/2G/3G, which every other observation here would accept from a fixed set too.
PRE_TERM_EPOCH=$(( COMMITTEE_TERM_EPOCH - COMMITTEE_TERM_EPOCHS ))
PRE_TERM_ANCHOR_EPOCH=$(( PRE_TERM_EPOCH - 2 ))
PRE_TERM_ANCHOR_HEIGHT="$(epoch_start "$PRE_TERM_ANCHOR_EPOCH")"

COMMITTEE_SEAT_COUNT=3
COMMITTEE_THRESHOLD_M=2

# Six rows is the committee floor: 3 seats x the 2N registry minimum, two rows per
# member key so the draw seats exactly the three node keys whichever rows win. One
# more note funds the private collateralnode registration, which is a different
# verb over the same kind of note.
COLLATERAL_ROWS=$(( COMMITTEE_SEAT_COUNT * 2 ))
PRIVATE_CN_ROWS=1
REGISTER_ROWS=$(( COLLATERAL_ROWS + PRIVATE_CN_ROWS ))
# node0 note-votes, and its voter takes the wallet's largest eligible note and skips only
# collateral that is already registered. The epoch the carved notes become spendable is
# the epoch their registrations run in, so the voter takes one of them at that boundary,
# before the harness can register it. One spare keeps every registration row funded.
VOTE_SPARE_ROWS=1
CARVE_ROWS=$(( REGISTER_ROWS + VOTE_SPARE_ROWS ))
COLLATERAL_VALUE=25000

# Funding the pool. A shield splits its value across two notes at a uniformly
# random point, so no amount shielded in one step can be made to land as a single
# 25000 INN note: the collateral notes are carved by in-pool transfer. Selection is
# largest-first and every carve strands whatever it over-selected, so many smaller
# shields keep the strand small. Eight carves need 200000; the rest is strand
# headroom and the notes the mask section spends.
POOL_SHIELD_ROWS=24
POOL_SHIELD_VALUE=11500
POOL_SHIELD_TOTAL=$(( POOL_SHIELD_ROWS * POOL_SHIELD_VALUE ))

# Inside POOL_FUND_EPOCH: late enough that mature coinbase covers
# POOL_SHIELD_TOTAL, early enough that all shield rows land in the epoch. The
# balance is polled, not assumed.
POOL_FUND_HEIGHT=$(( $(epoch_start "$POOL_FUND_EPOCH") + 100 ))
POOL_FUND_DEADLINE=$(( $(epoch_start "$POOL_FUND_EPOCH") + 260 ))
CARVE_HEIGHT="$(epoch_start "$CARVE_EPOCH")"
REGISTER_HEIGHT="$(epoch_start "$REGISTER_EPOCH")"
MASK_HEIGHT="$(epoch_start "$MASK_EPOCH")"

# Boundaries observed for note votes: both epochs of the term the draw seats.
NOTE_VOTE_EPOCHS="$COMMITTEE_TERM_EPOCH $(( COMMITTEE_TERM_EPOCH + 1 ))"
NOTE_VOTE_WINDOW=10
# FINALITY_VOTE_INCLUSION_WINDOW: an epoch-E vote connects only in [H_E, H_E + 24).
FINALITY_VOTE_WINDOW_BLOCKS=24
NOTE_VOTE_SETTLE=30

# One member secret per node. These are NOT a committee: nothing is pinned. A node
# holds a seat only if some IV5 collateral registration published the matching
# pubkey and that registration wins the term's draw. Scalars 1/2/3, the well-known
# secp256k1 test points.
COMMITTEE_PRIVKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
# The same three secrets in wallet-import form (regtest secret prefix 230), so the
# wallet that registers a note holds the private half of the member key it
# publishes -- finality-register refuses a key it cannot decrypt to.
COMMITTEE_WIFS=(
    "b2N2W7suGMid823gCRnQ72m2EwD31FNCScGyhUgmw4LhmdmxgjPn"
    "b2N2W7suGMid823gCRnQ72m2EwD31FNCScGyhUgmw4Lhn8iV52zc"
    "b2N2W7suGMid823gCRnQ72m2EwD31FNCScGyhUgmw4LhndY5atD1"
)
COMMITTEE_PUBKEYS=(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)

# OP_RETURN payload tags of the three coinbase envelopes this run reads.
NOTE_VOTE_OPERATION=10          # a note vote is an operation-10 transaction
TALLY_CERT_TAG_HEX="49464343"   # IFCC, a canonical tally certificate
IDAG_TAG_HEX="49444147"         # IDAG, the DAG parent commitment

TALLY_EPOCH="${NOTE_VOTE_EPOCHS%% *}"
TALLY_WINDOW_CLOSE=$(( 11 + (TALLY_EPOCH - 1) * 300 + 24 ))
TALLY_CARRY_HEIGHT=$(( TALLY_WINDOW_CLOSE + 40 ))
TALLY_SETTLE=45

# Off testnet announcements are pinned to port 14539 (peers drop others).
# Nothing needs to listen; peers record the announcement without connecting.
PRIVATE_CN_ENDPOINT="127.0.0.1:14539"
COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY=15
# Off testnet the collateralnode payment gate is height >= 2085000, unreachable
# on regtest; the harness asserts no payment.
CN_PAYMENT_START_HEIGHT=2085000

# IDNS.
IDNS_NAME="dns:combined.inn"
IDNS_VALUE="10.9.8.7"
IDNS_DAYS=1

PASSED=0
FAILED=0
WARNED=0
WARNINGS=()

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; WARNED=$((WARNED + 1)); WARNINGS+=("$*"); }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

RESULTS_PRINTED=0
print_results() {
    RESULTS_PRINTED=1
    header "Results"
    if [ -f "$TEST_DIR/rpc_timeouts" ]; then
        echo -e "${RED}RPC timeouts: $(rpc_timeout_count)${NC}"
        sed 's/^/  - /' "$TEST_DIR/rpc_timeouts"
    fi
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo -e "${YELLOW}Warnings: $WARNED${NC}"
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

# Every RPC is bounded. On the first timeout, capture the wedged daemon's state
# before anything is killed.
RPC_TIMEOUT="${IV5_COMBINED_RPC_TIMEOUT:-180}"
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"; fi

# Set by the run, read back from a file: rpc() is nearly always called in a
# subshell, so a shell variable would not survive.
rpc_timeout_count() { [ -f "$TEST_DIR/rpc_timeouts" ] && wc -l < "$TEST_DIR/rpc_timeouts" || echo 0; }

# Wait channel per thread plus the tail of the log, for every node still alive.
capture_wedge() {
    local why="$1" n p dir out
    out="$TEST_DIR/wedge_evidence.txt"
    {
        echo "=== wedge: $why at $(date -u '+%Y-%m-%d %H:%M:%SZ') ==="
        for n in 0 1 2 3 "$NEG_NODE"; do
            for p in $(node_pids "$n"); do
                echo "--- node$n pid $p threads ---"
                for t in /proc/"$p"/task/*; do
                    [ -d "$t" ] || continue
                    echo "  tid=$(basename "$t") name=$(cat "$t/comm" 2>/dev/null) wchan=$(cat "$t/wchan" 2>/dev/null)"
                done
            done
            dir="$(node_log "$n")"
            [ -f "$dir" ] && { echo "--- node$n debug.log tail ---"; tail -400 "$dir"; }
        done
    } >> "$out" 2>&1
}

rpc() {
    local node="$1"; shift
    local out rc
    if [ -z "$TIMEOUT_BIN" ]; then
        "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser="$RPCUSER" \
            -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>&1
        return $?
    fi
    out="$("$TIMEOUT_BIN" -k 5 "$RPC_TIMEOUT" \
        "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -rpcuser="$RPCUSER" \
        -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>&1)"
    rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        echo "node$node $* (${RPC_TIMEOUT}s)" >> "$TEST_DIR/rpc_timeouts"
        echo -e "${RED}[RPC-TIMEOUT]${NC} node$node $* did not answer in ${RPC_TIMEOUT}s" >&2
        if [ ! -f "$TEST_DIR/wedge_evidence.txt" ]; then
            capture_wedge "node$node $*"
            echo -e "${RED}[RPC-TIMEOUT]${NC} wedge evidence written to $TEST_DIR/wedge_evidence.txt" >&2
        fi
        echo "RPC-TIMEOUT"
        return "$rc"
    fi
    printf '%s\n' "$out"
    return "$rc"
}

# A daemon that stops answering is the defect, not a slow run: stop here rather
# than spending the remaining stall budget polling a wedged node.
abort_if_wedged() {
    [ -f "$TEST_DIR/rpc_timeouts" ] || return 0
    fail "a node stopped answering RPC ($(rpc_timeout_count) timed-out call(s)); evidence in $TEST_DIR/wedge_evidence.txt"
    exit 1
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
fgt() { [ "$(python3 -c "print(1 if ($1) > ($2) else 0)" 2>/dev/null)" = "1" ]; }
fsub() { python3 -c "print('%.8f' % (($1) - ($2)))" 2>/dev/null; }
fadd() { python3 -c "print('%.8f' % (($1) + ($2)))" 2>/dev/null; }

is_zero_hex() {
    case "$1" in
        ""|*[!0]*) [ -z "$1" ] && return 0 || return 1 ;;
        *) return 0 ;;
    esac
}

# 64-hex and not all-zero: a failed RPC yields empty and a stateless epoch
# yields the zero hash, and nodes trivially agree on both.
is_real_hash() { [ ${#1} -eq 64 ] && ! is_zero_hex "$1"; }

# ------------------------------------------------------------------
# Process and port hygiene
# ------------------------------------------------------------------

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
        for n in 0 1 2 3 "$NEG_NODE"; do
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

stop_node() {
    rpc "$1" setgenerate false 0 >/dev/null 2>&1 || true
    rpc "$1" stop >/dev/null 2>&1 || true
    wait_rpc_down "$1" || { force_kill_node "$1"; return 1; }
    return 0
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
        abort_if_wedged
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

# Mine on NODE until TARGET. Re-arms the miner if height stalls: setgenerate takes
# a block count, and a template that loses a race consumes one.
mine_chunk() {
    local node="$1" target="$2" h last stall=0
    h="$(height "$node")"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$node" setgenerate true $((target - h)) "$MINE_THREADS_NOW" >/dev/null 2>&1
    for ((i=0; i<3000; i++)); do
        abort_if_wedged
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
            [ $((h % 200)) -eq 0 ] && log "  ...height $h/$target"
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

# Mine on NODE to TARGET in chunks; mining far ahead of peers wedges their
# block fetch.
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

# Transparent votes for the epoch at BOUNDARY. Mining pauses at the boundary so
# each node's 5s vote cycle lands inside [H_E, H_E+24).
vote_round() {
    local boundary="$1" settle="${2:-18}" carry="${3:-3}"
    mine_to 0 "$boundary" || return 1
    wait_sync "$boundary" || return 1
    sleep "$settle"
    mine_to 0 $((boundary + carry)) || return 1
    wait_sync $((boundary + carry)) || return 1
}

# The wallet treats the tip coinbase as mature at regtest depth 1 but
# ConnectInputs refuses it; mine one block and retry.
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
# broadcast is confirmed everywhere before the next is built on top of it.
confirm_on() {
    local count="${1:-2}" target
    target=$(( $(height 0) + count ))
    mine_to 0 "$target" >/dev/null || return 1
    wait_sync "$target" >/dev/null || return 1
    return 0
}

# Drive the transparent vote round at every boundary in [from, to]. A note is
# attestable only once its epoch is finalized.
advance_through_epochs() {
    local from="$1" to="$2" e b
    for ((e=from; e<=to; e++)); do
        b="$(epoch_start "$e")"
        log "  epoch $e boundary at height $b"
        vote_round "$b" || return 1
    done
    return 0
}

# ------------------------------------------------------------------
# Chain observation
# ------------------------------------------------------------------

coinbase_txid() {
    local bh; bh="$(block_hash "$1" "$2")"
    [ ${#bh} -eq 64 ] || return 1
    rpc "$1" getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["tx"][0])
except Exception: pass
'
}

# The producer's claim is vout[0] only; other coinbase outputs pay other
# parties (e.g. finality settlement).
coinbase_value() {
    local cb; cb="$(coinbase_txid "$1" "$2")"
    [ ${#cb} -eq 64 ] || return 1
    rpc "$1" getrawtransaction "$cb" 1 2>/dev/null | python3 -c '
import json, sys
try: print("%.8f" % float(json.load(sys.stdin)["vout"][0]["value"]))
except Exception: pass
'
}

coinbase_version() {
    local cb; cb="$(coinbase_txid "$1" "$2")"
    [ ${#cb} -eq 64 ] || return 1
    rpc "$1" getrawtransaction "$cb" 1 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["version"])
except Exception: pass
'
}

block_tx_count() { jlen "$(block_json "$1" "$2")" tx; }

# ------------------------------------------------------------------
# Pool accounting identity: ConnectBlock moves the pool by (balance - fee) of every IV5
# tx, coinbase included, and nothing else. Both terms are read from serialized bytes.

# INN decimal to whole satoshi, so the comparisons below are exact rather than a
# float tolerance a one-satoshi imbalance would slip through.
to_sat() { python3 -c "import decimal, sys; print(int(decimal.Decimal(sys.argv[1]).scaleb(8)))" "$1" 2>/dev/null; }

IV5_TERMS_READER='
import sys

MARKER = bytes([0xff]) + b"IV5P"
IV5_TX_VERSION = 2008
# The payload prefix is fixed width up to the two value fields: schema(2),
# operation, profile, authorization, mask, finality object, network, reserved,
# genesis(32), parameter digest(32), finalized root(32), tree size(8).
VB_OFFSET = 113
FEE_OFFSET = 121


def compact(b, o):
    v = b[o]
    o += 1
    if v < 253:
        return v, o
    if v == 253:
        return int.from_bytes(b[o:o + 2], "little"), o + 2
    if v == 254:
        return int.from_bytes(b[o:o + 4], "little"), o + 4
    return int.from_bytes(b[o:o + 8], "little"), o + 8


def read_tx(raw):
    b = bytes.fromhex(raw)
    version = int.from_bytes(b[0:4], "little")
    o = 8
    n, o = compact(b, o)
    for _ in range(n):
        o += 36
        length, o = compact(b, o)
        o += length + 4
    vouts, o = compact(b, o)
    for _ in range(vouts):
        o += 8
        length, o = compact(b, o)
        o += length
    o += 4
    if version != IV5_TX_VERSION:
        return None, vouts
    if b[o:o + 5] != MARKER:
        raise ValueError("no IV5 envelope marker at offset %d" % o)
    o += 7
    size, o = compact(b, o)
    payload = b[o:o + size]
    if len(payload) != size:
        raise ValueError("the envelope declares %d payload bytes and carries %d"
                         % (size, len(payload)))
    # A short payload would read past its end and yield zero for both value fields
    # rather than fail, which is the one way this reader could be quietly wrong.
    if size < FEE_OFFSET + 8:
        raise ValueError("a %d-byte payload is shorter than its own value fields" % size)
    return {
        "size": size,
        "operation": payload[2],
        "mask": payload[5],
        "vb": int.from_bytes(payload[VB_OFFSET:VB_OFFSET + 8], "little", signed=True),
        "fee": int.from_bytes(payload[FEE_OFFSET:FEE_OFFSET + 8], "little"),
    }, vouts


total = 0
coinbase_term = 0
iv5_rows = 0
duplicates = 0
fee_rows = 0
note_rows = 0
max_vouts = 0
min_vouts = 0
malformed = 0
seen = set()
detail = []
for line in sys.stdin:
    parts = line.split()
    if len(parts) != 3:
        if line.strip():
            malformed += 1
        continue
    role, txid, raw = parts
    if txid in seen:
        duplicates += 1
        continue
    seen.add(txid)
    try:
        record, vouts = read_tx(raw)
    except Exception as error:
        sys.stdout.write("READER-ERROR %s %s\n" % (txid[:16], error))
        sys.exit(1)
    if role == "coinbase":
        if vouts > max_vouts:
            max_vouts = vouts
        if min_vouts == 0 or vouts < min_vouts:
            min_vouts = vouts
    if record is None:
        continue
    iv5_rows += 1
    delta = record["vb"] - record["fee"]
    total += delta
    if role == "coinbase":
        coinbase_term += delta
        if record["vb"] > 0:
            note_rows += 1
    elif record["fee"] > 0:
        fee_rows += 1
    detail.append("%s op=%d mask=%d size=%d vb=%d fee=%d"
                  % (role, record["operation"], record["mask"], record["size"],
                     record["vb"], record["fee"]))
sys.stdout.write("%d %d %d %d %d %d %d %d %d %d\n"
                 % (total, coinbase_term, total - coinbase_term, iv5_rows,
                    duplicates, fee_rows, note_rows, max_vouts, min_vouts,
                    malformed))
for row in detail:
    sys.stdout.write("# " + row + "\n")
'

# Cross-check the reader: payload length and mask from the bytes must equal the
# node's own parse.
assert_reader_agrees() {
    local label="$1" node="$2" txid="$3" want="$4"
    local raw parsed size mask json rpc_size rpc_mask
    raw="$(rpc "$node" getrawtransaction "$txid" 2>/dev/null | tr -d '"[:space:]')"
    parsed="$(printf "tx %s %s\n" "$txid" "$raw" | python3 -c "$IV5_TERMS_READER" 2>&1 | tail -1)"
    size="$(printf '%s\n' "$parsed" | sed -n 's/.* size=\([0-9]*\) .*/\1/p')"
    mask="$(printf '%s\n' "$parsed" | sed -n 's/.* mask=\([0-9]*\) .*/\1/p')"
    json="$(rpc "$node" getrawtransaction "$txid" 1 2>/dev/null)"
    rpc_size="$(jget2 "$json" privacy_vnext payload_size)"
    rpc_mask="$(jget2 "$json" privacy_vnext disclosure_mask)"
    if [ -z "$size" ] || [ "$size" != "$rpc_size" ] || [ "$mask" != "$rpc_mask" ]; then
        fail "$label: the byte reader reads size='$size' mask='$mask' where the node reports size='$rpc_size' mask='$rpc_mask'"
        return 1
    fi
    if [ "$mask" = "$want" ]; then
        success "$label: the mask byte of the confirmed transaction is $mask, and the reader and the node agree on a $size-byte payload"
        return 0
    fi
    fail "$label: the confirmed transaction's own bytes declare mask $mask, not the $want that was asked for"
    return 1
}

# Every transaction the fleet connected in (h1, h2], as "role txid rawhex" lines.
window_raw_txs() {
    local node="$1" h1="$2" h2="$3" h bh list role txid raw
    for ((h = h1 + 1; h <= h2; h++)); do
        bh="$(block_hash "$node" "$h")"
        [ ${#bh} -eq 64 ] || return 1
        list="$(rpc "$node" getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: txs = json.load(sys.stdin)["tx"]
except Exception: sys.exit(1)
for i, t in enumerate(txs): print(("coinbase" if i == 0 else "tx") + " " + t)
')"
        [ -n "$list" ] || return 1
        while read -r role txid; do
            [ ${#txid} -eq 64 ] || return 1
            raw="$(rpc "$node" getrawtransaction "$txid" 2>/dev/null | tr -d '"[:space:]')"
            [ ${#raw} -ge 20 ] || return 1
            printf "%s %s %s\n" "$role" "$txid" "$raw"
        done <<< "$list"
    done
}

# The window sum and the counts that say whether it measured anything.
WINDOW_TOTAL=0; WINDOW_COINBASE=0; WINDOW_NONCOINBASE=0; WINDOW_IV5=0
WINDOW_DUPS=0; WINDOW_FEEROWS=0; WINDOW_NOTEROWS=0; WINDOW_MAXVOUTS=0
WINDOW_MINVOUTS=0; WINDOW_MALFORMED=0; WINDOW_DETAIL=""
window_pool_terms() {
    local node="$1" h1="$2" h2="$3" out first
    out="$(window_raw_txs "$node" "$h1" "$h2" | python3 -c "$IV5_TERMS_READER" 2>&1)" || {
        WINDOW_DETAIL="$out"
        return 1
    }
    first="$(printf '%s\n' "$out" | head -1)"
    case "$first" in
        READER-ERROR*) WINDOW_DETAIL="$first"; return 1 ;;
    esac
    read -r WINDOW_TOTAL WINDOW_COINBASE WINDOW_NONCOINBASE WINDOW_IV5 \
            WINDOW_DUPS WINDOW_FEEROWS WINDOW_NOTEROWS WINDOW_MAXVOUTS \
            WINDOW_MINVOUTS WINDOW_MALFORMED <<< "$first"
    is_int "${WINDOW_TOTAL:-x}" || { WINDOW_DETAIL="$first"; return 1; }
    WINDOW_DETAIL="$(printf '%s\n' "$out" | tail -n +2 | tr '\n' ';')"
    return 0
}

#   pool(h2) - pool(h1) == sum over connected IV5 payloads of (balance - fee)
# Controls: dropping the fee-note term or shifting the sum by one satoshi must break it.
POOL_WINDOWS_CHECKED=0
assert_pool_conserved_over_window() {
    local label="$1" node="$2" h1="$3" h2="$4" before="$5" after="$6"
    local before_sat after_sat delta
    before_sat="$(to_sat "$before")"; after_sat="$(to_sat "$after")"
    if ! is_int "${before_sat:-x}" || ! is_int "${after_sat:-x}"; then
        fail "$label: the pool balance could not be read as satoshi ($before -> $after)"
        return 1
    fi
    delta=$(( after_sat - before_sat ))
    if ! window_pool_terms "$node" "$h1" "$h2"; then
        fail "$label: the window ($h1, $h2] could not be read: $WINDOW_DETAIL"
        return 1
    fi

    # Positive controls first. Every one of these can be false while the
    # equality below still holds, and each of them makes it worth nothing.
    if [ "$WINDOW_MALFORMED" -ne 0 ]; then
        fail "$label: $WINDOW_MALFORMED row(s) in ($h1, $h2] could not be read as a transaction; the sum is missing a term"
        return 1
    fi
    if [ "$WINDOW_DUPS" -ne 0 ]; then
        fail "$label: $WINDOW_DUPS transaction(s) appear twice in ($h1, $h2]; the sum would double-count a DAG-merged payload"
        return 1
    fi
    if [ "$WINDOW_IV5" -lt 2 ]; then
        fail "$label: the window carries $WINDOW_IV5 IV5 payload(s); it cannot show a fee leaving and returning"
        return 1
    fi
    if [ "$WINDOW_FEEROWS" -lt 1 ] || [ "$WINDOW_NOTEROWS" -lt 1 ]; then
        fail "$label: the window carries $WINDOW_FEEROWS fee-paying payload(s) and $WINDOW_NOTEROWS crediting coinbase note(s); both are needed"
        return 1
    fi
    if [ "$WINDOW_COINBASE" -eq 0 ]; then
        fail "$label: the coinbase notes in the window sum to zero, so dropping them could not be detected"
        return 1
    fi

    if [ "$delta" -eq "$WINDOW_TOTAL" ]; then
        success "$label: the pool moved $delta satoshi over ($h1, $h2] and the payloads it connected declare $WINDOW_TOTAL"
    else
        fail "$label: the pool moved $delta satoshi over ($h1, $h2] against $WINDOW_TOTAL declared (coinbase $WINDOW_COINBASE, rest $WINDOW_NONCOINBASE) [$WINDOW_DETAIL]"
        return 1
    fi

    # Negative controls: drop the coinbase fee-note term; shift the sum by one
    # satoshi. Both must break the equality.
    if [ "$delta" -ne "$WINDOW_NONCOINBASE" ]; then
        success "$label: dropping the coinbase fee-note term breaks the identity ($WINDOW_NONCOINBASE against $delta), so that term is load-bearing"
    else
        fail "THE HARNESS CANNOT FAIL: $label: the identity survives dropping the coinbase fee-note term"
        return 1
    fi
    if [ "$delta" -ne $(( WINDOW_TOTAL + 1 )) ]; then
        success "$label: a one-satoshi imbalance is detected ($(( WINDOW_TOTAL + 1 )) against $delta)"
    else
        fail "THE HARNESS CANNOT FAIL: $label: a one-satoshi imbalance is not detected"
        return 1
    fi

    POOL_WINDOWS_CHECKED=$((POOL_WINDOWS_CHECKED + 1))
    return 0
}

# Tagged coinbase envelopes, one scriptPubKey hex per line. An envelope is
# OP_RETURN <tag || object>; the tag follows the push opcode.
tagged_scripts() {
    local node="$1" h="$2" tag_hex="$3" cb
    cb="$(coinbase_txid "$node" "$h")"
    [ ${#cb} -eq 64 ] || return 1
    rpc "$node" getrawtransaction "$cb" 1 2>/dev/null | \
    TAG="$tag_hex" python3 -c '
import json, os, sys
tag = os.environ["TAG"]
try:
    tx = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for out in tx.get("vout", []):
    h = (out.get("scriptPubKey") or {}).get("hex") or ""
    if h.startswith("6a") and tag in h[:16]:
        print(h)
'
}

# A note vote is an operation-10 transaction in the block, not a coinbase envelope.
notevote_scripts() {
    local node="$1" h="$2" bh
    bh="$(block_hash "$node" "$h")"
    [ ${#bh} -eq 64 ] || return 1
    local txids t
    txids="$(rpc "$node" getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print("\n".join(json.load(sys.stdin).get("tx", [])))
except Exception: pass
')"
    while read -r t; do
        [ ${#t} -eq 64 ] || continue
        rpc "$node" getrawtransaction "$t" 1 2>/dev/null | \
        TXID="$t" OP="$NOTE_VOTE_OPERATION" python3 -c '
import json, os, sys
try: tx = json.load(sys.stdin)
except Exception: sys.exit(0)
if (tx.get("privacy_vnext") or {}).get("operation") == int(os.environ["OP"]):
    print(os.environ["TXID"])
'
    done <<< "$txids"
}
idag_scripts()     { tagged_scripts "$1" "$2" "$IDAG_TAG_HEX"; }

count_lines() {
    local c
    c="$(grep -c . 2>/dev/null || true)"
    is_int "$c" && echo "$c" || echo 0
}

# Every distinct note-vote envelope a node sees in [from, to], and the height of the
# first block carrying each. Prints "height hex" lines.
notevotes_in_range() {
    local node="$1" from="$2" to="$3" h s
    for ((h=from; h<=to; h++)); do
        while read -r s; do
            [ -n "$s" ] && echo "$h $s"
        done < <(notevote_scripts "$node" "$h" 2>/dev/null)
    done
}

votes_in_range() {
    local node="$1" from="$2" to="$3" total=0 h c
    for ((h=from; h<=to; h++)); do
        c="$(jlen "$(block_json "$node" "$h")" finality_votes)"
        is_int "$c" && [ "$c" -gt 0 ] && total=$((total + c))
    done
    echo "$total"
}

# Reorganize() opens with an unconditional printf, so this counts actual block
# disconnections rather than a state a node could also reach by fast-forward.
reorg_count() {
    local c
    c="$(grep -cF "REORGANIZE" "$(node_log "$1")" 2>/dev/null | tr -d '[:space:]')"
    if is_int "$c"; then echo "$c"; else echo 0; fi
}

# Consensus pool balance, identical on every node that connected the same chain.
pool_value()   { jget "$(rpc "$1" z_getshieldedinfo 2>/dev/null)" privacy_vnext_pool_value; }
# Total issued value, the cap's measure. Pool value is included: ConnectBlock
# counts IV5 absorption as a value-out.
money_supply() { jget "$(rpc "$1" getblockchaininfo 2>/dev/null)" moneysupply; }

# The block at HEIGHT is the same block on every node. node0's hash has to be real
# first: three nodes whose getblockhash all failed also return the same value.
assert_converged() {
    local label="$1" h="$2" bh0 n ok=1
    bh0="$(block_hash 0 "$h")"
    [ ${#bh0} -eq 64 ] || ok=0
    for ((n=1; n<NUM_NODES; n++)); do
        [ "$(block_hash "$n" "$h")" = "$bh0" ] || ok=0
    done
    if [ "$ok" -eq 1 ]; then
        success "$label: every peer holds the same block at height $h (${bh0:0:16})"
        return 0
    fi
    fail "$label: the block at height $h did not converge across the fleet"
    for ((n=0; n<NUM_NODES; n++)); do
        echo "  node$n: $(block_hash "$n" "$h")"
    done
    return 1
}

# The height a confirmed transaction landed at, or empty.
tx_height() {
    local node="$1" txid="$2" bh
    bh="$(jget "$(rpc "$node" gettransaction "$txid" 2>&1)" blockhash)"
    [ ${#bh} -eq 64 ] || return 1
    jget "$(rpc "$node" getblock "$bh" 2>/dev/null)" height
}

# ------------------------------------------------------------------
# Spendability predicate: pool value was detected AND given a tree position.
# ------------------------------------------------------------------
POOL_DIAG=""
pool_is_spendable() {
    local node="$1" info bal unconf notes tree
    info="$(rpc "$node" z_getshieldedinfo 2>/dev/null)"
    bal="$(jget "$info" privacy_vnext_balance)"
    unconf="$(jget "$info" privacy_vnext_unconfirmed_balance)"
    notes="$(jget "$info" privacy_vnext_note_count)"
    tree="$(jget "$info" privacy_vnext_tree_size)"
    POOL_DIAG="spendable=${bal:-0} detected_unplaced=${unconf:-0} notes=${notes:-0} tree=${tree:-0}"
    is_int "${notes:-x}" && [ "${notes:-0}" -gt 0 ] || return 1
    is_int "${tree:-x}" && [ "${tree:-0}" -gt 0 ] || return 1
    fgt "${bal:-0}" 0 || return 1
    return 0
}

# ------------------------------------------------------------------
# Note-vote observation from ProducePrivacyVNextNoteVote log lines (gate lines need fDebug).
# ------------------------------------------------------------------
producer_success()  { grep -F "ProducePrivacyVNextNoteVote: epoch=$1 " "$(node_log 0)" 2>/dev/null; }
producer_refused()  { grep -F "no IV5 note vote for epoch $1: the note finality vote was built but could not be committed" "$(node_log 0)" 2>/dev/null; }
producer_dup_tag()  { grep -F "no IV5 note vote for epoch $1: this wallet already has a note finality vote pending" "$(node_log 0)" 2>/dev/null; }
producer_all()      { grep -E "ProducePrivacyVNextNoteVote:|no IV5 note vote for epoch" "$(node_log 0)" 2>/dev/null; }

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

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

# Every switch this harness exists to compose, on every node. hold=1 adds the
# fault injection; it is only ever passed by the negative phase.
write_config() {
    local node="$1" hold="${2:-0}" standalone="${3:-0}" dir peer
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
        # One lane per node: emitting both vote kinds links the tag to the wallet. node0
        # (the only note holder) takes the note lane; the two peers meet FINALITY_MIN_VOTERS.
        if [ "$node" -eq 0 ]; then
            echo "finalityvotemode=note"
        else
            echo "finalityvotemode=transparent"
        fi
        echo "regtestboundaryb=$BOUNDARY_B"
        echo "regtestiv5rehearsal=1"
        echo "regtestiv5notevote=$NOTE_VOTE_HEIGHT"
        echo "regtestiv5feenote=$FEE_NOTE_HEIGHT"
        echo "regtestidnsreset=$IDNS_RESET_HEIGHT"
        echo "regtestsupplycapheight=$SUPPLY_CAP_HEIGHT"
        echo "regtestsupplycap=$SUPPLY_CAP"
        # No committee is configured anywhere: the canonical set is drawn from the
        # IV5 collateral registry and carried by the chain's own epoch state. A node
        # is told only the secret it would serve a seat with.
        [ "$node" -lt "$NUM_NODES" ] && echo "finalitytallyprivkey=${COMMITTEE_PRIVKEYS[$node]}"
        # Every producer gate log is behind fDebug, and -debug deliberately does
        # NOT imply -debugnet, which carries the peer-side receive line.
        echo "debug=1"
        echo "debugnet=1"
        [ "$hold" = "1" ] && echo "regtestiv5holdleafindex=1"
        # Only the stamping node reads paths off its filesystem. The peers verify
        # the same stamp from its digest, which needs no flag at all.
        [ "$node" = "0" ] && echo "enablefilerpc=1"
        if [ "$standalone" != "1" ]; then
            for ((peer=0; peer<NUM_NODES; peer++)); do
                [ "$peer" -eq "$node" ] && continue
                echo "addnode=127.0.0.1:$(node_port "$peer")"
            done
        fi
    } > "$dir/innova.conf"
}

cleanup() {
    local n
    # Teardown talks to nodes that may already be wedged; the run's budget is for
    # the run, not for five stop calls that will not be answered.
    RPC_TIMEOUT=20
    for n in 0 1 2 3 "$NEG_NODE"; do rpc "$n" setgenerate false 0 >/dev/null 2>&1 || true; done
    for n in 0 1 2 3 "$NEG_NODE"; do rpc "$n" stop >/dev/null 2>&1 || true; done
    for n in 0 1 2 3 "$NEG_NODE"; do
        if ! wait_rpc_down "$n"; then
            warn "node$n did not stop; killing it by pid"
            force_kill_node "$n"
        fi
    done
    for n in 0 1 2 3 "$NEG_NODE"; do force_kill_node "$n"; done
    wait_ports_free >/dev/null 2>&1 || warn "regtest ports were still held at exit"
    if [ "${IV5_COMBINED_KEEP_DIR:-${KEEP_DIR:-0}}" = "1" ] || [ "$FAILED" -gt 0 ] || [ -f "$TEST_DIR/rpc_timeouts" ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
    [ "$RESULTS_PRINTED" = "1" ] || print_results
}
trap cleanup EXIT

header "IV5 combined all-features regtest fleet"

[ -x "$INNOVAD" ] || { fail "innovad not found at $INNOVAD"; exit 1; }

BUSY="$(wait_ports_free)" || {
    fail "regtest ports still in use before the run starts:$BUSY"
    fail "a previous run's daemon is still holding them; stop it before retrying"
    exit 1
}

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# ============================================================
header "0. The whole switch set is parsed, and the gates it moves land where intended"
# ============================================================

# -printactivations resolves every gate from argv and exits before the datadir
# lock; all eight switches at once also catches mutually exclusive init.
LADDER="$(
    "$INNOVAD" -datadir="$TEST_DIR" -regtest \
        -regtestboundaryb="$BOUNDARY_B" -regtestiv5rehearsal \
        -regtestiv5notevote="$NOTE_VOTE_HEIGHT" \
        -regtestiv5feenote="$FEE_NOTE_HEIGHT" \
        -regtestidnsreset="$IDNS_RESET_HEIGHT" \
        -regtestsupplycapheight="$SUPPLY_CAP_HEIGHT" \
        -regtestsupplycap="$SUPPLY_CAP" \
        -printactivations 2>&1
)"

gate_height() {
    NAME="$1" python3 -c '
import json, os, sys
name = os.environ["NAME"]
raw = sys.stdin.read()
i = raw.find("{")
try:
    doc = json.loads(raw[i:]) if i >= 0 else {}
except Exception:
    sys.exit(0)
for g in doc.get("gates", []):
    if g.get("name") == name:
        v = g.get("height", g.get("value"))
        if isinstance(v, bool): print(str(v).lower())
        elif v is None: print("")
        else: print(v)
        break
' <<< "$LADDER" 2>/dev/null
}

LADDER_OK=1
LADDER_WHY=""
check_gate() {
    [ "$(gate_height "$1")" = "$2" ] || { LADDER_OK=0; LADDER_WHY="$LADDER_WHY $1=$(gate_height "$1") (expected $2);"; }
}
check_gate FORK_HEIGHT_DAG 11
check_gate FORK_HEIGHT_DAGKNIGHT 13
check_gate FORK_HEIGHT_BOUNDARY_A "$BOUNDARY_B"
check_gate FORK_HEIGHT_BOUNDARY_B "$BOUNDARY_B"
check_gate FORK_HEIGHT_IV5_FEE_NOTE "$FEE_NOTE_HEIGHT"
check_gate FORK_HEIGHT_IV5_NOTE_VOTE "$NOTE_VOTE_HEIGHT"
check_gate FORK_HEIGHT_IDNS_RESET "$IDNS_RESET_HEIGHT"
check_gate FORK_HEIGHT_SUPPLY_CAP "$SUPPLY_CAP_HEIGHT"
check_gate IsShieldedVNextConsensusReady true
check_gate IsBoundaryBConfigured true
check_gate IsIV5FeeNoteConfigured true
check_gate IsIV5NoteVoteConfigured true
check_gate IsPrivacyVNextLeafIndexAssignmentHeld false
check_gate GetSupplyCapAmount "$SUPPLY_CAP"
if [ "$LADDER_OK" -eq 1 ]; then
    success "all eight switches parse together and place their gates: DAG 11, DAGKnight 13, Boundary A/B $BOUNDARY_B, fee note $FEE_NOTE_HEIGHT, note vote $NOTE_VOTE_HEIGHT, IDNS reset $IDNS_RESET_HEIGHT, supply cap $SUPPLY_CAP_HEIGHT at $SUPPLY_CAP_INN INN"
else
    fail "the compiled activation ladder is not what the switches asked for:$LADDER_WHY"
    echo "$LADDER" | head -30
    exit 1
fi

# The two init refusals that bound the ladder. Both prove the flag is parsed as
# well as enforced, and both are cheap: a refusal exits immediately.
PREFLIGHT_TIMEOUT=""
command -v timeout >/dev/null 2>&1 && PREFLIGHT_TIMEOUT="timeout 120"
preflight_refusal() {
    local label="$1" want="$2"; shift 2
    local dir out
    dir="$TEST_DIR/preflight"
    rm -rf "$dir"; mkdir -p "$dir"
    out="$(
        $PREFLIGHT_TIMEOUT "$INNOVAD" -datadir="$dir" -regtest -listen=0 \
            -dnsseed=0 -nobootstrap=1 -nosmsg=1 -rpcuser=x -rpcpassword=y \
            -rpcport=$((BASE_RPC + 90)) -port=$((BASE_PORT + 90)) \
            -regtestboundaryb="$BOUNDARY_B" "$@" 2>&1 | head -20
    )"
    rm -rf "$dir"
    if echo "$out" | grep -qi "$want"; then
        success "$label"
    else
        fail "$label -- init did not refuse: $(echo "$out" | head -3)"
    fi
}
preflight_refusal "a note-vote fork below Boundary B is refused at startup" \
    "below the Boundary-B height" -regtestiv5notevote=$((BOUNDARY_B - 1))
preflight_refusal "a fee-note fork below Boundary B is refused at startup" \
    "below the Boundary-B height" -regtestiv5feenote=$((BOUNDARY_B - 1))
preflight_refusal "a supply cap above MAX_MONEY is refused at startup" \
    "at most MAX_MONEY" -regtestsupplycap=1800000000000001

# ============================================================
header "N. NEGATIVE PHASE: the spendability predicate must be able to fail"
# ============================================================

# Same switch set, plus -regtestiv5holdleafindex, which holds wallet leaf-index
# assignment and so leaves every received note without the tree position that makes
# it provable. The pool is funded exactly as the positive path funds it and the tip
# is carried a full epoch past the shield, so nothing but the hold can keep the
# value unspendable. pool_is_spendable is then called -- the same function, not a
# copy -- and must report a failure.

write_config "$NEG_NODE" 1 1
start_node "$NEG_NODE" || { fail "the negative-phase node did not start"; exit 1; }

if grep -qF "IV5 leaf-index assignment held" "$(node_log "$NEG_NODE")" 2>/dev/null; then
    success "the fault-injection node reports the leaf-index hold in force"
else
    fail "the negative-phase node did not report -regtestiv5holdleafindex; the phase would prove nothing"
    exit 1
fi

NEG_MINE() {
    local target="$1" h last stall=0
    h="$(height "$NEG_NODE")"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$NEG_NODE" setgenerate true $((target - h)) 1 >/dev/null 2>&1
    for ((i=0; i<3000; i++)); do
        h="$(height "$NEG_NODE")"
        if is_int "$h" && [ "$h" -ge "$target" ]; then
            rpc "$NEG_NODE" setgenerate false 0 >/dev/null 2>&1
            return 0
        fi
        if [ "$h" = "$last" ]; then
            stall=$((stall + 1))
        else
            stall=0; last="$h"
            [ $((h % 200)) -eq 0 ] && log "  ...negative phase height $h/$target"
        fi
        if [ "$stall" -ge 20 ]; then
            rpc "$NEG_NODE" setgenerate true $((target - h)) 1 >/dev/null 2>&1
            stall=0
        fi
        sleep 1
    done
    rpc "$NEG_NODE" setgenerate false 0 >/dev/null 2>&1
    return 1
}

NEG_MINE "$NEG_SEED_HEIGHT" || { fail "the negative phase could not mine to $NEG_SEED_HEIGHT"; exit 1; }
rpc "$NEG_NODE" encryptwallet "$WALLETPASS" >/dev/null 2>&1
wait_rpc_down "$NEG_NODE" || { fail "the negative-phase node did not stop after encrypting"; exit 1; }
start_node "$NEG_NODE" || { fail "the negative-phase node did not restart"; exit 1; }
rpc "$NEG_NODE" walletpassphrase "$WALLETPASS" 1000000 >/dev/null 2>&1
NEG_SEED="$(rpc "$NEG_NODE" z_createiv5seed 2>&1)"
if echo "$NEG_SEED" | grep -q '"created"'; then
    success "the fault-injection node holds an IV5 seed"
else
    fail "z_createiv5seed failed on the negative-phase node: $(echo "$NEG_SEED" | head -2)"
    exit 1
fi

NEG_MINE "$NEG_SHIELD_HEIGHT" || { fail "the negative phase could not mine to the shield height"; exit 1; }
NEG_SHIELDED=0
for _ in 1 2 3; do
    NEG_SH="$(rpc "$NEG_NODE" z_shieldall 2>&1)"
    NEG_TXID="$(jget "$NEG_SH" txid)"
    [ ${#NEG_TXID} -eq 64 ] || break
    NEG_SHIELDED="$(fadd "$NEG_SHIELDED" "$(jget "$NEG_SH" shielded)")"
    NEG_MINE $(( $(height "$NEG_NODE") + 2 )) || break
done
if fgt "$NEG_SHIELDED" 0; then
    success "the fault-injection node put $NEG_SHIELDED INN into the pool"
else
    fail "nothing was shielded on the negative-phase node; there is nothing to strand"
    exit 1
fi
NEG_MINE "$NEG_END_HEIGHT" || { fail "the negative phase could not carry the tip past the shield epoch"; exit 1; }

# Precondition: the value must be DETECTED; the hold affects only assignment.
NEG_INFO="$(rpc "$NEG_NODE" z_getshieldedinfo 2>/dev/null)"
NEG_NOTES="$(jget "$NEG_INFO" privacy_vnext_note_count)"
NEG_UNCONF="$(jget "$NEG_INFO" privacy_vnext_unconfirmed_balance)"
if is_int "${NEG_NOTES:-x}" && [ "${NEG_NOTES:-0}" -ge 1 ] && feq "${NEG_UNCONF:-0}" "$NEG_SHIELDED"; then
    success "all $NEG_UNCONF INN was detected across $NEG_NOTES note(s) and none of it was placed"
else
    fail "the hold did not produce the stranded state (notes=$NEG_NOTES detected=$NEG_UNCONF expected $NEG_SHIELDED)"
    exit 1
fi

# THE MUTATION. The predicate the positive path asserts with, run against a chain
# whose notes are provably unspendable.
if pool_is_spendable "$NEG_NODE"; then
    fail "THE HARNESS CANNOT FAIL: pool_is_spendable reported a spendable pool on a chain built with the leaf-index hold ($POOL_DIAG)"
    fail "  every later use of that predicate in this run is worthless; fix the predicate before trusting the positive result"
    exit 1
else
    success "the spendability predicate reports the injected fault rather than passing through it ($POOL_DIAG)"
fi

stop_node "$NEG_NODE" || warn "the negative-phase node needed a kill"
rm -rf "$(node_dir "$NEG_NODE")"

# ============================================================
header "1. Fleet up with every switch live"
# ============================================================

for ((n=0; n<NUM_NODES; n++)); do write_config "$n"; done
for ((n=0; n<NUM_NODES; n++)); do
    start_node "$n" || { fail "node$n did not start"; exit 1; }
done
wait_peers || { fail "fleet did not mesh"; exit 1; }
success "$NUM_NODES-node fleet up and meshed"

# Each switch, read back from the node that parsed it rather than from the config
# this harness wrote. A config file is not evidence about a daemon.
SWITCH_OK=1
SWITCH_WHY=""
want_log() {
    local n="$1" what="$2" line="$3"
    grep -qF "$line" "$(node_log "$n")" 2>/dev/null || \
        { SWITCH_OK=0; SWITCH_WHY="$SWITCH_WHY node$n: no $what;"; }
}
for ((n=0; n<NUM_NODES; n++)); do
    want_log "$n" "Boundary-B rehearsal" "Boundary-B rehearsal: height=$BOUNDARY_B ready=1"
    want_log "$n" "note-vote fork"       "IV5 note-vote fork height: $NOTE_VOTE_HEIGHT (regtest only)"
    want_log "$n" "fee-note fork"        "IV5 fee-note/unshield-retirement fork height: $FEE_NOTE_HEIGHT (regtest only)"
    want_log "$n" "IDNS reset"           "IDNS reset rehearsal: height=$IDNS_RESET_HEIGHT (regtest only)"
    want_log "$n" "supply cap"           "Supply-cap rehearsal: height=$SUPPLY_CAP_HEIGHT cap=$SUPPLY_CAP"
    # The fault injection must be OFF here, or every positive result below is one
    # the negative phase just proved is unreadable.
    if grep -qF "IV5 leaf-index assignment held" "$(node_log "$n")" 2>/dev/null; then
        SWITCH_OK=0; SWITCH_WHY="$SWITCH_WHY node$n: the leaf-index hold is IN FORCE;"
    fi
done
if [ "$SWITCH_OK" -eq 1 ]; then
    success "every node reports all five height switches and none holds leaf-index assignment"
else
    fail "a node did not report the switch set:$SWITCH_WHY"
    exit 1
fi

# The pinned-committee path is not gone from the daemon, but it is unused here:
# no node is given those inputs and every node reports back that it holds none.
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
    [ "$(jget "$FI" tally_committee_valid)" = "false" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n reports a valid CONFIGURED committee"; }
    is_zero_hex "$(jget "$FI" tally_committee_set_hash)" || \
        { CONFIG_OK=0; CONFIG_WHY="node$n has a non-zero CONFIGURED committee set hash"; }
    [ "$(jget "$FI" tally_privkey_valid)" = "true" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n did not load its member secret"; }
done
if [ "$PINNED" -eq 0 ] && [ "$CONFIG_OK" -eq 1 ]; then
    success "no committee is pinned: every node holds only its own member secret"
else
    fail "the pinned-committee path is in play (config files carry it: $PINNED; $CONFIG_WHY)"
    exit 1
fi

# The term this run schedules has to be a term the chain recognises. A term epoch
# off the grid is carried and then never resolved, and the seating stage is
# thousands of blocks away, so it is checked here rather than found there.
NODE_TERM_LEN="$(jget "$(rpc 0 getfinalityinfo 2>/dev/null)" committee_term_epochs)"
if [ "$NODE_TERM_LEN" = "$COMMITTEE_TERM_EPOCHS" ] && \
   [ $(( COMMITTEE_TERM_EPOCH % COMMITTEE_TERM_EPOCHS )) -eq 0 ] && \
   [ $(( PRE_TERM_EPOCH % COMMITTEE_TERM_EPOCHS )) -eq 0 ] && \
   [ "$PRE_TERM_ANCHOR_HEIGHT" -le "$REGISTER_HEIGHT" ]; then
    success "term $COMMITTEE_TERM_EPOCH is on the chain's $NODE_TERM_LEN-epoch grid (anchor $COMMITTEE_ANCHOR_EPOCH at $COMMITTEE_ANCHOR_HEIGHT, carrier $COMMITTEE_CARRIER_EPOCH, seated at $COMMITTEE_SEATED_HEIGHT); the previous term $PRE_TERM_EPOCH anchors at $PRE_TERM_ANCHOR_HEIGHT"
else
    fail "the committee schedule is off the grid: term $COMMITTEE_TERM_EPOCH / previous $PRE_TERM_EPOCH against a chain term length of $NODE_TERM_LEN, previous anchor $PRE_TERM_ANCHOR_HEIGHT vs registration height $REGISTER_HEIGHT"
    exit 1
fi

# ============================================================
header "2. node0 holds an IV5 seed and a collateralnode key"
# ============================================================

# genkey before encrypting, so the collateralnodeprivkey can be written into the
# config during the restart the encryption forces and the node comes back with it.
CNKEY="$(rpc 0 collateralnode genkey 2>/dev/null | tr -d '"[:space:]')"
if [ ${#CNKEY} -ge 40 ]; then
    success "node0 generated a collateralnodeprivkey"
else
    fail "collateralnode genkey failed: $CNKEY"
    exit 1
fi

rpc 0 encryptwallet "$WALLETPASS" >/dev/null 2>&1
wait_rpc_down 0 || { fail "node0 did not stop after encrypting the wallet"; exit 1; }
printf 'collateralnodeprivkey=%s\n' "$CNKEY" >> "$(node_dir 0)/innova.conf"
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

# Negative control: peers hold no stake at the epoch-1 boundary and node0 is in
# the anonymous lane, so epoch 1 has no transparent vote.
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
header "4. IDAG ordering and DAGKnight are running, not merely configured"
# ============================================================

vote_round "$BOUNDARY_B" || { fail "epoch 2 vote round failed"; exit 1; }
E2_VOTES="$(votes_in_range 0 "$BOUNDARY_B" $((BOUNDARY_B + 4)))"
if is_int "$E2_VOTES" && [ "$E2_VOTES" -ge 2 ]; then
    success "epoch 2 carried $E2_VOTES relayed finality votes"
else
    fail "epoch 2 carried $E2_VOTES finality votes, need >= 2"
    for ((n=1; n<NUM_NODES; n++)); do
        grep -h "AddVote: rejected finality vote" "$(node_dir "$n")/regtest/debug.log" 2>/dev/null |
            sort | uniq -c | sed "s/^/    node$n: /"
    done
fi

DAG_OK=1
DAG_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    DI="$(rpc "$n" getdaginfo 2>/dev/null)"
    [ "$(jget "$DI" dag_active)" = "true" ]        || { DAG_OK=0; DAG_WHY="node$n dag_active=$(jget "$DI" dag_active)"; }
    [ "$(jget "$DI" dagknight_active)" = "true" ]  || { DAG_OK=0; DAG_WHY="node$n dagknight_active=$(jget "$DI" dagknight_active)"; }
    [ "$(jget "$DI" boundary_a_active)" = "true" ] || { DAG_OK=0; DAG_WHY="node$n boundary_a_active=$(jget "$DI" boundary_a_active)"; }
    [ "$(jget "$DI" parent_commitment_strict_active)" = "true" ] || \
        { DAG_OK=0; DAG_WHY="node$n does not enforce the strict parent commitment"; }
    [ "$(jget "$DI" pos_block_production)" = "false" ] || \
        { DAG_OK=0; DAG_WHY="node$n still allows proof-of-stake block production"; }
    ORDER="$(jget "$DI" ordering_algorithm)"
    CONTRACT="$(jget "$DI" dagknight_contract)"
    [ -n "$ORDER" ] && [ "$ORDER" = "$CONTRACT" ] || \
        { DAG_OK=0; DAG_WHY="node$n orders by '$ORDER', not the DAGKnight contract '$CONTRACT'"; }
    E="$(jget "$DI" dag_entries)"
    is_int "${E:-x}" && [ "${E:-0}" -gt 0 ] || { DAG_OK=0; DAG_WHY="node$n holds $E DAG entries"; }
done
if [ "$DAG_OK" -eq 1 ]; then
    DI0="$(rpc 0 getdaginfo 2>/dev/null)"
    success "every node runs the DAG with DAGKnight ordering ($(jget "$DI0" ordering_algorithm)), $(jget "$DI0" dag_entries) DAG entries, proof-of-stake production closed"
else
    fail "the DAG is not actually running: $DAG_WHY"
    exit 1
fi

# The ordering layer on the wire, not in an RPC's opinion of itself: every block
# the fleet accepts carries exactly one IDAG parent commitment in its coinbase.
IDAG_H="$(height 0)"
IDAG_CARRIED=0
IDAG_BAD=""
for ((h=IDAG_H-4; h<=IDAG_H; h++)); do
    C="$(idag_scripts 0 "$h" | count_lines)"
    if [ "$C" = "1" ]; then
        IDAG_CARRIED=$((IDAG_CARRIED + 1))
    else
        IDAG_BAD="$IDAG_BAD height $h carries $C;"
    fi
done
if [ "$IDAG_CARRIED" -eq 5 ]; then
    success "the last 5 blocks each carry exactly one IDAG parent commitment (tag $IDAG_TAG_HEX)"
else
    fail "the IDAG parent commitment is not on every block:$IDAG_BAD"
fi

# ============================================================
header "5. Value enters the FCMP++ pool and is genuinely spendable"
# ============================================================

INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
B_ACTIVE="$(jget "$INFO" boundary_b_active)"
B_ACCEPT="$(jget "$INFO" privacy_vnext_transactions_accepted)"
B_LINKED="$(jget "$INFO" privacy_vnext_abi_linked)"
if [ "$B_ACTIVE" = "true" ] && [ "$B_ACCEPT" = "true" ] && [ "$B_LINKED" = "true" ]; then
    success "Boundary B is active, the FCMP++ ABI is linked and consensus accepts IV5 transactions"
else
    fail "IV5 inactive (boundary_b_active=$B_ACTIVE accepted=$B_ACCEPT abi_linked=$B_LINKED)"
    exit 1
fi

# The verifier is linked on every network: privacy_vnext_consensus_ready must
# be true with a non-empty consensus set.
B_READY="$(jget "$INFO" privacy_vnext_consensus_ready)"
B_CAPS="$(jget "$INFO" privacy_vnext_consensus_capabilities)"
if [ "$B_READY" = "true" ] && is_int "$B_CAPS" && [ "$B_CAPS" -ne 0 ]; then
    success "the build reports the linked verifier's consensus set (consensus_ready=$B_READY, consensus_capabilities=$B_CAPS)"
else
    fail "privacy_vnext_consensus_ready is '$B_READY' with consensus_capabilities '$B_CAPS'; the linked verifier is not reporting its consensus set"
fi

mine_to 0 "$SHIELD_HEIGHT" || { fail "could not mine to the shield height"; exit 1; }
wait_sync "$SHIELD_HEIGHT" || { fail "peers did not sync to the shield height"; exit 1; }

# A vote needs ONE note >= GetFinalityMinVoteWeight (500 INN), so sweep several
# addresses, each confirmed before the next (a shield names the tree it saw).
SHIELDS=0
FIRST_SHIELD_TXID=""
for ((s=0; s<SHIELD_SWEEPS; s++)); do
    SH="$(rpc 0 z_shieldall 2>&1)"
    SH_TXID="$(jget "$SH" txid)"
    [ ${#SH_TXID} -eq 64 ] || break
    [ -z "$FIRST_SHIELD_TXID" ] && FIRST_SHIELD_TXID="$SH_TXID"
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

SHIELD_BLOCK_H="$(tx_height 0 "$FIRST_SHIELD_TXID")"
if is_int "${SHIELD_BLOCK_H:-x}"; then
    assert_converged "the shield" "$SHIELD_BLOCK_H"
else
    fail "the first shield did not confirm to a readable height"
fi

mine_to 0 "$SHIELD_CONFIRM_HEIGHT" || { fail "could not confirm the shields"; exit 1; }
wait_sync "$SHIELD_CONFIRM_HEIGHT" || { fail "peers did not accept the shield blocks"; exit 1; }

# ============================================================
header "6. The IV5 fee note: the pool's fees stop crossing the boundary"
# ============================================================

# Pre-fork the coinbase allowance (subsidy + nFees) pays pool fees
# transparently; post-fork it drops them and the coinbase carries one pool note
# of that sum instead.

# Nothing may be in flight: a pending transaction lands in whichever block comes
# next and breaks whichever comparison that block was serving.
mine_to 0 $(( FEE_NOTE_HEIGHT - 12 )) || { fail "could not mine towards the fee-note fork"; exit 1; }
for _ in $(seq 1 8); do
    MEMPOOL="$(rpc 0 getrawmempool 2>/dev/null | tr -d '[:space:]')"
    [ "$MEMPOOL" = "[]" ] && break
    mine_to 0 $(( $(height 0) + 1 )) || break
done
wait_sync "$(height 0)" || { fail "the fleet did not follow the drain"; exit 1; }

FN_INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
if [ "$(jget "$FN_INFO" privacy_vnext_fee_note_height)" = "$FEE_NOTE_HEIGHT" ] && \
   [ "$(jget "$FN_INFO" privacy_vnext_fee_note_active)" = "false" ]; then
    success "the fee-note fork reports height $FEE_NOTE_HEIGHT and inactive at $(height 0)"
else
    fail "fee-note fork state is wrong before the fork (height=$(jget "$FN_INFO" privacy_vnext_fee_note_height) active=$(jget "$FN_INFO" privacy_vnext_fee_note_active))"
fi

# The baseline. A block with no transactions at all, so the comparison below is
# exact.
PLAIN_H=$(( $(height 0) + 1 ))
mine_to 0 "$PLAIN_H" || { fail "could not mine the baseline block"; exit 1; }
for _ in $(seq 1 6); do
    [ "$(block_tx_count 0 "$PLAIN_H")" = "1" ] && break
    PLAIN_H=$(( PLAIN_H + 1 ))
    mine_to 0 "$PLAIN_H" || { fail "could not mine the baseline block"; exit 1; }
done
if [ "$(block_tx_count 0 "$PLAIN_H")" != "1" ]; then
    fail "no transaction-free block was available for the baseline"
    exit 1
fi
PLAIN_CB="$(coinbase_value 0 "$PLAIN_H")"
[ -n "$PLAIN_CB" ] || { fail "could not read the baseline coinbase"; exit 1; }
success "a block with no transactions pays $PLAIN_CB transparently (height $PLAIN_H)"

# Pre-fork: the shield's fee is the miner's, transparently.
POOL_PRE="$(pool_value 0)"
SH="$(rpc 0 z_shieldall 2>&1)"
SH_TXID="$(jget "$SH" txid)"
if [ ${#SH_TXID} -ne 64 ]; then
    fail "could not build a pre-fork shield: $(echo "$SH" | head -3)"
    exit 1
fi
PRE_H=$(( PLAIN_H + 1 ))
mine_to 0 "$PRE_H" || { fail "could not mine the pre-fork shield"; exit 1; }
wait_sync "$PRE_H" || { fail "peers did not accept the pre-fork shield block"; exit 1; }
if [ "$(block_tx_count 0 "$PRE_H")" = "2" ]; then
    PRE_CB="$(coinbase_value 0 "$PRE_H")"
    PRE_EXCESS="$(fsub "$PRE_CB" "$PLAIN_CB")"
    if feq "$PRE_EXCESS" "$SHIELD_FEE"; then
        success "pre-fork the coinbase is $PRE_CB, exactly $SHIELD_FEE above a plain block: the IV5 fee is claimed transparently"
    else
        fail "pre-fork coinbase excess is $PRE_EXCESS, expected $SHIELD_FEE ($PRE_CB against $PLAIN_CB)"
    fi
    if [ "$(coinbase_version 0 "$PRE_H")" = "1" ]; then
        success "the pre-fork coinbase carries no IV5 payload"
    else
        fail "the pre-fork coinbase is version $(coinbase_version 0 "$PRE_H")"
    fi
else
    fail "the pre-fork block carries $(block_tx_count 0 "$PRE_H") transactions; the coinbase comparison would not be exact"
fi

# The fork block itself. Drive the tip to one below it before building, so the
# shield is selected into the activation block and not into some block on the way.
mine_to 0 $(( FEE_NOTE_HEIGHT - 1 )) || { fail "could not mine to the fork block"; exit 1; }
wait_sync $(( FEE_NOTE_HEIGHT - 1 )) || { fail "peers did not follow to the fork"; exit 1; }
POOL_PRE_FORK="$(pool_value 0)"
SH2="$(rpc 0 z_shieldall 2>&1)"
SH2_TXID="$(jget "$SH2" txid)"
SH2_VALUE="$(jget "$SH2" shielded)"
if [ ${#SH2_TXID} -ne 64 ]; then
    fail "could not build a shield for the fork block: $(echo "$SH2" | head -3)"
    exit 1
fi
mine_to 0 "$FEE_NOTE_HEIGHT" || { fail "could not mine the fork block"; exit 1; }
wait_sync "$FEE_NOTE_HEIGHT" || { fail "peers did not accept the fork block"; exit 1; }

FORK_TXS="$(block_tx_count 0 "$FEE_NOTE_HEIGHT")"
FORK_CB="$(coinbase_value 0 "$FEE_NOTE_HEIGHT")"
FORK_VER="$(coinbase_version 0 "$FEE_NOTE_HEIGHT")"
if [ "$FORK_VER" = "2008" ]; then
    success "the fork coinbase carries an IV5 payload (version $FORK_VER)"
else
    fail "the fork coinbase is version $FORK_VER, expected 2008"
fi
if [ "$FORK_TXS" = "2" ]; then
    # A fee-note block must claim a plain block's value; PLAIN_CB + SHIELD_FEE
    # means the fee was paid twice.
    if feq "$FORK_CB" "$PLAIN_CB"; then
        success "the fork coinbase pays $FORK_CB transparently, the same as a plain block: the IV5 fee is not claimed as well as noted"
    elif fgt "$FORK_CB" "$PLAIN_CB"; then
        fail "the fork coinbase pays $FORK_CB against $PLAIN_CB for a plain block; the IV5 fee was claimed transparently AND noted"
    else
        fail "the fork coinbase pays $FORK_CB, below the $PLAIN_CB baseline"
    fi
else
    fail "the fork block carries $FORK_TXS transactions; the coinbase comparison would not be exact"
fi
assert_converged "the fee-note fork block" "$FEE_NOTE_HEIGHT"

# The shield takes (value - fee) into the pool and the note takes the fee, so the
# pool rises by the whole shielded value and the fee is not destroyed.
POOL_FORK="$(pool_value 0)"
if [ -n "$POOL_PRE_FORK" ] && [ -n "$POOL_FORK" ] && [ -n "$SH2_VALUE" ]; then
    POOL_RISE="$(fsub "$POOL_FORK" "$POOL_PRE_FORK")"
    EXPECTED_RISE="$(fadd "$SH2_VALUE" "$SHIELD_FEE")"
    if feq "$POOL_RISE" "$EXPECTED_RISE"; then
        success "the pool rose by $POOL_RISE: the shielded value plus the fee the note collected"
    else
        fail "the pool rose by $POOL_RISE, expected $EXPECTED_RISE (before $POOL_PRE_FORK, after $POOL_FORK)"
    fi
else
    fail "could not read the pool balance across the fork block"
fi

# The pool balance is consensus state, so it is the same number on a node that
# built none of this.
POOL_AGREE=1
for ((n=1; n<NUM_NODES; n++)); do
    feq "$(pool_value "$n")" "$POOL_FORK" || POOL_AGREE=0
done
if [ "$POOL_AGREE" -eq 1 ]; then
    success "every node computes the same pool balance ($POOL_FORK INN) from the same chain"
else
    fail "the nodes disagree about the pool balance: node0=$POOL_FORK node1=$(pool_value 1) node2=$(pool_value 2)"
fi

# A post-fork block with no IV5 fees must carry no note and claim no more.
EMPTY_H=$(( FEE_NOTE_HEIGHT + 1 ))
mine_to 0 "$EMPTY_H" || { fail "could not mine an empty post-fork block"; exit 1; }
if [ "$(coinbase_version 0 "$EMPTY_H")" = "1" ] && feq "$(coinbase_value 0 "$EMPTY_H")" "$PLAIN_CB"; then
    success "a post-fork block with no IV5 fees carries no payload and claims $PLAIN_CB, unchanged"
else
    fail "a post-fork block with no IV5 fees is version $(coinbase_version 0 "$EMPTY_H") claiming $(coinbase_value 0 "$EMPTY_H") against $PLAIN_CB"
fi

# The retirement half of the same fork.
T_ADDR="$(rpc 0 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
UNSHIELD="$(rpc 0 z_iv5unshield "$T_ADDR" 1 2>&1)"
if echo "$UNSHIELD" | grep -qi "retired"; then
    success "the wallet refuses to build an unshield after the fork"
else
    fail "z_iv5unshield did not report retirement: $(echo "$UNSHIELD" | head -3)"
fi

# ============================================================
header "7. The IDNS reset is in force, and a name still registers over it"
# ============================================================

vote_round 611 || { fail "epoch 3 vote round failed"; exit 1; }

# Below the reset the wallet must refuse the fee, proving -regtestidnsreset
# reached the name code.
mine_to 0 $(( IDNS_RESET_HEIGHT - 60 )) || { fail "could not mine below the IDNS reset"; exit 1; }
wait_sync $(( IDNS_RESET_HEIGHT - 60 )) || { fail "peers did not follow below the reset"; exit 1; }
EARLY="$(rpc 0 name_new "$IDNS_NAME" "$IDNS_VALUE" "$IDNS_DAYS" 2>&1)"
if echo "$EARLY" | grep -qi "IDNS reset at height $IDNS_RESET_HEIGHT"; then
    success "below the reset the wallet refuses a name whose term the reset would wipe"
else
    fail "name_new below the reset did not report the wipe: $(echo "$EARLY" | head -3)"
fi

mine_to 0 $(( IDNS_RESET_HEIGHT + 10 )) || { fail "could not mine past the IDNS reset"; exit 1; }
wait_sync $(( IDNS_RESET_HEIGHT + 10 )) || { fail "peers did not follow past the reset"; exit 1; }
NAME_TXID="$(rpc 0 name_new "$IDNS_NAME" "$IDNS_VALUE" "$IDNS_DAYS" 2>&1 | tr -d '"[:space:]')"
if [ ${#NAME_TXID} -eq 64 ]; then
    success "above the reset name_new is accepted (txid ${NAME_TXID:0:16})"
else
    fail "name_new above the reset failed: $(echo "$NAME_TXID" | head -3)"
fi
if [ ${#NAME_TXID} -eq 64 ]; then
    confirm_on 3 || { fail "could not confirm the name registration"; }
    NAME_H="$(tx_height 0 "$NAME_TXID")"
    if is_int "${NAME_H:-x}"; then
        assert_converged "the IDNS registration" "$NAME_H"
    else
        fail "the name registration did not confirm to a readable height"
    fi
    # Resolution on a node that did not build it: the name index is rebuilt by
    # every node's own ConnectBlock, so this is the fleet-wide half of IDNS.
    RESOLVE_OK=1
    for ((n=0; n<NUM_NODES; n++)); do
        SHOWN="$(rpc "$n" name_show "$IDNS_NAME" 2>&1)"
        echo "$SHOWN" | grep -qF "$IDNS_VALUE" || RESOLVE_OK=0
    done
    if [ "$RESOLVE_OK" -eq 1 ]; then
        success "every node resolves $IDNS_NAME to $IDNS_VALUE"
    else
        fail "a node could not resolve the registered name: $(rpc 1 name_show "$IDNS_NAME" 2>&1 | head -3)"
    fi
fi

# ============================================================
header "8. A proof-of-data stamp on the same chain"
# ============================================================

POD_FILE="$TEST_DIR/pod-data.bin"
python3 -c "open('$POD_FILE','wb').write(b'innova combined fleet proof-of-data payload\n' * 64)" 2>/dev/null
POD_SHA="$(python3 -c "
import hashlib
print(hashlib.sha256(open('$POD_FILE','rb').read()).hexdigest())
" 2>/dev/null)"
if [ ${#POD_SHA} -eq 64 ]; then
    success "a local file was prepared for stamping (sha256 ${POD_SHA:0:16})"
else
    fail "could not prepare the proof-of-data file"
fi

POD="$(rpc 0 proofofdata "$POD_FILE" false 2>&1)"
POD_TXID="$(jget "$POD" podtxid)"
POD_DIGEST="$(jget "$POD" filesha256)"
if [ ${#POD_TXID} -eq 64 ] && [ "$POD_DIGEST" = "$POD_SHA" ]; then
    success "proofofdata anchored the file's own sha256 (txid ${POD_TXID:0:16})"
else
    fail "proofofdata failed or stamped the wrong digest: $(echo "$POD" | head -4)"
fi
if [ ${#POD_TXID} -eq 64 ]; then
    confirm_on 3 || fail "could not confirm the proof-of-data stamp"
    POD_H="$(tx_height 0 "$POD_TXID")"
    if is_int "${POD_H:-x}"; then
        assert_converged "the proof-of-data stamp" "$POD_H"
    else
        fail "the proof-of-data stamp did not confirm to a readable height"
    fi
    # A peer holds neither the file nor -enablefilerpc, and verifies the stamp from
    # the digest alone. That is the whole point of the digest form.
    POD_PEER="$(rpc 1 podverify "$POD_SHA" "$POD_TXID" 2>&1)"
    if [ "$(jget "$POD_PEER" match)" = "true" ]; then
        success "a peer with no file access verifies the stamp from its digest at height $(jget "$POD_PEER" height)"
    else
        fail "the peer could not verify the stamp: $(echo "$POD_PEER" | head -4)"
    fi
    POD_WRONG="$(rpc 1 podverify "0000000000000000000000000000000000000000000000000000000000000001" "$POD_TXID" 2>&1)"
    if [ "$(jget "$POD_WRONG" match)" = "true" ]; then
        fail "podverify accepted a digest the stamp does not carry"
    else
        success "podverify refuses a digest the stamp does not carry"
    fi
fi

# ============================================================
header "9. Three consecutive HARD epochs produce a finalized height"
# ============================================================

vote_round 911 || { fail "epoch 4 vote round failed"; exit 1; }

# A note is spendable only once an epoch build has put it in the IV5 tree and given
# it a leaf index, which happens when the chain crosses into the next epoch. This is
# the positive side of the predicate the negative phase proved can fail.
if pool_is_spendable 0; then
    success "node0's pool value is detected, placed in the tree and spendable ($POOL_DIAG)"
else
    fail "node0 has no spendable IV5 note ($POOL_DIAG)"
    exit 1
fi

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
header "10. node0 holds the private half of every member key"
# ============================================================

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
header "11. The pool is funded for eight collateral notes"
# ============================================================

advance_through_epochs 5 "$POOL_FUND_EPOCH" || { fail "the epoch 5-$POOL_FUND_EPOCH vote rounds failed"; exit 1; }

log "mining to $POOL_FUND_HEIGHT and waiting for node0's mature coinbase to cover $POOL_SHIELD_TOTAL INN"
mine_to 0 "$POOL_FUND_HEIGHT" || { fail "could not mine to the pool-funding height"; exit 1; }
wait_sync "$POOL_FUND_HEIGHT" || { fail "fleet did not sync to the pool-funding height"; exit 1; }

# Polled, not assumed: the emission tail sets when this balance arrives.
BAL="$(rpc 0 getbalance 2>/dev/null | tr -d '"[:space:]')"
while ! fgt "${BAL:-0}" "$POOL_SHIELD_TOTAL" && [ "$(height 0)" -lt "$POOL_FUND_DEADLINE" ]; do
    mine_to 0 $(( $(height 0) + 20 )) || break
    BAL="$(rpc 0 getbalance 2>/dev/null | tr -d '"[:space:]')"
done
if fgt "${BAL:-0}" "$POOL_SHIELD_TOTAL"; then
    success "node0 holds $BAL INN at height $(height 0), over the $POOL_SHIELD_TOTAL the carve needs"
else
    fail "node0 holds $BAL INN at height $(height 0) and needs $POOL_SHIELD_TOTAL by $POOL_FUND_DEADLINE; the funding epoch is too early for this emission schedule"
    exit 1
fi

# Consolidate each row, then sweep it: z_shieldall moves one address's whole
# value with no transparent change.
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
    SHIELDED_TOTAL="$(fadd "$SHIELDED_TOTAL" "$(jget "$SH" shielded)")"
    [ $((r % 5)) -eq 0 ] && log "  row $r: pool total now $SHIELDED_TOTAL INN at height $(height 0)"
done
if [ "$SHIELDED_ROWS" -eq "$POOL_SHIELD_ROWS" ] && fgt "$SHIELDED_TOTAL" $(( CARVE_ROWS * COLLATERAL_VALUE )); then
    success "$SHIELDED_ROWS shields put $SHIELDED_TOTAL INN into the pool, over the $(( CARVE_ROWS * COLLATERAL_VALUE )) the carve needs"
else
    fail "only $SHIELDED_ROWS of $POOL_SHIELD_ROWS rows reached the pool ($SHIELDED_TOTAL INN)"
    exit 1
fi

# Every funding shield must be inside POOL_FUND_EPOCH: a shield that lands in the
# carve epoch is not in the tree the carve proves against.
if [ "$(height 0)" -le "$(epoch_end "$POOL_FUND_EPOCH")" ]; then
    success "every funding shield confirmed inside epoch $POOL_FUND_EPOCH, which the carve spends against"
else
    fail "the funding shields ran past epoch $POOL_FUND_EPOCH (tip $(height 0) > $(epoch_end "$POOL_FUND_EPOCH"))"
    exit 1
fi

# ============================================================
header "12. Eight 25000 INN collateral notes are carved in the pool"
# ============================================================

advance_through_epochs "$CARVE_EPOCH" "$CARVE_EPOCH" || { fail "the epoch $CARVE_EPOCH vote round failed"; exit 1; }
mine_to 0 $((CARVE_HEIGHT + 10)) || { fail "could not mine into epoch $CARVE_EPOCH"; exit 1; }
wait_sync $((CARVE_HEIGHT + 10)) || { fail "fleet did not sync into epoch $CARVE_EPOCH"; exit 1; }

IV5ADDR="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
if [ ${#IV5ADDR} -ge 20 ]; then
    success "node0 holds an IV5 address to carve the collateral notes to"
else
    fail "could not create an IV5 address for the carve"
    exit 1
fi

# All carves in one epoch: selection is largest-first, so a later carve would
# spend a 25000 INN note just made.
CARVED=0
for ((r=0; r<CARVE_ROWS; r++)); do
    TR="$(rpc 0 z_iv5transfer "$IV5ADDR" "$COLLATERAL_VALUE" 2>&1)"
    TR_TXID="$(jget "$TR" txid)"
    if [ ${#TR_TXID} -ne 64 ]; then
        fail "carving note $r failed: $(echo "$TR" | head -3)"
        INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
        log "  pool=$(jget "$INFO" privacy_vnext_pool_value) spendable=$(jget "$INFO" privacy_vnext_balance) pending=$(jget "$INFO" privacy_vnext_unconfirmed_balance) notes=$(jget "$INFO" privacy_vnext_note_count)"
        break
    fi
    confirm_on 3 || { fail "could not confirm carve $r"; break; }
    CARVED=$((CARVED + 1))
done
if [ "$CARVED" -eq "$CARVE_ROWS" ]; then
    success "$CARVED exact-$COLLATERAL_VALUE INN notes carved by in-pool transfer"
else
    fail "only $CARVED of $CARVE_ROWS collateral notes were carved"
    exit 1
fi
if [ "$(height 0)" -le "$(epoch_end "$CARVE_EPOCH")" ]; then
    success "all $CARVED carves confirmed inside epoch $CARVE_EPOCH, before its build makes them selectable"
else
    fail "the carves ran past epoch $CARVE_EPOCH (tip $(height 0) > $(epoch_end "$CARVE_EPOCH"))"
    exit 1
fi

# ============================================================
header "13. Six committee registrations and one private collateralnode"
# ============================================================

advance_through_epochs "$REGISTER_EPOCH" "$REGISTER_EPOCH" || { fail "the epoch $REGISTER_EPOCH vote round failed"; exit 1; }
mine_to 0 $((REGISTER_HEIGHT + 10)) || { fail "could not mine into epoch $REGISTER_EPOCH"; exit 1; }
wait_sync $((REGISTER_HEIGHT + 10)) || { fail "fleet did not sync into epoch $REGISTER_EPOCH"; exit 1; }

NOTE_IDS=()
while read -r nid; do [ -n "$nid" ] && NOTE_IDS+=("$nid"); done < <(collateral_note_ids 0)
if [ "${#NOTE_IDS[@]}" -ge "$REGISTER_ROWS" ]; then
    success "${#NOTE_IDS[@]} attestable $COLLATERAL_VALUE INN note(s) are visible to the wallet"
else
    fail "only ${#NOTE_IDS[@]} attestable note(s); the carve did not finalize into the anchor"
    rpc 0 collateralnode collateral-notes 2>&1 | head -20
    exit 1
fi

# The private collateralnode first, on note 0, so it cannot collide with the six
# rows the draw reads. registerprivate binds endpoint, collateralnodeprivkey and
# pool payout into the attestation and they can never change for that note.
PRIVATE_PAYOUT="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
if [ ${#PRIVATE_PAYOUT} -ge 20 ]; then
    success "node0 issued an IV5 pool payout address for the private collateralnode"
else
    fail "could not issue a pool payout address"
fi
CN_DRY="$(rpc 0 collateralnode registerprivate "$PRIVATE_CN_ENDPOINT" "$PRIVATE_PAYOUT" "${NOTE_IDS[0]}" 2>&1)"
if [ "$(jget "$CN_DRY" dry_run)" = "true" ] && [ -z "$(jget "$CN_DRY" attestation_txid)" ]; then
    success "registerprivate previews without the confirm word and broadcasts nothing"
else
    fail "registerprivate did not behave as a dry run: $(echo "$CN_DRY" | head -4)"
fi
CN_REG="$(rpc 0 collateralnode registerprivate "$PRIVATE_CN_ENDPOINT" "$PRIVATE_PAYOUT" "${NOTE_IDS[0]}" confirm 2>&1)"
CN_ATTEST_TXID="$(jget "$CN_REG" attestation_txid)"
CN_KEYIMAGE="$(jget "$CN_REG" key_image)"
if [ ${#CN_ATTEST_TXID} -eq 64 ]; then
    success "the private collateralnode attestation is broadcast (txid ${CN_ATTEST_TXID:0:16}, key image ${CN_KEYIMAGE:0:16})"
else
    fail "registerprivate failed: $(echo "$CN_REG" | head -5)"
fi
confirm_on 3 || fail "could not confirm the private collateralnode attestation"
if [ ${#CN_ATTEST_TXID} -eq 64 ]; then
    CN_H="$(tx_height 0 "$CN_ATTEST_TXID")"
    if is_int "${CN_H:-x}"; then
        assert_converged "the private collateralnode attestation" "$CN_H"
    else
        fail "the private collateralnode attestation did not confirm to a readable height"
    fi
fi

# Two rows per member key across the remaining six notes. Three distinct keys and
# one seat per key means the draw seats exactly these three whichever rows win.
REGISTERED=0
REG_KEYIMAGES=()
for ((r=0; r<COLLATERAL_ROWS; r++)); do
    KEYIDX=$(( r % NUM_NODES ))
    REG="$(rpc 0 collateralnode finality-register "${COMMITTEE_PUBKEYS[$KEYIDX]}" \
              "${NOTE_IDS[$((r + PRIVATE_CN_ROWS))]}" confirm 2>&1)"
    REG_TXID="$(jget "$REG" registration_txid)"
    if [ ${#REG_TXID} -ne 64 ]; then
        fail "registration $r (key $KEYIDX) failed: $(echo "$REG" | head -4)"
        break
    fi
    KI="$(jget "$REG" key_image)"
    [ -n "$KI" ] && REG_KEYIMAGES+=("$KI")
    confirm_on 3 || { fail "could not confirm registration $r"; break; }
    REGISTERED=$((REGISTERED + 1))
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

REGISTRY_N="$(jget "$(rpc 0 collateralnode finality-registry "$COMMITTEE_ANCHOR_HEIGHT" 2>&1)" count)"
if is_int "${REGISTRY_N:-x}" && [ "${REGISTRY_N:-0}" -ge "$COLLATERAL_ROWS" ]; then
    success "the registry holds $REGISTRY_N member rows at the anchor height"
else
    fail "the registry holds '$REGISTRY_N' rows at height $COMMITTEE_ANCHOR_HEIGHT, expected >= $COLLATERAL_ROWS"
    exit 1
fi

# The same snapshot at the PREVIOUS term's anchor height. Every registration above
# confirmed after this height, so a draw that reads the registry can seat nothing
# for that term -- which is what section 15 then requires.
PRE_REGISTRY_N="$(jget "$(rpc 0 collateralnode finality-registry "$PRE_TERM_ANCHOR_HEIGHT" 2>&1)" count)"
if [ "$PRE_REGISTRY_N" = "0" ]; then
    success "the registry is empty at term $PRE_TERM_EPOCH's anchor height $PRE_TERM_ANCHOR_HEIGHT, so a registry-drawn committee cannot seat for that term"
else
    fail "the registry already holds '$PRE_REGISTRY_N' row(s) at height $PRE_TERM_ANCHOR_HEIGHT; the discriminator in section 15 would be worthless"
    exit 1
fi

# ============================================================
header "14. Every disclosure mask confirms on the same chain"
# ============================================================

advance_through_epochs "$MASK_EPOCH" "$MASK_EPOCH" || { fail "the epoch $MASK_EPOCH vote round failed"; exit 1; }
mine_to 0 $(( MASK_HEIGHT + 12 )) || { fail "could not mine into the mask epoch"; exit 1; }
wait_sync $(( MASK_HEIGHT + 12 )) || { fail "fleet did not sync into the mask epoch"; exit 1; }

# Under the fee-note fork the fee leaves the spent note and returns as the
# coinbase note, so the pool balance is unchanged across a transfer block.
assert_transfer_conserved() {
    local label="$1" h="$2" before="$3" after="$4" txs cb cb_prev delta
    txs="$(block_tx_count 0 "$h")"
    delta="$(fsub "$after" "$before")"
    if feq "$delta" 0; then
        success "$label: the pool balance is unchanged across the transfer block ($after INN): the fee stayed in the pool as the coinbase note"
    else
        fail "$label: the pool moved by $delta across the transfer block ($before -> $after); under the fee-note fork a transfer's fee must return as the coinbase note"
    fi
    if [ "$txs" != "2" ]; then
        warn "$label: the transfer block carries $txs transactions, so the coinbase claim comparison was skipped"
        return
    fi
    cb="$(coinbase_value 0 "$h")"
    cb_prev="$(coinbase_value 0 $((h - 1)))"
    if [ -z "$cb" ] || [ -z "$cb_prev" ]; then
        fail "$label: the transfer block's coinbase could not be read"
        return
    fi
    if feq "$cb" "$cb_prev"; then
        success "$label: the coinbase claims $cb, the same as the block before it: the fee was not claimed transparently"
    else
        fail "$label: the coinbase claims $cb against $cb_prev for the previous block; the IV5 fee crossed the boundary"
    fi
    if [ "$(coinbase_version 0 "$h")" = "2008" ]; then
        success "$label: the transfer block's coinbase carries the IV5 fee note"
    else
        fail "$label: the transfer block's coinbase is version $(coinbase_version 0 "$h"), expected 2008"
    fi
}

# A clear bit discloses: bit 0 spend authorities, bit 1 receiver addresses,
# bit 2 output amounts. Each cleared bit changes the payload layout; bit 2
# replaces the range proof with a disclosed commitment check.
mask_bit_flags() {
    local m="$1"
    echo "$(( (m & 1) == 0 ))|$(( (m & 2) == 0 ))|$(( (m & 4) == 0 ))"
}

DISCLOSED_AMOUNT=1
MASKS_EXERCISED=0
MASK_CONSERVED=0
disclosed_transfer() {
    local mask="$1" want_sender="$2" want_receiver="$3" want_amount="$4"
    local addr result txid declared target block h raw pool_before pool_after
    local h_before h_after

    addr="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
    if [ ${#addr} -lt 20 ]; then
        fail "mask $mask: z_getnewiv5address failed"
        return 1
    fi
    # The height the opening reading belongs to. Nothing mines between the two
    # calls, and the second read of it says so rather than assuming it.
    h_before="$(height 0)"
    pool_before="$(pool_value 0)"
    if [ "$(height 0)" != "$h_before" ]; then
        fail "mask $mask: the tip moved while the opening pool balance was read"
        return 1
    fi
    result="$(rpc 0 z_iv5transfer "$addr" "$DISCLOSED_AMOUNT" "$mask" 2>&1)"
    txid="$(jget "$result" txid)"
    if [ ${#txid} -ne 64 ]; then
        if echo "$result" | grep -q "insufficient spendable shielded balance"; then
            fail "mask $mask: no positioned note left to spend; the pool funding is short, not the mask refused"
            return 1
        fi
        fail "mask $mask: z_iv5transfer failed: $(echo "$result" | head -3)"
        return 1
    fi
    declared="$(jget "$result" disclosure_mask)"
    if [ "$declared" = "$mask" ] && \
       [ "$(jget "$result" discloses_sender)" = "$want_sender" ] && \
       [ "$(jget "$result" discloses_receiver)" = "$want_receiver" ] && \
       [ "$(jget "$result" discloses_amount)" = "$want_amount" ]; then
        success "mask $mask: built and reported (sender=$want_sender receiver=$want_receiver amount=$want_amount)"
    else
        fail "mask $mask: the wallet reported mask '$declared' with the wrong flags"
        return 1
    fi

    target=$(( $(height 0) + 3 ))
    mine_to 0 "$target" || { fail "mask $mask: could not mine the transfer"; return 1; }
    wait_sync "$target" || { fail "mask $mask: peers did not accept the block"; return 1; }

    block="$(jget "$(rpc 0 gettransaction "$txid" 2>&1)" blockhash)"
    if [ ${#block} -ne 64 ]; then
        fail "mask $mask: the transfer did not confirm"
        return 1
    fi
    h="$(jget "$(rpc 0 getblock "$block" 2>/dev/null)" height)"
    assert_converged "mask $mask" "$h"

    raw="$(rpc 0 getrawtransaction "$txid" 1 2>&1)"
    if [ "$(jget2 "$raw" privacy_vnext disclosure_mask)" = "$mask" ] && \
       [ "$(jget2 "$raw" privacy_vnext discloses_sender)" = "$want_sender" ] && \
       [ "$(jget2 "$raw" privacy_vnext discloses_receiver)" = "$want_receiver" ] && \
       [ "$(jget2 "$raw" privacy_vnext discloses_amount)" = "$want_amount" ]; then
        success "mask $mask: the confirmed transaction declares it on chain"
    else
        fail "mask $mask: the confirmed transaction does not declare mask $mask"
    fi
    if [ "$(jlen "$raw" vin)" = "0" ] && [ "$(jlen "$raw" vout)" = "0" ]; then
        success "mask $mask: carries no transparent input or output"
    else
        fail "mask $mask: leaked transparent value"
    fi

    pool_after="$(pool_value 0)"
    h_after="$(height 0)"

    # The mask this transaction declares, taken off its own serialized bytes
    # rather than an RPC field that echoes back what the wallet was asked for.
    assert_reader_agrees "mask $mask" 0 "$txid" "$mask"

    # The block-local comparison reads only while the transfer is alone in its
    # block, which holds for the first mask and for no later one.
    if [ "$MASK_CONSERVED" -eq 0 ]; then
        assert_transfer_conserved "mask $mask" "$h" "$pool_before" "$pool_after"
        MASK_CONSERVED=1
    fi

    # The window form sums declared payloads only; settlements, votes and plain
    # blocks declare nothing.
    assert_pool_conserved_over_window "mask $mask" 0 "$h_before" "$h_after" \
        "$pool_before" "$pool_after" || MASK_WINDOWS_FAILED=$((MASK_WINDOWS_FAILED + 1))
    return 0
}

MASK_WINDOWS_FAILED=0
SWEEP_H_BEFORE="$(height 0)"
SWEEP_POOL_BEFORE="$(pool_value 0)"

for MASK in 0 1 2 3 4 5 6 7; do
    IFS='|' read -r WS WR WA <<< "$(mask_bit_flags "$MASK")"
    [ "$WS" = "1" ] && WS=true || WS=false
    [ "$WR" = "1" ] && WR=true || WR=false
    [ "$WA" = "1" ] && WA=true || WA=false
    disclosed_transfer "$MASK" "$WS" "$WR" "$WA" && MASKS_EXERCISED=$((MASKS_EXERCISED + 1))
done
if [ "$MASKS_EXERCISED" -eq 8 ]; then
    success "all eight disclosure masks confirmed on chain and converged fleet-wide"
else
    fail "only $MASKS_EXERCISED of 8 disclosure masks were confirmed on chain"
fi

SWEEP_H_AFTER="$(height 0)"
SWEEP_POOL_AFTER="$(pool_value 0)"

if [ "$POOL_WINDOWS_CHECKED" -eq 8 ] && [ "$MASK_WINDOWS_FAILED" -eq 0 ]; then
    success "value conservation is proved for all eight masks, each over a window free to carry anything"
else
    fail "value conservation was proved for $POOL_WINDOWS_CHECKED of 8 masks ($MASK_WINDOWS_FAILED window(s) failed)"
fi

# The epoch settlement is the transparent movement the identity has to be blind
# to, so the measured span has to cover one.
MASK_SETTLEMENT_HEIGHT=$(( MASK_HEIGHT + 24 ))
if [ "$MASK_SETTLEMENT_HEIGHT" -gt "$SWEEP_H_BEFORE" ] && \
   [ "$MASK_SETTLEMENT_HEIGHT" -le "$SWEEP_H_AFTER" ]; then
    success "the measured span covers the epoch $MASK_EPOCH settlement height $MASK_SETTLEMENT_HEIGHT"
else
    fail "the mask sweep spans ($SWEEP_H_BEFORE, $SWEEP_H_AFTER], which does not cover the epoch $MASK_EPOCH settlement height $MASK_SETTLEMENT_HEIGHT"
fi

# The settlement reward is coin-age truncated to whole days; a 300-second
# regtest epoch accrues under a coin-day, so the reward is zero here. Reported,
# not assumed.
SETTLE_VOUTS="$(jlen "$(rpc 0 getrawtransaction "$(coinbase_txid 0 "$MASK_SETTLEMENT_HEIGHT")" 1 2>/dev/null)" vout)"
SETTLE_PREV_VOUTS="$(jlen "$(rpc 0 getrawtransaction "$(coinbase_txid 0 $(( MASK_SETTLEMENT_HEIGHT - 1 )))" 1 2>/dev/null)" vout)"
if is_int "${SETTLE_VOUTS:-x}" && is_int "${SETTLE_PREV_VOUTS:-x}" && \
   [ "$SETTLE_VOUTS" -gt "$SETTLE_PREV_VOUTS" ]; then
    success "the settlement at $MASK_SETTLEMENT_HEIGHT pays $(( SETTLE_VOUTS - SETTLE_PREV_VOUTS )) output(s) the block before it does not, so a settlement payout is live inside the measured span"
else
    warn "the epoch $MASK_EPOCH settlement at $MASK_SETTLEMENT_HEIGHT carries $SETTLE_VOUTS coinbase outputs against $SETTLE_PREV_VOUTS before it: the finality reward truncates to zero at this vote weight, so no run of this harness exercises a settlement that pays"
fi

# And the whole sweep as one window: eight transfers, eight coinbase notes, the
# settlement and every plain block between them, against a single pool movement.
assert_pool_conserved_over_window "the mask sweep" 0 "$SWEEP_H_BEFORE" \
    "$SWEEP_H_AFTER" "$SWEEP_POOL_BEFORE" "$SWEEP_POOL_AFTER"
if [ "$WINDOW_IV5" -ge 16 ]; then
    success "the sweep window carries $WINDOW_IV5 IV5 payloads, the eight transfers and their coinbase notes"
else
    fail "the sweep window carries $WINDOW_IV5 IV5 payloads, fewer than the sixteen the eight masks must have produced"
fi

# A window coinbase carries extra outputs (the finality certificate) that must
# not reach the sum.
if [ "$WINDOW_MAXVOUTS" -gt "$WINDOW_MINVOUTS" ]; then
    success "a coinbase in the sweep window carries $WINDOW_MAXVOUTS outputs against $WINDOW_MINVOUTS on the plainest, and the identity held across it"
else
    fail "every coinbase in the sweep window carries $WINDOW_MAXVOUTS outputs, so the identity was never measured against extra coinbase content"
fi

BAD_MASK="$(rpc 0 z_iv5transfer "$IV5ADDR" "$DISCLOSED_AMOUNT" 8 2>&1)"
if echo "$BAD_MASK" | grep -qi "three-bit"; then
    success "a mask above 7 is refused"
else
    fail "a mask above 7 was not refused: $(echo "$BAD_MASK" | head -2)"
fi

# ============================================================
header "15. The private collateralnode announces and the fleet records it"
# ============================================================

# Peers refuse an attested announcement until the attestation is
# COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY deep, and the announcement is one-shot.
CN_STATUS="$(rpc 0 collateralnode statusprivate 2>&1)"
if [ ${#CN_KEYIMAGE} -eq 64 ] && echo "$CN_STATUS" | grep -qF "$CN_KEYIMAGE"; then
    success "statusprivate reports the held registration ${CN_KEYIMAGE:0:16}"
else
    fail "statusprivate does not report the registration (key image '$CN_KEYIMAGE'): $(echo "$CN_STATUS" | head -5)"
fi
CN_HELD="$(jget "$CN_STATUS" held_balance)"
if fgt "${CN_HELD:-0}" 0; then
    success "the registration holds $CN_HELD INN of collateral out of ordinary spending"
else
    fail "statusprivate reports a held balance of '$CN_HELD'"
fi

CN_ANNOUNCED=0
for _ in 1 2 3 4 5; do
    ANN="$(rpc 0 collateralnode announceprivate 2>&1)"
    if echo "$ANN" | grep -q "announced and relayed"; then
        CN_ANNOUNCED=1
        break
    fi
    confirm_on 4 || break
done
if [ "$CN_ANNOUNCED" -eq 1 ]; then
    success "node0 announced its private collateralnode registration"
else
    fail "announceprivate never reported a relayed announcement: $(echo "$ANN" | head -6)"
fi

# The fleet-wide half: a peer that built none of this has to accept the
# announcement and hold the node in its own list.
CN_SEEN=0
for _ in $(seq 1 30); do
    CN_SEEN=1
    for ((n=1; n<NUM_NODES; n++)); do
        C="$(rpc "$n" collateralnode count 2>/dev/null | tr -d '"[:space:]')"
        is_int "${C:-x}" && [ "${C:-0}" -ge 1 ] || CN_SEEN=0
    done
    [ "$CN_SEEN" -eq 1 ] && break
    sleep 2
done
if [ "$CN_SEEN" -eq 1 ]; then
    success "both peers accepted the announcement and hold the collateralnode in their own list"
else
    fail "a peer never recorded the collateralnode (node1=$(rpc 1 collateralnode count 2>/dev/null | tr -d '"[:space:]') node2=$(rpc 2 collateralnode count 2>/dev/null | tr -d '"[:space:]'))"
    for ((n=1; n<NUM_NODES; n++)); do
        grep -F "isee - " "$(node_log "$n")" 2>/dev/null | tail -3
    done
fi

# Payment is unreachable (off-testnet gate at 2085000); assert no coinbase
# carried one.
if [ "$(height 0)" -lt "$CN_PAYMENT_START_HEIGHT" ]; then
    success "collateralnode PAYMENT is unreachable on regtest (miner gate is height $CN_PAYMENT_START_HEIGHT, tip is $(height 0)); registration is covered above, payment is not"
else
    fail "the chain passed the collateralnode payment gate; this harness does not cover the paid path"
fi

# ============================================================
header "16. The chain draws its committee from that registry"
# ============================================================

advance_through_epochs $(( MASK_EPOCH + 1 )) "$COMMITTEE_CARRIER_EPOCH" || { fail "the epoch $(( MASK_EPOCH + 1 ))-$COMMITTEE_CARRIER_EPOCH vote rounds failed"; exit 1; }

# THE DISCRIMINATOR. The chain is now inside term PRE_TERM_EPOCH, whose anchor
# registry section 13 proved is empty. Every other observable here -- the seat
# identities, the set hash, the fleet agreement, the certificate -- is equally
# produced by an implementation that ignores the registry and seats the three
# configured member keys every term, because those keys ARE 1G/2G/3G. This is the
# only check that separates the two.
PRE_SEAT_HEIGHT="$(height 0)"
PRE_SEAT_OK=1
PRE_SEAT_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    [ "$(jget "$FI" committee_term_epoch)" = "$PRE_TERM_EPOCH" ] || { PRE_SEAT_OK=0; PRE_SEAT_WHY="node$n is in term '$(jget "$FI" committee_term_epoch)', not $PRE_TERM_EPOCH"; }
    [ "$(jget "$FI" committee_seated)" = "false" ]              || { PRE_SEAT_OK=0; PRE_SEAT_WHY="node$n reports committee_seated=$(jget "$FI" committee_seated)"; }
    [ "$(jget "$FI" committee_seat_count)" = "0" ]              || { PRE_SEAT_OK=0; PRE_SEAT_WHY="node$n reports $(jget "$FI" committee_seat_count) seat(s)"; }
done
if [ "$PRE_SEAT_OK" -eq 1 ]; then
    success "at height $PRE_SEAT_HEIGHT the chain is in term $PRE_TERM_EPOCH and seats nothing, because that term's anchor registry was empty"
else
    fail "the seats do not come from the collateral registry: $PRE_SEAT_WHY, while term $PRE_TERM_EPOCH's anchor height $PRE_TERM_ANCHOR_HEIGHT held $PRE_REGISTRY_N registry rows"
    exit 1
fi

FI0="$(rpc 0 getfinalityinfo 2>/dev/null)"
NEXT_TERM="$(jget2 "$FI0" committee_next_term_draw term_epoch)"
NEXT_ANCHOR_H="$(jget2 "$FI0" committee_next_term_draw anchor_height)"
NEXT_ROWS="$(jget2 "$FI0" committee_next_term_draw registry_rows)"
NEXT_SEATED="$(jget2 "$FI0" committee_next_term_draw seated)"
if [ "$NEXT_TERM" = "$COMMITTEE_TERM_EPOCH" ] && [ "$NEXT_ANCHOR_H" = "$COMMITTEE_ANCHOR_HEIGHT" ] && \
   is_int "${NEXT_ROWS:-x}" && [ "${NEXT_ROWS:-0}" -ge "$COLLATERAL_ROWS" ] && [ "$NEXT_SEATED" = "true" ]; then
    success "the term $COMMITTEE_TERM_EPOCH draw reads $NEXT_ROWS registry rows at anchor height $NEXT_ANCHOR_H and will seat"
else
    fail "the term $COMMITTEE_TERM_EPOCH draw does not read the registrations (term=$NEXT_TERM anchor=$NEXT_ANCHOR_H rows=$NEXT_ROWS seated=$NEXT_SEATED)"
fi

log "mining to $COMMITTEE_SEATED_HEIGHT, where epoch $COMMITTEE_CARRIER_EPOCH is built and carries the draw"
mine_to 0 "$COMMITTEE_SEATED_HEIGHT" || { fail "could not mine to the seating height"; exit 1; }
wait_sync "$COMMITTEE_SEATED_HEIGHT" || { fail "fleet did not sync to the seating height"; exit 1; }

SEAT_OK=1
SEAT_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    [ "$(jget "$FI" committee_seated)" = "true" ]                     || { SEAT_OK=0; SEAT_WHY="node$n committee_seated=$(jget "$FI" committee_seated)"; }
    [ "$(jget "$FI" committee_term_epoch)" = "$COMMITTEE_TERM_EPOCH" ] || { SEAT_OK=0; SEAT_WHY="node$n is in term '$(jget "$FI" committee_term_epoch)'"; }
    [ "$(jget "$FI" committee_threshold_m)" = "$COMMITTEE_THRESHOLD_M" ] || { SEAT_OK=0; SEAT_WHY="node$n threshold M='$(jget "$FI" committee_threshold_m)'"; }
    [ "$(jget "$FI" committee_seat_count)" = "$COMMITTEE_SEAT_COUNT" ] || { SEAT_OK=0; SEAT_WHY="node$n seat count='$(jget "$FI" committee_seat_count)'"; }
done
if [ "$SEAT_OK" -eq 1 ]; then
    success "every node seats term $COMMITTEE_TERM_EPOCH's committee at exactly $COMMITTEE_SEAT_COUNT seats and M=$COMMITTEE_THRESHOLD_M"
else
    fail "the committee did not seat as drawn on every node: $SEAT_WHY"
    exit 1
fi

SEATS0="$(committee_seats 0 | sort | tr '\n' ' ')"
EXPECTED_SEATS="$(printf '%s\n' "${COMMITTEE_PUBKEYS[@]}" | sort | tr '\n' ' ')"
if [ "$SEATS0" = "$EXPECTED_SEATS" ]; then
    success "the drawn seats are exactly the three registered member keys"
else
    fail "drawn seats [$SEATS0] are not the registered keys [$EXPECTED_SEATS]"
fi

SEATS_AGREE=1
SEATS_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    SN="$(committee_seats "$n" | count_lines)"
    [ "$SN" -eq "$COMMITTEE_SEAT_COUNT" ] || { SEATS_AGREE=0; SEATS_WHY="node$n lists $SN seat(s)"; }
    [ "$(committee_seats "$n" | tr '\n' ' ')" = "$(committee_seats 0 | tr '\n' ' ')" ] || \
        { SEATS_AGREE=0; SEATS_WHY="node$n resolves a different seat list from node0"; }
done
if [ "$SEATS_AGREE" -eq 1 ]; then
    success "all $NUM_NODES nodes resolve the identical $COMMITTEE_SEAT_COUNT-seat committee in the identical seat order"
else
    fail "the nodes disagree about the drawn committee: $SEATS_WHY"
    exit 1
fi

# ============================================================
header "17. Note finality votes over the finalized chain"
# ============================================================

for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    log "epoch $E: holding the chain at boundary $B for ${NOTE_VOTE_SETTLE}s"
    vote_round "$B" "$NOTE_VOTE_SETTLE" "$NOTE_VOTE_WINDOW" || { fail "epoch $E vote round failed"; exit 1; }

    if [ "$E" = "$TALLY_EPOCH" ]; then
        log "epoch $E: mining to the vote-inclusion window close at $TALLY_WINDOW_CLOSE"
        mine_to 0 "$TALLY_WINDOW_CLOSE" || { fail "epoch $E did not reach the freeze point"; exit 1; }
        wait_sync "$TALLY_WINDOW_CLOSE" || { fail "fleet did not sync to the freeze point"; exit 1; }
        log "epoch $E: resting ${TALLY_SETTLE}s for the note tally committee"
        sleep "$TALLY_SETTLE"
        log "epoch $E: mining to $TALLY_CARRY_HEIGHT so an own-epoch block can carry the certificate"
        mine_to 0 "$TALLY_CARRY_HEIGHT" || { fail "epoch $E did not reach the carry height"; exit 1; }
        wait_sync "$TALLY_CARRY_HEIGHT" || { fail "fleet did not sync to the carry height"; exit 1; }
        sleep 20
        mine_to 0 $((TALLY_CARRY_HEIGHT + 20)) || { fail "epoch $E did not extend past the carry height"; exit 1; }
        wait_sync $((TALLY_CARRY_HEIGHT + 20)) || { fail "fleet did not sync past the carry height"; exit 1; }
    fi
done

E4="$(rpc 0 getepochinfo "$FINALIZED_EPOCH" 2>/dev/null)"
if [ "$(jget "$E4" finalized)" = "true" ] && [ "$(jget "$E4" finalized_height_as_of)" = "$FINALIZED_HEIGHT" ]; then
    success "epoch $FINALIZED_EPOCH finalizes height $FINALIZED_HEIGHT after $(jget "$E4" consecutive_hard_epochs) consecutive HARD epochs"
else
    fail "epoch $FINALIZED_EPOCH did not finalize (finalized=$(jget "$E4" finalized) height=$(jget "$E4" finalized_height_as_of))"
fi

BUILT_EPOCHS=""
ACCEPTED_EPOCHS=""
REFUSED_EPOCHS=""
F2_LINE=""
for E in $NOTE_VOTE_EPOCHS; do
    if [ -n "$(producer_success "$E")" ]; then
        BUILT_EPOCHS="$BUILT_EPOCHS $E"
        ACCEPTED_EPOCHS="$ACCEPTED_EPOCHS $E"
    elif [ -n "$(producer_refused "$E")" ]; then
        BUILT_EPOCHS="$BUILT_EPOCHS $E"
        REFUSED_EPOCHS="$REFUSED_EPOCHS $E"
        [ -z "$F2_LINE" ] && F2_LINE="$(producer_refused "$E" | head -1)"
    elif [ -n "$(producer_dup_tag "$E")" ]; then
        BUILT_EPOCHS="$BUILT_EPOCHS $E"
    fi
done
if [ -n "$BUILT_EPOCHS" ]; then
    success "node0 built a note vote in epoch(s)$BUILT_EPOCHS"
else
    fail "node0 never built a note vote; the producer stopped at a gate:"
    producer_all | tail -12
fi
if [ -n "$ACCEPTED_EPOCHS" ] && [ -z "$REFUSED_EPOCHS" ]; then
    success "every built note vote entered node0's own mempool (epoch(s)$ACCEPTED_EPOCHS)"
elif [ -n "$REFUSED_EPOCHS" ]; then
    fail "node0 REFUSED ITS OWN note vote in epoch(s)$REFUSED_EPOCHS: $F2_LINE"
else
    fail "no note vote reached node0's relay check at all"
fi

RECEIVED_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    # Votes relay through the mempool as ordinary transactions now; the coinbase
    # envelope and the finality message that carried them were deleted.
    RX="$(rpc "$n" getrawmempool 2>/dev/null | grep -c . || echo 0)"
    REJ="$(grep -F "rejected note vote from peer" "$(node_log "$n")" 2>/dev/null | head -1)"
    if is_int "${RX:-x}" && [ "${RX:-0}" -gt 0 ] && [ -z "$REJ" ]; then
        log "  node$n received $RX note vote message(s)"
    else
        RECEIVED_OK=0
        [ -n "$REJ" ] && fail "node$n rejected a relayed note vote: $REJ"
    fi
done
if [ "$RECEIVED_OK" -eq 1 ]; then
    success "both peers received the note vote over relay and none rejected it"
else
    fail "the note vote did not reach both peers"
fi


# ------------------------------------------------------------
# C6: no node originates both a named and an anonymous vote, read from the producer
# log lines ProduceFinalityVote and ProducePrivacyVNextNoteVote.
LANE_OK=1
LANE_TOTAL_ANON=0
LANE_TOTAL_IDENT=0
for ((n=0; n<NUM_NODES; n++)); do
    L="$(node_log "$n")"
    N_IDENT="$(grep -cF "ProduceFinalityVote: epoch=" "$L" 2>/dev/null)"
    N_ANON="$(grep -cF "ProducePrivacyVNextNoteVote: epoch=" "$L" 2>/dev/null)"
    is_int "${N_IDENT:-x}" || N_IDENT=0
    is_int "${N_ANON:-x}" || N_ANON=0
    N_LANE="$(grep -oE "FINALITY vote lane latched: lane=[a-z]+" "$L" 2>/dev/null | \
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

# Liveness: node0 contributes nothing to the tally, so the identity voters
# alone must finalize.
FIN_NOW="$(jget "$(rpc 0 getfinalityinfo 2>/dev/null)" finalized_height)"
if is_int "${FIN_NOW:-x}" && [ "${FIN_NOW:-0}" -ge "$FINALIZED_HEIGHT" ]; then
    success "finality still advances with node0 silent on the identity lane (finalized_height=$FIN_NOW)"
else
    fail "finality stalled once node0 left the identity lane (finalized_height=$FIN_NOW, need >= $FINALIZED_HEIGHT)"
fi

CARRIED_TOTAL=0
CARRY_HEIGHTS=""
for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    ROWS="$(notevotes_in_range 0 "$B" $((B + NOTE_VOTE_WINDOW)))"
    DISTINCT="$(echo "$ROWS" | awk 'NF{print $2}' | sort -u | count_lines)"
    if [ "$DISTINCT" -gt 0 ]; then
        FIRST_H="$(echo "$ROWS" | awk 'NF{print $1; exit}')"
        CARRY_HEIGHTS="$CARRY_HEIGHTS $FIRST_H"
        CARRIED_TOTAL=$((CARRIED_TOTAL + DISTINCT))
        log "  epoch $E: $DISTINCT distinct note-vote envelope(s), first at height $FIRST_H"
    fi
done
if [ "$CARRIED_TOTAL" -gt 0 ]; then
    success "coinbases carry $CARRIED_TOTAL note-vote envelope(s)"
else
    fail "no coinbase carried a note-vote envelope"
fi

CONNECT_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    R="$(grep -F "ConnectBlockNoteVotes: rejected vote in block" "$(node_log "$n")" 2>/dev/null | head -1)"
    [ -n "$R" ] && CONNECT_REJECT="node$n: $R"
done
if [ -z "$CONNECT_REJECT" ]; then
    success "no node rejected a note vote at connect"
else
    fail "a node rejected a note vote at connect: $CONNECT_REJECT"
fi
for H in $CARRY_HEIGHTS; do
    assert_converged "the note-vote carrier block" "$H"
done

# ============================================================
header "18. One coinbase, three features"
# ============================================================

# The miner appends note-vote envelopes, then builds the fee-note payload over
# the final vector. A block with both must be accepted by peers.
NOTE_VOTE_CARRIER=""
for H in $CARRY_HEIGHTS; do NOTE_VOTE_CARRIER="$H"; break; done
if [ -n "$NOTE_VOTE_CARRIER" ]; then
    IDAG_ON_VOTE="$(idag_scripts 0 "$NOTE_VOTE_CARRIER" | count_lines)"
    if [ "$IDAG_ON_VOTE" = "1" ]; then
        success "the note-vote carrier at $NOTE_VOTE_CARRIER also carries the IDAG parent commitment: DAG ordering and note finality voting share one coinbase"
    else
        fail "the note-vote carrier at $NOTE_VOTE_CARRIER carries $IDAG_ON_VOTE IDAG parent commitment(s)"
    fi
fi

# Force a fee note into the note-vote epoch: an IV5 transfer whose fee the coinbase
# must collect as a pool note, in a block that also carries the IDAG commitment.
COMBO_ADDR="$(jget "$(rpc 0 z_getnewiv5address 2>&1)" address)"
COMBO_TXID="$(jget "$(rpc 0 z_iv5transfer "$COMBO_ADDR" 1 2>&1)" txid)"
if [ ${#COMBO_TXID} -eq 64 ]; then
    confirm_on 3 || fail "could not confirm the combined-coinbase transfer"
    COMBO_H="$(tx_height 0 "$COMBO_TXID")"
    if is_int "${COMBO_H:-x}"; then
        COMBO_VER="$(coinbase_version 0 "$COMBO_H")"
        COMBO_IDAG="$(idag_scripts 0 "$COMBO_H" | count_lines)"
        if [ "$COMBO_VER" = "2008" ] && [ "$COMBO_IDAG" = "1" ]; then
            success "the block at $COMBO_H carries the IDAG parent commitment and an IV5 fee-note payload in one coinbase"
        else
            fail "the block at $COMBO_H is coinbase version $COMBO_VER with $COMBO_IDAG IDAG commitment(s); the fee note and the ordering commitment did not compose"
        fi
        assert_converged "the fee-note + IDAG block" "$COMBO_H"
        # Report when the vote and fee note share a block; it is a race, so absence is
        # not a failure.
        if [ "$(notevote_scripts 0 "$COMBO_H" | count_lines)" -gt 0 ]; then
            log "  that same block also carries a note-vote envelope: all three in one coinbase"
        fi
    else
        fail "the combined-coinbase transfer did not confirm to a readable height"
    fi
else
    fail "could not build a transfer for the combined-coinbase block"
fi

# ============================================================
header "19. The note tally committee and its certificate"
# ============================================================

TALLY_LINE=""
TALLY_NODE=""
for ((n=0; n<NUM_NODES; n++)); do
    L="$(grep -F "ProcessNoteTallyCommitteeEpoch: epoch $TALLY_EPOCH tier=" "$(node_log "$n")" 2>/dev/null | tail -1)"
    if [ -n "$L" ]; then TALLY_LINE="$L"; TALLY_NODE="$n"; break; fi
done
if [ -n "$TALLY_LINE" ]; then
    success "node$TALLY_NODE ran the note tally for epoch $TALLY_EPOCH"
    log "  $TALLY_LINE"
else
    fail "no node ran the note tally committee pass for epoch $TALLY_EPOCH"
fi

# The tally counts votes; it opens no weight. note_votes is what the epoch connected and
# note_winners how many of those back the winning boundary.
NOTE_VOTES="$(echo "$TALLY_LINE" | sed -n 's/.* note_votes=\([0-9]*\).*/\1/p')"
NOTE_WINNERS="$(echo "$TALLY_LINE" | sed -n 's/.* note_winners=\([0-9]*\).*/\1/p')"
if is_int "${NOTE_VOTES:-x}" && is_int "${NOTE_WINNERS:-x}" && \
   [ "${NOTE_WINNERS:-0}" -gt 0 ] && [ "${NOTE_WINNERS:-0}" -le "${NOTE_VOTES:-0}" ]; then
    success "the note tally counted $NOTE_WINNERS of $NOTE_VOTES note vote(s) for the winning boundary"
else
    fail "the note tally counted no note vote for the winner (note_votes='$NOTE_VOTES' note_winners='$NOTE_WINNERS')"
fi

NOTE_CERT_HASHES=""
for ((n=0; n<NUM_NODES; n++)); do
    while read -r L; do
        [ -n "$L" ] || continue
        H="$(echo "$L" | sed -n 's/.*note certificate \([0-9a-f]\{64\}\).*/\1/p')"
        [ -n "$H" ] && NOTE_CERT_HASHES="$NOTE_CERT_HASHES $H"
    done < <(grep -F "FinalityNoteTally: epoch $TALLY_EPOCH note certificate " "$(node_log "$n")" 2>/dev/null)
done
NOTE_CERT_HASHES="$(echo "$NOTE_CERT_HASHES" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
if [ -n "$NOTE_CERT_HASHES" ]; then
    success "the committee assembled $(echo "$NOTE_CERT_HASHES" | wc -w | tr -d ' ') note certificate(s) for epoch $TALLY_EPOCH"
else
    fail "no M-of-N note certificate was assembled for epoch $TALLY_EPOCH"
fi

CERT_CARRY_HEIGHT=""
for ((h=TALLY_WINDOW_CLOSE; h<=TALLY_CARRY_HEIGHT + 20; h++)); do
    if [ -n "$(tagged_scripts 0 "$h" "$TALLY_CERT_TAG_HEX")" ]; then CERT_CARRY_HEIGHT="$h"; break; fi
done
if [ -n "$CERT_CARRY_HEIGHT" ]; then
    success "a tally certificate envelope is carried at height $CERT_CARRY_HEIGHT, inside epoch $TALLY_EPOCH"
else
    fail "no tally certificate envelope was carried inside epoch $TALLY_EPOCH"
fi

TALLY_EI="$(rpc 0 getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
TALLY_CERT="$(jget "$TALLY_EI" finality_certificate)"
TALLY_TIER="$(jget "$TALLY_EI" finality_tier)"
TALLY_ROOT="$(jget "$TALLY_EI" vote_set_root)"
TALLY_DIGEST="$(jget "$TALLY_EI" epoch_state_digest)"
if [ -n "$TALLY_CERT" ] && ! is_zero_hex "$TALLY_CERT" && \
   echo " $NOTE_CERT_HASHES " | grep -qF " $TALLY_CERT "; then
    success "epoch $TALLY_EPOCH selected the note certificate ${TALLY_CERT:0:16} (tier=$TALLY_TIER)"
elif [ -n "$TALLY_CERT" ] && ! is_zero_hex "$TALLY_CERT"; then
    fail "epoch $TALLY_EPOCH selected certificate ${TALLY_CERT:0:16}, which is not one of the assembled note certificates"
else
    fail "epoch $TALLY_EPOCH selected no certificate at all"
fi
if [ "$TALLY_TIER" = "hard" ]; then
    success "epoch $TALLY_EPOCH is tier=$TALLY_TIER under the note-weighted certificate"
else
    fail "epoch $TALLY_EPOCH is tier=$TALLY_TIER"
fi

EPOCH_AGREE=1
EPOCH_WHY=""
is_real_hash "$TALLY_ROOT"   || { EPOCH_AGREE=0; EPOCH_WHY="node0's vote-set root is '$TALLY_ROOT'"; }
is_real_hash "$TALLY_DIGEST" || { EPOCH_AGREE=0; EPOCH_WHY="node0's epoch state digest is '$TALLY_DIGEST'"; }
for ((n=1; n<NUM_NODES; n++)); do
    PEER_EI="$(rpc "$n" getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
    [ "$(jget "$PEER_EI" finality_certificate)" = "$TALLY_CERT" ] || { EPOCH_AGREE=0; EPOCH_WHY="node$n has a different certificate"; }
    [ "$(jget "$PEER_EI" vote_set_root)" = "$TALLY_ROOT" ]        || { EPOCH_AGREE=0; EPOCH_WHY="node$n has a different vote-set root"; }
    [ "$(jget "$PEER_EI" epoch_state_digest)" = "$TALLY_DIGEST" ] || { EPOCH_AGREE=0; EPOCH_WHY="node$n has a different epoch state digest"; }
done
if [ "$EPOCH_AGREE" -eq 1 ]; then
    success "every node agrees on epoch $TALLY_EPOCH's certificate, vote-set root (${TALLY_ROOT:0:16}) and state digest (${TALLY_DIGEST:0:16})"
else
    fail "epoch $TALLY_EPOCH's state is missing or divergent: $EPOCH_WHY"
fi

# ============================================================
# Soak with every lane live, off unless IV5_COMBINED_SOAK_MINUTES is set. Runs before the
# supply-cap section so emission is still the ordinary schedule.
SOAK_MINUTES="${IV5_COMBINED_SOAK_MINUTES:-0}"
if is_int "$SOAK_MINUTES" && [ "$SOAK_MINUTES" -gt 0 ]; then
    header "19b. Soak: $SOAK_MINUTES minutes of consecutive epochs"

    # Anything a healthy fleet never logs. Counted fleet-wide and compared per epoch, so one
    # occurrence anywhere fails the epoch it appeared in.
    SOAK_BAD='block mints value|ConnectBlockNoteVotes: rejected|InvalidChainFound: invalid block|IV5 pool balance|negative money supply|coinbase reward exceeded'
    soak_bad_count() {
        local total=0 n c
        for ((n=0; n<NUM_NODES; n++)); do
            c="$(grep -acE "$SOAK_BAD" "$(node_log "$n")" 2>/dev/null)"
            is_int "${c:-x}" || c=0
            total=$((total + c))
        done
        echo "$total"
    }

    SOAK_END=$(( $(date +%s) + SOAK_MINUTES * 60 ))
    SOAK_EPOCHS=0
    SOAK_BAD_EPOCHS=0
    SOAK_E=$(( ( $(height 0) - 11 ) / 300 + 2 ))
    while [ "$(date +%s)" -lt "$SOAK_END" ]; do
        E="$SOAK_E"
        B="$(epoch_start "$E")"
        BAD_BEFORE="$(soak_bad_count)"
        vote_round "$B" || { fail "soak: the epoch $E vote round failed"; SOAK_BAD_EPOCHS=$((SOAK_BAD_EPOCHS + 1)); break; }
        TOP=$(( B + FINALITY_VOTE_WINDOW_BLOCKS + 6 ))
        mine_to 0 "$TOP" || { fail "soak: could not mine past epoch $E's window"; SOAK_BAD_EPOCHS=$((SOAK_BAD_EPOCHS + 1)); break; }
        wait_sync "$TOP" || { fail "soak: the fleet did not sync past epoch $E's window"; SOAK_BAD_EPOCHS=$((SOAK_BAD_EPOCHS + 1)); break; }

        WHY=""
        TV="$(votes_in_range 0 "$B" $(( B + FINALITY_VOTE_WINDOW_BLOCKS - 1 )))"
        { is_int "${TV:-x}" && [ "$TV" -ge 2 ]; } || WHY="$WHY transparent_votes=${TV:-?}"

        NV_TXID="$(grep -aF "ProducePrivacyVNextNoteVote: epoch=$E " "$(node_log 0)" | tail -1 | sed -n 's/.*txid=\([0-9a-f]*\).*/\1/p')"
        NV_H=""
        if [ -n "$NV_TXID" ]; then
            NV_FULL="$(rpc 0 listtransactions "*" 50 2>/dev/null | grep -o "\"txid\" : \"$NV_TXID[0-9a-f]*\"" | head -1 | cut -d'"' -f4)"
            [ ${#NV_FULL} -eq 64 ] && NV_H="$(tx_height 0 "$NV_FULL")"
            if ! is_int "${NV_H:-x}" || [ "$NV_H" -lt "$B" ] || [ "$NV_H" -ge $(( B + FINALITY_VOTE_WINDOW_BLOCKS )) ]; then
                # The wallet listing does not always carry a vote; scan the window instead.
                NV_H=""
                for ((h=B; h<B+FINALITY_VOTE_WINDOW_BLOCKS; h++)); do
                    if block_json 0 "$h" | grep -q "\"$NV_TXID"; then NV_H="$h"; break; fi
                done
            fi
            is_int "${NV_H:-x}" || WHY="$WHY note_vote_unmined=$NV_TXID"
        else
            WHY="$WHY note_vote_not_built"
        fi

        FIN_AS_OF="$(jget "$(rpc 0 getepochinfo $((E - 1)) 2>/dev/null)" finalized_height_as_of)"
        [ "$FIN_AS_OF" = "$(epoch_start $((E - 1)))" ] || WHY="$WHY finalized_as_of=${FIN_AS_OF:-?}"

        BH0="$(block_hash 0 "$TOP")"
        for ((n=1; n<NUM_NODES; n++)); do
            [ ${#BH0} -eq 64 ] && [ "$(block_hash "$n" "$TOP")" = "$BH0" ] || WHY="$WHY node${n}_diverged"
        done

        MP="$(rpc 0 getrawmempool 2>/dev/null | grep -c '"')"
        { is_int "${MP:-x}" && [ "$MP" -le 20 ]; } || WHY="$WHY mempool=${MP:-?}"

        BAD_AFTER="$(soak_bad_count)"
        [ "$BAD_AFTER" = "$BAD_BEFORE" ] || WHY="$WHY bad_log_lines=$((BAD_AFTER - BAD_BEFORE))"

        SOAK_EPOCHS=$((SOAK_EPOCHS + 1))
        if [ -z "$WHY" ]; then
            log "  soak epoch $E: transparent_votes=$TV note_vote_at=$NV_H finalized_as_of=$FIN_AS_OF converged"
        else
            fail "soak epoch $E:$WHY"
            SOAK_BAD_EPOCHS=$((SOAK_BAD_EPOCHS + 1))
        fi
        SOAK_E=$((SOAK_E + 1))
    done
    if [ "$SOAK_EPOCHS" -gt 0 ] && [ "$SOAK_BAD_EPOCHS" -eq 0 ]; then
        success "soak: $SOAK_EPOCHS consecutive epochs over $SOAK_MINUTES minutes, each with two transparent votes, a mined note vote, finality keeping pace, one chain and no conservation or record error"
    else
        fail "soak: $SOAK_BAD_EPOCHS of $SOAK_EPOCHS epochs failed"
    fi
fi

# ============================================================
header "20. Value conservation with every minting path live"
# ============================================================

# Pool and issued supply are consensus state; divergence is an unsurfaced
# chain split.
POOL0="$(pool_value 0)"
SUPPLY0="$(money_supply 0)"
CONS_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    feq "$(pool_value "$n")" "$POOL0"     || { CONS_OK=0; fail "node$n's pool balance is $(pool_value "$n") against node0's $POOL0"; }
    feq "$(money_supply "$n")" "$SUPPLY0" || { CONS_OK=0; fail "node$n's issued supply is $(money_supply "$n") against node0's $SUPPLY0"; }
done
if [ "$CONS_OK" -eq 1 ]; then
    success "every node computes the same pool balance ($POOL0 INN) and the same issued supply ($SUPPLY0 INN)"
fi

# moneysupply is TOTAL issued value. ConnectBlock gives an IV5 transaction a
# synthetic value-out equal to its pool absorption, so pool value must be a
# subset of supply.
if fgt "$POOL0" 0 && fgt "$SUPPLY0" 0 && ! fgt "$POOL0" "$SUPPLY0"; then
    TRANSPARENT0="$(fsub "$SUPPLY0" "$POOL0")"
    success "the $POOL0 INN pool is inside the $SUPPLY0 INN of issued supply, leaving $TRANSPARENT0 INN circulating transparently"
else
    fail "the pool is not inside the issued supply (supply=$SUPPLY0 pool=$POOL0); shielded value was credited without being minted"
fi

# The cap bounds total issuance, pool included.
CAP_HEADROOM="$(fsub "$SUPPLY_CAP_INN" "$SUPPLY0")"
log "  supply-cap headroom is $CAP_HEADROOM INN against a $SUPPLY_CAP_INN INN cap"
log "  the cap bounds issued supply with the pool inside it, so a shield moves value without buying headroom"

# ============================================================
header "21. The supply cap clamps issuance with everything else live"
# ============================================================

# Retighten the cap just above issued supply with every lane running. A binding cap must
# reduce the subsidy, not reject the block (settlement outputs are must-pay).
CAP_TIP="$(height 0)"
CAP_EPOCH=$(( ( CAP_TIP - 11 ) / 300 + 1 ))
CAP_SETTLEMENT=$(( $(epoch_start "$CAP_EPOCH") + 24 ))
# The next settlement strictly above the tip, so the window always opens just past
# one and the following one is a whole epoch away.
[ "$CAP_SETTLEMENT" -le "$CAP_TIP" ] && CAP_SETTLEMENT=$(( $(epoch_start $(( CAP_EPOCH + 1 ))) + 24 ))
log "stepping past the settlement at $CAP_SETTLEMENT before retightening the cap (tip $CAP_TIP)"
mine_to 0 $(( CAP_SETTLEMENT + 6 )) || { fail "could not mine past the settlement height"; exit 1; }
wait_sync $(( CAP_SETTLEMENT + 6 )) || { fail "the fleet did not follow past the settlement height"; exit 1; }

SUPPLY_BEFORE="$(money_supply 0)"
TIGHT_CAP_INN="$(python3 -c "print(int(float('$SUPPLY_BEFORE')) + $SUPPLY_CAP_TIGHTEN_INN)")"
TIGHT_CAP="$(python3 -c "print(int($TIGHT_CAP_INN) * 100000000)")"
CAP_BASELINE_CB="$(coinbase_value 0 "$(height 0)")"
log "retightening the cap from $SUPPLY_CAP_INN INN to $TIGHT_CAP_INN INN, against an issued supply of $SUPPLY_BEFORE INN"

for ((n=0; n<NUM_NODES; n++)); do
    stop_node "$n" || warn "node$n needed a kill before the cap restart"
    sed -i.bak "s/^regtestsupplycap=.*/regtestsupplycap=$TIGHT_CAP/" "$(node_dir "$n")/innova.conf"
    rm -f "$(node_dir "$n")/innova.conf.bak"
done
for ((n=0; n<NUM_NODES; n++)); do
    start_node "$n" || { fail "node$n did not restart with the tightened cap"; exit 1; }
done
connect_mesh
wait_peers || warn "the mesh did not fully re-form after the cap restart"
rpc 0 walletpassphrase "$WALLETPASS" 1000000 >/dev/null 2>&1

CAP_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    grep -qF "Supply-cap rehearsal: height=$SUPPLY_CAP_HEIGHT cap=$TIGHT_CAP" "$(node_log "$n")" 2>/dev/null || CAP_OK=0
done
if [ "$CAP_OK" -eq 1 ]; then
    success "every node came back enforcing the $TIGHT_CAP_INN INN cap"
else
    fail "a node did not report the tightened cap"
    exit 1
fi

# The reserve is height-only and clamped to the subsidy, so the first clamped
# block pays headroom less the reserve and the next pays nothing; supply rests
# below the cap.
CAP_START="$(height 0)"
mine_to 0 $(( CAP_START + CAP_DRAIN_BLOCKS )) || { fail "the chain stopped producing blocks once the cap bound"; exit 1; }
wait_sync $(( CAP_START + CAP_DRAIN_BLOCKS )) || { fail "peers did not follow the chain past the cap"; exit 1; }
success "the chain kept producing blocks across the cap: $CAP_START -> $(height 0)"

SUPPLY_AFTER="$(money_supply 0)"
if ! fgt "$SUPPLY_AFTER" "$TIGHT_CAP_INN"; then
    success "the issued supply is $SUPPLY_AFTER INN and never passed the $TIGHT_CAP_INN INN cap"
else
    fail "the issued supply is $SUPPLY_AFTER INN, ABOVE the $TIGHT_CAP_INN INN cap: issuance was not clamped"
fi

# The clamp has to have actually bitten, or the assertion above is satisfied by a
# cap that was simply never approached.
CAP_LAST_CB="$(coinbase_value 0 "$(height 0)")"
if [ -n "$CAP_BASELINE_CB" ] && [ -n "$CAP_LAST_CB" ] && fgt "$CAP_BASELINE_CB" "$CAP_LAST_CB"; then
    success "the producer's claim fell from $CAP_BASELINE_CB to $CAP_LAST_CB: the clamp is what stopped issuance, not the schedule"
else
    fail "the coinbase claim did not fall across the cap ($CAP_BASELINE_CB -> $CAP_LAST_CB); the cap may never have bound"
fi

# Consecutive blocks must leave issued supply unchanged; fees are not
# issuance.
CAP_S1="$(money_supply 0)"
mine_to 0 $(( $(height 0) + 3 )) || { fail "could not mine past the cap"; exit 1; }
wait_sync "$(height 0)" || warn "the fleet lagged past the cap"
CAP_S2="$(money_supply 0)"
if feq "$CAP_S1" "$CAP_S2"; then
    success "three further blocks issued nothing: the supply is pinned at $CAP_S2 INN"
else
    fail "the supply moved from $CAP_S1 to $CAP_S2 while the cap was binding; $CAP_DRAIN_BLOCKS blocks were not enough for the headroom to empty"
fi
CAP_GAP="$(fsub "$TIGHT_CAP_INN" "$CAP_S2")"
log "  the supply came to rest $CAP_GAP INN below the $TIGHT_CAP_INN INN cap"
assert_converged "a post-cap block" "$(height 0)"

CAP_AGREE=1
for ((n=1; n<NUM_NODES; n++)); do
    feq "$(money_supply "$n")" "$CAP_S2" || CAP_AGREE=0
done
if [ "$CAP_AGREE" -eq 1 ]; then
    success "every node agrees the capped supply is $CAP_S2 INN"
else
    fail "the nodes disagree about the capped supply: node1=$(money_supply 1) node2=$(money_supply 2) against $CAP_S2"
fi

# ============================================================
header "22. The fleet reports no errors"
# ============================================================

ERR_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    E="$(jget "$(rpc "$n" getinfo 2>/dev/null)" errors)"
    [ -z "$E" ] || { fail "node$n reports errors: $E"; ERR_OK=0; }
    if grep -qiE "IV5 pool balance|takes more from the pool|does not validate|IV5 finalized context rejected|coinbase reward exceeded|block mints value|negative money supply" \
            "$(node_log "$n")" 2>/dev/null; then
        fail "node$n log carries a pool, reward or validation complaint"
        grep -iE "IV5 pool balance|takes more from the pool|does not validate|IV5 finalized context rejected|coinbase reward exceeded|block mints value|negative money supply" \
            "$(node_log "$n")" | tail -3
        ERR_OK=0
    fi
done
[ "$ERR_OK" -eq 1 ] && success "no node reports errors or pool, reward and validation complaints"

# ============================================================
header "Features live simultaneously"
# ============================================================
echo "  1. IDAG ordering + DAGKnight        section 4"
echo "  2. FCMP++ pool (Boundary B)         sections 5, 9"
echo "  3. Disclosure masks 0-7             section 14"
echo "  4. Note finality voting             sections 17, 19"
echo "  5. IDNS reset + name resolution     section 7"
echo "  6. IV5 coinbase fee note            sections 6, 14, 18"
echo "  7. Total-supply cap                 sections 20, 21"
echo "  8. Private collateralnode           sections 13, 15 (registration; payment is unreachable on regtest)"
echo "  +  Proof-of-data stamp              section 8"

print_results
[ "$FAILED" -eq 0 ] || exit 1
exit 0
