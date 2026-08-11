#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 note finality vote regtest: drive CNoteFinalityVote end to end.
#
# A note vote is the IV5-native private finality vote: an FCMP++ membership proof
# over the IV5 note tree, an ed25519 sigma authorisation, Shamir tally shares to
# the canonical committee, and a weight-floor range proof. It anchors to an
# ALREADY-FINALIZED epoch's IV5 root, so this needs a chain that finalizes, which
# one node can never do: a finalized height needs FINALITY_CONFIRMATION_EPOCHS
# consecutive HARD epochs, a HARD epoch needs >= FINALITY_MIN_VOTERS distinct
# transparent voters, and one wallet casts exactly one vote. Three wallets, each
# casting its own transparent vote at every boundary, is the smallest fleet that
# reaches a finalized height. Only node0 holds an IV5 seed and IV5 notes, so only
# node0 can cast a note vote and the observation stays deterministic.
#
# Configuration this harness needs that the spend harness does not:
#   -regtestiv5notevote=<h>  the note-vote fork; init refuses a height below
#                            Boundary B (src/init.cpp)
#   -finalitytallyprivkey    the ONLY committee key a node is configured with.
#                            There is no pinned committee any more: seats are
#                            drawn per term from the IV5 collateral registry, and
#                            a node serves a seat only when the drawn set names
#                            the pubkey of this secret
#   -finalityvotemode=auto   "transparent" returns before the note vote is even
#                            attempted
#   -debug -debugnet         every producer gate log is behind if(fDebug), and
#                            the peer-side receive log is behind fDebugNet
#
# The specific untested claim this exists to settle (F2): the producer builds its
# vote against a DETERMINISTIC anchor, but only pushes it if AddPendingNoteVote
# succeeds, and that calls CheckNoteVoteForContext with nContextHeight = -1 --
# the relay branch -- which resolves the anchor through
# CDAGManager::GetLastFinalizedEpochState. That function skips every epoch whose
# LEGACY hashCurveRoot is zero, and on a pure-IV5 chain with no ring-signature
# history it is zero for every epoch. If it fires, the node builds a valid vote,
# its own relay check refuses it as local state, the vote is never pushed, and
# the note has already been burned in the per-epoch cast set.
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
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_NOTE_VOTE_TEST_DIR:-${TEST_DIR:-/tmp/innova_iv5_notevote_$$}}"
NUM_NODES=3
BASE_PORT="${IV5_NOTE_VOTE_BASE_PORT:-28650}"
BASE_RPC="${IV5_NOTE_VOTE_BASE_RPC:-28700}"
BASE_IDNS="${IV5_NOTE_VOTE_BASE_IDNS:-8760}"
RPCUSER="iv5notevote"
RPCPASS="iv5notevotepass"
WALLETPASS="iv5notevotewallet"

BOUNDARY_B=311
# The note-vote fork. init refuses anything below Boundary B, so this is the
# earliest legal height and every epoch boundary from 2 on is an attempt.
NOTE_VOTE_HEIGHT=311

FUND_AMOUNT=100
FUND_HEIGHT=20
FUND_CONFIRM_HEIGHT=25
SHIELD_HEIGHT=330
SHIELD_CONFIRM_HEIGHT=345
SHIELD_SWEEPS=4

# Epochs 2, 3 and 4 are the HARD run; epoch 4 ends at 1210.
FINALIZED_HEIGHT=1210
FINALIZED_EPOCH=4

# Boundaries observed for note votes, all after the finalized height exists.
NOTE_VOTE_EPOCHS="5 6 7"
# Blocks mined past a boundary while the vote is pending. Stays inside
# FINALITY_VOTE_INCLUSION_WINDOW (24) so every one of them may carry the vote.
NOTE_VOTE_WINDOW=10
# Seconds the chain is held at the boundary. ThreadFinalityVoter wakes on a 5s
# cycle and the note vote's proofs are the slow part of the call.
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

# OP_RETURN payload tag of a note-vote coinbase envelope ("IFNV").
NOTE_VOTE_TAG_HEX="49464e56"
# OP_RETURN payload tag of a canonical tally-certificate envelope ("IFCC").
TALLY_CERT_TAG_HEX="49464343"

# The epoch whose note tally is driven to a certificate. It must be one of
# NOTE_VOTE_EPOCHS, and the certificate has to be carried by a block of that same
# epoch: the deterministic tier reads the epoch's OWN blocks, so a cert carried a
# whole epoch later is block-valid and tier-irrelevant.
TALLY_EPOCH=5
# H_E + FINALITY_VOTE_INCLUSION_WINDOW is the freeze point: before it the counted
# note-vote set still grows and no certificate can satisfy connect-time coverage.
TALLY_WINDOW_CLOSE=$(( 11 + (TALLY_EPOCH - 1) * 300 + 24 ))
# Blocks mined past the freeze point, inside the same epoch, for the committee to
# converge and for a miner to carry the certificate it assembles.
TALLY_CARRY_HEIGHT=$(( TALLY_WINDOW_CLOSE + 40 ))
# Seconds the chain rests at the freeze point. ThreadFinalityVoter drives
# ProcessFinalityTallyCommittee on a 5s cycle, and the pass, the partial exchange
# and the M-of-N signature round each need one.
TALLY_SETTLE=45

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

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
        for ((n=0; n<NUM_NODES; n++)); do
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

# Mine on NODE until TARGET. Re-arms the miner if height stalls: setgenerate
# takes a block count, and a template that loses a race consumes one.
mine_to() {
    local node="$1" target="$2" h last stall=0
    h="$(height "$node")"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    last="$h"
    rpc "$node" setgenerate true $((target - h)) >/dev/null 2>&1
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
            rpc "$node" setgenerate true $((target - h)) >/dev/null 2>&1
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

# The producer's own account of one epoch, straight out of node0's log.
# All of these are printf'd by ProduceNoteFinalityVote; the gate lines are
# behind fDebug, which is why this harness runs with -debug.
producer_success()  { grep -F "ProduceNoteFinalityVote: epoch=$1 " "$(node_log 0)" 2>/dev/null; }
producer_refused()  { grep -F "ProduceNoteFinalityVote: epoch $1 vote was refused locally:" "$(node_log 0)" 2>/dev/null; }
producer_dup_tag()  { grep -F "ProduceNoteFinalityVote: epoch $1 already carries this note's tag" "$(node_log 0)" 2>/dev/null; }

# Everything the producer said, for a diagnosis dump.
producer_all()      { grep -F "ProduceNoteFinalityVote:" "$(node_log 0)" 2>/dev/null; }

# The tag the producer reported for an epoch (its first 10 hex chars).
producer_tag() {
    producer_success "$1" | head -1 | sed -n 's/.*tag=\([0-9a-f]*\).*/\1/p'
}

# Tagged finality envelopes carried by a block's coinbase, one scriptPubKey hex
# per line. An envelope is OP_RETURN <tag || object>, so the tag sits immediately
# after the push opcode whatever its width.
tagged_scripts() {
    local node="$1" h="$2" tag_hex="$3" bh cb
    bh="$(block_hash "$node" "$h")"
    [ ${#bh} -eq 64 ] || return 1
    cb="$(rpc "$node" getblock "$bh" 2>/dev/null | python3 -c '
import json, sys
try: print(json.load(sys.stdin)["tx"][0])
except Exception: pass
')"
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

notevote_scripts() { tagged_scripts "$1" "$2" "$NOTE_VOTE_TAG_HEX"; }

# Every distinct note-vote envelope a node sees in [from, to], and the height of
# the first block carrying each. Prints "height hex" lines.
notevotes_in_range() {
    local node="$1" from="$2" to="$3" h s
    for ((h=from; h<=to; h++)); do
        while read -r s; do
            [ -n "$s" ] && echo "$h $s"
        done < <(notevote_scripts "$node" "$h" 2>/dev/null)
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
        # A note vote is the private tier: "transparent" makes the producer
        # return before it is attempted at all.
        echo "finalityvotemode=auto"
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
    local n
    for ((n=0; n<NUM_NODES; n++)); do rpc "$n" setgenerate false 0 >/dev/null 2>&1 || true; done
    for ((n=0; n<NUM_NODES; n++)); do rpc "$n" stop >/dev/null 2>&1 || true; done
    for ((n=0; n<NUM_NODES; n++)); do
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

# No pinned committee exists any more, on any network. Assert the negative
# directly: nothing configures a committee, and the resolver says so.
PINNED=0
for ((n=0; n<NUM_NODES; n++)); do
    grep -q "finalitytallypubkey" "$(node_dir "$n")/innova.conf" && PINNED=1
    grep -q "finalitytallythreshold" "$(node_dir "$n")/innova.conf" && PINNED=1
done
if [ "$PINNED" -eq 0 ]; then
    success "no node is configured with a committee key or threshold"
else
    fail "a node still carries pinned committee configuration"
fi

DRAW_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    [ "$(jget "$FI" committee_source)" = "collateral_registry_draw" ] || DRAW_OK=0
    [ "$(jget "$FI" committee_seated)" = "false" ] || DRAW_OK=0
done
if [ "$DRAW_OK" -eq 1 ]; then
    success "every node resolves its committee from the collateral registry draw, and none is seated yet"
else
    fail "a node did not report an unseated collateral-registry-draw committee"
fi

# Everything from section 7 on needs a SEATED committee, and seats are won, not
# configured. What this harness still has to grow, in order:
#
#   1. node0 imports COMMITTEE_WIFS so its wallet holds the private half of each
#      member key (collateralnode finality-register refuses a key it cannot
#      decrypt to), and each node keeps its own finalitytallyprivkey.
#   2. After the finalized height exists, node0 carves six 25000 INN IV5 notes
#      with z_iv5transfer -- two per member key -- and lets the next epoch build
#      put them in the tree.
#   3. node0 runs `collateralnode finality-register <pubkey> <txid:n> confirm`
#      six times. Six rows is the floor: regtest draws 3 seats and refuses a
#      registry smaller than 2N. Two rows per key and one seat per key means the
#      draw seats exactly the three node keys whichever rows win.
#   4. Every registration must confirm at or below the first height of epoch
#      (term - 2). The seats then appear when the epoch ending the term's lead-in
#      is built, and the term they serve is the two epochs after that.
#   5. NOTE_VOTE_EPOCHS and TALLY_EPOCH move into that term.
#
# Until then the sections below have no committee to share to and will fail.
SEATED="$(jget "$(rpc 0 getfinalityinfo 2>/dev/null)" committee_seated)"
if [ "$SEATED" != "true" ]; then
    fail "no committee is seated: the registration flow above is not implemented in this harness yet, so the note-vote and certificate rounds cannot run"
fi

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

# Negative control first: only node0 holds stake at the epoch-1 boundary, so its
# vote connects but the epoch stays below FINALITY_MIN_VOTERS.
vote_round 11 || { fail "epoch 1 vote round failed"; exit 1; }
E1_VOTES="$(votes_in_range 0 11 14)"
if [ "$E1_VOTES" = "1" ]; then
    success "epoch 1 carried exactly one connected finality vote"
else
    fail "epoch 1 carried $E1_VOTES finality votes, expected 1"
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

# A vote needs ONE note worth at least FINALITY_MIN_VOTE_WEIGHT (100 INN), so
# sweep several addresses: each sweep moves one address's whole value with no
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

# A note is only spendable -- and only votable -- once an epoch build has put it
# in the IV5 tree and assigned its leaf index, which happens when the chain
# crosses into the next epoch. Nothing before this boundary could have voted.
INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
POOL_BAL="$(jget "$INFO" privacy_vnext_balance)"
POOL_NOTES="$(jget "$INFO" privacy_vnext_note_count)"
TREE_SIZE="$(jget "$INFO" privacy_vnext_tree_size)"
if [ "$(python3 -c "print(1 if float('${POOL_BAL:-0}') >= 100 else 0)")" = "1" ] && \
   is_int "$TREE_SIZE" && [ "$TREE_SIZE" -gt 0 ]; then
    success "node0 holds $POOL_BAL INN across $POOL_NOTES leaf-indexed note(s), tree=$TREE_SIZE"
else
    fail "node0 has no votable IV5 note (balance=$POOL_BAL notes=$POOL_NOTES tree=$TREE_SIZE)"
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
header "6. Note-vote rounds over the finalized chain"
# ============================================================

# Epoch 5 is the first boundary at which a finalized height can exist, so each
# round below both drives the transparent votes that keep finality advancing and
# gives node0 its one chance that epoch to cast a note vote.
for E in $NOTE_VOTE_EPOCHS; do
    B=$(( 11 + (E - 1) * 300 ))
    log "epoch $E: holding the chain at boundary $B for ${NOTE_VOTE_SETTLE}s"
    vote_round "$B" "$NOTE_VOTE_SETTLE" "$NOTE_VOTE_WINDOW" || {
        fail "epoch $E vote round failed"
        exit 1
    }
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

# The anchor a note vote must prove against: the finalized epoch's IV5 tree.
ANCHOR_TREE_ROOT="$(jget "$E4" iv5_tree_root)"
ANCHOR_TREE_SIZE="$(jget "$E4" iv5_tree_size)"
ANCHOR_CURVE_ROOT="$(jget "$E4" curve_root)"
if [ ${#ANCHOR_TREE_ROOT} -ge 64 ] && ! is_zero_hex "$ANCHOR_TREE_ROOT" && \
   is_int "$ANCHOR_TREE_SIZE" && [ "$ANCHOR_TREE_SIZE" -gt 0 ]; then
    success "the finalized epoch carries an IV5 tree ($ANCHOR_TREE_SIZE leaves, root ${ANCHOR_TREE_ROOT:0:12})"
else
    fail "the finalized epoch carries no IV5 tree (root='$ANCHOR_TREE_ROOT' size='$ANCHOR_TREE_SIZE')"
    exit 1
fi

# ============================================================
header "7. (a) node0 builds a note vote"
# ============================================================

BUILT_EPOCHS=""
for E in $NOTE_VOTE_EPOCHS; do
    if [ -n "$(producer_success "$E")" ] || [ -n "$(producer_refused "$E")" ] || \
       [ -n "$(producer_dup_tag "$E")" ]; then
        BUILT_EPOCHS="$BUILT_EPOCHS $E"
    fi
done
if [ -n "$BUILT_EPOCHS" ]; then
    success "node0 built a note vote in epoch(s)$BUILT_EPOCHS"
else
    fail "node0 never built a note vote; the producer stopped at a gate:"
    producer_all | tail -12
    if [ -z "$(producer_all)" ]; then
        fail "the producer logged nothing at all -- it was never reached"
    fi
fi

# ============================================================
header "8. (b) node0's own relay check accepts the vote  [F2]"
# ============================================================

# ProduceNoteFinalityVote prints its success line only AFTER AddPendingNoteVote
# returns true, and prints "vote was refused locally" when it does not. So the
# presence of one and the absence of the other is exactly the F2 question.
ACCEPTED_EPOCHS=""
REFUSED_EPOCHS=""
F2_REASON=""
F2_LINE=""
for E in $NOTE_VOTE_EPOCHS; do
    if [ -n "$(producer_success "$E")" ]; then
        ACCEPTED_EPOCHS="$ACCEPTED_EPOCHS $E"
    elif [ -n "$(producer_refused "$E")" ]; then
        REFUSED_EPOCHS="$REFUSED_EPOCHS $E"
        if [ -z "$F2_LINE" ]; then
            F2_LINE="$(producer_refused "$E" | head -1)"
            F2_REASON="${F2_LINE##*refused locally: }"
        fi
    fi
done

if [ -n "$ACCEPTED_EPOCHS" ] && [ -z "$REFUSED_EPOCHS" ]; then
    success "every built note vote passed node0's own relay check (epoch(s)$ACCEPTED_EPOCHS)"
elif [ -n "$REFUSED_EPOCHS" ]; then
    fail "node0 REFUSED ITS OWN note vote in epoch(s)$REFUSED_EPOCHS"
    fail "  reason: $F2_REASON"
    echo "  $F2_LINE"
else
    fail "no note vote reached node0's relay check at all"
fi

# ============================================================
header "9. (c) Peers receive the note vote"
# ============================================================

RECEIVED_OK=1
for ((n=1; n<NUM_NODES; n++)); do
    RX="$(grep -cF "received: fnvote" "$(node_log "$n")" 2>/dev/null)"
    RX="${RX:-0}"
    REJ="$(grep -F "rejected note vote from peer" "$(node_log "$n")" 2>/dev/null | head -1)"
    if is_int "$RX" && [ "$RX" -gt 0 ] && [ -z "$REJ" ]; then
        log "  node$n received $RX note vote message(s)"
    else
        RECEIVED_OK=0
        [ -n "$REJ" ] && fail "node$n rejected a relayed note vote: $REJ"
    fi
done
if [ "$RECEIVED_OK" -eq 1 ]; then
    success "both peers received the note vote over $NUM_NODES-node relay and none rejected it"
else
    fail "the note vote did not reach both peers (no fnvote message on at least one node)"
fi

# ============================================================
header "10. (d) The vote is carried in a coinbase and connects"
# ============================================================

CARRIED_TOTAL=0
CARRIED_EPOCHS=""
CARRY_HEIGHTS=""
for E in $NOTE_VOTE_EPOCHS; do
    B=$(( 11 + (E - 1) * 300 ))
    ROWS="$(notevotes_in_range 0 "$B" $((B + NOTE_VOTE_WINDOW)))"
    DISTINCT="$(echo "$ROWS" | awk 'NF{print $2}' | sort -u | grep -c . || true)"
    is_int "$DISTINCT" || DISTINCT=0
    if [ "$DISTINCT" -gt 0 ]; then
        FIRST_H="$(echo "$ROWS" | awk 'NF{print $1; exit}')"
        CARRIED_EPOCHS="$CARRIED_EPOCHS $E"
        CARRY_HEIGHTS="$CARRY_HEIGHTS $FIRST_H"
        CARRIED_TOTAL=$((CARRIED_TOTAL + DISTINCT))
        log "  epoch $E: $DISTINCT distinct note-vote envelope(s), first at height $FIRST_H"
    else
        log "  epoch $E: no note-vote envelope in [$B, $((B + NOTE_VOTE_WINDOW))]"
    fi
done

if [ "$CARRIED_TOTAL" -gt 0 ]; then
    success "coinbases carry $CARRIED_TOTAL note-vote envelope(s) across epoch(s)$CARRIED_EPOCHS"
else
    fail "no coinbase carried a note-vote envelope"
fi

# A block whose ConnectBlockNoteVotes rejected the vote is invalid, so a carrier
# that every node holds at the same height is a connected vote on every node.
CONVERGED=1
for H in $CARRY_HEIGHTS; do
    BH0="$(block_hash 0 "$H")"
    for ((n=1; n<NUM_NODES; n++)); do
        [ "$(block_hash "$n" "$H")" = "$BH0" ] || CONVERGED=0
    done
done
CONNECT_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    R="$(grep -F "ConnectBlockNoteVotes: rejected vote in block" "$(node_log "$n")" 2>/dev/null | head -1)"
    [ -n "$R" ] && CONNECT_REJECT="node$n: $R"
done
if [ -n "$CARRY_HEIGHTS" ] && [ "$CONVERGED" -eq 1 ] && [ -z "$CONNECT_REJECT" ]; then
    success "every carrier block converged fleet-wide, so the vote connected on all $NUM_NODES nodes"
elif [ -n "$CONNECT_REJECT" ]; then
    fail "a node rejected a note vote at connect: $CONNECT_REJECT"
elif [ -z "$CARRY_HEIGHTS" ]; then
    fail "there was no carrier block to check for convergence"
else
    fail "a carrier block did not converge across the fleet"
fi

# ============================================================
header "11. (e) One note yields at most one vote per epoch"
# ============================================================

# The tag T_e = x*U_e is one note's single identity for one epoch. node0 holds
# several notes but the producer casts once per epoch, so each epoch must show
# exactly one production and exactly one distinct envelope, and the tag must
# differ between epochs because the epoch generator does.
DEDUP_OK=1
TAGS=""
for E in $NOTE_VOTE_EPOCHS; do
    B=$(( 11 + (E - 1) * 300 ))
    NPROD="$(producer_success "$E" | grep -c . || true)"
    is_int "$NPROD" || NPROD=0
    NENV="$(notevotes_in_range 0 "$B" $((B + NOTE_VOTE_WINDOW)) | awk 'NF{print $2}' | sort -u | grep -c . || true)"
    is_int "$NENV" || NENV=0
    [ "$NPROD" -le 1 ] || { DEDUP_OK=0; fail "epoch $E produced $NPROD note votes, expected at most 1"; }
    [ "$NENV" -le 1 ]  || { DEDUP_OK=0; fail "epoch $E carried $NENV distinct note-vote envelopes, expected at most 1"; }
    T="$(producer_tag "$E")"
    [ -n "$T" ] && TAGS="$TAGS $T"
done
NTAGS="$(echo "$TAGS" | tr ' ' '\n' | grep -c . || true)"
NUNIQ="$(echo "$TAGS" | tr ' ' '\n' | grep . | sort -u | grep -c . || true)"
is_int "$NTAGS" || NTAGS=0
is_int "$NUNIQ" || NUNIQ=0
if [ "$NTAGS" -gt 0 ] && [ "$NTAGS" != "$NUNIQ" ]; then
    DEDUP_OK=0
    fail "the same tag was cast in more than one epoch ($NTAGS votes, $NUNIQ distinct tags)"
fi
if [ "$DEDUP_OK" -eq 1 ] && [ "$NTAGS" -gt 0 ]; then
    success "each epoch cast exactly one note vote under its own tag ($NTAGS epoch(s), $NUNIQ distinct tags)"
elif [ "$DEDUP_OK" -eq 1 ]; then
    fail "no note vote was cast, so the per-epoch tag rule could not be exercised"
fi

# ============================================================
header "12. The note tally committee runs over the counted set"
# ============================================================

# Increment B. Each node is a seat on the canonical committee, decrypts its own
# evaluation of every counted note vote, sums them, seals the sum to the other
# seats, and interpolates M of those partials into an opening of the aggregate a
# validator recomputes from the votes' own commitments.
TALLY_LINE=""
TALLY_NODE=""
for ((n=0; n<NUM_NODES; n++)); do
    L="$(grep -F "ProcessNoteTallyCommitteeEpoch: epoch $TALLY_EPOCH tier=" "$(node_log "$n")" 2>/dev/null | tail -1)"
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
        grep -F "ProcessNoteTallyCommitteeEpoch:" "$(node_log "$n")" 2>/dev/null | tail -3
    done
fi

# The note weight really entered the tier comparison: an opened aggregate of zero
# would mean the committee summed nothing and the tier is transparent-only.
NOTE_ACTIVE="$(echo "$TALLY_LINE" | sed -n 's/.*note_active=\([0-9.]*\).*/\1/p')"
NOTE_COVERED="$(echo "$TALLY_LINE" | sed -n 's/.*covered=\([0-9]*\).*/\1/p')"
if [ -n "$NOTE_ACTIVE" ] && ! feq "${NOTE_ACTIVE:-0}" 0 && \
   is_int "${NOTE_COVERED:-x}" && [ "${NOTE_COVERED:-0}" -gt 0 ]; then
    success "the committee opened $NOTE_COVERED covered note vote(s) to $NOTE_ACTIVE of note weight"
else
    fail "the note tally opened no weight (covered='$NOTE_COVERED' note_active='$NOTE_ACTIVE')"
fi

# Partials are relay/automation state, never consensus input, so the only thing
# that has to be true of them on the wire is that peers accept them.
PART_OK=0
PART_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    RX="$(grep -cF "received: fnpart" "$(node_log "$n")" 2>/dev/null)"
    is_int "${RX:-x}" && [ "${RX:-0}" -gt 0 ] && PART_OK=1
    R="$(grep -F "AddNoteTallyAggregatePartial: rejected partial" "$(node_log "$n")" 2>/dev/null | head -1)"
    [ -n "$R" ] && PART_REJECT="node$n: $R"
done
if [ "$PART_OK" -eq 1 ] && [ -z "$PART_REJECT" ]; then
    success "note tally partials relayed across the fleet and none were rejected"
elif [ -n "$PART_REJECT" ]; then
    fail "a node rejected a relayed note tally partial: $PART_REJECT"
else
    fail "no node received a note tally partial"
fi

# ============================================================
header "13. A v4 note certificate connects in its own epoch"
# ============================================================

# The assembled certificate's hash, straight from the producer. The M-of-N
# signature set is a note certificate's whole authorization: its range proofs are
# entropy-bearing, so no validator can rebuild it byte-for-byte.
# Every hash the fleet assembled, not just the first: a note certificate's range
# proofs carry entropy, so each member's candidate is a different object and more
# than one can reach the threshold. Which of them an epoch selects is decided
# deterministically at connect time, so the epoch's certificate has to be one of
# these -- but not necessarily any particular node's.
NOTE_CERT_HASHES=""
NOTE_CERT_LINE=""
for ((n=0; n<NUM_NODES; n++)); do
    while read -r L; do
        [ -n "$L" ] || continue
        [ -n "$NOTE_CERT_LINE" ] || NOTE_CERT_LINE="$L"
        H="$(echo "$L" | sed -n 's/.*note certificate \([0-9a-f]\{64\}\).*/\1/p')"
        [ -n "$H" ] && NOTE_CERT_HASHES="$NOTE_CERT_HASHES $H"
    done < <(grep -F "FinalityNoteTally: epoch $TALLY_EPOCH note certificate " \
                  "$(node_log "$n")" 2>/dev/null)
done
NOTE_CERT_HASHES="$(echo "$NOTE_CERT_HASHES" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
if [ -n "$NOTE_CERT_HASHES" ]; then
    success "the committee assembled $(echo "$NOTE_CERT_HASHES" | wc -w | tr -d ' ') note certificate(s) for epoch $TALLY_EPOCH"
    log "  $NOTE_CERT_LINE"
else
    fail "no M-of-N note certificate was assembled for epoch $TALLY_EPOCH"
fi

# A certificate envelope in a block of the tally epoch's own span. The
# deterministic tier reads the epoch's OWN blocks, so a certificate carried a
# whole epoch later is block-valid and tier-irrelevant.
CERT_CARRY_HEIGHT=""
for ((h=TALLY_WINDOW_CLOSE; h<=TALLY_CARRY_HEIGHT + 20; h++)); do
    if [ -n "$(tagged_scripts 0 "$h" "$TALLY_CERT_TAG_HEX")" ]; then
        CERT_CARRY_HEIGHT="$h"
        break
    fi
done
if [ -n "$CERT_CARRY_HEIGHT" ]; then
    success "a tally certificate envelope is carried at height $CERT_CARRY_HEIGHT, inside epoch $TALLY_EPOCH"
else
    fail "no tally certificate envelope was carried inside epoch $TALLY_EPOCH [$TALLY_WINDOW_CLOSE, $((TALLY_CARRY_HEIGHT + 20))]"
fi

CERT_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    R="$(grep -F "excluding finality tally certificate" "$(node_log "$n")" 2>/dev/null | tail -1)"
    [ -n "$R" ] && CERT_REJECT="node$n: $R"
done
[ -z "$CERT_REJECT" ] && success "no node excluded a tally certificate from a block it built" \
                      || warn "a node excluded a certificate at some point: $CERT_REJECT"

# ============================================================
header "14. The epoch's tier comes from the note-weighted certificate"
# ============================================================

TALLY_EI="$(rpc 0 getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
TALLY_CERT="$(jget "$TALLY_EI" finality_certificate)"
TALLY_TIER="$(jget "$TALLY_EI" finality_tier)"
TALLY_ROOT="$(jget "$TALLY_EI" vote_set_root)"
TALLY_DIGEST="$(jget "$TALLY_EI" epoch_state_digest)"

if [ -n "$TALLY_CERT" ] && ! is_zero_hex "$TALLY_CERT" && \
   echo " $NOTE_CERT_HASHES " | grep -qF " $TALLY_CERT "; then
    success "epoch $TALLY_EPOCH selected the note certificate ${TALLY_CERT:0:16} (tier=$TALLY_TIER)"
elif [ -n "$TALLY_CERT" ] && ! is_zero_hex "$TALLY_CERT"; then
    fail "epoch $TALLY_EPOCH selected certificate ${TALLY_CERT:0:16}, which is not one of the assembled note certificates:$NOTE_CERT_HASHES"
else
    fail "epoch $TALLY_EPOCH selected no certificate at all (finality_certificate=$TALLY_CERT)"
fi

if [ "$TALLY_TIER" = "hard" ]; then
    success "epoch $TALLY_EPOCH is tier=$TALLY_TIER under the note-weighted certificate"
else
    fail "epoch $TALLY_EPOCH is tier=$TALLY_TIER"
fi

# The counted note votes are committed in hashVoteSetRoot, so fleet-wide equality
# of the root and the whole epoch-state digest is the determinism claim: a
# certificate is a function of the connected chain plus its own bytes, and the
# node-local partial and complaint gossip that produced it never enters one.
EPOCH_AGREE=1
for ((n=1; n<NUM_NODES; n++)); do
    PEER_EI="$(rpc "$n" getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
    [ "$(jget "$PEER_EI" finality_certificate)" = "$TALLY_CERT" ] || EPOCH_AGREE=0
    [ "$(jget "$PEER_EI" vote_set_root)" = "$TALLY_ROOT" ] || EPOCH_AGREE=0
    [ "$(jget "$PEER_EI" epoch_state_digest)" = "$TALLY_DIGEST" ] || EPOCH_AGREE=0
    [ "$(jget "$PEER_EI" finality_tier)" = "$TALLY_TIER" ] || EPOCH_AGREE=0
done
if [ "$EPOCH_AGREE" -eq 1 ]; then
    success "every node agrees on epoch $TALLY_EPOCH's certificate, vote-set root and state digest"
else
    fail "nodes disagree on epoch $TALLY_EPOCH's epoch state -- a note certificate has split the chain"
fi

# ============================================================
header "15. The fleet reports no errors"
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
header "F2 verdict"
# ============================================================

if [ -n "$ACCEPTED_EPOCHS" ] && [ -z "$REFUSED_EPOCHS" ]; then
    echo -e "${GREEN}F2 does NOT fire.${NC} node0's relay check accepted its own note vote in"
    echo "epoch(s)$ACCEPTED_EPOCHS and the vote was pushed to the fleet."
elif [ -n "$REFUSED_EPOCHS" ]; then
    echo -e "${RED}F2 FIRES.${NC} node0 built a valid note vote and then refused it itself."
    echo "  epochs affected:$REFUSED_EPOCHS"
    echo "  refusal:        $F2_LINE"
    echo "  reason string:  $F2_REASON"
    case "$F2_REASON" in
        *"unavailable finalized epoch state"*)
            echo
            echo "  This is the predicted path. AddPendingNoteVote calls"
            echo "  CheckNoteVoteForContext with nContextHeight = -1, whose anchor comes from"
            echo "  CDAGManager::GetLastFinalizedEpochState, and that skips every epoch whose"
            echo "  LEGACY hashCurveRoot is zero."
            echo "  Corroboration from the finalized epoch $FINALIZED_EPOCH itself:"
            echo "    curve_root    = ${ANCHOR_CURVE_ROOT:-<empty>}"
            echo "    iv5_tree_root = ${ANCHOR_TREE_ROOT:-<empty>} ($ANCHOR_TREE_SIZE leaves)"
            if is_zero_hex "$ANCHOR_CURVE_ROOT"; then
                echo "    the legacy curve root IS zero while the IV5 tree is populated, so"
                echo "    GetLastFinalizedEpochState finds nothing and the relay check reports"
                echo "    local state for a vote whose deterministic anchor resolved fine."
            fi
            ;;
        *"already-finalized epoch"*)
            echo "  The relay check saw NO finalized height at all (live GetFinalizedHeight"
            echo "  was zero when the vote was offered), which is a different failure from F2."
            ;;
        *)
            echo "  The refusal is real but the reason is not the predicted anchor path."
            ;;
    esac
    echo
    echo "  The note was already recorded in the per-epoch cast set before the proof, so"
    echo "  each refused epoch cost that note its vote."
else
    echo -e "${YELLOW}Undetermined.${NC} No note vote reached the relay check, so F2 was not exercised."
    echo "  the producer's last words:"
    producer_all | tail -8
fi

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
