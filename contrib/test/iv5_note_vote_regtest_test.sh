#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 note finality vote (op-10) end to end: cast, relay, mine inside the inclusion window, v4 certificate.
# node0/node3 vote in the note lane (node0 mines, encrypted wallet); node1/node2 are transparent voters.

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
NUM_NODES=4
BASE_PORT="${IV5_NOTE_VOTE_BASE_PORT:-$(iv5_port 0 28650)}"
BASE_RPC="${IV5_NOTE_VOTE_BASE_RPC:-$(iv5_port 16 28700)}"
BASE_IDNS="${IV5_NOTE_VOTE_BASE_IDNS:-$(iv5_port 32 8760)}"
RPCUSER="iv5notevote"
RPCPASS="iv5notevotepass"
WALLETPASS="iv5notevotewallet"

# Lanes. A node latches one lane per process.
NOTE_NODES="0 3"
TRANSPARENT_NODES="1 2"
is_note_node() { case " $NOTE_NODES " in *" $1 "*) return 0 ;; esac; return 1; }

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
# node3's transparent funding, shielded in one step. A shield splits its value in two,
# so one of the notes is at least half: 1500 INN always leaves a note above the floor.
NOTE3_FUND=1500

# Epochs 2, 3 and 4 are the HARD run. The third consecutive HARD epoch's record
# carries a finalized height of its own start: epoch 4 finalizes 911.
FINALIZED_HEIGHT=911
FINALIZED_EPOCH=4

MINE_THREADS="${IV5_NOTE_VOTE_MINE_THREADS:-1}"
MINE_THREADS_NOW=1
# Blocks mined before the fleet has to catch up. A peer far behind the miner can
# wedge its block fetch.
MINE_CHUNK="${IV5_NOTE_VOTE_MINE_CHUNK:-50}"

# Epoch E spans [11 + 300*(E-1), 310 + 300*(E-1)].
epoch_start() { echo $(( 11 + ($1 - 1) * 300 )); }
epoch_end()   { echo $(( 310 + ($1 - 1) * 300 )); }

# Held note-vote epochs: FULL (all voters), ONE_T (node2 silent), NOTE_ONLY (node1 and
# node2 silent), RESTORED (both transparent voters back).
FULL_EPOCH=5
ONE_T_EPOCH=6
NOTE_ONLY_EPOCH=7
RESTORED_EPOCH=8
NOTE_VOTE_EPOCHS="$FULL_EPOCH $ONE_T_EPOCH $NOTE_ONLY_EPOCH $RESTORED_EPOCH"
declare -A EXPECT_TRANSPARENT=(
    [$FULL_EPOCH]=2 [$ONE_T_EPOCH]=1 [$NOTE_ONLY_EPOCH]=0 [$RESTORED_EPOCH]=2
)
NOTE_VOTERS=2
# The epoch after them, for the carrier-disconnect case in section 15a.
REORG_VOTE_EPOCH=$(( RESTORED_EPOCH + 1 ))
# FINALITY_VOTE_INCLUSION_WINDOW: a transparent vote for boundary B connects only in [B, B+24).
TRANSPARENT_VOTE_INCLUSION_WINDOW=24
# FINALITY_NOTE_VOTE_INCLUSION_WINDOW: a note vote for boundary B connects only in [B, B+120).
NOTE_VOTE_INCLUSION_WINDOW=120
# FINALITY_VOTE_EMIT_OFFSET_POST_DAG: the producer casts once the tip is 2 blocks past
# the boundary, so a note-vote round holds the chain there.
NOTE_VOTE_EMIT_OFFSET=2
# Blocks mined past a boundary while the votes are pending, inside the window.
NOTE_VOTE_WINDOW=10
# Seconds the chain may be held at the emit height. ThreadFinalityVoter wakes on a
# 5s cycle and proving takes ~5s; the hold ends early once both votes are everywhere.
NOTE_VOTE_SETTLE=60

# A note vote is an ordinary shielded transaction, operation 10.
NOTE_VOTE_OPERATION=10
# FINALITY_NOTE_CERT_VERSION: the certificate whose note leg is a root and a count.
NOTE_CERT_VERSION=4
ZERO_HASH="0000000000000000000000000000000000000000000000000000000000000000"

# The epoch the double-vote probe and the section 12-14 detail checks run on.
TALLY_EPOCH="$FULL_EPOCH"
# H_E + FINALITY_NOTE_VOTE_INCLUSION_WINDOW is the freeze point: before it the counted
# note-vote set still grows and no certificate can satisfy connect-time coverage.
window_close() { echo $(( $(epoch_start "$1") + NOTE_VOTE_INCLUSION_WINDOW )); }
# Blocks mined past the freeze point, inside the same epoch, for a miner to carry
# the certificate.
TALLY_CARRY_BLOCKS=40
# Seconds the chain rests at the freeze point. ThreadFinalityVoter drives the
# certificate producer on a 5s cycle.
TALLY_SETTLE=30

# Operation-9 member registrations and the member-registry RPC verbs are gone.
REMOVED_COLLATERAL_VERBS="finality-register finality-status finality-registry"

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

# Extra arguments follow -daemon, so node_pids still matches the process.
start_node() {
    local node="$1"; shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -daemon "$@" >/dev/null 2>&1
    wait_rpc "$node"
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
# lands inside the [H_E, H_E+24) transparent inclusion window.
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

# ------------------------------------------------------------------
# Note-vote observation
# ------------------------------------------------------------------

# A note node's own account of one epoch, from its success or refusal log line:
#   ProducePrivacyVNextNoteVote: epoch=E boundary=B height=H txid=<10 hex>
producer_success()  { grep -aF "ProducePrivacyVNextNoteVote: epoch=$2 " "$(node_log "$1")" 2>/dev/null; }
producer_all()      { grep -aE "ProducePrivacyVNextNoteVote:|no IV5 note vote for epoch" "$(node_log "$1")" 2>/dev/null; }
producer_txid()     { producer_success "$1" "$2" | head -1 | sed -n 's/.*txid=\([0-9a-f]*\).*/\1/p'; }
producer_boundary() { producer_success "$1" "$2" | head -1 | sed -n 's/.* boundary=\([0-9]*\).*/\1/p'; }

# The certificate producer's line for one epoch on NODE, the last one printed.
#   ProduceNoteTallyCertificateEpoch: epoch E tier=T note_votes=N transparent_votes=M
cert_producer_line() {
    grep -aF "ProduceNoteTallyCertificateEpoch: epoch $2 tier=" "$(node_log "$1")" 2>/dev/null | tail -1
}

# Restart NODE with extra arguments (none restores its config).
restart_node() {
    local node="$1"; shift
    rpc "$node" stop >/dev/null 2>&1 || true
    wait_rpc_down "$node" || { force_kill_node "$node"; wait_rpc_down "$node" || return 1; }
    start_node "$node" "$@" || return 1
    connect_mesh
    wait_peers || return 1
    wait_sync "$(height 0)" 120 || return 1
}

# getstakinginfo finality_voting is false under -nofinalityvoting.
voting_enabled() { jget "$(rpc "$1" getstakinginfo 2>/dev/null)" finality_voting; }

# Certificates carried by blocks [from, to] for EPOCH, via getblock:
# "<height> <version> <signer_count> <committee_set_hash> <tier> <vote_nullifiers> <hash>".
epoch_carried_certs() {
    local node="$1" epoch="$2" from="$3" to="$4" h
    for ((h=from; h<=to; h++)); do
        block_json "$node" "$h" | H="$h" E="$epoch" python3 -c '
import json, os, sys
try: certs = json.load(sys.stdin).get("finality_tally_certificates") or []
except Exception: certs = []
for c in certs:
    if c.get("epoch") == int(os.environ["E"]):
        print(os.environ["H"], c.get("version"), c.get("signer_count"),
              c.get("committee_set_hash"), c.get("tier"), c.get("vote_nullifiers"),
              c.get("hash"))
'
    done
}

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
# "<cert version> <epoch> <tier> <signers> <note count> <note root> <committee set hash>"
# per IFCC envelope, hashes in RPC byte order. getblock reports neither note field.
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
        take(64); cset = take(32); take(24)
        for _ in range(cs()): take(32)
        signers, cnt, root = 0, 0, bytes(32)
        if lv >= 2:
            signers = cs(); take(2 * signers)
            for _ in range(cs()): take(cs())
            root = take(32); cnt = u(4)
        if i != len(b): raise ValueError("trailing bytes")
        print(cv, ep, tier, signers, cnt, root[::-1].hex(), cset[::-1].hex())
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

# One note-vote epoch, held at the emit height while both note nodes cast and relay.
# Records NV_TX_<V>[E] and NV_SEEN_<V>[E]; PROBE=1 offers node1 a second vote from node0's note.
declare -A NV_TX=()
declare -A NV_SEEN=()
PROBE_MEMPOOL_OK=""
PROBE_MEMPOOL_WHY=""
PROBE_MINED_OK=""
PROBE_MINED_WHY=""
note_vote_round() {
    local e="$1" b="$2" carry="$3" probe="${4:-0}" hold s n v t10 full done_all
    hold=$(( b + NOTE_VOTE_EMIT_OFFSET ))
    mine_to 0 "$hold" || return 1
    wait_sync "$hold" || return 1
    for v in $NOTE_NODES; do NV_SEEN[$v,$e]=""; NV_TX[$v,$e]=""; done
    for ((s=0; s<NOTE_VOTE_SETTLE; s++)); do
        sleep 1
        done_all=1
        for v in $NOTE_NODES; do
            t10="$(producer_txid "$v" "$e")"
            [ -n "$t10" ] || { done_all=0; continue; }
            for ((n=0; n<NUM_NODES; n++)); do
                case " ${NV_SEEN[$v,$e]} " in *" $n "*) continue ;; esac
                full="$(mempool_txid "$n" "$t10")"
                [ ${#full} -eq 64 ] || { done_all=0; continue; }
                NV_SEEN[$v,$e]="${NV_SEEN[$v,$e]} $n"
                NV_TX[$v,$e]="$full"
            done
        done
        [ "$done_all" -eq 1 ] && [ "$s" -ge 5 ] && break
    done
    if [ "$probe" = "1" ]; then
        full="$(mempool_txid 1 "$(producer_txid 0 "$e")")"
        if [ ${#full} -eq 64 ] && double_vote_probe 1 "$full" "is reserved by"; then
            PROBE_MEMPOOL_OK=1
        else
            PROBE_MEMPOOL_OK=0
            PROBE_MEMPOOL_WHY="${PROBE_WHY:-node1 never held the epoch $e vote}"
        fi
    fi
    mine_to 0 $(( b + carry )) || return 1
    wait_sync $(( b + carry )) || return 1
    # Mined, still inside the window, so only the spent-key rule can refuse it.
    if [ "$probe" = "2" ]; then
        if double_vote_probe 1 "${NV_TX[0,$e]}" "was already consumed by"; then
            PROBE_MINED_OK=1
        else
            PROBE_MINED_OK=0
            PROBE_MINED_WHY="$PROBE_WHY"
        fi
    fi
}

# The rest of a held epoch: rest at the freeze point so the certificate is built and
# relayed, then mine blocks of the same epoch so one of them carries it.
certificate_stop() {
    local e="$1" wc
    wc="$(window_close "$e")"
    mine_to 0 "$wc" || return 1
    wait_sync "$wc" || return 1
    sleep "$TALLY_SETTLE"
    mine_to 0 $(( wc + TALLY_CARRY_BLOCKS )) || return 1
    wait_sync $(( wc + TALLY_CARRY_BLOCKS )) || return 1
    sleep 10
    mine_to 0 $(( wc + TALLY_CARRY_BLOCKS + 20 )) || return 1
    wait_sync $(( wc + TALLY_CARRY_BLOCKS + 20 )) || return 1
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
        # One lane per node: a node that cast both an identity vote and a note vote
        # would link the tag to its wallet for every directly connected peer.
        if is_note_node "$node"; then
            echo "finalityvotemode=note"
        else
            echo "finalityvotemode=transparent"
        fi
        echo "regtestboundaryb=$BOUNDARY_B"
        echo "regtestiv5rehearsal=1"
        echo "regtestiv5notevote=$NOTE_VOTE_HEIGHT"
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
PREFLIGHT_TIMEOUT=""
command -v timeout >/dev/null 2>&1 && PREFLIGHT_TIMEOUT="timeout 120"
PREFLIGHT_OUT="$(
    $PREFLIGHT_TIMEOUT "$INNOVAD" -datadir="$PREFLIGHT_DIR" -regtest -listen=0 \
        -dnsseed=0 -nobootstrap=1 -nosmsg=1 -rpcuser=x -rpcpassword=y \
        -rpcport=$((BASE_RPC + 12)) -port=$((BASE_PORT + 12)) \
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
header "1. Fleet up with the note-vote fork configured and no committee"
# ============================================================

for ((n=0; n<NUM_NODES; n++)); do
    start_node "$n" || { fail "node$n did not start"; exit 1; }
done
wait_peers || { fail "fleet did not mesh"; exit 1; }
success "$NUM_NODES-node fleet up and meshed (Boundary B at $BOUNDARY_B; note lane: node0 node3, transparent lane: node1 node2)"

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

# No tally key or committee input is given to any node, and every node reports none.
KEYCFG=0
for ((n=0; n<NUM_NODES; n++)); do
    grep -qE '^[[:space:]]*(finalitytallypubkey|finalitytallythreshold|finalitytallyprivkey)[[:space:]]*=' \
        "$(node_dir "$n")/innova.conf" && KEYCFG=1
done
CONFIG_OK=1
CONFIG_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    FI="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    [ "$(jget "$FI" tally_configured_pubkeys)" = "0" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n reports $(jget "$FI" tally_configured_pubkeys) configured pubkeys"; }
    [ "$(jget "$FI" tally_privkey_configured)" = "false" ] || \
        { CONFIG_OK=0; CONFIG_WHY="node$n reports a configured tally private key"; }
    is_zero_hex "$(jget "$FI" tally_committee_set_hash)" || \
        { CONFIG_OK=0; CONFIG_WHY="node$n has a non-zero configured committee set hash"; }
done
if [ "$KEYCFG" -eq 0 ] && [ "$CONFIG_OK" -eq 1 ]; then
    success "no node is given a tally key or committee, and every node reports 0 configured pubkeys and no private key"
else
    fail "a tally key or committee is configured (config files: $KEYCFG; $CONFIG_WHY)"
    exit 1
fi

# getfinalityinfo carries no committee field at all.
COMMITTEE_KEYS=""
for ((n=0; n<NUM_NODES; n++)); do
    K="$(rpc "$n" getfinalityinfo 2>/dev/null | python3 -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: print("unreadable"); raise SystemExit
print(" ".join(k for k in d if k.startswith("committee")))
')"
    [ -n "$K" ] && COMMITTEE_KEYS="$COMMITTEE_KEYS node$n:[$K]"
done
if [ -z "$COMMITTEE_KEYS" ]; then
    success "getfinalityinfo reports no committee_* field on any node"
else
    fail "getfinalityinfo still reports committee fields:$COMMITTEE_KEYS"
fi

# The member-registration verbs are gone: each answers with the collateralnode usage.
VERBS_OK=1
for VERB in $REMOVED_COLLATERAL_VERBS; do
    OUT="$(rpc 0 collateralnode "$VERB" 2>&1)"
    if ! echo "$OUT" | grep -qF "Set of commands to execute collateralnode related actions" || \
       echo "$OUT" | grep -qF "$VERB"; then
        VERBS_OK=0
        fail "collateralnode $VERB is still dispatched or listed: $(echo "$OUT" | head -2)"
    fi
done
[ "$VERBS_OK" -eq 1 ] && \
    success "collateralnode $REMOVED_COLLATERAL_VERBS each return the usage text, and the usage lists none of them"

# Operation 9 cannot be built over RPC; its refusal is covered by the unit case
# a_member_registration_is_refused_at_every_height.
log "operation 9 refusal: covered by the unit case a_member_registration_is_refused_at_every_height (no RPC can build one)"

# ============================================================
header "2. The note nodes hold IV5 seeds"
# ============================================================

# z_createiv5seed requires an encrypted wallet.
for v in $NOTE_NODES; do
    rpc "$v" encryptwallet "$WALLETPASS" >/dev/null 2>&1
    wait_rpc_down "$v" || { fail "node$v did not stop after encrypting the wallet"; exit 1; }
    start_node "$v" || { fail "node$v did not restart after encrypting the wallet"; exit 1; }
    UNLOCK="$(rpc "$v" walletpassphrase "$WALLETPASS" 1000000 2>&1)"
    if echo "$UNLOCK" | grep -qiE "error"; then
        fail "could not unlock node$v: $(echo "$UNLOCK" | head -2)"
        exit 1
    fi
done
connect_mesh
wait_peers || { fail "the note nodes did not rejoin the mesh"; exit 1; }
for v in $NOTE_NODES; do
    SEED="$(rpc "$v" z_createiv5seed 2>&1)"
    if echo "$SEED" | grep -q '"created"'; then
        success "IV5 seed created on node$v"
    else
        fail "z_createiv5seed failed on node$v: $(echo "$SEED" | head -3)"
        exit 1
    fi
done

# ============================================================
header "3. Two distinct wallets hold votable transparent stake"
# ============================================================

# Negative control: the peers hold no stake at the epoch-1 boundary and the note nodes
# are in the anonymous lane, so epoch 1 carries no transparent vote.
vote_round 11 || { fail "epoch 1 vote round failed"; exit 1; }
E1_VOTES="$(votes_in_range 0 11 14)"
if [ "$E1_VOTES" = "0" ]; then
    success "epoch 1 carried no transparent finality vote: no peer holds stake yet and the note nodes cast none"
else
    fail "epoch 1 carried $E1_VOTES finality votes, expected 0"
fi

mine_to 0 "$FUND_HEIGHT" || { fail "mining to the funding height failed"; exit 1; }
wait_sync "$FUND_HEIGHT" || { fail "peers did not sync the funding chain"; exit 1; }

FUND_OK=1
for n in $TRANSPARENT_NODES; do
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
for n in $TRANSPARENT_NODES; do
    BAL="$(rpc "$n" getbalance 2>/dev/null | tr -d '"[:space:]')"
    feq "${BAL:-0}" "$FUND_AMOUNT" || STAKE_OK=0
done
if [ "$STAKE_OK" -eq 1 ]; then
    success "node1 and node2 each hold $FUND_AMOUNT INN under their own key"
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

# node3 is funded and shields first, before node0's sweeps consume its addresses.
ADDR3="$(rpc 3 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
SENT3="$(fund_peer "$ADDR3" "$NOTE3_FUND")"
[ ${#SENT3} -eq 64 ] || { fail "funding node3 failed"; exit 1; }
confirm_on 2 || { fail "could not confirm node3's funding"; exit 1; }
SH3="$(rpc 3 z_shieldall 2>&1)"
SH3_TXID="$(jget "$SH3" txid)"
if [ ${#SH3_TXID} -eq 64 ]; then
    confirm_on 2 || { fail "could not confirm node3's shield"; exit 1; }
    success "node3 shielded $(jget "$SH3" shielded) INN into the pool"
else
    fail "node3 could not shield: $(echo "$SH3" | head -3)"
    exit 1
fi

# A vote needs ONE note worth at least the stake floor (500 INN), so sweep several
# addresses. Each is confirmed before the next is built.
SHIELDS=0
for ((s=0; s<SHIELD_SWEEPS; s++)); do
    SH="$(rpc 0 z_shieldall 2>&1)"
    SH_TXID="$(jget "$SH" txid)"
    [ ${#SH_TXID} -eq 64 ] || break
    SHIELDS=$((SHIELDS + 1))
    log "  swept $(jget "$SH" shielded) INN from $(jget "$SH" inputs) output(s) into the pool"
    confirm_on 2 || break
done
if [ "$SHIELDS" -ge 1 ]; then
    success "$SHIELDS node0 shield sweep(s) confirmed into the IV5 pool"
else
    fail "no value could be shielded into the IV5 pool"
    exit 1
fi

if [ "$(height 0)" -le "$(epoch_end 2)" ]; then
    mine_to 0 "$SHIELD_CONFIRM_HEIGHT" || { fail "could not confirm the shields"; exit 1; }
    wait_sync "$SHIELD_CONFIRM_HEIGHT" || { fail "peers did not accept the shield blocks"; exit 1; }
    success "every shield confirmed inside epoch 2 (tip $(height 0))"
else
    fail "the shields ran past epoch 2 (tip $(height 0)); they are not placed by the epoch-2 build"
    exit 1
fi

# ============================================================
header "5. Three consecutive HARD epochs produce a finalized height"
# ============================================================

vote_round 611  || { fail "epoch 3 vote round failed"; exit 1; }

# A note is votable once an epoch build has placed it. The vote anchors to epoch state
# E-1, not to finality. Placed value is owned value less the unplaced part.
for v in $NOTE_NODES; do
    INFO="$(rpc "$v" z_getshieldedinfo 2>/dev/null)"
    POOL_OWNED="$(python3 -c "print(float('$(jget "$INFO" privacy_vnext_balance)' or 0) + float('$(jget "$INFO" privacy_vnext_unconfirmed_balance)' or 0))" 2>/dev/null)"
    POOL_UNPLACED="$(jget "$INFO" privacy_vnext_unplaced_balance)"
    POOL_NOTES="$(jget "$INFO" privacy_vnext_note_count)"
    TREE_SIZE="$(jget "$INFO" privacy_vnext_tree_size)"
    if [ "$(python3 -c "print(1 if float('${POOL_OWNED:-0}') - float('${POOL_UNPLACED:-0}') >= 500 else 0)" 2>/dev/null)" = "1" ] && \
       is_int "$TREE_SIZE" && [ "$TREE_SIZE" -gt 0 ]; then
        success "node$v owns $POOL_OWNED INN ($POOL_UNPLACED not yet placed) across $POOL_NOTES note(s), tree=$TREE_SIZE"
    else
        fail "node$v has no votable IV5 note (owned=${POOL_OWNED:-?} unplaced=${POOL_UNPLACED:-?} notes=$POOL_NOTES tree=$TREE_SIZE)"
        exit 1
    fi
done

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
header "6. Held note-vote epochs"
# ============================================================

# FULL: every voter. ONE_T: node2 restarted with -nofinalityvoting=1. NOTE_ONLY: node1
# silenced as well. RESTORED: both restarted from their own configs. Each epoch is
# held for the note votes, then stopped at the freeze point for the certificate.
for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    SILENT=""
    if [ "$E" = "$ONE_T_EPOCH" ]; then
        restart_node 2 -nofinalityvoting=1 || { fail "could not silence node2"; exit 1; }
    elif [ "$E" = "$NOTE_ONLY_EPOCH" ]; then
        restart_node 1 -nofinalityvoting=1 || { fail "could not silence node1"; exit 1; }
    elif [ "$E" = "$RESTORED_EPOCH" ]; then
        restart_node 1 || { fail "could not restore node1"; exit 1; }
        restart_node 2 || { fail "could not restore node2"; exit 1; }
    fi
    LIVE_T=0
    for n in $TRANSPARENT_NODES; do
        if [ "$(voting_enabled "$n")" = "true" ]; then
            LIVE_T=$((LIVE_T + 1))
        else
            SILENT="$SILENT node$n"
        fi
    done
    if [ "$LIVE_T" = "${EXPECT_TRANSPARENT[$E]}" ]; then
        success "epoch $E starts with $LIVE_T transparent voter(s) running (silenced:${SILENT:- none})"
    else
        fail "epoch $E starts with $LIVE_T transparent voter(s) running, expected ${EXPECT_TRANSPARENT[$E]}"
        exit 1
    fi
    log "epoch $E: holding the chain at $((B + NOTE_VOTE_EMIT_OFFSET)) for the note votes"
    PROBE=0
    [ "$E" = "$TALLY_EPOCH" ] && PROBE=1
    [ "$E" = "${NOTE_VOTE_EPOCHS##* }" ] && PROBE=2
    note_vote_round "$E" "$B" "$NOTE_VOTE_WINDOW" "$PROBE" || { fail "epoch $E vote round failed"; exit 1; }
    for v in $NOTE_NODES; do
        log "epoch $E: node$v vote ${NV_TX[$v,$E]:-<none>} held by node(s)${NV_SEEN[$v,$E]:- none}"
    done
    log "epoch $E: stopping at the freeze point $(window_close "$E") for the certificate"
    certificate_stop "$E" || { fail "epoch $E certificate stop failed"; exit 1; }
done

# Cross into the reorg epoch so the last held epoch's record is built; the note
# producer casts only from its emit height, so nothing for that epoch is cast yet.
RV_B="$(epoch_start "$REORG_VOTE_EPOCH")"
mine_to 0 "$RV_B" || { fail "could not cross into epoch $REORG_VOTE_EPOCH"; exit 1; }
wait_sync "$RV_B" || { fail "fleet did not sync into epoch $REORG_VOTE_EPOCH"; exit 1; }

E4="$(rpc 0 getepochinfo "$FINALIZED_EPOCH" 2>/dev/null)"
E4_TIER="$(jget "$E4" finality_tier)"
E4_HARD="$(jget "$E4" consecutive_hard_epochs)"
E4_FIN="$(jget "$E4" finalized_height_as_of)"
if [ "$E4_TIER" = "hard" ] && [ "$E4_HARD" = "3" ] && [ "$E4_FIN" = "$FINALIZED_HEIGHT" ]; then
    success "epoch $FINALIZED_EPOCH finalizes height $E4_FIN after $E4_HARD consecutive HARD epochs"
else
    fail "epoch $FINALIZED_EPOCH did not finalize (tier=$E4_TIER consecutive_hard=$E4_HARD finalized_height_as_of=$E4_FIN)"
    exit 1
fi

ANCHOR_TREE_ROOT="$(jget "$E4" iv5_tree_root)"
ANCHOR_TREE_SIZE="$(jget "$E4" iv5_tree_size)"
if [ ${#ANCHOR_TREE_ROOT} -ge 64 ] && ! is_zero_hex "$ANCHOR_TREE_ROOT" && \
   is_int "$ANCHOR_TREE_SIZE" && [ "$ANCHOR_TREE_SIZE" -gt 0 ]; then
    success "the finalized epoch carries an IV5 tree ($ANCHOR_TREE_SIZE leaves, root ${ANCHOR_TREE_ROOT:0:12})"
else
    fail "the finalized epoch carries no IV5 tree (root='$ANCHOR_TREE_ROOT' size='$ANCHOR_TREE_SIZE')"
    exit 1
fi

LAST_NV_EPOCH="${NOTE_VOTE_EPOCHS##* }"

# ============================================================
header "7. (a) Each note node builds one note vote per epoch"
# ============================================================

BUILT_OK=1
for v in $NOTE_NODES; do
    BUILT_EPOCHS=""
    for ((E=3; E<=LAST_NV_EPOCH; E++)); do
        N="$(producer_success "$v" "$E" | grep -c . || true)"
        is_int "$N" || N=0
        [ "$N" -le 1 ] || { BUILT_OK=0; fail "node$v built $N note votes in epoch $E"; }
        [ "$N" -eq 1 ] && BUILT_EPOCHS="$BUILT_EPOCHS $E"
    done
    for E in $NOTE_VOTE_EPOCHS; do
        PB="$(producer_boundary "$v" "$E")"
        [ "$PB" = "$(epoch_start "$E")" ] || \
            { BUILT_OK=0; fail "node$v epoch $E: the producer named boundary '$PB', expected $(epoch_start "$E")"; }
    done
    log "  node$v built one note vote in epoch(s)$BUILT_EPOCHS"
    [ "$BUILT_OK" -eq 1 ] || producer_all "$v" | tail -12
done
[ "$BUILT_OK" -eq 1 ] && \
    success "node0 and node3 each built exactly one note vote per epoch, every held epoch naming its own boundary"

# ============================================================
header "8. (b) Each note node's own mempool accepts its vote"
# ============================================================

OWN_OK=1
for v in $NOTE_NODES; do
    for E in $NOTE_VOTE_EPOCHS; do
        case " ${NV_SEEN[$v,$E]} " in
            *" $v "*) ;;
            *) OWN_OK=0; fail "epoch $E: node$v's mempool never held its vote (producer txid '$(producer_txid "$v" "$E")')" ;;
        esac
        if [ ${#NV_TX[$v,$E]} -ne 64 ] || [ "${NV_TX[$v,$E]:0:10}" != "$(producer_txid "$v" "$E")" ]; then
            OWN_OK=0
            fail "epoch $E: node$v's mempool vote '${NV_TX[$v,$E]}' is not the producer's '$(producer_txid "$v" "$E")'"
        fi
    done
    OWN_REFUSED="$(grep -aF "the note finality vote was built but could not be committed" "$(node_log "$v")" 2>/dev/null | head -1)"
    [ -z "$OWN_REFUSED" ] || { OWN_OK=0; fail "node$v refused its own note vote: $OWN_REFUSED"; }
done
[ "$OWN_OK" -eq 1 ] && success "every held epoch's votes entered their producers' mempools and none was refused locally"

# ============================================================
header "9. (c) Peers receive the note votes"
# ============================================================

# A vote relays as an ordinary transaction. A peer that took it after the hold ended
# leaves a TXRELAY accept line, which AcceptToMemoryPool writes only on admission.
relay_accepted() { grep -aqF "TXRELAY accept tx=${2:0:10} " "$(node_log "$1")" 2>/dev/null; }
RELAY_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    for v in $NOTE_NODES; do
        for ((n=0; n<NUM_NODES; n++)); do
            [ "$n" -eq "$v" ] && continue
            case " ${NV_SEEN[$v,$E]} " in
                *" $n "*) ;;
                *) relay_accepted "$n" "${NV_TX[$v,$E]}" || {
                       RELAY_OK=0
                       fail "epoch $E: node$n never accepted node$v's vote ${NV_TX[$v,$E]:0:16} by relay"
                   } ;;
            esac
        done
    done
done
[ "$RELAY_OK" -eq 1 ] && success "every peer accepted each note vote by relay before any block carried it"

# No node originates both a named and an anonymous vote. Relay carries every object to
# every node, so the producer lines are the only place the origin is visible.
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
    if [ "$N_IDENT" -gt 0 ] && [ "$N_ANON" -gt 0 ]; then
        LANE_OK=0
        fail "node$n originated BOTH an identity vote and a note vote"
    fi
    case "$N_LANE" in
        identity|anonymous|"") ;;
        *) LANE_OK=0; fail "node$n latched more than one vote lane: '$N_LANE'" ;;
    esac
    if is_note_node "$n"; then
        [ "$N_IDENT" -eq 0 ] || { LANE_OK=0; fail "node$n is note-only but originated $N_IDENT transparent vote(s)"; }
        [ "$N_ANON" -gt 0 ]  || { LANE_OK=0; fail "node$n originated no note vote"; }
        [ "$N_LANE" = "anonymous" ] || { LANE_OK=0; fail "node$n latched lane '$N_LANE', expected anonymous"; }
    else
        [ "$N_ANON" -eq 0 ] || { LANE_OK=0; fail "node$n is transparent-only but originated $N_ANON note vote(s)"; }
        [ "$N_IDENT" -gt 0 ] || { LANE_OK=0; fail "node$n originated no transparent vote"; }
        [ "$N_LANE" = "identity" ] || { LANE_OK=0; fail "node$n latched lane '$N_LANE', expected identity"; }
    fi
done
[ "$LANE_OK" -eq 1 ] && \
    success "no node originated both lanes ($LANE_TOTAL_IDENT identity, $LANE_TOTAL_ANON anonymous, split across nodes)"

# ============================================================
header "10. (d) The votes are mined inside their inclusion window and connect"
# ============================================================

CARRIED_OK=1
CARRIED_EPOCHS=""
for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    ROWS="$(notevotes_in_range 0 "$B" $((B + NOTE_VOTE_WINDOW)))"
    GOT="$(echo "$ROWS" | awk 'NF{print $2}' | sort | tr '\n' ' ')"
    WANT="$(for v in $NOTE_NODES; do echo "${NV_TX[$v,$E]}"; done | sort | tr '\n' ' ')"
    if [ "$GOT" != "$WANT" ]; then
        CARRIED_OK=0
        fail "epoch $E: carried operation-10 set [$GOT] in [$B, $((B + NOTE_VOTE_WINDOW))] is not the cast set [$WANT]"
        continue
    fi
    while read -r H T; do
        [ -n "$H" ] || continue
        if [ "$H" -lt "$B" ] || [ "$H" -ge $((B + NOTE_VOTE_INCLUSION_WINDOW)) ]; then
            CARRIED_OK=0
            fail "epoch $E: vote ${T:0:16} is carried at $H, outside [$B, $((B + NOTE_VOTE_INCLUSION_WINDOW)))"
            continue
        fi
        BH0="$(block_hash 0 "$H")"
        for ((n=0; n<NUM_NODES; n++)); do
            BHN="$(block_hash "$n" "$H")"
            TBN="$(jget "$(rpc "$n" getrawtransaction "$T" 1 2>/dev/null)" blockhash)"
            if [ ${#BH0} -ne 64 ] || [ "$BHN" != "$BH0" ] || [ "$TBN" != "$BH0" ]; then
                CARRIED_OK=0
                fail "epoch $E: node$n holds '${BHN:0:16}' at $H and places ${T:0:16} in '${TBN:0:16}', node0 has '${BH0:0:16}'"
            fi
        done
        CARRIED_EPOCHS="$CARRIED_EPOCHS $E@$H"
    done <<< "$ROWS"
done
CONNECT_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    R="$(grep -aF "ConnectBlockNoteVotes: rejected vote in block" "$(node_log "$n")" 2>/dev/null | head -1)"
    [ -n "$R" ] && CONNECT_REJECT="node$n: $R"
done
[ -z "$CONNECT_REJECT" ] || { CARRIED_OK=0; fail "a node rejected a note vote at connect: $CONNECT_REJECT"; }
[ "$CARRIED_OK" -eq 1 ] && \
    success "each held epoch's $NOTE_VOTERS votes were mined once inside the window and connected on all $NUM_NODES nodes (epoch@height:$CARRIED_EPOCHS)"

# ============================================================
header "11. (e) One note, one vote: a second vote from it is a double spend"
# ============================================================

declare -A NV_KI=()
KI_ALL=""
FIELDS_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    for v in $NOTE_NODES; do
        read -r NIN KI BHT BHASH <<< "$(notevote_fields 0 "${NV_TX[$v,$E]}")"
        if [ "$NIN" = "1" ] && [ ${#KI} -eq 64 ] && [ "$BHT" = "$B" ] && \
           [ "$BHASH" = "$(block_hash 0 "$B")" ]; then
            NV_KI[$v,$E]="$KI"
            KI_ALL="$KI_ALL $KI"
        else
            FIELDS_OK=0
            fail "epoch $E: node$v vote ${NV_TX[$v,$E]:0:16} reads inputs='$NIN' key_image='${KI:0:16}' boundary='$BHT', expected 1 input naming $B"
        fi
    done
done
NKI="$(echo "$KI_ALL" | tr ' ' '\n' | grep -c . || true)"
NKI_UNIQ="$(echo "$KI_ALL" | tr ' ' '\n' | grep . | sort -u | grep -c . || true)"
if [ "$FIELDS_OK" -eq 1 ] && [ "$NKI" -gt 0 ] && [ "$NKI" = "$NKI_UNIQ" ]; then
    success "each vote spends one note and names its own boundary; $NKI vote(s), $NKI_UNIQ distinct key image(s)"
elif [ "$FIELDS_OK" -eq 1 ]; then
    fail "a key image repeats ($NKI votes, $NKI_UNIQ distinct)"
fi

if [ "$PROBE_MEMPOOL_OK" = "1" ]; then
    success "node1 refused a second epoch-$TALLY_EPOCH vote from node0's note while the first was pending: its key image is reserved"
else
    fail "the pending double-vote probe did not refuse on the spent key: ${PROBE_MEMPOOL_WHY:-it never ran}"
fi

if [ "$PROBE_MINED_OK" = "1" ]; then
    success "node1 refused a second epoch-$LAST_NV_EPOCH vote from node0's note after the first was mined, inside the window: its key image is spent"
else
    fail "the mined double-vote probe: ${PROBE_MINED_WHY:-it never ran}"
fi

EQUIV_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    for ((n=0; n<NUM_NODES; n++)); do
        read -r C Q _ <<< "$(epoch_note_view "$n" "$E")"
        [ "$C" = "$NOTE_VOTERS" ] && [ "$Q" = "0" ] || \
            { EQUIV_OK=0; fail "node$n epoch $E: counted='$C' equivocated='$Q', expected $NOTE_VOTERS and 0"; }
    done
done
[ "$EQUIV_OK" -eq 1 ] && success "every node counts exactly $NOTE_VOTERS note votes per held epoch, none equivocated"

# ============================================================
header "12. Every node builds the certificate without a committee"
# ============================================================

# ProduceNoteTallyCertificateEpoch: tier is FinalityTier (HARD = 3).
PROD_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    WANT_T="${EXPECT_TRANSPARENT[$E]}"
    PRODUCERS=""
    for ((n=0; n<NUM_NODES; n++)); do
        L="$(cert_producer_line "$n" "$E")"
        [ -n "$L" ] || continue
        if echo "$L" | grep -qF "tier=3 note_votes=$NOTE_VOTERS transparent_votes=$WANT_T"; then
            PRODUCERS="$PRODUCERS node$n"
        else
            PROD_OK=0
            fail "epoch $E: node$n built '$L', expected tier=3 note_votes=$NOTE_VOTERS transparent_votes=$WANT_T"
        fi
    done
    if [ -n "$PRODUCERS" ]; then
        log "  epoch $E: built by$PRODUCERS: $(cert_producer_line "${PRODUCERS##*node}" "$E" | sed 's/.*ProduceNote/ProduceNote/')"
    else
        PROD_OK=0
        fail "epoch $E: no node built a note certificate"
        for ((n=0; n<NUM_NODES; n++)); do
            grep -aF "ProduceNoteTallyCertificateEpoch: epoch $E" "$(node_log "$n")" 2>/dev/null | tail -2
        done
    fi
done
[ "$PROD_OK" -eq 1 ] && \
    success "every held epoch's certificate was built by the nodes themselves at tier HARD over $NOTE_VOTERS note votes and the expected transparent count"

# A producer's admitted certificate and a template's self-built one each log their hash and
# signer count. Both must name zero signers; they are tallied apart so a producer count
# comes only from producer lines. The carried check below accepts either.
ASM_OK=1
declare -A ASSEMBLED=()
declare -A PRODUCED_HASHES=()
declare -A SELFBUILT_HASHES=()
for E in $NOTE_VOTE_EPOCHS; do
    for ((n=0; n<NUM_NODES; n++)); do
        while read -r L; do
            [ -n "$L" ] || continue
            H="$(echo "$L" | sed -n 's/.*note certificate \([0-9a-f]\{64\}\).*/\1/p')"
            [ -n "$H" ] && PRODUCED_HASHES[$E]="${PRODUCED_HASHES[$E]} $H"
            echo "$L" | grep -qE ' signers=0$' || { ASM_OK=0; fail "epoch $E: node$n produced a certificate with signers: $L"; }
        done < <(grep -aF "FinalityNoteTally: epoch $E note certificate " "$(node_log "$n")" 2>/dev/null)
        # Once a block carries the template's certificate, the producer's add is a
        # duplicate and logs nothing.
        while read -r L; do
            [ -n "$L" ] || continue
            H="$(echo "$L" | sed -n 's/.*certificate \([0-9a-f]\{64\}\) .*/\1/p')"
            [ ${#H} -eq 64 ] && SELFBUILT_HASHES[$E]="${SELFBUILT_HASHES[$E]} $H"
            echo "$L" | grep -qE ' signers=0$' || { ASM_OK=0; fail "epoch $E: node$n self-built a certificate with signers: $L"; }
        done < <(grep -a "CreateNewBlock: self-built tally certificate [0-9a-f]\{64\} epoch $E version $NOTE_CERT_VERSION " \
                     "$(node_log "$n")" 2>/dev/null)
    done
    PRODUCED_HASHES[$E]="$(echo "${PRODUCED_HASHES[$E]}" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
    SELFBUILT_HASHES[$E]="$(echo "${SELFBUILT_HASHES[$E]}" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
    ASSEMBLED[$E]="$(echo "${PRODUCED_HASHES[$E]} ${SELFBUILT_HASHES[$E]}" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
    [ -n "${ASSEMBLED[$E]}" ] || { ASM_OK=0; fail "epoch $E: no node logged a produced or self-built note certificate"; }
    log "  epoch $E: producer-admitted $(echo "${PRODUCED_HASHES[$E]}" | wc -w | tr -d ' '), template-built $(echo "${SELFBUILT_HASHES[$E]}" | wc -w | tr -d ' ')"
done
[ "$ASM_OK" -eq 1 ] && success "every produced and self-built note certificate names zero signers"

# ============================================================
header "13. The v4 certificate is carried in its own epoch and commits the counted set"
# ============================================================

declare -A CARRIED_CERT=()
declare -A CARRIED_H=()
CERT_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    WC="$(window_close "$E")"
    END="$(epoch_end "$E")"
    ALL="$(epoch_carried_certs 0 "$E" "$WC" "$END")"
    V4="$(echo "$ALL" | awk -v v="$NOTE_CERT_VERSION" 'NF && $2 == v' | head -1)"
    OTHER="$(echo "$ALL" | awk -v v="$NOTE_CERT_VERSION" 'NF && $2 != v')"
    read -r CH CV CS CSET CTIER CNUL CHASH <<< "$V4"
    if [ -z "$V4" ]; then
        CERT_OK=0
        fail "epoch $E: no v$NOTE_CERT_VERSION certificate carried in [$WC, $END]"
        continue
    fi
    CARRIED_CERT[$E]="$CHASH"
    CARRIED_H[$E]="$CH"
    if [ "$CS" = "0" ] && [ "$CSET" = "$ZERO_HASH" ] && [ "$CTIER" = "hard" ] && \
       [ "$CNUL" = "${EXPECT_TRANSPARENT[$E]}" ]; then
        success "epoch $E: v4 certificate ${CHASH:0:16} carried at $CH: signers=0 committee_set_hash=0 tier=hard transparent_votes=$CNUL"
    else
        CERT_OK=0
        fail "epoch $E: carried v4 certificate at $CH reads signers=$CS committee_set_hash=${CSET:0:16} tier=$CTIER transparent_votes=$CNUL"
    fi
    if ! echo " ${ASSEMBLED[$E]} " | grep -qF " $CHASH "; then
        CERT_OK=0
        fail "epoch $E: carried certificate ${CHASH:0:16} is not one a node assembled (${ASSEMBLED[$E]})"
    fi
    # Below two transparent voters no transparent-only certificate can exist.
    if [ "${EXPECT_TRANSPARENT[$E]}" -lt 2 ]; then
        if [ -z "$OTHER" ]; then
            success "epoch $E: its blocks carry no certificate other than the v4 one"
        else
            CERT_OK=0
            fail "epoch $E: its blocks carry a non-v4 certificate: $OTHER"
        fi
    fi

    # The envelope bytes: count, root and committee set hash.
    ENV="$(cert_envelopes 0 "$CH" | awk -v v="$NOTE_CERT_VERSION" -v e="$E" '$1 == v && $2 == e' | head -1)"
    read -r F_VER F_EPOCH F_TIER F_SIGNERS F_COUNT F_ROOT F_CSET <<< "$ENV"
    TAGS="$(epoch_note_tags "$(rpc 0 getepochinfo "$E" 2>/dev/null)")"
    ROOT_RPC="$(note_set_root $TAGS)"
    ROOT_TX="$(note_set_root $(for v in $NOTE_NODES; do echo "${NV_KI[$v,$E]}"; done))"
    if is_real_hash "$F_ROOT" && [ "$F_COUNT" = "$NOTE_VOTERS" ] && [ "$F_SIGNERS" = "0" ] && \
       [ "$F_TIER" = "3" ] && [ "$F_CSET" = "$ZERO_HASH" ] && \
       [ "$F_ROOT" = "$ROOT_RPC" ] && [ "$F_ROOT" = "$ROOT_TX" ]; then
        success "epoch $E: envelope commits count=$F_COUNT root ${F_ROOT:0:16} (rebuilt from the RPC tags and from the votes' key images), 0 signers, set hash 0"
    else
        CERT_OK=0
        fail "epoch $E: envelope '$ENV' vs counted=$NOTE_VOTERS rpc_root=$ROOT_RPC tx_root=$ROOT_TX"
    fi

    BH0="$(block_hash 0 "$CH")"
    CONV=1
    for ((n=1; n<NUM_NODES; n++)); do
        [ "$(block_hash "$n" "$CH")" = "$BH0" ] || CONV=0
    done
    [ ${#BH0} -eq 64 ] && [ "$CONV" -eq 1 ] || \
        { CERT_OK=0; fail "epoch $E: the carrier block at $CH did not converge fleet-wide"; }
done
[ "$CERT_OK" -eq 1 ] && success "every held epoch carries its committee-free v4 certificate in its own blocks, on every node"

CERT_REJECT=""
for ((n=0; n<NUM_NODES; n++)); do
    R="$(grep -aF "excluding finality tally certificate" "$(node_log "$n")" 2>/dev/null | tail -1)"
    [ -n "$R" ] && CERT_REJECT="node$n: $R"
done
[ -z "$CERT_REJECT" ] && log "no node excluded a tally certificate from a block it built" || \
    warn "a node excluded a certificate at some point: $CERT_REJECT"

# ============================================================
header "14. Each held epoch's tier comes from its v4 certificate"
# ============================================================

TIER_OK=1
for E in $NOTE_VOTE_EPOCHS; do
    EI0="$(rpc 0 getepochinfo "$E" 2>/dev/null)"
    T_CERT="$(jget "$EI0" finality_certificate)"
    T_TIER="$(jget "$EI0" finality_tier)"
    T_ROOT="$(jget "$EI0" vote_set_root)"
    T_DIG="$(jget "$EI0" epoch_state_digest)"
    if is_real_hash "$T_CERT" && [ "$T_CERT" = "${CARRIED_CERT[$E]}" ] && [ "$T_TIER" = "hard" ]; then
        success "epoch $E selected the carried v4 certificate ${T_CERT:0:16}, tier=$T_TIER"
    else
        TIER_OK=0
        fail "epoch $E selected '${T_CERT:0:16}' tier=$T_TIER, expected '${CARRIED_CERT[$E]:0:16}' tier=hard"
    fi
    AGREE=1
    WHY=""
    is_real_hash "$T_ROOT" || { AGREE=0; WHY="node0 vote-set root '$T_ROOT'"; }
    is_real_hash "$T_DIG"  || { AGREE=0; WHY="node0 epoch digest '$T_DIG'"; }
    for ((n=1; n<NUM_NODES; n++)); do
        PEI="$(rpc "$n" getepochinfo "$E" 2>/dev/null)"
        [ "$(jget "$PEI" finality_certificate)" = "$T_CERT" ] || { AGREE=0; WHY="node$n certificate"; }
        [ "$(jget "$PEI" vote_set_root)" = "$T_ROOT" ]        || { AGREE=0; WHY="node$n vote-set root"; }
        [ "$(jget "$PEI" epoch_state_digest)" = "$T_DIG" ]    || { AGREE=0; WHY="node$n epoch digest"; }
        [ "$(jget "$PEI" finality_tier)" = "$T_TIER" ]        || { AGREE=0; WHY="node$n tier"; }
    done
    if [ "$AGREE" -eq 1 ]; then
        success "epoch $E: every node agrees on the certificate, vote-set root (${T_ROOT:0:16}) and state digest (${T_DIG:0:16})"
    else
        TIER_OK=0
        fail "epoch $E's state is missing or divergent: $WHY"
    fi
done

# ============================================================
header "14b. HARD depends on note votes, and finality advances through it"
# ============================================================

# Transparent votes each held epoch's own window carried.
for E in $NOTE_VOTE_EPOCHS; do
    B="$(epoch_start "$E")"
    TV="$(votes_in_range 0 "$B" $((B + TRANSPARENT_VOTE_INCLUSION_WINDOW - 1)))"
    if [ "$TV" = "${EXPECT_TRANSPARENT[$E]}" ]; then
        success "epoch $E carried $TV transparent vote(s) in [$B, $((B + TRANSPARENT_VOTE_INCLUSION_WINDOW)))"
    else
        fail "epoch $E carried $TV transparent vote(s), expected ${EXPECT_TRANSPARENT[$E]}"
    fi
done

# One transparent voter is below FINALITY_MIN_VOTERS, and a note-only epoch has none:
# neither can be HARD from transparent votes. Both are HARD above, from the v4
# certificate alone (section 13 shows it is the only certificate their blocks carry).
for E in $ONE_T_EPOCH $NOTE_ONLY_EPOCH; do
    EI="$(rpc 0 getepochinfo "$E" 2>/dev/null)"
    if [ "$(jget "$EI" finality_tier)" = "hard" ] && [ "${EXPECT_TRANSPARENT[$E]}" -lt 2 ] && \
       [ "$(jget "$EI" finality_certificate)" = "${CARRIED_CERT[$E]}" ]; then
        success "EVIDENCE epoch $E: HARD with ${EXPECT_TRANSPARENT[$E]} transparent voter(s) + $NOTE_VOTERS note votes, from v4 certificate ${CARRIED_CERT[$E]:0:16} (signers=0, committee_set_hash=0)"
    else
        fail "epoch $E is not HARD from its v4 certificate (tier=$(jget "$EI" finality_tier))"
    fi
done

# The streak runs through the held epochs and the finalized height follows each one.
PREV_HARD="$(jget "$(rpc 0 getepochinfo "$FINALIZED_EPOCH" 2>/dev/null)" consecutive_hard_epochs)"
PREV_E="$FINALIZED_EPOCH"
for ((E=FINALIZED_EPOCH+1; E<=LAST_NV_EPOCH; E++)); do
    EI="$(rpc 0 getepochinfo "$E" 2>/dev/null)"
    H="$(jget "$EI" consecutive_hard_epochs)"
    F="$(jget "$EI" finalized_height_as_of)"
    if is_int "${H:-x}" && is_int "${PREV_HARD:-x}" && [ "$H" -eq $((PREV_HARD + 1)) ] && \
       [ "$H" -ge 3 ] && [ "$F" = "$(epoch_start "$E")" ]; then
        success "epoch $E: consecutive_hard=$H (epoch $PREV_E had $PREV_HARD), finalized_height_as_of=$F, its own boundary"
    else
        fail "epoch $E: consecutive_hard='$H' (previous $PREV_HARD) finalized_height_as_of='$F', expected $((PREV_HARD + 1)) and $(epoch_start "$E")"
    fi
    PREV_HARD="$H"
    PREV_E="$E"
done

FIN_OK=1
for ((n=0; n<NUM_NODES; n++)); do
    FH="$(jget "$(rpc "$n" getfinalityinfo 2>/dev/null)" finalized_height)"
    is_int "${FH:-x}" && [ "$FH" -ge "$(epoch_start "$LAST_NV_EPOCH")" ] || \
        { FIN_OK=0; fail "node$n finalized_height='$FH', expected >= $(epoch_start "$LAST_NV_EPOCH")"; }
done
[ "$FIN_OK" -eq 1 ] && \
    success "every node's finalized height reached $(epoch_start "$LAST_NV_EPOCH"), past the one-transparent-voter and note-only epochs"

# ============================================================
header "14a. An operator can read the counted note-vote set over RPC"
# ============================================================

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

TALLY_EI_NV="$(rpc 0 getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
NV_COUNTED="$(jget "$TALLY_EI_NV" note_votes_counted)"
NV_EQUIV="$(jget "$TALLY_EI_NV" note_votes_equivocated)"
NV_TAGS="$(jlen "$TALLY_EI_NV" note_vote_tags)"
is_int "$NV_COUNTED" || NV_COUNTED=0
is_int "$NV_EQUIV" || NV_EQUIV=0
is_int "$NV_TAGS" || NV_TAGS=0
if [ "$NV_COUNTED" = "$NOTE_VOTERS" ] && [ "$NV_TAGS" = "$NV_COUNTED" ] && [ "$NV_EQUIV" = "0" ]; then
    success "getepochinfo $TALLY_EPOCH reports $NV_COUNTED counted note votes, $NV_TAGS tags, 0 equivocated"
else
    fail "getepochinfo $TALLY_EPOCH reports counted=$NV_COUNTED tags=$NV_TAGS equivocated=$NV_EQUIV"
fi

# The tags the RPC publishes are the key images the vote transactions spent.
RPC_TAGS="$(epoch_note_tags "$TALLY_EI_NV" | tr ' ' '\n' | grep . | sort | tr '\n' ' ')"
TX_TAGS="$(for v in $NOTE_NODES; do echo "${NV_KI[$v,$TALLY_EPOCH]}"; done | sort | tr '\n' ' ')"
if [ -n "$(echo "$RPC_TAGS" | tr -d ' ')" ] && [ "$RPC_TAGS" = "$TX_TAGS" ]; then
    success "the tags getepochinfo publishes are the key images the two votes spent"
else
    fail "getepochinfo tags [$RPC_TAGS] are not the votes' key images [$TX_TAGS]"
fi

NV_AGREE=1
for ((n=1; n<NUM_NODES; n++)); do
    PEER_EI="$(rpc "$n" getepochinfo "$TALLY_EPOCH" 2>/dev/null)"
    [ "$(jget "$PEER_EI" note_votes_counted)" = "$NV_COUNTED" ] || NV_AGREE=0
    [ "$(epoch_note_tags "$PEER_EI")" = "$(epoch_note_tags "$TALLY_EI_NV")" ] || NV_AGREE=0
done
[ "$NV_AGREE" -eq 1 ] && success "every node reports the same counted note-vote set for epoch $TALLY_EPOCH" || \
    fail "nodes disagree on epoch $TALLY_EPOCH's counted note-vote set"

BLIND_OK=1
BLIND_WHY=""
for ((n=0; n<NUM_NODES; n++)); do
    PV="$(jget "$(rpc "$n" getfinalityinfo 2>/dev/null)" private_votes)"
    is_int "$PV" || PV=-1
    [ "$PV" = "0" ] || { BLIND_OK=0; BLIND_WHY="node$n reports private_votes=$PV"; }
done
[ "$BLIND_OK" -eq 1 ] && success "private_votes reads 0 on every node: the note lane carries no transparent-carrier private vote" || \
    fail "a transparent-carrier private vote appeared: $BLIND_WHY"

# ============================================================
header "15a. A reorg that disconnects the note votes' carrier takes them out of the counted set"
# ============================================================

# node0 invalidates the block carrying the epoch's votes, then outruns the fleet so
# every peer reorganises off it too. Throughout, a node's counted set must be exactly
# the operation-10 votes its active chain carries in the epoch's window.
RV_E="$REORG_VOTE_EPOCH"
RV_B="$(epoch_start "$RV_E")"
# Short on purpose: node0 drops below the carrier, and a peer chain far ahead of an
# invalidated tip is a large-work fork warning rather than a reorg.
RV_CARRY=5
log "epoch $RV_E: holding the chain at $((RV_B + NOTE_VOTE_EMIT_OFFSET)) for the note votes"
note_vote_round "$RV_E" "$RV_B" "$RV_CARRY" || { fail "epoch $RV_E vote round failed"; exit 1; }

RV_ROWS="$(notevotes_in_range 0 "$RV_B" $((RV_B + RV_CARRY)))"
RV_GOT="$(echo "$RV_ROWS" | awk 'NF{print $2}' | sort | tr '\n' ' ')"
RV_WANT="$(for v in $NOTE_NODES; do echo "${NV_TX[$v,$RV_E]}"; done | sort | tr '\n' ' ')"
RV_H="$(echo "$RV_ROWS" | awk -v t="${NV_TX[0,$RV_E]}" '$2 == t {print $1}')"
RV_RUN=1
if [ "$RV_GOT" = "$RV_WANT" ] && is_int "${RV_H:-x}"; then
    success "epoch $RV_E's two votes are carried; node0's at height $RV_H"
else
    fail "epoch $RV_E carries [$RV_GOT], cast [$RV_WANT]; nothing to disconnect"
    RV_RUN=0
fi

if [ "$RV_RUN" -eq 1 ]; then
    RV_KIS="$(for v in $NOTE_NODES; do notevote_fields 0 "${NV_TX[$v,$RV_E]}" | awk '{print $2}'; done | sort | tr '\n' ' ' | sed 's/ $//')"
    PRE_OK=1
    for ((n=0; n<NUM_NODES; n++)); do
        V="$(epoch_note_view "$n" "$RV_E")"
        [ "$V" = "$NOTE_VOTERS 0 $RV_KIS" ] || \
            { PRE_OK=0; fail "node$n does not count the carried votes before the disconnect (view '${V:0:60}')"; }
    done
    [ "$PRE_OK" -eq 1 ] && success "every node's live view counts both votes before the disconnect"

    # Every vote in or above the invalidated block leaves the chain with it.
    RV_HASH="$(block_hash 0 "$RV_H")"
    R1_BEFORE="$(reorg_count 1)"
    R2_BEFORE="$(reorg_count 2)"
    INV="$(rpc 0 invalidateblock "$RV_HASH" 2>&1)"
    for _ in $(seq 1 30); do
        [ "$(height 0)" = "$((RV_H - 1))" ] && break
        sleep 1
    done
    LEFT_KIS=""
    for ((h=RV_B; h<RV_H; h++)); do
        while read -r T; do
            [ ${#T} -eq 64 ] && LEFT_KIS="$LEFT_KIS $(notevote_fields 0 "$T" | awk '{print $2}')"
        done < <(notevote_txids 0 "$h" 2>/dev/null)
    done
    LEFT_KIS="$(echo "$LEFT_KIS" | tr ' ' '\n' | grep . | sort | tr '\n' ' ' | sed 's/ $//')"
    LEFT_N="$(echo "$LEFT_KIS" | wc -w | tr -d ' ')"
    V0="$(epoch_note_view 0 "$RV_E")"
    if [ "$(height 0)" = "$((RV_H - 1))" ] && [ "$V0" = "$(echo "$LEFT_N 0 $LEFT_KIS" | sed 's/ $//')" ] && \
       [ "$LEFT_N" -lt "$NOTE_VOTERS" ]; then
        success "with its carrier ${RV_HASH:0:16} disconnected, node0 counts $LEFT_N note vote(s) for epoch $RV_E, exactly those still on its chain"
    else
        fail "after invalidating the carrier node0 is at $(height 0) (expected $((RV_H - 1))) and reports '${V0:0:60}', chain carries $LEFT_N ($INV)"
    fi
    # Regtest reorgs return nothing to the mempool (Checkpoints::GetTotalBlocksEstimate
    # reads the mainnet map), so each disconnected vote is offered again by hand: its
    # key image is unspent once its carrier is gone.
    READMIT_OK=1
    for v in $NOTE_NODES; do
        T="${NV_TX[$v,$RV_E]}"
        [ -n "$(mempool_txid 0 "$T")" ] && continue
        echo " $LEFT_KIS " | grep -qF " $(notevote_fields 1 "$T" | awk '{print $2}') " && continue
        RAW="$(raw_tx 1 "$T")"
        RS="$(rpc 0 sendrawtransaction "$RAW" 2>&1 | tr -d '"[:space:]')"
        if [ "$RS" != "$T" ] || [ -z "$(mempool_txid 0 "$T")" ]; then
            READMIT_OK=0
            fail "node0 refused node$v's disconnected vote ($RS): $(grep -a "CTxMemPool::accept()" "$(node_log 0)" | tail -1)"
        fi
    done
    [ "$READMIT_OK" -eq 1 ] && success "with their carrier disconnected, node0 re-admits the same votes: their key images are unspent again"

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
        success "the peers reorganised onto node0's branch (height $RV_TARGET) and no node holds the old carrier at $RV_H"
    else
        fail "the fleet did not reorganise off the carrier: converged=$RV_CONV replaced=$SWAP_OK node1 $R1_BEFORE->$R1_AFTER node2 $R2_BEFORE->$R2_AFTER"
    fi

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
            { SET_OK=0; fail "node$n reports '${V:0:60}' for epoch $RV_E; its chain carries $NEW_N [${NEW_KIS:0:16}]"; }
    done
    [ "$SET_OK" -eq 1 ] && \
        success "every node's epoch $RV_E counted set equals the $NEW_N vote(s) its reorganised chain carries"

    RE_OK=1
    for v in $NOTE_NODES; do
        RE_H="$(echo "$NEW_ROWS" | awk -v t="${NV_TX[$v,$RV_E]}" '$2 == t {print $1}')"
        is_int "${RE_H:-x}" && [ "$RE_H" -lt $((RV_B + NOTE_VOTE_INCLUSION_WINDOW)) ] || RE_OK=0
    done
    if [ "$RE_OK" -eq 1 ] && [ "$NEW_N" = "$NOTE_VOTERS" ] && [ "$NEW_KIS" = "$RV_KIS" ]; then
        success "both votes are carried again inside their window under the same tags"
    else
        fail "the disconnected votes were not re-carried once each (carried $NEW_N: [$NEW_KIS])"
    fi

    RC="$(rpc 0 reconsiderblock "$RV_HASH" 2>&1)"
    log "  reconsiderblock: tip_moved=$(jget "$RC" tip_moved) tip_height=$(jget "$RC" tip_height)"
fi

# ============================================================
header "15b. A miner that runs no certificate producer carries the certificate it builds"
# ============================================================

# node1 restarts with -nofinalityvoting=1 and mines the first carrier heights alone: it
# must embed the same v4 certificate bytes as node0, and HARD comes only through it.
SB_E=$(( REORG_VOTE_EPOCH + 1 ))
SB_B="$(epoch_start "$SB_E")"
SB_WC="$(window_close "$SB_E")"
SB_OK=1
restart_node 1 -nofinalityvoting=1 || { fail "could not restart node1 without the voter"; SB_OK=0; }
if [ "$SB_OK" -eq 1 ] && [ "$(voting_enabled 1)" = "true" ]; then
    fail "node1 still runs the finality voter"
    SB_OK=0
fi
if [ "$SB_OK" -eq 1 ]; then
    note_vote_round "$SB_E" "$SB_B" "$NOTE_VOTE_WINDOW" || { fail "epoch $SB_E vote round failed"; SB_OK=0; }
fi
SB_FORK="$(height 1)"
if [ "$SB_OK" -eq 1 ] && { ! is_int "${SB_FORK:-x}" || [ "$SB_FORK" -ge $(( SB_WC - 1 )) ]; }; then
    fail "node1 is at ${SB_FORK:-?}; the window of epoch $SB_E closes at tip $(( SB_WC - 1 ))"
    SB_OK=0
fi
if [ "$SB_OK" -eq 1 ]; then
    SB_PARTED=0
    # Every peer is 127.0.0.1 and carries node1 as addnode: a ban on node1 keeps the
    # reconnect timers from healing the partition while both sides mine.
    rpc 1 setban 127.0.0.1 add 3600 >/dev/null 2>&1 || true
    for _ in $(seq 1 10); do
        for ((p=0; p<NUM_NODES; p++)); do
            [ "$p" -eq 1 ] && continue
            rpc 1 disconnectnode "127.0.0.1:$(node_port "$p")" >/dev/null 2>&1 || true
            rpc "$p" disconnectnode "127.0.0.1:$(node_port 1)" >/dev/null 2>&1 || true
        done
        sleep 3
        [ "$(peer_count 1)" = "0" ] && { SB_PARTED=1; break; }
    done
    [ "$SB_PARTED" -eq 1 ] || { fail "node1 could not be isolated (peers=$(peer_count 1))"; SB_OK=0; }
fi
if [ "$SB_OK" -eq 1 ]; then
    mine_chunk 1 $(( SB_WC + 2 )) || fail "node1 did not mine to $(( SB_WC + 2 ))"
    SB_ONE="$(epoch_carried_certs 1 "$SB_E" "$SB_WC" $(( SB_WC + 2 )) | \
              awk -v v="$NOTE_CERT_VERSION" 'NF && $2 == v' | head -1)"
    read -r SB_H1 _ SB_S1 _ SB_T1 SB_N1 SB_HASH1 <<< "$SB_ONE"
    SB_SELF="$(grep -aF "CreateNewBlock: self-built tally certificate $SB_HASH1 epoch $SB_E version $NOTE_CERT_VERSION " \
               "$(node_log 1)" 2>/dev/null | tail -1)"
    if is_real_hash "${SB_HASH1:-x}" && [ "$SB_T1" = "hard" ] && [ "$SB_S1" = "0" ] && \
       { [ "$SB_N1" = "0" ] || [ "$SB_N1" = "1" ]; } && [ -n "$SB_SELF" ]; then
        success "isolated node1 carried the v4 certificate ${SB_HASH1:0:16} at $SB_H1 (tier hard, $SB_N1 transparent vote(s)), built by its own template"
    else
        fail "isolated node1 carried '${SB_ONE:-nothing}' in [$SB_WC, $(( SB_WC + 2 ))]; self-built line: '${SB_SELF:-none}'"
        SB_OK=0
    fi
    mine_chunk 0 $(( SB_WC + 1 )) || fail "node0 did not mine to $(( SB_WC + 1 ))"
    SB_ZERO="$(epoch_carried_certs 0 "$SB_E" "$SB_WC" $(( SB_WC + 1 )) | \
               awk -v v="$NOTE_CERT_VERSION" 'NF && $2 == v' | head -1)"
    read -r _ _ _ _ _ _ SB_HASH0 <<< "$SB_ZERO"
    if [ "$SB_OK" -eq 1 ] && [ "$SB_HASH0" = "$SB_HASH1" ] && \
       [ "$(block_hash 0 "$SB_WC")" != "$(block_hash 1 "$SB_WC")" ]; then
        success "node0's branch carries the same certificate bytes ${SB_HASH0:0:16} in a different block"
    else
        fail "node0 carried '${SB_ZERO:-nothing}', node1 carried ${SB_HASH1:-nothing}"
        SB_OK=0
    fi
    rpc 1 setban 127.0.0.1 remove >/dev/null 2>&1 || true
    connect_mesh
    wait_peers >/dev/null 2>&1 || true
    SB_CONV=0
    SB_TIP1="$(block_hash 1 $(( SB_WC + 2 )))"
    for _ in $(seq 1 240); do
        OK=1
        for ((n=0; n<NUM_NODES; n++)); do
            [ ${#SB_TIP1} -eq 64 ] && [ "$(block_hash "$n" $(( SB_WC + 2 )))" = "$SB_TIP1" ] || OK=0
        done
        [ "$OK" -eq 1 ] && { SB_CONV=1; break; }
        sleep 1
    done
    [ "$SB_CONV" -eq 1 ] && success "the fleet reorganised onto node1's branch" || \
        { fail "the fleet did not converge on node1's branch"; SB_OK=0; }
fi
rpc 1 setban 127.0.0.1 remove >/dev/null 2>&1 || true
restart_node 1 || fail "could not restore node1"
if [ "$SB_OK" -eq 1 ]; then
    SB_NEXT="$(epoch_start $(( SB_E + 1 )))"
    mine_to 0 $(( SB_NEXT + 1 )) || fail "could not cross into epoch $(( SB_E + 1 ))"
    wait_sync $(( SB_NEXT + 1 )) || fail "the fleet did not sync into epoch $(( SB_E + 1 ))"
    REC_OK=1
    for ((n=0; n<NUM_NODES; n++)); do
        EI="$(rpc "$n" getepochinfo "$SB_E" 2>/dev/null)"
        [ "$(jget "$EI" finality_tier)" = "hard" ] && \
            [ "$(jget "$EI" finality_certificate)" = "$SB_HASH1" ] || {
            REC_OK=0
            fail "node$n epoch $SB_E record: tier=$(jget "$EI" finality_tier) certificate=$(jget "$EI" finality_certificate)"
        }
    done
    [ "$REC_OK" -eq 1 ] && success "every node's epoch $SB_E record is HARD through the self-built certificate ${SB_HASH1:0:16}"
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
