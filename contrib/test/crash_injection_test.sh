#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Crash-injection recovery gate: SIGKILL a victim at fragile persistence points and require
# its recovered state to match an uninterrupted control. See WHAT THIS DOES NOT COVER below.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${CRASH_TEST_DIR:-/tmp/innova_crash_injection_$$}"
EVIDENCE_DIR="${CRASH_EVIDENCE_DIR:-$TEST_DIR/evidence}"
KEEP_DIR="${KEEP_DIR:-0}"

PORT_BASE="${CRASH_PORT_BASE:-28840}"
RPC_BASE="${CRASH_RPC_BASE:-28850}"
IDNS_BASE="${CRASH_IDNS_BASE:-28860}"
RPCUSER="crashinj"
RPCPASS="crashinjpass"
WALLETPASS="crashinjwalletpass"

# Small enough that a few dozen blocks cross several boundaries, so a kill at an
# arbitrary moment lands mid-batch rather than on a just-flushed cursor.
NAMEINDEX_BATCH="${CRASH_NAMEINDEX_BATCH:-25}"
# Large enough that the block-count trigger never fires, so the locator lags the chain
# state at the kill. The 30s time trigger still fires (WALLET_LOCATOR_BATCH_MAX_SECONDS).
WALLET_LOCATOR_BATCH="${CRASH_WALLET_LOCATOR_BATCH:-100000}"

# Regtest DAG fork is 11 and the post-DAG epoch interval is 300, so epochs close
# at 311 and 611. Boundary B is pinned just past the schema-V3 epoch height, as
# the IV5 regtest harnesses do, so the shielded phase has a pool to put value in.
BOUNDARY_B=311
H_CONNECT=300     # past the DAG fork, inside epoch 0
H_IDNS=560        # past the 311 boundary: epoch 0 is durable
H_WALLET=580      # room to fund, shield and confirm
# The shielded notes only reach the commitment tree when the epoch closes, so
# the wallet phase runs past 611 before it kills. Below that the wallet holds
# notes the tree has never seen, and the scan being tested is half-exercised.
H_WALLET_TREE=640
H_REORG_TIP=660   # past the 611 boundary: epoch 1 is durable
REORG_FROM=600    # invalidated height; the rebuild recrosses 611
H_REORG_NEW=700   # new branch outruns the old tip

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

node_dir()  { echo "$TEST_DIR/node$1"; }
node_rpc()  { echo $(( RPC_BASE + $1 )); }
node_port() { echo $(( PORT_BASE + $1 )); }

rpc() {
    local n="$1"; shift
    "$INNOVAD" -datadir="$(node_dir "$n")" -regtest \
        -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport="$(node_rpc "$n")" "$@" 2>&1
}

height()   { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
besthash() { rpc "$1" getbestblockhash 2>/dev/null | tr -d '"[:space:]'; }
is_int()   { echo "${1:-}" | grep -qE '^[0-9]+$'; }

jstr() { echo "$1" | sed -n "s/.*\"$2\" *: *\"\([^\"]*\)\".*/\1/p" | head -1; }
jval() { echo "$1" | sed -n "s/.*\"$2\" *: *\([^,}\"]*\).*/\1/p" | tr -d '[:space:]' | head -1; }

# The daemon's own argv. A bare datadir match also catches the short-lived RPC
# helper processes, which share that fragment, so the node never looks gone.
daemon_pids() {
    pgrep -f -- "-datadir=$(node_dir "$1") -regtest -daemon" 2>/dev/null
}

write_conf() {
    local n="$1" extra="${2:-}"
    local d; d="$(node_dir "$n")"
    mkdir -p "$d"
    cat > "$d/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$(node_rpc "$n")
port=$(node_port "$n")
listen=1
idnsport=$(( IDNS_BASE + n ))
dnsseed=0
stakingmode=0
nofinalityvoting=1
maxconnections=125
regtestboundaryb=$BOUNDARY_B
regtestiv5rehearsal=1
nameindexbatch=$NAMEINDEX_BATCH
walletlocatorbatch=$WALLET_LOCATOR_BATCH
$extra
EOF
}

# Start the daemon and return without waiting for RPC readiness: a regtest node
# finishes catch-up inside that wait, leaving nothing to interrupt.
launch_node() {
    "$INNOVAD" -datadir="$(node_dir "$1")" -regtest -daemon >/dev/null 2>&1
}

start_node() {
    local n="$1" i
    launch_node "$n"
    for i in $(seq 1 180); do
        rpc "$n" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

stop_node() {
    local n="$1" i
    rpc "$n" stop >/dev/null 2>&1 || true
    for i in $(seq 1 180); do
        daemon_pids "$n" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

# The injection itself. SIGKILL cannot be caught, so nothing on the shutdown
# path runs: no batch flush, no pid-file removal, no datadir unlock.
kill_node() {
    local n="$1" pids i
    pids="$(daemon_pids "$n")"
    [ -n "$pids" ] || return 1
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null
    for i in $(seq 1 60); do
        daemon_pids "$n" >/dev/null 2>&1 || break
        sleep 1
    done
    # A SIGKILLed node leaves its pid file behind, naming a process that has
    # exited. Anything reading it to decide whether a node is running gets a
    # stale answer, so the restart clears it exactly as an operator would.
    rm -f "$(node_dir "$n")/innovad.pid" 2>/dev/null
    return 0
}

victim_log() { echo "$(node_dir 1)/regtest/debug.log"; }

# Read the failure reason from the node's own log. The signatures below are known
# recovery-path refusals; anything else is kept verbatim.
diagnose_failed_start() {
    local what="$1" log; log="$(victim_log)"
    if [ ! -f "$log" ]; then
        fail "$what: victim did not restart and left no debug.log"
        return
    fi
    tail -120 "$log" > "$EVIDENCE_DIR/victim.failed-start.log" 2>/dev/null
    if grep -q "IV5 seed is locked" "$log"; then
        fail "$what: RECOVERY DEADLOCK -- the startup rescan fails closed on a locked IV5 seed, and the daemon exits before its RPC server exists, so the wallet can never be unlocked to satisfy it"
        {
            echo "finding: startup-rescan deadlock on an encrypted IV5 wallet"
            grep "Wallet rescan failed" "$log" | tail -1
            grep "Rescanning last" "$log" | tail -1
        } >> "$EVIDENCE_DIR/manifest.txt"
    elif grep -q "recovery outbox was preserved" "$log"; then
        fail "$what: the shielded-wallet recovery outbox refused the restart"
        grep "recovery outbox" "$log" | tail -1 >> "$EVIDENCE_DIR/manifest.txt"
    else
        fail "$what: victim did not restart; see $EVIDENCE_DIR/victim.failed-start.log"
    fi
}

wait_height() {
    local n="$1" target="$2" limit="${3:-300}" i h
    for i in $(seq 1 "$limit"); do
        h="$(height "$n")"
        is_int "$h" && [ "$h" -ge "$target" ] && return 0
        sleep 1
    done
    return 1
}

# A byte-compare is only meaningful between two nodes on the same block. The
# producer overshoots its target routinely, so "both past height N" is not a
# precondition: identical tip hashes is.
wait_converge() {
    local a="$1" b="$2" limit="${3:-300}" i ha hb
    for i in $(seq 1 "$limit"); do
        ha="$(besthash "$a")"; hb="$(besthash "$b")"
        if echo "$ha" | grep -qE '^[0-9a-f]{64}$' && [ "$ha" = "$hb" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

mine_to() {
    local n="$1" target="$2" i h
    for i in $(seq 1 200); do
        h="$(height "$n")"
        is_int "$h" || { sleep 2; continue; }
        [ "$h" -ge "$target" ] && return 0
        rpc "$n" setgenerate true $(( target - h )) >/dev/null 2>&1
        sleep 3
    done
    return 1
}

connect_peers() {
    rpc "$1" addnode "127.0.0.1:$(node_port 0)" onetry >/dev/null 2>&1 || true
}

# Kill the victim while its tip is inside (lo, hi); prints the death height, or empty if
# it reached the tip first. No sleep in the poll. A non-zero modulus keeps the kill
# height off a batch boundary.
kill_while_syncing() {
    local lo="$1" hi="$2" limit="${3:-600}" modulus="${4:-0}" h deadline
    deadline=$(( SECONDS + limit ))
    while [ "$SECONDS" -lt "$deadline" ]; do
        h="$(height 1)"
        if is_int "$h"; then
            if [ "$h" -gt "$lo" ] && [ "$h" -lt "$hi" ] \
               && { [ "$modulus" -eq 0 ] || [ $(( h % modulus )) -ne 0 ]; }; then
                if kill_node 1; then echo "$h"; return 0; fi
            fi
            [ "$h" -ge "$hi" ] && return 1
        fi
    done
    return 1
}

# State digest: consensus-derived, node-independent values only.
EPOCH_NUM_FIELDS="height_start height_end block_count consecutive_hard_epochs \
finalized_height_as_of schema_version finalized"
EPOCH_STR_FIELDS="boundary_block total_trust curve_root nullifier_root \
vote_set_root finality_certificate finality_tier anchor_rule \
epoch_state_digest status"

state_dump() {
    local n="$1" h e maxepoch info f
    h="$(height "$n")"
    is_int "$h" || { echo "UNREADABLE"; return 1; }
    echo "tip_height $h"
    echo "tip_hash $(besthash "$n")"

    # Epoch 0 is 0-10, then 11-310, 311-610, ... Walk two past the end to include the
    # in-progress epoch; an epoch absent on both nodes compares equal.
    maxepoch=$(( (h - 11) / 300 + 2 ))
    [ "$maxepoch" -lt 1 ] && maxepoch=1
    for e in $(seq 0 "$maxepoch"); do
        info="$(rpc "$n" getepochinfo "$e" 2>/dev/null)"
        echo "$info" | grep -q '"epoch"' || { echo "epoch $e ABSENT"; continue; }
        for f in $EPOCH_NUM_FIELDS; do
            echo "epoch $e $f $(jval "$info" "$f")"
        done
        for f in $EPOCH_STR_FIELDS; do
            echo "epoch $e $f $(jstr "$info" "$f")"
        done
    done

    # The IDNS name index as committed (name_scan), which exposes a misplaced cursor.
    # expires_in is excluded: it depends on the tip.
    rpc "$n" name_scan "" 1000 2>/dev/null \
        | grep -oE '"(name|value)" *: *"[^"]*"' \
        | sed 's/[[:space:]]\+/ /g' | sort | sed 's/^/nameidx /'
}

digest_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

capture() {
    local n="$1" tag="$2"
    mkdir -p "$EVIDENCE_DIR"
    state_dump "$n" > "$EVIDENCE_DIR/state.$tag.txt"
}

compare_states() {
    local tag_a="$1" tag_b="$2" what="$3" da db
    da="$(digest_of "$EVIDENCE_DIR/state.$tag_a.txt")"
    db="$(digest_of "$EVIDENCE_DIR/state.$tag_b.txt")"
    if [ -n "$da" ] && [ "$da" = "$db" ]; then
        success "$what: recovered state is byte-identical ($da)"
        echo "MATCH $what $da" >> "$EVIDENCE_DIR/manifest.txt"
        return 0
    fi
    fail "$what: recovered state differs (victim=$da control=$db)"
    echo "DIFFER $what victim=$da control=$db" >> "$EVIDENCE_DIR/manifest.txt"
    diff "$EVIDENCE_DIR/state.$tag_a.txt" "$EVIDENCE_DIR/state.$tag_b.txt" \
        > "$EVIDENCE_DIR/diff.$tag_a.$tag_b.txt" 2>&1 || true
    head -40 "$EVIDENCE_DIR/diff.$tag_a.$tag_b.txt"
    return 1
}

cleanup() {
    local n pids
    for n in 0 1 2; do
        stop_node "$n" >/dev/null 2>&1 || {
            pids="$(daemon_pids "$n")"
            # Scoped to this run's own datadirs; never a host-wide pkill on
            # -regtest, which would kill unrelated regtest nodes.
            # shellcheck disable=SC2086
            [ -n "$pids" ] && kill -9 $pids 2>/dev/null
        }
    done
    if [ "$KEEP_DIR" = "1" ]; then
        echo "kept: $TEST_DIR"
    else
        [ -n "${CRASH_EVIDENCE_DIR:-}" ] || rm -rf "$TEST_DIR"
    fi
}
trap cleanup EXIT

# ===========================================================================
header "Crash-injection recovery gate"
# ===========================================================================

[ -x "$INNOVAD" ] || { fail "no innovad at $INNOVAD"; exit 1; }

rm -rf "$TEST_DIR"
mkdir -p "$EVIDENCE_DIR"
{
    echo "commit:             $(cd "$INNOVA_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "binary:             $INNOVAD"
    echo "binary_sha256:      $(digest_of "$INNOVAD")"
    echo "started:            $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "nameindexbatch:     $NAMEINDEX_BATCH"
    echo "walletlocatorbatch: $WALLET_LOCATOR_BATCH"
    echo "boundary_b:         $BOUNDARY_B"
} > "$EVIDENCE_DIR/manifest.txt"

# node0 produces, node1 is the victim, node2 is the control. Victim and control
# carry identical flags so any difference between them is recovery, not config.
write_conf 0
write_conf 1 "addnode=127.0.0.1:$(node_port 0)"
write_conf 2 "addnode=127.0.0.1:$(node_port 0)"

start_node 0 || { fail "producer did not start"; exit 1; }
success "producer is up"

# ===========================================================================
header "1. SIGKILL during ConnectBlock"
# ===========================================================================
# Kill while the victim's height is increasing (inside the connect loop). The producer
# builds the whole span first so the victim faces a bulk download.

mine_to 0 "$H_CONNECT" || { fail "producer could not reach $H_CONNECT"; exit 1; }
success "producer mined to $(height 0) before the victim ever started"

# The control syncs first and out of the way; then the victim is launched and
# polled from the same instant, so the kill lands inside its catch-up.
start_node 2 || { fail "control did not start"; exit 1; }
connect_peers 2
wait_height 2 "$H_CONNECT" 900 || { fail "control did not sync to $H_CONNECT"; exit 1; }
success "control synced to $(height 2) uninterrupted"

launch_node 1
KILL_CONNECT="$(kill_while_syncing 20 "$H_CONNECT" 600 || true)"
if [ -z "$KILL_CONNECT" ]; then
    warn "victim reached the tip before a mid-connect kill landed; killing at the tip instead"
    KILL_CONNECT="$(height 1)"
    kill_node 1 || { fail "could not kill the victim"; exit 1; }
    echo "kill_connectblock_height: $KILL_CONNECT (AT TIP, not mid-connect)" >> "$EVIDENCE_DIR/manifest.txt"
    # Recorded as a failure rather than a warning: a kill at the tip exercises
    # restart, not interruption, and reporting it as a pass would put the phase
    # name on evidence the run did not produce.
    fail "no mid-connect window was reached: the ConnectBlock kill proved only that a restart works"
else
    success "victim SIGKILLed mid-connect at height $KILL_CONNECT of $H_CONNECT"
    echo "kill_connectblock_height: $KILL_CONNECT (mid-connect)" >> "$EVIDENCE_DIR/manifest.txt"
fi

if start_node 1; then
    success "victim restarted without operator intervention"
else
    diagnose_failed_start "ConnectBlock kill"
    exit 1
fi
connect_peers 1

wait_height 1 "$H_CONNECT" 900 || { fail "victim did not resync to $H_CONNECT"; exit 1; }
wait_height 2 "$H_CONNECT" 900 || { fail "control did not sync to $H_CONNECT"; exit 1; }
if wait_converge 1 2 300; then
    success "victim and control are on the same tip"
else
    fail "victim and control never converged on one tip after the ConnectBlock kill"
fi

capture 1 "connect.victim"
capture 2 "connect.control"
compare_states "connect.victim" "connect.control" "ConnectBlock kill"

# ===========================================================================
header "2. SIGKILL mid-batch in the IDNS name-index cursor"
# ===========================================================================
# The cursor commits once per NAMEINDEX_BATCH blocks; a kill between commits must
# restart from the last committed cursor and reach the same index.

log "parking the victim so it faces a bulk name-index rebuild"
stop_node 1 || warn "victim did not stop cleanly before the name-index phase"

log "registering IDNS names on the producer"
NAMES_REGISTERED=0
for i in $(seq 1 12); do
    OUT="$(rpc 0 name_new "crash-$i.inn" "value-$i" 30 2>&1)"
    if echo "$OUT" | grep -qE '^[0-9a-f]{64}$'; then
        NAMES_REGISTERED=$((NAMES_REGISTERED + 1))
    else
        warn "name_new crash-$i.inn: $(echo "$OUT" | head -1)"
    fi
    mine_to 0 $(( $(height 0) + 4 )) >/dev/null 2>&1
done
log "registered $NAMES_REGISTERED of 12 names"
echo "names_registered: $NAMES_REGISTERED" >> "$EVIDENCE_DIR/manifest.txt"

mine_to 0 "$H_IDNS" || { fail "producer could not reach $H_IDNS"; exit 1; }
success "producer at $(height 0) with $NAMES_REGISTERED names registered"

# Kill deliberately off a batch boundary and at least one boundary past the
# resume point, so the cursor is provably mid-batch rather than just-flushed.
launch_node 1
KILL_IDNS="$(kill_while_syncing $(( H_CONNECT + NAMEINDEX_BATCH )) "$H_IDNS" 600 "$NAMEINDEX_BATCH" || true)"

if [ -z "$KILL_IDNS" ]; then
    warn "victim reached $H_IDNS before a mid-batch kill landed"
    echo "kill_nameindex_height: NONE (batch boundary not crossed under a kill)" >> "$EVIDENCE_DIR/manifest.txt"
    fail "the name-index mid-batch kill did not happen: this phase proved nothing"
else
    success "victim SIGKILLed at height $KILL_IDNS (batch $NAMEINDEX_BATCH, remainder $(( KILL_IDNS % NAMEINDEX_BATCH )))"
    echo "kill_nameindex_height: $KILL_IDNS remainder $(( KILL_IDNS % NAMEINDEX_BATCH ))" >> "$EVIDENCE_DIR/manifest.txt"
    if start_node 1; then
        success "victim restarted after a mid-batch name-index kill"
    else
        diagnose_failed_start "name-index batch kill"
        exit 1
    fi
    connect_peers 1
fi

wait_height 1 "$H_IDNS" 900 || { fail "victim did not resync to $H_IDNS"; exit 1; }
wait_height 2 "$H_IDNS" 900 || { fail "control did not sync to $H_IDNS"; exit 1; }
if wait_converge 1 2 300; then
    success "victim and control are on the same tip after the name-index kill"
else
    fail "victim and control never converged after the name-index kill"
fi

capture 1 "idns.victim"
capture 2 "idns.control"
compare_states "idns.victim" "idns.control" "name-index batch kill"

# The comparison above is only meaningful if the index is non-empty: two empty
# indexes match trivially and would report a pass that proves nothing.
NAMEIDX_LINES="$(grep -c '^nameidx ' "$EVIDENCE_DIR/state.idns.control.txt" 2>/dev/null || true)"
NAMEIDX_LINES="${NAMEIDX_LINES:-0}"
if [ "$NAMEIDX_LINES" -gt 0 ]; then
    success "name index is non-empty ($NAMEIDX_LINES indexed fields), so the match is a real comparison"
else
    fail "name index is empty: the name-index comparison proved nothing"
fi
echo "nameidx_fields: $NAMEIDX_LINES" >> "$EVIDENCE_DIR/manifest.txt"

# ===========================================================================
header "3. SIGKILL with the wallet best-block locator lagging"
# ===========================================================================
# A lagging locator must be recovered by the startup rescan for shielded and
# transparent paths; the victim's note set is compared across the kill.

WALLET_PHASE_OK=1
NOTE_LINES=0

VADDR="$(rpc 1 getnewaddress 2>&1 | tr -d '"[:space:]')"
if ! echo "$VADDR" | grep -qE '^[a-zA-Z0-9]{25,}$'; then
    warn "could not get a victim address ($VADDR)"
    WALLET_PHASE_OK=0
fi

if [ "$WALLET_PHASE_OK" = "1" ]; then
    log "funding the victim at $VADDR"
    rpc 0 sendtoaddress "$VADDR" 1000 >/dev/null 2>&1 || true
    mine_to 0 $(( $(height 0) + 30 )) >/dev/null 2>&1
    wait_converge 1 0 300 >/dev/null 2>&1
    log "victim transparent balance: $(rpc 1 getbalance 2>&1 | tr -d '"[:space:]')"

    # The IV5 seed is spend authority for every note the wallet will own, so it
    # is only created into an encrypted wallet. Encrypting stops the daemon.
    rpc 1 encryptwallet "$WALLETPASS" >/dev/null 2>&1
    for _ in $(seq 1 90); do daemon_pids 1 >/dev/null 2>&1 || break; sleep 1; done
    start_node 1 || { fail "victim did not restart after encrypting its wallet"; WALLET_PHASE_OK=0; }
fi

if [ "$WALLET_PHASE_OK" = "1" ]; then
    connect_peers 1
    rpc 1 walletpassphrase "$WALLETPASS" 36000 >/dev/null 2>&1
    SEED="$(rpc 1 z_createiv5seed 2>&1)"
    echo "$SEED" | grep -q '"created"' \
        && success "victim created an IV5 seed" \
        || warn "z_createiv5seed: $(echo "$SEED" | head -1)"

    mine_to 0 "$H_WALLET" >/dev/null 2>&1
    wait_converge 1 0 600 >/dev/null 2>&1

    SHIELD_OUT="$(rpc 1 z_shieldall 2>&1)"
    if echo "$SHIELD_OUT" | grep -q '"txid"'; then
        success "victim shielded value into the pool"
    else
        warn "z_shieldall did not produce a txid: $(echo "$SHIELD_OUT" | head -1)"
    fi

    # Confirm the shield, then run past the epoch close at 611 so the notes are
    # committed to the tree rather than sitting in the wallet only.
    mine_to 0 "$H_WALLET_TREE" >/dev/null 2>&1
    wait_converge 1 0 900 >/dev/null 2>&1
    TARGET="$(height 1)"
fi

if [ "$WALLET_PHASE_OK" = "1" ]; then
    # The IV5 note state lives behind z_getshieldedinfo. z_listunspent reports
    # the legacy pool and stays empty for a 2008-envelope shield, so a capture
    # built on it would compare nothing and pass. privacy_vnext_note_count is
    # the wallet-side count a missed scan actually decrements.
    capture_notes() {
        local out="$1"
        : > "$out"
        rpc 1 z_getshieldedinfo 2>/dev/null \
            | grep -oE '"(privacy_vnext_note_count|privacy_vnext_balance|privacy_vnext_pool_value|privacy_vnext_tree_size)" *: *-?[0-9.]+' \
            | sort >> "$out"
        rpc 1 z_listunspent 2>/dev/null \
            | grep -oE '"(txid|amount|address)" *: *("[^"]*"|-?[0-9.]+)' | sort >> "$out"
        rpc 1 listunspent 2>/dev/null \
            | grep -oE '"(txid|amount|vout)" *: *("[^"]*"|-?[0-9.]+)' | sort >> "$out"
        rpc 1 z_gettotalbalance 2>/dev/null \
            | grep -oE '"(transparent|shielded|total)" *: *-?[0-9.]+' | sort >> "$out"
    }

    capture_notes "$EVIDENCE_DIR/notes.before.txt"
    NOTES_BEFORE="$(digest_of "$EVIDENCE_DIR/notes.before.txt")"
    NOTE_LINES="$(wc -l < "$EVIDENCE_DIR/notes.before.txt" | tr -d ' ')"
    log "victim note set captured at height $TARGET: $NOTE_LINES fields, digest $NOTES_BEFORE"

    # Connect a few blocks and kill inside the 30s window so neither locator trigger fires.
    mine_to 0 $(( TARGET + 5 )) >/dev/null 2>&1
    wait_height 1 $(( TARGET + 5 )) 60 >/dev/null 2>&1
    KILL_WALLET="$(height 1)"
    if kill_node 1; then
        success "victim SIGKILLed at height $KILL_WALLET with the locator behind the chain"
        echo "kill_wallet_height: $KILL_WALLET" >> "$EVIDENCE_DIR/manifest.txt"
        echo "notes_before: $NOTES_BEFORE ($NOTE_LINES fields)" >> "$EVIDENCE_DIR/manifest.txt"
    else
        fail "could not kill the victim in the wallet phase"
        WALLET_PHASE_OK=0
    fi
fi

if [ "$WALLET_PHASE_OK" = "1" ]; then
    if start_node 1; then
        success "victim restarted and completed its startup recovery"
    else
        diagnose_failed_start "wallet-locator kill"
        WALLET_PHASE_OK=0
    fi
fi

if [ "$WALLET_PHASE_OK" = "1" ]; then
    connect_peers 1
    rpc 1 walletpassphrase "$WALLETPASS" 36000 >/dev/null 2>&1
    wait_height 1 "$KILL_WALLET" 900 >/dev/null 2>&1

    capture_notes "$EVIDENCE_DIR/notes.after.txt"
    NOTES_AFTER="$(digest_of "$EVIDENCE_DIR/notes.after.txt")"
    echo "notes_after: $NOTES_AFTER" >> "$EVIDENCE_DIR/manifest.txt"

    # Every note identity known before the kill must still be known after it.
    # Containment rather than digest equality: the balance summary legitimately
    # moves as the chain advances, but a note may never disappear.
    MISSING=0
    : > "$EVIDENCE_DIR/notes.lost.txt"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        grep -qxF "$line" "$EVIDENCE_DIR/notes.after.txt" || {
            MISSING=$((MISSING + 1))
            echo "$line" >> "$EVIDENCE_DIR/notes.lost.txt"
        }
    done < "$EVIDENCE_DIR/notes.before.txt"

    # The sharpest signal on its own: the wallet's own count of the notes it
    # can see. A rescan that skips the shielded scan drives this down.
    note_count_in() {
        sed -n 's/.*"privacy_vnext_note_count" *: *\([0-9]*\).*/\1/p' "$1" | head -1
    }
    NC_BEFORE="$(note_count_in "$EVIDENCE_DIR/notes.before.txt")"
    NC_AFTER="$(note_count_in "$EVIDENCE_DIR/notes.after.txt")"
    NC_BEFORE="${NC_BEFORE:-0}"; NC_AFTER="${NC_AFTER:-0}"
    echo "note_count: before=$NC_BEFORE after=$NC_AFTER" >> "$EVIDENCE_DIR/manifest.txt"

    if [ "$NC_BEFORE" -le 0 ]; then
        fail "the victim held no shielded notes to lose: the fund-loss case proved nothing"
    elif [ "$NC_AFTER" -lt "$NC_BEFORE" ]; then
        fail "FUND LOSS: shielded note count fell from $NC_BEFORE to $NC_AFTER across the SIGKILL"
    else
        success "shielded note count survived the SIGKILL ($NC_BEFORE before, $NC_AFTER after)"
    fi

    if [ "$NOTE_LINES" -le 1 ]; then
        fail "the victim held no wallet state to lose: the fund-loss case proved nothing"
    elif [ "$MISSING" -eq 0 ]; then
        success "no note field was lost across the SIGKILL (all $NOTE_LINES pre-kill fields present)"
        echo "notes_lost: 0" >> "$EVIDENCE_DIR/manifest.txt"
    else
        fail "FUND LOSS: $MISSING note fields present before the kill are absent after recovery"
        echo "notes_lost: $MISSING" >> "$EVIDENCE_DIR/manifest.txt"
        head -20 "$EVIDENCE_DIR/notes.lost.txt"
    fi
else
    fail "the wallet-locator phase could not run: the fund-loss case is unproven"
    echo "wallet_phase: NOT RUN" >> "$EVIDENCE_DIR/manifest.txt"
fi

# ===========================================================================
header "4. SIGKILL during a reorg that recrosses an epoch boundary"
# ===========================================================================
# Kill during the epoch-state suffix rewrite; the invalidated span crosses the 611
# boundary, so recovery must redo the suffix.

mine_to 0 "$H_REORG_TIP" || { fail "producer could not reach $H_REORG_TIP"; exit 1; }
wait_height 1 "$H_REORG_TIP" 900 || { fail "victim did not reach $H_REORG_TIP"; exit 1; }
wait_height 2 "$H_REORG_TIP" 900 || { fail "control did not reach $H_REORG_TIP"; exit 1; }
success "all three nodes past $H_REORG_TIP with epoch 1 durable"

# Park the victim while the competing branch is built so it meets the reorg at once.
# The reorg has started once its height leaves this parked height.
PARKED_HEIGHT="$(height 1)"
stop_node 1 || warn "victim did not stop cleanly before the reorg phase"
log "victim parked at $PARKED_HEIGHT on the old branch"

REORG_HASH="$(rpc 0 getblockhash "$REORG_FROM" 2>/dev/null | tr -d '"[:space:]')"
if ! echo "$REORG_HASH" | grep -qE '^[0-9a-f]{64}$'; then
    fail "could not read the block hash at $REORG_FROM: the reorg phase cannot run"
    echo "reorg_phase: NOT RUN" >> "$EVIDENCE_DIR/manifest.txt"
else
    log "invalidating $REORG_FROM ($REORG_HASH) on the producer and building a longer branch"
    rpc 0 invalidateblock "$REORG_HASH" >/dev/null 2>&1
    mine_to 0 "$H_REORG_NEW" || { fail "producer could not build the competing branch"; exit 1; }
    success "producer built a competing branch to $(height 0)"

    launch_node 1

    # The victim starts at its parked height and stays there until the rollback
    # moves it, so "height is in range" is not the trigger -- it is true before
    # anything has happened. Having left the parked height is the trigger.
    KILL_REORG=""
    reorg_deadline=$(( SECONDS + 900 ))
    while [ "$SECONDS" -lt "$reorg_deadline" ]; do
        h="$(height 1)"
        if is_int "$h" && [ "$h" -ne "$PARKED_HEIGHT" ]; then
            if [ "$h" -lt "$H_REORG_NEW" ]; then
                if kill_node 1; then KILL_REORG="$h"; break; fi
            else
                break
            fi
        fi
    done

    if [ -z "$KILL_REORG" ]; then
        warn "victim completed the reorg before a kill landed; killing at the new tip instead"
        KILL_REORG="$(height 1)"
        kill_node 1 || true
        echo "kill_reorg_height: $KILL_REORG (AT TIP, not mid-reorg)" >> "$EVIDENCE_DIR/manifest.txt"
        fail "no mid-reorg window was reached: the epoch-suffix write was not interrupted"
    else
        success "victim SIGKILLed during the reorg at height $KILL_REORG (parked at $PARKED_HEIGHT)"
        echo "kill_reorg_height: $KILL_REORG (mid-reorg, parked $PARKED_HEIGHT)" >> "$EVIDENCE_DIR/manifest.txt"
    fi

    REORG_RESTARTED=1
    if start_node 1; then
        success "victim restarted after a reorg-time kill"
    else
        # Not fatal. The run still has to emit its manifest: a node that will
        # not come back is the result, not a reason to print nothing.
        diagnose_failed_start "reorg + epoch-suffix kill"
        REORG_RESTARTED=0
    fi
fi

if [ "${REORG_RESTARTED:-0}" = "1" ]; then
    connect_peers 1

    wait_height 1 "$H_REORG_NEW" 900 || fail "victim did not reach the new tip $H_REORG_NEW"
    wait_height 2 "$H_REORG_NEW" 900 || fail "control did not reach the new tip $H_REORG_NEW"
    if wait_converge 1 2 600; then
        success "victim and control converged on one tip after the reorg kill"
    else
        fail "victim and control never converged after the reorg kill"
    fi

    capture 1 "reorg.victim"
    capture 2 "reorg.control"
    compare_states "reorg.victim" "reorg.control" "reorg + epoch-suffix kill"

    # The comparison is only meaningful if both actually left the old chain.
    V_TIP="$(besthash 1)"; P_TIP="$(besthash 0)"
    if [ "$V_TIP" = "$P_TIP" ]; then
        success "victim followed the producer onto the rebuilt branch"
    else
        fail "victim did not reach the producer's branch (victim=$V_TIP producer=$P_TIP)"
    fi
fi

# ===========================================================================
header "Evidence"
# ===========================================================================

{
    echo "finished:           $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "passed:             $PASSED"
    echo "failed:             $FAILED"
} >> "$EVIDENCE_DIR/manifest.txt"

MANIFEST_SHA="$(digest_of "$EVIDENCE_DIR/manifest.txt")"
echo
echo "evidence:               $EVIDENCE_DIR"
echo "crash_injection_sha256: $MANIFEST_SHA"
echo

echo -e "${CYAN}WHAT THIS DOES NOT COVER${NC}"
cat <<'LIMITS'
  - Not a torn-write test. SIGKILL ends the process; it does not cut power or
    lose the page cache. Berkeley DB and LevelDB still see an ordered, complete
    write stream, so this cannot fail the way a real power loss can. Proving
    durability under a lost cache needs a block-device fault injector, and this
    harness is not one.
  - The kill points are timing-driven, not instrumented. The harness kills a
    node whose height is moving, which puts it inside the connect loop, but it
    cannot aim at a named line. A specific window -- between the LevelDB outbox
    write and the Berkeley DB log flush, for instance -- is reached only by
    chance, and only across repeated runs.
  - The locator lag in phase 3 is arranged, not observed. Neither
    HasPendingWalletLocator nor HasPendingNameIndexCursor is exposed by RPC, so
    the harness sets the batch knobs so a count-triggered flush cannot have
    happened and kills inside the 30s time trigger. It cannot assert the batch
    was actually in flight.
  - One kill per phase, one ordering. Concurrent kills, kills during the
    startup rescan itself, and kills of the producer are not exercised.
  - Regtest only, single host, no network partition and no clock skew.
  - The digest compares what RPC exposes: tip, per-epoch consensus state and
    the IDNS name index. It is not a full database byte-compare. State that no
    RPC reports can differ without this test seeing it.
  - A pass is evidence about this commit on this platform. It says nothing
    about a crash on a different storage stack or filesystem.
LIMITS

echo
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}crash-injection gate passed: $PASSED checks${NC}"
    exit 0
fi
echo -e "${RED}crash-injection gate failed: $FAILED of $((PASSED + FAILED)) checks${NC}"
exit 1
