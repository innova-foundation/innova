#!/bin/bash
# IDAG finality bootstrap and legacy-privacy quarantine regression: the transparent
# bootstrap vote relays, and legacy private vote/share/certificate production stays
# fail-closed through Boundary A (height 311) with Boundary B unconfigured.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init idag_finality_relay_test || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IDAG_RELAY_TEST_DIR:-/tmp/innova_finality_relay_$$}"
BASE_PORT="${IDAG_RELAY_BASE_PORT:-$(iv5_port 0 18240)}"
BASE_RPC="${IDAG_RELAY_BASE_RPC:-$(iv5_port 16 19240)}"
BASE_IDNS="${IDAG_RELAY_BASE_IDNS:-$(iv5_port 32 8440)}"
NUM_NODES=3
KEEP_DIR="${IDAG_RELAY_KEEP_DIR:-0}"
RPCUSER="${IDAG_RELAY_RPCUSER:-relayfinality}"
RPCPASS="${IDAG_RELAY_RPCPASS:-relaypass}"

# Finality tally committee: N ordered pubkeys + an M-of-N threshold. Defaults to a
# 1-of-1 committee (member 0 on node0). Override for M-of-N, e.g. a 2-of-3:
#   IDAG_RELAY_COMMITTEE_THRESHOLD=2-of-3
#   IDAG_RELAY_COMMITTEE_PUBKEYS="<P0> <P1> <P2>"
#   IDAG_RELAY_COMMITTEE_PRIVKEYS="<k0> <k1> <k2>"   # node i holds committee key i
# All nodes list the SAME ordered pubkeys (the set hash and signer indexes are
# order-dependent); node i's local committee index is the position of key i.
COMMITTEE_THRESHOLD="${IDAG_RELAY_COMMITTEE_THRESHOLD:-1-of-1}"
read -r -a COMMITTEE_PUBKEYS <<< "${IDAG_RELAY_COMMITTEE_PUBKEYS:-0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798}"
read -r -a COMMITTEE_PRIVKEYS <<< "${IDAG_RELAY_COMMITTEE_PRIVKEYS:-0000000000000000000000000000000000000000000000000000000000000001}"
COMMITTEE_M="${COMMITTEE_THRESHOLD%%-of-*}"

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

node_dir() { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc() { echo $((BASE_RPC + $1)); }
node_idns() { echo $((BASE_IDNS + $1)); }

rpc() {
    local node="$1"
    shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest \
        -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>&1
}

json_field() {
    local json="$1"
    local field="$2"
    FIELD="$field" python3 -c '
import json
import os
import sys
try:
    value = json.load(sys.stdin).get(os.environ["FIELD"], "")
    if isinstance(value, bool):
        print(str(value).lower())
    elif value is None:
        print("")
    else:
        print(value)
except Exception:
    pass
' <<< "$json" 2>/dev/null
}

json_array_len() {
    local json="$1"
    local field="$2"
    FIELD="$field" python3 -c '
import json
import os
import sys
try:
    value = json.load(sys.stdin).get(os.environ["FIELD"], [])
    print(len(value) if isinstance(value, list) else 0)
except Exception:
    print(0)
' <<< "$json" 2>/dev/null
}

json_private_cert_count() {
    local json="$1"
    python3 -c '
import json
import sys
try:
    obj = json.load(sys.stdin)
    certs = obj.get("finality_tally_certificates", [])
    # A private tally certificate is v2 pre-governance-fork and v3 once the
    # committee signer-set rule is active (FORK_HEIGHT_TALLY_GOVERNANCE); accept
    # either so the check is valid on both sides of the fork.
    print(sum(1 for cert in certs
              if isinstance(cert, dict)
              and cert.get("private_weight") is True
              and int(cert.get("version", 0)) in (2, 3)))
except Exception:
    print(0)
' <<< "$json" 2>/dev/null
}

# Max committee signer_count across the block's private certificates (M-of-N proof).
json_max_cert_signers() {
    local json="$1"
    python3 -c '
import json
import sys
try:
    obj = json.load(sys.stdin)
    certs = obj.get("finality_tally_certificates", [])
    counts = [int(cert.get("signer_count", 0)) for cert in certs
              if isinstance(cert, dict) and cert.get("private_weight") is True]
    print(max(counts) if counts else 0)
except Exception:
    print(0)
' <<< "$json" 2>/dev/null
}

json_canonical() {
    python3 -c '
import json, sys
try:
    print(json.dumps(json.load(sys.stdin), sort_keys=True, separators=(",", ":")))
except Exception:
    print("INVALID_JSON")
'
}

json_sorted_dag_tips() {
    python3 -c '
import json, sys
try:
    value = json.load(sys.stdin)
    value = sorted(value, key=lambda item: str(item.get("hash", "")))
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
except Exception:
    print("INVALID_JSON")
'
}

json_sorted_array() {
    python3 -c '
import json, sys
try:
    value = sorted(json.load(sys.stdin))
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
except Exception:
    print("INVALID_JSON")
'
}

json_consensus_finality() {
    python3 -c '
import json, sys
fields = (
    "height", "epoch", "finalized_height", "finalized_hash", "finality_tier",
    "consecutive_hard_epochs", "tally_threshold", "tally_committee_set_hash",
    "connected_committee_rotations", "epoch_state_health",
    "epoch_state_schema_version", "epoch_state_schema_marker_present",
    "epoch_state_anchor_rule", "epoch_state_digest",
    "deterministic_finalized_height_available", "deterministic_finalized_height",
)
try:
    value = json.load(sys.stdin)
    selected = {field: value.get(field) for field in fields}
    print(json.dumps(selected, sort_keys=True, separators=(",", ":")))
except Exception:
    print("INVALID_JSON")
'
}

# Connected committee rotation at a given effective epoch: prints
# "<signers> <new_set_hash> <new_threshold>" or "MISSING".
json_rotation_at_epoch() {
    local json="$1"
    EFF="$2" python3 -c '
import json, os, sys
try:
    obj = json.load(sys.stdin)
    eff = int(os.environ["EFF"])
    for r in obj.get("connected_committee_rotations", []):
        if isinstance(r, dict) and int(r.get("effective_epoch", -1)) == eff:
            print("%d %s %s" % (int(r.get("signers", 0)), r.get("new_set_hash", ""), r.get("new_threshold", "")))
            sys.exit(0)
    print("MISSING")
except Exception:
    print("ERROR")
' <<< "$json" 2>/dev/null
}

is_int() {
    echo "$1" | grep -qE '^[0-9]+$'
}

height() {
    rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'
}

block_hash() {
    rpc "$1" getblockhash "$2" 2>/dev/null | tr -d '"[:space:]'
}

block_json() {
    local node="$1"
    local h="$2"
    local hash
    hash="$(block_hash "$node" "$h")"
    [ -n "$hash" ] || return 1
    rpc "$node" getblock "$hash" 2>/dev/null
}

peer_count() {
    rpc "$1" getpeerinfo 2>/dev/null | python3 -c '
import json
import sys
try:
    peers = json.load(sys.stdin)
    print(len(peers) if isinstance(peers, list) else 0)
except Exception:
    print(0)
'
}

wait_rpc() {
    local node="$1"
    local attempt
    for ((attempt=0; attempt<60; attempt++)); do
        rpc "$node" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

wait_rpc_down() {
    local node="$1"
    local attempt
    local pidfile="$(node_dir "$node")/finality_relay.pid"
    local pid
    for ((attempt=0; attempt<45; attempt++)); do
        if ! rpc "$node" getinfo >/dev/null 2>&1; then
            # RPC stops before the DB flush and datadir lock release. Wait until no process holds
            # the datadir (the lock, not the pid file, is authoritative).
            if pgrep -f "datadir=$(node_dir "$node")" >/dev/null 2>&1; then
                sleep 1
                continue
            fi
            if [ ! -s "$pidfile" ]; then
                return 0
            fi
            pid="$(tr -dc '0-9' < "$pidfile" 2>/dev/null)"
            if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}

wait_peer_count() {
    local node="$1"
    local target="$2"
    local attempt
    local count
    for ((attempt=0; attempt<45; attempt++)); do
        count="$(peer_count "$node")"
        if is_int "$count" && [ "$count" -ge "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

connect_mesh() {
    local node
    local peer
    for ((node=0; node<NUM_NODES; node++)); do
        for ((peer=0; peer<NUM_NODES; peer++)); do
            [ "$node" -eq "$peer" ] && continue
            [ "$node" -gt "$peer" ] && continue
            rpc "$node" addnode "127.0.0.1:$(node_port "$peer")" onetry >/dev/null 2>&1 || true
        done
    done
}

add_persistent_peer() {
    local node="$1"
    local peer="$2"
    local address="127.0.0.1:$(node_port "$peer")"
    rpc "$node" addnode "$address" add >/dev/null 2>&1 || true
    rpc "$node" addnode "$address" onetry >/dev/null 2>&1 || true
}

remove_persistent_peer() {
    local node="$1"
    local peer="$2"
    local address="127.0.0.1:$(node_port "$peer")"
    rpc "$node" addnode "$address" remove >/dev/null 2>&1 || true
    rpc "$node" disconnectnode "$address" >/dev/null 2>&1 || true
}

wait_hash_convergence() {
    local target_height="$1"
    local max_attempts="${2:-180}"
    local attempt
    local node
    local expected
    local observed
    for ((attempt=0; attempt<max_attempts; attempt++)); do
        expected="$(block_hash 0 "$target_height")"
        if [ -n "$expected" ]; then
            local converged=1
            for ((node=1; node<NUM_NODES; node++)); do
                observed="$(block_hash "$node" "$target_height")"
                if [ "$observed" != "$expected" ]; then
                    converged=0
                    break
                fi
            done
            [ "$converged" -eq 1 ] && return 0
        fi
        sleep 1
    done
    return 1
}

# wait_all_height TARGET [MAX_ATTEMPTS]
# MAX_ATTEMPTS defaults to 90 (~90s). Blocks that carry private finality
# payloads (vote/share/certificate) must verify FCMP + nullifier-binding +
# committee proofs during ConnectBlock, which is CPU-bound and can take
# minutes on a shared/oversubscribed host. Pass a larger MAX_ATTEMPTS for
# those steps so the test does not false-fail on slow hardware; a genuine
# rejection still fails because the peer never reaches TARGET at all.
wait_all_height() {
    local target="$1"
    local max_attempts="${2:-90}"
    local attempt
    local node
    local h
    for ((attempt=0; attempt<max_attempts; attempt++)); do
        local ready=1
        for ((node=0; node<NUM_NODES; node++)); do
            h="$(height "$node")"
            if ! is_int "$h" || [ "$h" -lt "$target" ]; then
                ready=0
                break
            fi
        done
        [ "$ready" -eq 1 ] && return 0
        sleep 1
    done
    return 1
}

mine_one() {
    local node="$1"
    local max_iters="${2:-600}"
    local before
    local after
    local attempt
    before="$(height "$node")"
    is_int "$before" || return 1

    rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1
    # max_iters*0.25s (default 600 -> 150s): regtest PoW for a single block can be
    # slow on a contended host, and a block that EMBEDS a committee certificate
    # also re-verifies it (VerifyMofN + BPAC + FCMP) in CreateNewBlock, which is
    # much heavier for an M-of-N cert -- callers pass a larger cap for that step.
    for ((attempt=0; attempt<max_iters; attempt++)); do
        after="$(height "$node")"
        if is_int "$after" && [ "$after" -gt "$before" ]; then
            rpc "$node" setgenerate false 0 >/dev/null 2>&1 || true
            return 0
        fi
        sleep 0.25
    done
    rpc "$node" setgenerate false 0 >/dev/null 2>&1 || true
    return 1
}

mine_until_height() {
    local node="$1"
    local target="$2"
    local h
    h="$(height "$node")"
    is_int "$h" || return 1
    while [ "$h" -lt "$target" ]; do
        mine_one "$node" || return 1
        h="$(height "$node")"
        is_int "$h" || return 1
        if [ $((h % 5)) -eq 0 ] || [ "$h" -eq "$target" ]; then
            log "  ...height $h/$target"
        fi
    done
}

mine_until_height_synced() {
    local node="$1"
    local target="$2"
    local h
    h="$(height "$node")"
    is_int "$h" || return 1
    while [ "$h" -lt "$target" ]; do
        mine_one "$node" || return 1
        h="$(height "$node")"
        is_int "$h" || return 1
        if [ $((h % 5)) -eq 0 ] || [ "$h" -eq "$target" ]; then
            log "  ...height $h/$target"
        fi
        wait_all_height "$h" || return 1
    done
}

wait_for_pending_vote() {
    local attempt
    local info
    local pending
    for ((attempt=0; attempt<120; attempt++)); do
        info="$(rpc 0 getfinalityinfo 2>/dev/null)"
        pending="$(json_field "$info" "pending_votes")"
        if is_int "$pending" && [ "$pending" -ge 1 ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

write_config() {
    local node="$1"
    local dir
    local peer
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
        echo "debug=1"
        echo "staking=1"
        echo "nofinalityvoting=0"
        # Auto: transparent voting starts immediately, private voting only after a finalized
        # epoch, which Boundary A preempts on regtest.
        echo "finalityvotemode=auto"
        echo "finalitytallymode=committee"
        echo "finalitytallythreshold=$COMMITTEE_THRESHOLD"
        for pk in "${COMMITTEE_PUBKEYS[@]}"; do echo "finalitytallypubkey=$pk"; done
        echo "getdatablockbatch=128"
        echo "maxconnections=32"
        # Keep the local fleet in the persistent addnode set.  The old harness
        # only issued one-shot connections, so a restarted committee member
        # could remain isolated forever even though its chain data was valid.
        for ((peer=0; peer<NUM_NODES; peer++)); do
            [ "$peer" -eq "$node" ] && continue
            echo "addnode=127.0.0.1:$(node_port "$peer")"
        done
        # Node i holds committee key i (so its local committee index is i). For the
        # default 1-of-1 only node0 is keyed; for M-of-N each member node is keyed.
        if [ "$node" -lt "${#COMMITTEE_PRIVKEYS[@]}" ]; then
            echo "finalitytallyprivkey=${COMMITTEE_PRIVKEYS[$node]}"
        fi
    } > "$dir/innova.conf"
}

start_node() {
    local node="$1"
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -daemon \
        -pid="$(node_dir "$node")/finality_relay.pid" >/dev/null 2>&1
}

cleanup() {
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        rpc "$node" stop >/dev/null 2>&1 || true
    done
    for ((node=0; node<NUM_NODES; node++)); do
        wait_rpc_down "$node" >/dev/null 2>&1 || true
    done
    iv5_kill_daemons "${TEST_DIR}" TERM 2>/dev/null || true
    if [ "$KEEP_DIR" = "1" ] || [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

header "IDAG Finality Relay"

COMMITTEE_N="${COMMITTEE_THRESHOLD##*-of-}"
if ! is_int "$COMMITTEE_M" || ! is_int "$COMMITTEE_N" || \
   [ "$COMMITTEE_M" -lt 1 ] || [ "$COMMITTEE_N" -lt "$COMMITTEE_M" ]; then
    fail "invalid committee threshold '$COMMITTEE_THRESHOLD' (expected M-of-N)"
    exit 1
fi
if [ "${#COMMITTEE_PUBKEYS[@]}" -ne "$COMMITTEE_N" ]; then
    fail "committee threshold declares N=$COMMITTEE_N but ${#COMMITTEE_PUBKEYS[@]} public keys were supplied"
    exit 1
fi
if [ "${#COMMITTEE_PRIVKEYS[@]}" -gt "$COMMITTEE_N" ]; then
    fail "more committee private keys than declared members"
    exit 1
fi
# Private certificate recovery is a Boundary-B test. Treat a request for the
# obsolete legacy lifecycle as an error, never as passing or skipped evidence.
if [ "${IDAG_RELAY_TEST_RECOVERY:-0}" = "1" ]; then
    fail "legacy private certificate recovery was requested, but Boundary B/privacy-vNext is unconfigured"
    exit 1
fi

if [ ! -x "$INNOVAD" ]; then
    fail "innovad not found at $INNOVAD"
    exit 1
fi

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

for ((node=0; node<NUM_NODES; node++)); do
    write_config "$node"
done

log "Starting $NUM_NODES-node local regtest mesh"
for ((node=0; node<NUM_NODES; node++)); do
    start_node "$node"
    sleep 1
done

for ((node=0; node<NUM_NODES; node++)); do
    if wait_rpc "$node"; then
        success "node$node RPC ready"
    else
        fail "node$node RPC did not become ready"
        exit 1
    fi
done

connect_mesh
for ((node=0; node<NUM_NODES; node++)); do
    if wait_peer_count "$node" 2; then
        success "node$node connected to peers"
    else
        fail "node$node did not connect to peers"
        exit 1
    fi
done

header "Committee Setup ($COMMITTEE_THRESHOLD)"
# Every node must resolve the SAME canonical committee (set hash + threshold), and
# each keyed member node must report its own local committee index. This is the
# precondition for M-of-N signature collection.
COMMITTEE_SET_HASH=""
COMMITTEE_OK=1
for ((node=0; node<NUM_NODES; node++)); do
    INFO="$(rpc "$node" getfinalityinfo 2>/dev/null)"
    cvalid="$(json_field "$INFO" "tally_committee_valid")"
    cthr="$(json_field "$INFO" "tally_threshold")"
    cset="$(json_field "$INFO" "tally_committee_set_hash")"
    cidx="$(json_field "$INFO" "tally_local_committee_index")"
    [ -z "$COMMITTEE_SET_HASH" ] && COMMITTEE_SET_HASH="$cset"
    log "  node$node: valid=$cvalid threshold=$cthr local_index=$cidx set_hash=${cset:0:12}"
    if [ "$cvalid" != "true" ] || [ "$cthr" != "$COMMITTEE_THRESHOLD" ] || [ "$cset" != "$COMMITTEE_SET_HASH" ]; then
        COMMITTEE_OK=0
    fi
    if [ "$node" -lt "${#COMMITTEE_PRIVKEYS[@]}" ] && [ "$cidx" != "$node" ]; then
        COMMITTEE_OK=0
    fi
done
if [ "$COMMITTEE_OK" -eq 1 ]; then
    success "committee resolves consistently ($COMMITTEE_THRESHOLD, set_hash ${COMMITTEE_SET_HASH:0:12}) with distinct member indexes"
else
    fail "committee configuration inconsistent across nodes"
    exit 1
fi

header "Pre-DAG Shielded Note"

log "Mining spendable funding before DAG activation"
mine_until_height_synced 0 8 || { fail "pre-DAG mining failed"; exit 1; }
wait_all_height 8 || { fail "peers did not sync to height 8"; exit 1; }

ZADDR="$(rpc 0 z_getnewaddress 2>/dev/null | tr -d '"[:space:]')"
if [ -z "$ZADDR" ]; then
    fail "z_getnewaddress failed"
    exit 1
fi
success "shielded address created"

SHIELD_RESULT="$(rpc 0 z_shield "*" 100.0 "$ZADDR" 2>/dev/null)"
if echo "$SHIELD_RESULT" | grep -q '"txid"'; then
    success "shielding transaction created before DAG activation"
else
    fail "z_shield failed: $SHIELD_RESULT"
    exit 1
fi

mine_one 0 || { fail "failed to confirm shielded note"; exit 1; }
wait_all_height 9 || { fail "shielded-note block did not relay"; exit 1; }
ZBAL="$(rpc 0 z_getbalance "$ZADDR" 2>/dev/null | tr -d '"[:space:]')"
if [ -n "$ZBAL" ] && [ "$ZBAL" != "0" ] && [ "$ZBAL" != "0.00000000" ]; then
    success "shielded note confirmed in epoch 0"
else
    fail "shielded note did not become wallet-visible, balance=$ZBAL"
    exit 1
fi

header "Transparent Finality Bootstrap Relay"

log "Mining to DAG activation so epoch 0 roots are available"
mine_until_height_synced 0 11 || { fail "DAG activation mining failed"; exit 1; }
wait_all_height 11 || { fail "peers did not sync to DAG activation"; exit 1; }
success "DAG activation block relayed"

# Votes are held until FINALITY_VOTE_EMIT_OFFSET_POST_DAG blocks past the boundary,
# which here is the activation height, so mine out the margin first. The carrier
# still lands inside the 24-block inclusion window from height 11.
log "Mining out the vote-emission ordering margin"
mine_until_height_synced 0 13 || { fail "emission-margin mining failed"; exit 1; }
wait_all_height 13 || { fail "peers did not sync past the emission margin"; exit 1; }

log "Waiting for node0 auto mode to produce the transparent bootstrap vote"
if wait_for_pending_vote; then
    success "transparent bootstrap vote is pending"
else
    INFO="$(rpc 0 getfinalityinfo 2>/dev/null)"
    fail "transparent bootstrap vote did not become pending: $INFO"
    exit 1
fi

PAYLOAD_BEFORE="$(height 0)"
mine_one 0 || { fail "failed to mine bootstrap-vote payload block"; exit 1; }
PAYLOAD_HEIGHT="$(height 0)"
wait_all_height "$PAYLOAD_HEIGHT" 600 || { fail "bootstrap-vote payload block did not relay"; exit 1; }

HASH0="$(block_hash 0 "$PAYLOAD_HEIGHT")"
HASH1="$(block_hash 1 "$PAYLOAD_HEIGHT")"
HASH2="$(block_hash 2 "$PAYLOAD_HEIGHT")"
if [ "$HASH0" = "$HASH1" ] && [ "$HASH0" = "$HASH2" ]; then
    success "transparent bootstrap-vote block relayed through P2P at height $PAYLOAD_HEIGHT"
else
    fail "nodes disagree on bootstrap-vote block hash: $HASH0 $HASH1 $HASH2"
    exit 1
fi

PAYLOAD_JSON="$(block_json 2 "$PAYLOAD_HEIGHT")"
VOTE_COUNT="$(json_array_len "$PAYLOAD_JSON" "finality_votes")"
SHARE_COUNT="$(json_array_len "$PAYLOAD_JSON" "finality_tally_shares")"
CERT_COUNT="$(json_private_cert_count "$PAYLOAD_JSON")"

if is_int "$VOTE_COUNT" && [ "$VOTE_COUNT" -ge 1 ]; then
    success "relayed block contains the transparent finality vote payload"
else
    fail "relayed block missing finality vote payload"
fi

if is_int "$SHARE_COUNT" && [ "$SHARE_COUNT" -eq 0 ] && \
   is_int "$CERT_COUNT" && [ "$CERT_COUNT" -eq 0 ]; then
    success "no legacy private share or certificate was produced without a finalized root"
else
    fail "legacy private payload appeared before finality bootstrap (shares=$SHARE_COUNT certs=$CERT_COUNT)"
fi

if [ "$PAYLOAD_BEFORE" != "$PAYLOAD_HEIGHT" ]; then
    success "bootstrap payload was delivered by mined block relay; submitblock was not used"
else
    fail "payload mining height did not advance"
fi

BOOTSTRAP_INFO="$(rpc 0 getfinalityinfo 2>/dev/null)"
BOOTSTRAP_FINALIZED="$(json_field "$BOOTSTRAP_INFO" "finalized_height")"
BOOTSTRAP_PRIVATE="$(json_field "$BOOTSTRAP_INFO" "private_votes")"
BOOTSTRAP_SHARES="$(json_field "$BOOTSTRAP_INFO" "current_epoch_tally_shares")"
BOOTSTRAP_CERT="$(json_field "$BOOTSTRAP_INFO" "pending_private_certificate_present")"
if [ "$BOOTSTRAP_FINALIZED" = "0" ] && [ "$BOOTSTRAP_PRIVATE" = "0" ] && \
   [ "$BOOTSTRAP_SHARES" = "0" ] && [ "$BOOTSTRAP_CERT" = "false" ]; then
    success "legacy private vote/share/certificate state is empty before a finalized root exists"
else
    fail "pre-finalization private state was not fail-closed (finalized=$BOOTSTRAP_FINALIZED private=$BOOTSTRAP_PRIVATE shares=$BOOTSTRAP_SHARES cert=$BOOTSTRAP_CERT)"
fi

header "Boundary A Unsafe-Legacy-Privacy Quarantine"

# Height 311 starts the next epoch and is Boundary A: auto mode casts a transparent
# vote and must never enter the legacy private path.
BOUNDARY_A_HEIGHT="$(json_field "$BOOTSTRAP_INFO" "boundary_a_activation_height")"
if ! is_int "$BOUNDARY_A_HEIGHT" || [ "$BOUNDARY_A_HEIGHT" -le "$PAYLOAD_HEIGHT" ]; then
    fail "invalid Boundary A activation height '$BOUNDARY_A_HEIGHT'"
    exit 1
fi
log "Mining transparently to Boundary A at height $BOUNDARY_A_HEIGHT"
mine_until_height_synced 0 "$BOUNDARY_A_HEIGHT" || { fail "failed to mine to Boundary A"; exit 1; }
wait_all_height "$BOUNDARY_A_HEIGHT" 600 || { fail "Boundary A block did not relay"; exit 1; }

# Boundary A is an epoch boundary too, so the same emission margin applies: the vote
# is held until the tip is two blocks past it.
MARGIN_HEIGHT=$((BOUNDARY_A_HEIGHT + 2))
mine_until_height_synced 0 "$MARGIN_HEIGHT" || { fail "Boundary A margin mining failed"; exit 1; }
wait_all_height "$MARGIN_HEIGHT" 600 || { fail "Boundary A margin blocks did not relay"; exit 1; }

if wait_for_pending_vote; then
    success "auto mode produced the next transparent vote at Boundary A"
else
    INFO="$(rpc 0 getfinalityinfo 2>/dev/null)"
    fail "Boundary A transparent vote did not become pending: $INFO"
    exit 1
fi

mine_one 0 || { fail "failed to mine Boundary A transparent-vote block"; exit 1; }
BOUNDARY_PAYLOAD_HEIGHT="$(height 0)"
wait_all_height "$BOUNDARY_PAYLOAD_HEIGHT" 600 || { fail "Boundary A vote block did not relay"; exit 1; }
BOUNDARY_JSON="$(block_json 2 "$BOUNDARY_PAYLOAD_HEIGHT")"
BOUNDARY_VOTES="$(json_array_len "$BOUNDARY_JSON" "finality_votes")"
BOUNDARY_SHARES="$(json_array_len "$BOUNDARY_JSON" "finality_tally_shares")"
BOUNDARY_CERTS="$(json_private_cert_count "$BOUNDARY_JSON")"
if is_int "$BOUNDARY_VOTES" && [ "$BOUNDARY_VOTES" -ge 1 ] && \
   is_int "$BOUNDARY_SHARES" && [ "$BOUNDARY_SHARES" -eq 0 ] && \
   is_int "$BOUNDARY_CERTS" && [ "$BOUNDARY_CERTS" -eq 0 ]; then
    success "Boundary A relayed transparent finality while legacy private carriers remained absent"
else
    fail "unexpected Boundary A finality payloads (votes=$BOUNDARY_VOTES shares=$BOUNDARY_SHARES certs=$BOUNDARY_CERTS)"
fi

BOUNDARY_INFO="$(rpc 0 getfinalityinfo 2>/dev/null)"
SHIELDED_INFO="$(rpc 0 z_getshieldedinfo 2>/dev/null)"
BOUNDARY_ACTIVE="$(json_field "$BOUNDARY_INFO" "boundary_a_active")"
BOUNDARY_B_CONFIGURED="$(json_field "$BOUNDARY_INFO" "boundary_b_configured")"
PRIVATE_MODE="$(json_field "$BOUNDARY_INFO" "private_finality_mode")"
PRIVATE_PROMOTION="$(json_field "$BOUNDARY_INFO" "private_promotion_enabled")"
BOUNDARY_PRIVATE="$(json_field "$BOUNDARY_INFO" "private_votes")"
BOUNDARY_TALLY_SHARES="$(json_field "$BOUNDARY_INFO" "current_epoch_tally_shares")"
BOUNDARY_PENDING_CERT="$(json_field "$BOUNDARY_INFO" "pending_private_certificate_present")"
VNEXT_READY="$(json_field "$SHIELDED_INFO" "privacy_vnext_consensus_ready")"
# Fail closed means the pool is shut, not the verifier absent: consensus pairs
# IsShieldedVNextConsensusReady with IsBoundaryBActiveAtHeight, so assert on
# whether payloads are accepted.
VNEXT_ACCEPTED="$(json_field "$SHIELDED_INFO" "privacy_vnext_transactions_accepted")"
VNEXT_B_ACTIVE="$(json_field "$SHIELDED_INFO" "boundary_b_active")"
VNEXT_DISCLOSURE_MODES="$(json_array_len "$SHIELDED_INFO" "privacy_vnext_disclosure_modes")"
VNEXT_NULLSTAKE_GENERATIONS="$(json_array_len "$SHIELDED_INFO" "privacy_vnext_nullstake_generation_ids")"
VNEXT_TREE_LAYERS="$(json_field "$SHIELDED_INFO" "privacy_vnext_tree_layers")"
VNEXT_MEMBERSHIP_SCOPE="$(json_field "$SHIELDED_INFO" "privacy_vnext_membership_scope")"
VNEXT_STAKING_ROLE="$(json_field "$SHIELDED_INFO" "privacy_vnext_post_dag_staking_role")"
LEGACY_RETIRED="$(json_field "$SHIELDED_INFO" "legacy_privacy_retired")"
PRIVACY_STATUS="$(json_field "$SHIELDED_INFO" "privacy_protocol_status")"
if [ "$BOUNDARY_ACTIVE" = "true" ] && [ "$BOUNDARY_B_CONFIGURED" = "false" ] && \
   [ "$PRIVATE_MODE" = "disabled" ] && [ "$PRIVATE_PROMOTION" = "false" ] && \
   [ "$BOUNDARY_PRIVATE" = "0" ] && [ "$BOUNDARY_TALLY_SHARES" = "0" ] && \
   [ "$BOUNDARY_PENDING_CERT" = "false" ] && \
   [ "$VNEXT_ACCEPTED" = "false" ] && [ "$VNEXT_B_ACTIVE" = "false" ] && \
   [ "$VNEXT_DISCLOSURE_MODES" = "8" ] && \
   [ "$VNEXT_NULLSTAKE_GENERATIONS" = "3" ] && \
   [ "$VNEXT_TREE_LAYERS" = "8" ] && \
   [ "$VNEXT_MEMBERSHIP_SCOPE" = "full_chain_finalized_root" ] && \
   [ "$VNEXT_STAKING_ROLE" = "finality" ] && \
   [ "$LEGACY_RETIRED" = "true" ] && \
   [ "$PRIVACY_STATUS" = "legacy_frozen_privacy_vnext_unavailable" ]; then
    success "Boundary B is fail-closed while the full privacy/finality product contract remains pinned"
else
    fail "legacy-encoding quarantine/product-contract mismatch (A=$BOUNDARY_ACTIVE B_configured=$BOUNDARY_B_CONFIGURED mode=$PRIVATE_MODE promotion=$PRIVATE_PROMOTION private=$BOUNDARY_PRIVATE shares=$BOUNDARY_TALLY_SHARES cert=$BOUNDARY_PENDING_CERT accepted=$VNEXT_ACCEPTED b_active=$VNEXT_B_ACTIVE vnext_linked=$VNEXT_READY disclosure_modes=$VNEXT_DISCLOSURE_MODES nullstake_generations=$VNEXT_NULLSTAKE_GENERATIONS tree_layers=$VNEXT_TREE_LAYERS membership=$VNEXT_MEMBERSHIP_SCOPE staking_role=$VNEXT_STAKING_ROLE quarantined=$LEGACY_RETIRED status=$PRIVACY_STATUS)"
fi

# --- Partition healing and short competing-tip convergence ---
# Isolate the last node, mine one block there and two on the connected side, restore
# peers; every node must select the same best hash.
if [ "${IDAG_RELAY_TEST_PARTITION:-0}" = "1" ]; then
    PART_NODE=$((NUM_NODES - 1))
    header "Partition Healing (node$PART_NODE isolated)"

    BASE_HEIGHT="$(height 0)"
    is_int "$BASE_HEIGHT" || { fail "could not read pre-partition height"; exit 1; }
    for ((node=0; node<PART_NODE; node++)); do
        remove_persistent_peer "$node" "$PART_NODE"
        remove_persistent_peer "$PART_NODE" "$node"
    done

    isolated=0
    for ((attempt=0; attempt<60; attempt++)); do
        pc="$(peer_count "$PART_NODE")"
        if is_int "$pc" && [ "$pc" -eq 0 ]; then isolated=1; break; fi
        sleep 1
    done
    [ "$isolated" -eq 1 ] || { fail "node$PART_NODE did not become isolated"; exit 1; }
    success "node$PART_NODE partition established"

    mine_one "$PART_NODE" || { fail "isolated node failed to mine competing tip"; exit 1; }
    ISOLATED_HEIGHT="$(height "$PART_NODE")"
    ISOLATED_HASH="$(block_hash "$PART_NODE" "$ISOLATED_HEIGHT")"
    mine_one 0 || { fail "connected partition failed to mine first block"; exit 1; }
    mine_one 0 || { fail "connected partition failed to mine longer branch"; exit 1; }
    HEALED_HEIGHT="$(height 0)"
    wait_all_height "$HEALED_HEIGHT" 1 >/dev/null 2>&1 || true

    for ((node=0; node<PART_NODE; node++)); do
        add_persistent_peer "$node" "$PART_NODE"
        add_persistent_peer "$PART_NODE" "$node"
    done
    connect_mesh
    if ! wait_peer_count "$PART_NODE" 2; then
        fail "node$PART_NODE did not reconnect after partition healing"
        exit 1
    fi
    if wait_all_height "$HEALED_HEIGHT" 600 && wait_hash_convergence "$HEALED_HEIGHT" 600; then
        success "partition healed and all nodes converged at height $HEALED_HEIGHT (isolated tip ${ISOLATED_HASH:0:12})"
    else
        fail "fleet did not converge after partition healing"
        exit 1
    fi
fi

# Legacy committee rotation is part of the retired private-finality protocol.
# It cannot be acceptance-tested after Boundary A; a future version-2008
# rotation test must use the distinct Boundary-B payload and transcript.
if [ "${IDAG_RELAY_TEST_ROTATION:-0}" = "1" ]; then
    fail "legacy committee rotation was requested, but Boundary B/privacy-vNext is unconfigured"
    exit 1
fi

# --- Sequential restart convergence ---
# Restart each member with the other two up; each must reconnect and not go stale.
if [ "${IDAG_RELAY_TEST_RESTART:-0}" = "1" ]; then
    header "Sequential Restart Convergence"
    RESTART_HEIGHT="$(height 0)"
    RESTART_HASH="$(block_hash 0 "$RESTART_HEIGHT")"
    is_int "$RESTART_HEIGHT" || { fail "could not read restart baseline height"; exit 1; }
    [ -n "$RESTART_HASH" ] || { fail "could not read restart baseline hash"; exit 1; }

    for ((node=0; node<NUM_NODES; node++)); do
        rpc "$node" stop >/dev/null 2>&1 || { fail "node$node stop RPC failed"; exit 1; }
        wait_rpc_down "$node" || { fail "node$node did not stop cleanly"; exit 1; }
        start_node "$node" || { fail "node$node failed to restart"; exit 1; }
        wait_rpc "$node" || { fail "node$node RPC did not return after restart"; exit 1; }
        connect_mesh
        wait_peer_count "$node" 2 || { fail "node$node did not reconnect to both peers"; exit 1; }
        wait_all_height "$RESTART_HEIGHT" 300 || { fail "node$node did not regain baseline height"; exit 1; }
        if [ "$(block_hash "$node" "$RESTART_HEIGHT")" != "$RESTART_HASH" ]; then
            fail "node$node restarted on a different hash at height $RESTART_HEIGHT"
            exit 1
        fi
        success "node$node restarted, reconnected, and retained the canonical hash"
    done

    if wait_hash_convergence "$RESTART_HEIGHT" 180; then
        success "all restarted nodes converged at $RESTART_HEIGHT/$RESTART_HASH"
    else
        fail "fleet hash mismatch after sequential restarts"
    fi
fi

# --- Differential state gate over the three-member committee ---
# Same strict snapshot logic as the four-node fleet comparator.
if [ "${IDAG_RELAY_TEST_DIFFERENTIAL:-0}" = "1" ]; then
    header "Schema-V3 Differential Snapshot"
    V3_COMPLETE_HEIGHT="${IDAG_RELAY_V3_COMPLETE_HEIGHT:-610}"
    log "Mining to first completed schema-V3 epoch at height $V3_COMPLETE_HEIGHT"
    mine_until_height_synced 0 "$V3_COMPLETE_HEIGHT" || {
        fail "failed to mine first complete schema-V3 epoch"; exit 1;
    }
    wait_all_height "$V3_COMPLETE_HEIGHT" 1200 || {
        fail "fleet did not reach schema-V3 completion height"; exit 1;
    }

    # Compare the exact fields directly because the production differential
    # tool intentionally refuses inventories with fewer than four nodes.
    REF_EPOCH="$(json_field "$(rpc 0 getfinalityinfo 2>/dev/null)" "epoch")"
    is_int "$REF_EPOCH" || { fail "could not resolve current epoch"; exit 1; }
    # Newest completed epoch with the schema this build writes; the schema is read from
    # the chain, not hardcoded.
    DIFF_EPOCH="$REF_EPOCH"
    WANT_SCHEMA=""
    while [ "$DIFF_EPOCH" -ge 0 ]; do
        DIFF_STATE="$(rpc 0 getepochinfo "$DIFF_EPOCH" 2>/dev/null)"
        DIFF_SCHEMA="$(json_field "$DIFF_STATE" "schema_version")"
        if is_int "$DIFF_SCHEMA"; then
            [ -z "$WANT_SCHEMA" ] && WANT_SCHEMA="$DIFF_SCHEMA"
            [ "$DIFF_SCHEMA" = "$WANT_SCHEMA" ] && break
        fi
        DIFF_EPOCH=$((DIFF_EPOCH - 1))
    done
    [ "$DIFF_EPOCH" -ge 0 ] || { fail "no epoch carries an epoch-state schema at all"; exit 1; }
    log "comparing epoch $DIFF_EPOCH, epoch-state schema $WANT_SCHEMA"

    DIFF_OK=1
    REF_HASH="$(block_hash 0 "$V3_COMPLETE_HEIGHT")"
    REF_DAG="$(rpc 0 getdagorder 1000 2>/dev/null | json_canonical)"
    REF_TIPS="$(rpc 0 getdagtips 2>/dev/null | json_sorted_dag_tips)"
    REF_STATE="$(rpc 0 getepochinfo "$DIFF_EPOCH" 2>/dev/null | json_canonical)"
    REF_FINALITY="$(rpc 0 getfinalityinfo 2>/dev/null | json_consensus_finality)"
    REF_MEMPOOL="$(rpc 0 getrawmempool 2>/dev/null | json_sorted_array)"
    for ((node=1; node<NUM_NODES; node++)); do
        [ "$(block_hash "$node" "$V3_COMPLETE_HEIGHT")" = "$REF_HASH" ] || DIFF_OK=0
        [ "$(rpc "$node" getdagorder 1000 2>/dev/null | json_canonical)" = "$REF_DAG" ] || DIFF_OK=0
        [ "$(rpc "$node" getdagtips 2>/dev/null | json_sorted_dag_tips)" = "$REF_TIPS" ] || DIFF_OK=0
        [ "$(rpc "$node" getepochinfo "$DIFF_EPOCH" 2>/dev/null | json_canonical)" = "$REF_STATE" ] || DIFF_OK=0
        [ "$(rpc "$node" getfinalityinfo 2>/dev/null | json_consensus_finality)" = "$REF_FINALITY" ] || DIFF_OK=0
        [ "$(rpc "$node" getrawmempool 2>/dev/null | json_sorted_array)" = "$REF_MEMPOOL" ] || DIFF_OK=0
    done
    if [ "$DIFF_OK" -eq 1 ]; then
        success "schema-V3 DAG tips/order, epoch state, finality, and mempool are byte-identical at epoch $DIFF_EPOCH"
    else
        fail "schema-V3 differential snapshot diverged"
    fi
fi

header "Summary"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ "$FAILED" -eq 0 ]; then
    success "IDAG finality relay regression passed"
    exit 0
fi

exit 1
