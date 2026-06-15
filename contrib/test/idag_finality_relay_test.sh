#!/bin/bash
# IDAG finality relay regression.
# Proves private finality vote, tally-share, and tally-certificate payloads
# arrive in normally mined P2P-relayed blocks without submitblock.

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

TEST_DIR="${IDAG_RELAY_TEST_DIR:-/tmp/innova_finality_relay_$$}"
BASE_PORT="${IDAG_RELAY_BASE_PORT:-18240}"
BASE_RPC="${IDAG_RELAY_BASE_RPC:-19240}"
BASE_IDNS="${IDAG_RELAY_BASE_IDNS:-8440}"
NUM_NODES=3
KEEP_DIR="${IDAG_RELAY_KEEP_DIR:-0}"
RPCUSER="${IDAG_RELAY_RPCUSER:-relayfinality}"
RPCPASS="${IDAG_RELAY_RPCPASS:-relaypass}"

COMMITTEE_PRIV="0000000000000000000000000000000000000000000000000000000000000001"
COMMITTEE_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

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
    for ((attempt=0; attempt<45; attempt++)); do
        if ! rpc "$node" getinfo >/dev/null 2>&1; then
            return 0
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
    local before
    local after
    local attempt
    before="$(height "$node")"
    is_int "$before" || return 1

    rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1
    # 600*0.25s = 150s: regtest PoW for a single block can be slow on a
    # contended host. Returns as soon as the node's own height advances.
    for ((attempt=0; attempt<600; attempt++)); do
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

wait_for_vote_and_share() {
    local attempt
    local info
    local pending
    local shares
    # Private vote+share production runs an FCMP/bulletproof build on node0;
    # 300*2s tolerates a slow/contended host (returns as soon as ready).
    for ((attempt=0; attempt<300; attempt++)); do
        info="$(rpc 0 getfinalityinfo 2>/dev/null)"
        pending="$(json_field "$info" "pending_votes")"
        shares="$(json_field "$info" "current_epoch_tally_shares")"
        if is_int "$pending" && is_int "$shares" && [ "$pending" -ge 1 ] && [ "$shares" -ge 1 ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_for_pending_private_cert() {
    local attempt
    local info
    local pending
    # Committee tally + certificate assembly is CPU-bound; 300*2s headroom.
    for ((attempt=0; attempt<300; attempt++)); do
        info="$(rpc 0 getfinalityinfo 2>/dev/null)"
        pending="$(json_field "$info" "pending_private_certificate_present")"
        [ "$pending" = "true" ] && return 0
        sleep 2
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
        echo "finalityvotemode=nullstake"
        echo "finalitytallymode=committee"
        echo "finalitytallythreshold=1-of-1"
        echo "finalitytallypubkey=$COMMITTEE_PUB"
        echo "getdatablockbatch=128"
        echo "maxconnections=32"
        if [ "$node" -eq 0 ]; then
            echo "finalitytallyprivkey=$COMMITTEE_PRIV"
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
    pkill -f "innovad.*${TEST_DIR}" 2>/dev/null || true
    if [ "$KEEP_DIR" = "1" ] || [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

header "IDAG Finality Relay"

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

header "Private Vote And Share Relay"

log "Mining to DAG activation so epoch 0 roots are available"
mine_until_height_synced 0 11 || { fail "DAG activation mining failed"; exit 1; }
wait_all_height 11 || { fail "peers did not sync to DAG activation"; exit 1; }
success "DAG activation block relayed"

log "Waiting for node0 to produce a private finality vote and encrypted tally share"
if wait_for_vote_and_share; then
    success "private vote and encrypted tally share are pending"
else
    INFO="$(rpc 0 getfinalityinfo 2>/dev/null)"
    fail "private vote/share did not become pending: $INFO"
    exit 1
fi

PAYLOAD_BEFORE="$(height 0)"
mine_one 0 || { fail "failed to mine vote/share payload block"; exit 1; }
PAYLOAD_HEIGHT="$(height 0)"
wait_all_height "$PAYLOAD_HEIGHT" 600 || { fail "vote/share payload block did not relay"; exit 1; }

HASH0="$(block_hash 0 "$PAYLOAD_HEIGHT")"
HASH1="$(block_hash 1 "$PAYLOAD_HEIGHT")"
HASH2="$(block_hash 2 "$PAYLOAD_HEIGHT")"
if [ "$HASH0" = "$HASH1" ] && [ "$HASH0" = "$HASH2" ]; then
    success "vote/share block relayed through P2P at height $PAYLOAD_HEIGHT"
else
    fail "nodes disagree on vote/share block hash: $HASH0 $HASH1 $HASH2"
    exit 1
fi

PAYLOAD_JSON="$(block_json 2 "$PAYLOAD_HEIGHT")"
VOTE_COUNT="$(json_array_len "$PAYLOAD_JSON" "finality_votes")"
SHARE_COUNT="$(json_array_len "$PAYLOAD_JSON" "finality_tally_shares")"
CERT_COUNT="$(json_private_cert_count "$PAYLOAD_JSON")"

if is_int "$VOTE_COUNT" && [ "$VOTE_COUNT" -ge 1 ]; then
    success "relayed block contains finality vote payload"
else
    fail "relayed block missing finality vote payload"
fi

if is_int "$SHARE_COUNT" && [ "$SHARE_COUNT" -ge 1 ]; then
    success "relayed block contains v2 tally-share payload"
else
    fail "relayed block missing v2 tally-share payload"
fi

header "Private Certificate Relay"

# A certificate for epoch E can only be built once E's vote-inclusion window has
# closed: tip >= H_E + FINALITY_VOTE_INCLUSION_WINDOW (24 blocks). Epoch 1's
# boundary is the DAG-activation height (11), so the window closes at height 35.
# Before that, ProcessFinalityTallyCommittee does not certify the current epoch
# and any cert is rejected at connect by the R2 position floor. node0 votes once
# per epoch (nullifier-bound), so blocks 13..35 carry no new vote and sync fast.
# The cert becomes pending only after block 35 connects, so the existing
# wait-pending -> mine_one flow then includes it at height 36 (which clears R2).
WINDOW_CLOSE_HEIGHT=35
log "Mining to epoch-1 vote-inclusion window close (height $WINDOW_CLOSE_HEIGHT) so the committee can certify"
mine_until_height_synced 0 "$WINDOW_CLOSE_HEIGHT" || { fail "failed to mine to vote-inclusion window close"; exit 1; }
wait_all_height "$WINDOW_CLOSE_HEIGHT" 600 || { fail "window-close blocks did not relay"; exit 1; }
success "epoch-1 vote-inclusion window closed at height $WINDOW_CLOSE_HEIGHT"

CERT_HEIGHT="$PAYLOAD_HEIGHT"
if ! is_int "$CERT_COUNT" || [ "$CERT_COUNT" -lt 1 ]; then
    log "Waiting for committee automation to create a private v2 certificate"
    if wait_for_pending_private_cert; then
        success "private v2 tally certificate is pending"
        mine_one 0 || { fail "failed to mine private certificate block"; exit 1; }
        CERT_HEIGHT="$(height 0)"
        wait_all_height "$CERT_HEIGHT" 600 || { fail "certificate payload block did not relay"; exit 1; }
        PAYLOAD_JSON="$(block_json 2 "$CERT_HEIGHT")"
        CERT_COUNT="$(json_private_cert_count "$PAYLOAD_JSON")"
    else
        fail "private v2 tally certificate did not become pending"
    fi
else
    success "private v2 tally certificate was included with vote/share block"
fi

HASH0="$(block_hash 0 "$CERT_HEIGHT")"
HASH1="$(block_hash 1 "$CERT_HEIGHT")"
HASH2="$(block_hash 2 "$CERT_HEIGHT")"
if [ "$HASH0" = "$HASH1" ] && [ "$HASH0" = "$HASH2" ]; then
    success "certificate block relayed through P2P at height $CERT_HEIGHT"
else
    fail "nodes disagree on certificate block hash: $HASH0 $HASH1 $HASH2"
fi

if is_int "$CERT_COUNT" && [ "$CERT_COUNT" -ge 1 ]; then
    success "relayed block contains private v2 tally-certificate payload"
else
    fail "relayed block missing private v2 tally-certificate payload"
fi

if [ "$PAYLOAD_BEFORE" != "$PAYLOAD_HEIGHT" ]; then
    success "payloads were delivered by mined block relay; submitblock was not used"
else
    fail "payload mining height did not advance"
fi

header "Summary"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ "$FAILED" -eq 0 ]; then
    success "IDAG finality relay regression passed"
    exit 0
fi

exit 1
