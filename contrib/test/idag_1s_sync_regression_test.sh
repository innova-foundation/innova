#!/bin/bash
# IDAG 1-second sync regression: multi-peer catch-up with a delayed node.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="${TEST_DIR:-/tmp/innova_idag_1s_sync}"
BASE_PORT="${BASE_PORT:-27660}"
BASE_RPC="${BASE_RPC:-27720}"
BASE_IDNS="${BASE_IDNS:-7780}"
RPCUSER="${RPCUSER:-idagsync}"
RPCPASS="${RPCPASS:-idagsyncpass}"

PASSED=0
FAILED=0

log() { echo -e "${YELLOW}[INFO]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }

rpc() {
    local node="$1"
    shift
    "$INNOVAD" -datadir="$TEST_DIR/node$node" -regtest -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$((BASE_RPC + node))" "$@" 2>&1
}

height() {
    rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'
}

is_int() {
    echo "$1" | grep -qE '^[0-9]+$'
}

cleanup() {
    for node in 0 1 2; do
        rpc "$node" stop >/dev/null 2>&1 || true
    done
    sleep 2
    pkill -f "innovad.*innova_idag_1s_sync" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}

write_config() {
    local node="$1"
    local dir="$TEST_DIR/node$node"
    mkdir -p "$dir"
    cat > "$dir/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$((BASE_RPC + node))
port=$((BASE_PORT + node))
bind=127.0.0.1
listen=1
idnsport=$((BASE_IDNS + node))
debug=1
showtimers=1
stakingmode=0
nofinalityvoting=0
EOF
    for peer in 0 1 2; do
        [ "$node" = "$peer" ] && continue
        echo "addnode=127.0.0.1:$((BASE_PORT + peer))" >> "$dir/innova.conf"
    done
}

start_node() {
    local node="$1"
    "$INNOVAD" -datadir="$TEST_DIR/node$node" -regtest -daemon -pid="$TEST_DIR/node$node/innova_idag_1s_sync.pid" >/dev/null 2>&1
}

wait_rpc() {
    local node="$1"
    for _ in $(seq 1 30); do
        if rpc "$node" getinfo >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

connect_mesh() {
    for node in 0 1 2; do
        for peer in 0 1 2; do
            [ "$node" = "$peer" ] && continue
            rpc "$node" addnode "127.0.0.1:$((BASE_PORT + peer))" onetry >/dev/null 2>&1 || true
        done
    done
}

peer_count() {
    rpc "$1" getpeerinfo 2>/dev/null | python3 -c '
import json, sys
try:
    peers = json.load(sys.stdin)
    print(len(peers) if isinstance(peers, list) else 0)
except Exception:
    print(0)
'
}

wait_peer_count() {
    local node="$1"
    local target="$2"
    local timeout="${3:-30}"
    for _ in $(seq 1 "$timeout"); do
        local count
        count="$(peer_count "$node")"
        if is_int "$count" && [ "$count" -ge "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

mine_until_height() {
    local node="$1"
    local target="$2"
    local max_per_block="${3:-30}"
    local current
    current="$(height "$node")"

    if ! is_int "$current"; then
        log "Cannot read current height from node $node"
        return 1
    fi

    while [ "$current" -lt "$target" ]; do
        local before="$current"
        rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1

        local waited=0
        local max_ticks=$((max_per_block * 10))
        while [ "$waited" -lt "$max_ticks" ]; do
            sleep 0.1
            current="$(height "$node")"
            if is_int "$current" && [ "$current" -gt "$before" ]; then
                break
            fi
            waited=$((waited + 1))
        done

        if ! is_int "$current" || [ "$current" -le "$before" ]; then
            log "Mining stalled at height $before while targeting $target"
            return 1
        fi

        if [ $((current % 10)) -eq 0 ] || [ "$current" -eq "$target" ]; then
            log "  ...height $current/$target"
        fi
    done
}

mine_blocks() {
    local node="$1"
    local count="$2"
    local current
    current="$(height "$node")"
    is_int "$current" || return 1
    mine_until_height "$node" "$((current + count))"
}

wait_height_near() {
    local node="$1"
    local target="$2"
    local max_delta="$3"
    for _ in $(seq 1 60); do
        local h
        h="$(height "$node")"
        if [ -n "$h" ] && [ "$h" -ge $((target - max_delta)) ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

fresh_peer_height_seen() {
    local node="$1"
    rpc "$node" getpeerinfo 2>/dev/null | python3 -c '
import json, sys
try:
    peers = json.load(sys.stdin)
except Exception:
    sys.exit(1)
fresh = [
    p for p in peers
    if isinstance(p, dict)
    and int(p.get("bestknownheight", -1)) >= 0
    and int(p.get("heightage", 999999)) <= 120
]
sys.exit(0 if fresh else 1)
'
}

main() {
    cleanup
    trap cleanup EXIT

    for node in 0 1 2; do
        write_config "$node"
        start_node "$node"
    done

    for node in 0 1 2; do
        if wait_rpc "$node"; then
            pass "node $node RPC ready"
        else
            fail "node $node RPC did not become ready"
            return 1
        fi
    done

    connect_mesh
    for node in 0 1 2; do
        if wait_peer_count "$node" 1 30; then
            pass "node $node has at least one peer"
        else
            fail "node $node did not connect to peers"
            return 1
        fi
    done

    log "Mining through DAG activation"
    mine_blocks 0 20 || { fail "initial mining failed"; return 1; }
    local h0
    h0="$(height 0)"
    wait_height_near 1 "$h0" 3 && pass "node 1 synced near height $h0" || fail "node 1 did not sync near height $h0"
    wait_height_near 2 "$h0" 3 && pass "node 2 synced near height $h0" || fail "node 2 did not sync near height $h0"

    log "Stopping node 2, mining ahead, then restarting it"
    rpc 2 stop >/dev/null 2>&1 || true
    sleep 2
    mine_blocks 0 30 || { fail "ahead mining failed"; return 1; }
    h0="$(height 0)"

    start_node 2
    wait_rpc 2 || { fail "node 2 did not restart"; return 1; }
    rpc 2 addnode "127.0.0.1:$BASE_PORT" onetry >/dev/null 2>&1 || true
    rpc 0 addnode "127.0.0.1:$((BASE_PORT + 2))" onetry >/dev/null 2>&1 || true
    wait_peer_count 2 1 30 || { fail "restarted node 2 did not connect to peers"; return 1; }

    wait_height_near 2 "$h0" 3 && pass "delayed node caught up within 3 blocks of $h0" || fail "delayed node failed to catch up to $h0"
    fresh_peer_height_seen 2 && pass "delayed node reports fresh peer best-known height" || fail "fresh peer height missing from getpeerinfo"

    echo
    echo "1s sync regression: $PASSED passed, $FAILED failed"
    [ "$FAILED" -eq 0 ]
}

main "$@"
