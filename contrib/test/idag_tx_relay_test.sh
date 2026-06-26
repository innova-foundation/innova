#!/bin/bash
# IDAG wallet tx relay regression with Dandelion disabled and enabled.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${TEST_DIR:-/tmp/innova_idag_tx_relay}"
BASE_PORT="${BASE_PORT:-27880}"
BASE_RPC="${BASE_RPC:-27940}"
BASE_IDNS="${BASE_IDNS:-7980}"
RPCUSER="${RPCUSER:-idagrelay}"
RPCPASS="${RPCPASS:-idagrelaypass}"
KEEP_DIR="${KEEP_DIR:-0}"
SYNC_TIMEOUT="${SYNC_TIMEOUT:-180}"
MINE_SYNC_EVERY="${MINE_SYNC_EVERY:-1}"
CASE_PORT_OFFSET=0

PASSED=0
FAILED=0

log() { echo -e "${YELLOW}[INFO]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }

rpc() {
    local node="$1"
    shift
    "$INNOVAD" -datadir="$TEST_DIR/node$node" -regtest \
        -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$((BASE_RPC + CASE_PORT_OFFSET + node))" "$@" 2>&1
}

height() {
    rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'
}

is_int() {
    echo "$1" | grep -qE '^[0-9]+$'
}

should_connect_pair() {
    local node="$1"
    local peer="$2"
    [ "$node" -lt "$peer" ]
}

cleanup() {
    for node in 0 1 2; do
        rpc "$node" stop >/dev/null 2>&1 || true
    done
    sleep 2
    pkill -f "innovad.*innova_idag_tx_relay" 2>/dev/null || true
    if [ "$KEEP_DIR" = "1" ] || [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

write_config() {
    local node="$1"
    local dandelion="$2"
    local dir="$TEST_DIR/node$node"
    mkdir -p "$dir"
    cat > "$dir/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$((BASE_RPC + CASE_PORT_OFFSET + node))
port=$((BASE_PORT + CASE_PORT_OFFSET + node))
bind=127.0.0.1
listen=1
dnsseed=0
nobootstrap=1
nosmsg=1
upnp=0
listenonion=0
idnsport=$((BASE_IDNS + CASE_PORT_OFFSET + node))
debug=1
debugtxrelay=1
staking=0
stakingmode=0
dandelion=$dandelion
getdatablockbatch=128
maxconnections=32
EOF
}

start_node() {
    local node="$1"
    "$INNOVAD" -datadir="$TEST_DIR/node$node" -regtest -daemon \
        -pid="$TEST_DIR/node$node/idag_tx_relay.pid" >/dev/null 2>&1
}

wait_rpc() {
    local node="$1"
    for _ in $(seq 1 45); do
        rpc "$node" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

connect_mesh() {
    for node in 0 1 2; do
        for peer in 0 1 2; do
            [ "$node" = "$peer" ] && continue
            if should_connect_pair "$node" "$peer"; then
                rpc "$node" addnode "127.0.0.1:$((BASE_PORT + CASE_PORT_OFFSET + peer))" onetry >/dev/null 2>&1 || true
            fi
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
    for _ in $(seq 1 45); do
        local count
        count="$(peer_count "$node")"
        if is_int "$count" && [ "$count" -ge "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_peer_count_at_most() {
    local node="$1"
    local target="$2"
    for _ in $(seq 1 45); do
        local count
        count="$(peer_count "$node")"
        if is_int "$count" && [ "$count" -le "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

mine_until_height() {
    local node="$1"
    local target="$2"
    local current
    current="$(height "$node")"
    is_int "$current" || return 1
    while [ "$current" -lt "$target" ]; do
        local before="$current"
        rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1
        for _ in $(seq 1 300); do
            sleep 0.1
            current="$(height "$node")"
            if is_int "$current" && [ "$current" -gt "$before" ]; then
                break
            fi
        done
        rpc "$node" setgenerate false 0 >/dev/null 2>&1 || true
        is_int "$current" && [ "$current" -gt "$before" ] || return 1
    done
}

mine_until_height_synced() {
    local node="$1"
    local target="$2"
    local current
    current="$(height "$node")"
    is_int "$current" || return 1

    while [ "$current" -lt "$target" ]; do
        local before="$current"
        rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1
        for _ in $(seq 1 300); do
            sleep 0.1
            current="$(height "$node")"
            if is_int "$current" && [ "$current" -gt "$before" ]; then
                break
            fi
        done
        is_int "$current" && [ "$current" -gt "$before" ] || return 1

        if [ "$current" -eq "$target" ] || [ "$MINE_SYNC_EVERY" -le 1 ] || [ $((current % MINE_SYNC_EVERY)) -eq 0 ]; then
            wait_all_height "$current" || return 1
        fi

        if [ $((current % 20)) -eq 0 ] || [ "$current" -eq "$target" ]; then
            log "  ...height $current/$target"
        fi
    done
}

wait_all_height() {
    local target="$1"
    for _ in $(seq 1 "$SYNC_TIMEOUT"); do
        local ok=1
        for node in 0 1 2; do
            local h
            h="$(height "$node")"
            if ! is_int "$h" || [ "$h" -lt "$target" ]; then
                ok=0
                break
            fi
        done
        [ "$ok" -eq 1 ] && return 0
        sleep 1
    done
    return 1
}

mempool_has_tx() {
    local node="$1"
    local txid="$2"
    rpc "$node" getrawmempool 2>/dev/null | grep -q "$txid"
}

wait_tx_on_peers() {
    local txid="$1"
    local timeout="$2"
    for _ in $(seq 1 "$timeout"); do
        if mempool_has_tx 1 "$txid" && mempool_has_tx 2 "$txid"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

run_case() {
    local dandelion="$1"
    local label="$2"

    cleanup
    CASE_PORT_OFFSET=$((dandelion * 20))
    for node in 0 1 2; do
        write_config "$node" "$dandelion"
        start_node "$node"
    done
    for node in 0 1 2; do
        wait_rpc "$node" || { fail "$label node$node RPC did not become ready"; return 1; }
    done
    connect_mesh
    for node in 0 1 2; do
        wait_peer_count "$node" 2 || { fail "$label node$node did not connect to peers"; return 1; }
    done

    log "$label: mining spendable funds"
    mine_until_height_synced 0 120 || { fail "$label mining/sync failed"; return 1; }

    local addr txid
    addr="$(rpc 1 getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    txid="$(rpc 0 sendtoaddress "$addr" 1.0 2>/dev/null | tr -d '"[:space:]')"
    if ! echo "$txid" | grep -qE '^[0-9a-f]{64}$'; then
        fail "$label sendtoaddress failed: $txid"
        return 1
    fi

    if wait_tx_on_peers "$txid" 90; then
        pass "$label wallet tx propagated to peer mempools"
    else
        fail "$label wallet tx did not reach both peer mempools: $txid"
        return 1
    fi
}

run_force_resend_case() {
    local label="forced-resend"

    cleanup
    CASE_PORT_OFFSET=40
    for node in 0 1 2; do
        write_config "$node" 1
        start_node "$node"
    done
    for node in 0 1 2; do
        wait_rpc "$node" || { fail "$label node$node RPC did not become ready"; return 1; }
    done

    connect_mesh
    for node in 0 1 2; do
        wait_peer_count "$node" 2 || { fail "$label node$node did not connect to peers"; return 1; }
    done

    log "$label: mining spendable funds"
    mine_until_height_synced 0 120 || { fail "$label mining/sync failed"; return 1; }

    local addr txid
    addr="$(rpc 1 getnewaddress 2>/dev/null | tr -d '"[:space:]')"

    rpc 0 disconnectnode "127.0.0.1:$((BASE_PORT + CASE_PORT_OFFSET + 1))" >/dev/null 2>&1 || true
    rpc 0 disconnectnode "127.0.0.1:$((BASE_PORT + CASE_PORT_OFFSET + 2))" >/dev/null 2>&1 || true
    wait_peer_count_at_most 0 0 || { fail "$label sender did not disconnect from peers"; return 1; }

    txid="$(rpc 0 sendtoaddress "$addr" 1.0 2>/dev/null | tr -d '"[:space:]')"
    if ! echo "$txid" | grep -qE '^[0-9a-f]{64}$'; then
        fail "$label sendtoaddress failed: $txid"
        return 1
    fi

    rpc 0 stop >/dev/null 2>&1 || true
    sleep 2
    start_node 0
    wait_rpc 0 || { fail "$label sender RPC did not return after restart"; return 1; }
    wait_peer_count_at_most 0 0 || { fail "$label restarted sender unexpectedly connected before resend"; return 1; }
    mempool_has_tx 0 "$txid" || { fail "$label tx missing from sender mempool after restart: $txid"; return 1; }

    rpc 0 addnode "127.0.0.1:$((BASE_PORT + CASE_PORT_OFFSET + 1))" onetry >/dev/null 2>&1 || true
    rpc 0 addnode "127.0.0.1:$((BASE_PORT + CASE_PORT_OFFSET + 2))" onetry >/dev/null 2>&1 || true
    wait_peer_count 0 2 || { fail "$label sender did not reconnect to peers"; return 1; }

    if mempool_has_tx 1 "$txid" || mempool_has_tx 2 "$txid"; then
        fail "$label tx reached peers before forced resend: $txid"
        return 1
    fi

    rpc 0 resendtx >/dev/null 2>&1 || { fail "$label resendtx RPC failed"; return 1; }
    if wait_tx_on_peers "$txid" 90; then
        pass "$label wallet tx propagated after resendtx"
    else
        fail "$label wallet tx did not reach both peer mempools after resendtx: $txid"
        return 1
    fi
}

main() {
    if [ ! -x "$INNOVAD" ]; then
        fail "innovad not found at $INNOVAD"
        return 1
    fi
    trap cleanup EXIT

    run_case 0 "dandelion-disabled" || return 1
    run_case 1 "dandelion-enabled" || return 1
    run_force_resend_case || return 1

    echo
    echo "IDAG tx relay regression: $PASSED passed, $FAILED failed"
    [ "$FAILED" -eq 0 ]
}

main "$@"
