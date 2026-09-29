#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Stops a node while an RPC connection is still open and requires a clean exit.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib/testports.sh"

INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
ITERATIONS="${RPC_STOP_ITERATIONS:-3}"

iv5_ports_init rpc_stop_open_connection || exit 1
RPCPORT=$(iv5_port 0 29750)
WORKROOT="$(iv5_test_dir "${TMPDIR:-/tmp}/innova-rpc-stop-open-conn")"
rm -rf "$WORKROOT"
mkdir -p "$WORKROOT"

NODE_PID=""
cleanup() {
    exec 3>&- 2>/dev/null
    if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill -KILL "$NODE_PID" 2>/dev/null
    fi
    iv5_ports_release
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

[ -x "$INNOVAD" ] || fail "no innovad at $INNOVAD (set INNOVAD)"
iv5_require_free_ports "$RPCPORT" || exit 1

for i in $(seq 1 "$ITERATIONS"); do
    DATADIR="$WORKROOT/n$i"
    mkdir -p "$DATADIR"
    {
        echo "regtest=1"
        echo "rpcuser=stopuser"
        echo "rpcpassword=stoppass"
        echo "server=1"
        echo "listen=0"
        echo "dnsseed=0"
        echo "idns=0"
        echo "staking=0"
        echo "rpcport=$RPCPORT"
    } > "$DATADIR/innova.conf"
    R="$INNOVAD -datadir=$DATADIR -regtest"

    # Freed memory is overwritten, so a read of the freed io_context faults instead of passing.
    MALLOC_PERTURB_=165 $R -daemon=0 > "$DATADIR/node.out" 2>&1 &
    NODE_PID=$!
    up=0
    for _ in $(seq 1 60); do
        $R getinfo > /dev/null 2>&1 && { up=1; break; }
        kill -0 "$NODE_PID" 2>/dev/null || break
        sleep 1
    done
    [ "$up" = 1 ] || fail "iteration $i: the node never answered RPC"

    # An idle connection keeps its handler thread blocked in the request read.
    exec 3<>"/dev/tcp/127.0.0.1/$RPCPORT" || fail "iteration $i: could not open an RPC connection"
    sleep 1
    $R stop > /dev/null 2>&1
    sleep 1
    # A connection after stop wakes the listener, which then leaves its loop.
    $R getinfo > /dev/null 2>&1
    sleep 2
    exec 3>&-

    wait "$NODE_PID"
    STATUS=$?
    NODE_PID=""
    if [ "$STATUS" -ne 0 ] || ! grep -q "Innova exited" "$DATADIR/regtest/debug.log"; then
        tail -5 "$DATADIR/node.out"
        fail "iteration $i: exit status $STATUS with an RPC connection open at stop"
    fi
    echo "iteration $i: exit 0 with an RPC connection open at stop"
done
echo "PASS: $ITERATIONS clean stops with an RPC connection open"
