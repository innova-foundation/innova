#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Repeats `stop` and fails on the first non-zero exit; the run is rejected unless the
# finality voter thread started and logged its stop.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib/testports.sh"

INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
ITERATIONS="${SHUTDOWN_ITERATIONS:-3}"

iv5_ports_init shutdown_clean_exit || exit 1
RPCPORT=$(iv5_port 0 29740)

WORKROOT="$(iv5_test_dir "${TMPDIR:-/tmp}/innova-shutdown-clean-exit")"
rm -rf "$WORKROOT"
mkdir -p "$WORKROOT"

NODE_PID=""
cleanup() {
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
    rm -rf "$DATADIR"
    mkdir -p "$DATADIR"
    {
        echo "rpcuser=shutdownuser"
        echo "rpcpassword=shutdownpass"
        echo "server=1"
        echo "listen=0"
        echo "dnsseed=0"
        echo "idns=0"
        echo "rpcport=$RPCPORT"
    } > "$DATADIR/innova.conf"

    "$INNOVAD" -datadir="$DATADIR" > "$DATADIR/node.out" 2>&1 &
    NODE_PID=$!

    up=0
    for _ in $(seq 1 60); do
        if "$INNOVAD" -datadir="$DATADIR" getinfo > /dev/null 2>&1; then
            up=1
            break
        fi
        kill -0 "$NODE_PID" 2>/dev/null || break
        sleep 2
    done
    [ "$up" = 1 ] || fail "iteration $i: the node never answered RPC"

    # The voter registers on the condition variable a few polls in; stopping
    # before it has slept once would not exercise the path at all.
    sleep 10

    "$INNOVAD" -datadir="$DATADIR" stop > /dev/null 2>&1
    wait "$NODE_PID"
    STATUS=$?
    NODE_PID=""

    LOG="$DATADIR/debug.log"
    [ -f "$LOG" ] || fail "iteration $i: no debug.log"

    grep -q "ThreadFinalityVoter started" "$LOG" \
        || fail "iteration $i: the voter thread never started; this run proves nothing"

    ORDER=$(awk '/ThreadFinalityVoter stopped/{v=NR} /Innova exited/{e=NR}
                 END{print (v>0 && e>0 && v<e) ? "ok" : "bad"}' "$LOG")

    if [ "$STATUS" -ne 0 ]; then
        echo "--- tail of $LOG"
        tail -15 "$LOG"
        echo "--- stderr"
        tail -5 "$DATADIR/node.out"
        fail "iteration $i: stop exited $STATUS (134 is the condition-variable abort)"
    fi
    [ "$ORDER" = ok ] \
        || fail "iteration $i: the voter did not report stopping before the process exited"

    echo "iteration $i: exit 0, voter stopped before exit"
done

echo "PASS: $ITERATIONS clean shutdowns, voter drained on every one"
