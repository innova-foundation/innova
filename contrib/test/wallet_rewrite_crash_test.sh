#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Kills a node after encryptwallet; a label written on the next start must survive a restart.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib/testports.sh"

INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
ITERATIONS="${REWRITE_CRASH_ITERATIONS:-2}"

iv5_ports_init wallet_rewrite_crash || exit 1
RPCPORT=$(iv5_port 0 29760)
WORKROOT="$(iv5_test_dir "${TMPDIR:-/tmp}/innova-wallet-rewrite-crash")"
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
    mkdir -p "$DATADIR"
    {
        echo "regtest=1"
        echo "rpcuser=rewriteuser"
        echo "rpcpassword=rewritepass"
        echo "server=1"
        echo "listen=0"
        echo "dnsseed=0"
        echo "idns=0"
        echo "staking=0"
        echo "rpcport=$RPCPORT"
    } > "$DATADIR/innova.conf"
    R="$INNOVAD -datadir=$DATADIR -regtest"
    start() {
        $R -daemon=0 >> "$DATADIR/node.out" 2>&1 &
        NODE_PID=$!
        for _ in $(seq 1 60); do
            $R getinfo > /dev/null 2>&1 && return 0
            kill -0 "$NODE_PID" 2>/dev/null || break
            sleep 1
        done
        fail "iteration $i: the node never answered RPC"
    }
    stop() { $R stop > /dev/null 2>&1; wait "$NODE_PID"; NODE_PID=""; }

    start
    # encryptwallet returns after the file rewrite; the kill lands before the clean close.
    $R encryptwallet rewritepass > /dev/null 2>&1
    kill -KILL "$NODE_PID"
    wait "$NODE_PID" 2>/dev/null
    NODE_PID=""

    start
    $R walletpassphrase rewritepass 600 > /dev/null 2>&1 || fail "iteration $i: unlock after the kill failed"
    ADDR=$($R getnewaddress rewritecheck 2>/dev/null)
    [ -n "$ADDR" ] || fail "iteration $i: no new address after the kill"
    stop

    start
    LABEL=$($R getaccount "$ADDR" 2>/dev/null)
    stop
    [ "$LABEL" = rewritecheck ] || fail "iteration $i: the label written after the kill is gone (got '$LABEL')"
    [ ! -e "$DATADIR/regtest/wallet.dat.rewrite" ] || fail "iteration $i: wallet.dat.rewrite left behind"
    echo "iteration $i: label kept across the restart after a kill at encryptwallet"
done
echo "PASS: $ITERATIONS kills after encryptwallet, no wallet writes lost"
