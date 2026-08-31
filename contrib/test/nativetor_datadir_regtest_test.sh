#!/bin/bash
# Copyright (c) 2026 The Innova developers
# -nativetor=1 must put tor's DataDirectory and hidden service under -datadir, with
# HOME redirected. SOCKS port 9089 is compile-time, so one nativetor node per host.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"

INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
# The hostname file appears once tor loads or mints the service key, well before
# the descriptor is published, so this does not wait on a bootstrapped circuit.
HOSTNAME_WAIT_SECS="${NATIVETOR_HOSTNAME_WAIT_SECS:-180}"
NATIVETOR_SOCKS_PORT=9089

iv5_ports_init nativetor_datadir || exit 1
P2P_PORT=$(iv5_port 0 29760)
RPC_PORT=$(iv5_port 1 29761)

WORKROOT="$(iv5_test_dir "${TMPDIR:-/tmp}/innova-nativetor-datadir")"
rm -rf "$WORKROOT"
mkdir -p "$WORKROOT"

FAKEHOME="$WORKROOT/home"
DATADIR="$WORKROOT/datadir"
mkdir -p "$FAKEHOME" "$DATADIR"

NODE_PID=""
cleanup() {
    if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill -TERM "$NODE_PID" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "$NODE_PID" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "$NODE_PID" 2>/dev/null
    fi
    iv5_ports_release
}
trap cleanup EXIT

PASSED=0
pass() { echo "PASS: $*"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $*"; exit 1; }

[ -x "$INNOVAD" ] || fail "no innovad at $INNOVAD (set INNOVAD)"
iv5_require_free_ports "$P2P_PORT" "$RPC_PORT" "$NATIVETOR_SOCKS_PORT" || exit 1

{
    echo "rpcuser=nativetoruser"
    echo "rpcpassword=nativetorpass"
    echo "server=1"
    echo "dnsseed=0"
    echo "idns=0"
    echo "staking=0"
    echo "port=$P2P_PORT"
    echo "rpcport=$RPC_PORT"
} > "$DATADIR/innova.conf"

rpc() { HOME="$FAKEHOME" "$INNOVAD" -datadir="$DATADIR" -regtest "$@" 2>&1; }

HOME="$FAKEHOME" "$INNOVAD" -datadir="$DATADIR" -regtest -nativetor=1 \
    > "$WORKROOT/node.out" 2>&1 &
NODE_PID=$!

UP=0
for _ in $(seq 1 90); do
    if rpc getinfo > /dev/null 2>&1; then UP=1; break; fi
    kill -0 "$NODE_PID" 2>/dev/null || break
    sleep 2
done

if [ "$UP" != 1 ]; then
    if grep -q "no bundled Tor daemon" "$WORKROOT/node.out" 2>/dev/null; then
        # Not a pass. This build cannot exercise the path at all; makefile.osx
        # forces USE_NATIVETOR=-, makefile.unix defaults it on.
        echo "SKIP: this innovad was built without the bundled Tor (USE_NATIVETOR)"
        echo "SKIP is not a pass: nothing below ran."
        exit 0
    fi
    echo "--- node.out"
    tail -20 "$WORKROOT/node.out"
    fail "the node never answered RPC with -nativetor=1"
fi
pass "the node came up with -nativetor=1 and -datadir=$DATADIR"

# Positive control. tor writes its own log inside the DataDirectory it was
# handed, so this is the only evidence that the argv path reached tor and that
# tor accepted it.
TOR_LOG="$DATADIR/tor/tor.log"
TOR_UP=0
for _ in $(seq 1 "$HOSTNAME_WAIT_SECS"); do
    [ -s "$TOR_LOG" ] && { TOR_UP=1; break; }
    kill -0 "$NODE_PID" 2>/dev/null || break
    sleep 1
done
if [ "$TOR_UP" != 1 ]; then
    echo "--- $DATADIR contents"
    ls -la "$DATADIR" 2>/dev/null
    echo "--- node.out"
    tail -20 "$WORKROOT/node.out"
    fail "no tor log under the configured datadir; tor never ran with our DataDirectory"
fi
pass "the bundled tor ran with DataDirectory $DATADIR/tor"

HOSTFILE="$DATADIR/onion/hostname"
ONION=""
for _ in $(seq 1 "$HOSTNAME_WAIT_SECS"); do
    if [ -s "$HOSTFILE" ]; then
        ONION="$(tr -d '[:space:]' < "$HOSTFILE")"
        [ -n "$ONION" ] && break
    fi
    kill -0 "$NODE_PID" 2>/dev/null || break
    sleep 1
done
case "$ONION" in
    *.onion) pass "the hidden service hostname is under the configured datadir ($ONION)" ;;
    "")      echo "--- $DATADIR/onion"; ls -la "$DATADIR/onion" 2>/dev/null
             tail -20 "$TOR_LOG" 2>/dev/null
             fail "no onion hostname under $DATADIR/onion" ;;
    *)       fail "the hostname file holds '$ONION', which is not an onion address" ;;
esac

# Negative control: the assertion the pre-fix build fails.
DEFAULT_DIR="$FAKEHOME/.innova"
STRAY=""
[ -e "$DEFAULT_DIR/tor" ]   && STRAY="$STRAY $DEFAULT_DIR/tor"
[ -e "$DEFAULT_DIR/onion" ] && STRAY="$STRAY $DEFAULT_DIR/onion"
if [ -n "$STRAY" ]; then
    fail "tor state appeared under the DEFAULT datadir, not the configured one:$STRAY"
fi
pass "nothing was written under the default datadir $DEFAULT_DIR"

# Reader agreement. getinfo's "ip" is read by a different call site than the one
# that handed tor its argv; both must resolve to the same file.
REPORTED="$(rpc getinfo 2>/dev/null | sed -n 's/.*"ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
if [ "$REPORTED" = "$ONION" ]; then
    pass "getinfo reports the same onion address the datadir holds"
else
    fail "getinfo reports ip='$REPORTED' but the hostname file holds '$ONION'"
fi

rpc stop > /dev/null 2>&1
wait "$NODE_PID"
STATUS=$?
NODE_PID=""
[ "$STATUS" -eq 0 ] || fail "the node exited $STATUS on stop"
pass "the node stopped cleanly"

echo "PASS: $PASSED checks, tor and onion state confined to -datadir"
rm -rf "$WORKROOT"
