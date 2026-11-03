#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Nyx v1 compatibility: n0 runs INNOVAD_V1 (a 5.2.0.2 binary), n1 this build with -nyxv2=1, n2 this
# build with v2 off. A v1 smsg is delivered in both directions between n0 and each of n1 and n2.
# Usage: IV5_TEST_PORT_BASE=auto INNOVAD_V1=/path/5.2.0.2/innovad contrib/test/nyx_v1_compat_test.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init nyx_v1_compat || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
INNOVAD_V1="${INNOVAD_V1:-$INNOVAD}"
TEST_DIR="$(iv5_test_dir "${TMPDIR:-/tmp}/nyx_v1_compat")"

[ -x "$INNOVAD" ] || { echo "FAIL: $INNOVAD not found"; exit 1; }
[ -x "$INNOVAD_V1" ] || { echo "FAIL: $INNOVAD_V1 not found"; exit 1; }

P2P=( "$(iv5_port 0 29760)" "$(iv5_port 1 29761)" "$(iv5_port 2 29762)" )
RPCP=( "$(iv5_port 3 29770)" "$(iv5_port 4 29771)" "$(iv5_port 5 29772)" )
BIN=( "$INNOVAD_V1" "$INNOVAD" "$INNOVAD" )
V2=( 0 1 0 )

RPC() {
    local i="$1"; shift
    "$INNOVAD" -datadir="$TEST_DIR/n$i" -regtest -rpcuser=nyx -rpcpassword=nyxv1pass -rpcport="${RPCP[$i]}" "$@" 2>&1
}

FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
pass() { echo "PASS: $*"; }

cleanup() {
    for i in 0 1 2; do RPC "$i" stop >/dev/null 2>&1 || true; done
    sleep 3
    iv5_kill_daemons "$TEST_DIR" KILL
    [ "${KEEP:-0}" = 1 ] || rm -rf "$TEST_DIR"
    iv5_ports_release
}
trap cleanup EXIT

rm -rf "$TEST_DIR"
for i in 0 1 2; do
    mkdir -p "$TEST_DIR/n$i"
    {
        echo "regtest=1"; echo "server=1"; echo "daemon=1"; echo "rpcuser=nyx"; echo "rpcpassword=nyxv1pass"
        echo "rpcport=${RPCP[$i]}"; echo "port=${P2P[$i]}"; echo "listen=1"; echo "dnsseed=0"; echo "idns=0"
        echo "listenonion=0"; echo "staking=0"; echo "smsg=1"; echo "nyx=1"; echo "printtoconsole=0"
        [ "${V2[$i]}" = 1 ] && echo "nyxv2=1"
        [ "$i" -gt 0 ] && echo "connect=127.0.0.1:${P2P[0]}"
    } > "$TEST_DIR/n$i/innova.conf"
done

for i in 0 1 2; do "${BIN[$i]}" -datadir="$TEST_DIR/n$i" -regtest -daemon; done
for i in 0 1 2; do
    for _ in $(seq 1 60); do RPC "$i" getinfo >/dev/null 2>&1 && break; sleep 1; done
done
sleep 15
for i in 0 1 2; do echo "node$i: $(RPC "$i" getinfo | grep -E '"version"' | tr -d ' ,') connections=$(RPC "$i" getconnectioncount)"; done

declare -a ADDR
for i in 0 1 2; do
    ADDR[$i]=$(RPC "$i" getnewaddress)
    PUB=$(RPC "$i" smsggetpubkey "${ADDR[$i]}" | sed -n 's/.*"compressed public key" : "\([^"]*\)".*/\1/p')
    [ -n "$PUB" ] || { fail "no pubkey on node$i"; exit 1; }
    for j in 0 1 2; do [ "$j" != "$i" ] && RPC "$j" smsgaddkey "${ADDR[$i]}" "$PUB" >/dev/null; done
done

check() {
    local from="$1" to="$2" text="v1 compat $1 to $2 $RANDOM$RANDOM"
    RPC "$from" smsgsend "${ADDR[$from]}" "${ADDR[$to]}" "$text" >/dev/null
    for _ in $(seq 1 60); do
        if RPC "$to" smsginbox all | grep -qF "$text"; then pass "v1 smsg node$from -> node$to delivered"; return; fi
        sleep 2
    done
    fail "v1 smsg node$from -> node$to not delivered"
}

check 0 1
check 1 0
check 0 2
check 2 0
check 1 2

for i in 0 1 2; do
    if grep -q "Misbehaving.*smsg" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null; then fail "node$i penalised a peer for smsg"; fi
done

[ "$FAILED" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$FAILED"
