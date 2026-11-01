#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Nyx v2 wire: a 200 KB {2,0} message between two -nyxv2=1 regtest nodes arrives once, and a
# v1-class peer connected to both sees no bucket resync loop. The v1 peer is a -nyxv2=0 node
# unless INNOVAD_V1 names a 5.2.0.2 binary.
# Usage: IV5_TEST_PORT_BASE=auto contrib/test/nyx_v2_multipart_test.sh   (INNOVAD=..., SETTLE=seconds)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init nyx_v2_multipart || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
INNOVAD_V1="${INNOVAD_V1:-$INNOVAD}"
SETTLE="${SETTLE:-180}"
BYTES="${BYTES:-204800}"
TEST_DIR="$(iv5_test_dir "${TMPDIR:-/tmp}/nyx_v2_multipart")"

[ -x "$INNOVAD" ] || { echo "FAIL: $INNOVAD not found"; exit 1; }

P2P=( "$(iv5_port 0 29710)" "$(iv5_port 1 29711)" "$(iv5_port 2 29712)" )
RPCP=( "$(iv5_port 3 29720)" "$(iv5_port 4 29721)" "$(iv5_port 5 29722)" )
BIN=( "$INNOVAD" "$INNOVAD" "$INNOVAD_V1" )
V2=( 1 1 0 )

RPC() {
    local i="$1"; shift
    "$INNOVAD" -datadir="$TEST_DIR/n$i" -regtest -rpcuser=nyx -rpcpassword=nyxv2pass -rpcport="${RPCP[$i]}" "$@" 2>&1
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
        echo "regtest=1"; echo "server=1"; echo "daemon=1"; echo "rpcuser=nyx"; echo "rpcpassword=nyxv2pass"
        echo "rpcport=${RPCP[$i]}"; echo "port=${P2P[$i]}"; echo "listen=1"; echo "dnsseed=0"; echo "idns=0"
        echo "listenonion=0"; echo "staking=0"; echo "smsg=1"; echo "nyx=1"; echo "debugsmsg=1"; echo "printtoconsole=0"
        [ "${V2[$i]}" = 1 ] && echo "nyxv2=1"
        for j in 0 1 2; do [ "$j" -lt "$i" ] && echo "connect=127.0.0.1:${P2P[$j]}"; done
        [ "$i" = 0 ] && echo "connect=127.0.0.1:${P2P[1]}"
    } > "$TEST_DIR/n$i/innova.conf"
done

for i in 0 1 2; do "${BIN[$i]}" -datadir="$TEST_DIR/n$i" -regtest -daemon; done

for i in 0 1 2; do
    for _ in $(seq 1 60); do RPC "$i" getinfo >/dev/null 2>&1 && break; sleep 1; done
done
sleep 15

for i in 0 1 2; do
    n=$(RPC "$i" getconnectioncount)
    echo "node$i: connections=$n"
done

V=$(RPC 1 nyx status | grep -o '"nyx_version" : [0-9]' | grep -o '[0-9]$')
[ "$V" = 2 ] && pass "node1 reports nyx_version 2" || fail "node1 nyx_version '$V'"

ADDR=$(RPC 1 getnewaddress)
PUB=$(RPC 1 smsggetpubkey "$ADDR" | sed -n 's/.*"compressed public key" : "\([^"]*\)".*/\1/p')
[ -n "$PUB" ] || { fail "no pubkey for $ADDR"; exit 1; }
RPC 0 smsgaddkey "$ADDR" "$PUB" >/dev/null

echo "=== sending $BYTES bytes node0 -> node1 ($ADDR) ==="
T0=$(date +%s)
OUT=$(RPC 0 nyx v2sendfill "$ADDR" "$BYTES")
echo "$OUT"
MSGID=$(echo "$OUT" | sed -n 's/.*"msgid" : "\([0-9a-f]*\)".*/\1/p')
SHA=$(echo "$OUT" | sed -n 's/.*"sha256" : "\([0-9a-f]*\)".*/\1/p')
PARTS=$(echo "$OUT" | sed -n 's/.*"parts" : \([0-9]*\).*/\1/p')
[ -n "$MSGID" ] || { fail "send failed"; exit 1; }
echo "sent $PARTS parts in $(( $(date +%s) - T0 ))s"

GOT=0
for _ in $(seq 1 120); do
    R=$(RPC 1 nyx v2recv)
    if echo "$R" | grep -q "$MSGID"; then GOT=1; break; fi
    sleep 2
done
if [ "$GOT" = 1 ]; then
    R=$(RPC 1 nyx v2recv)
    N=$(echo "$R" | grep -c "\"msgid\" : \"$MSGID\"")
    echo "$R" | grep -q "$SHA" && echo "$R" | grep -q "\"bytes\" : $BYTES" \
        && [ "$N" = 1 ] && pass "200 KB message arrived once, sha256 matches" || fail "delivery record wrong: $R"
else
    fail "message $MSGID not delivered"
fi

# v1 view: node2 holds none of the v2 parts and stops being asked for buckets.
echo "=== watching the v1 peer for ${SETTLE}s ==="
sleep 30
LOG2="$TEST_DIR/n2/regtest/debug.log"
[ -f "$LOG2" ] || LOG2=$(find "$TEST_DIR/n2" -name debug.log | head -1)
c0=$(grep -c "Requesting contents of bucket" "$LOG2")
s0=$(grep -c "Sifting through bucket" "$LOG2")
sleep "$SETTLE"
c1=$(grep -c "Requesting contents of bucket" "$LOG2")
s1=$(grep -c "Sifting through bucket" "$LOG2")
echo "v1 peer: show requests $c0 -> $c1, have lists $s0 -> $s1 over ${SETTLE}s"
[ $((c1 - c0)) -le 2 ] && [ $((s1 - s0)) -le 2 ] && pass "no resync loop at the v1 peer" || fail "v1 peer keeps re-requesting buckets"
B2=$(RPC 2 smsgbuckets stats)
echo "$B2" | grep -E '"(numbuckets|numpurged|messages|no. messages)"' | head -5
if grep -q "smsgData invalid message\|smsg public part" "$LOG2"; then fail "v1 peer logged a rejected object"; else pass "v1 peer received no v2 object"; fi
for i in 0 1; do
    if grep -q "Misbehaving.*smsg" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null; then fail "node$i penalised a peer for smsg"; fi
done

[ "$FAILED" = 0 ] && echo "ALL NYX V2 MULTIPART CHECKS PASSED" || echo "NYX V2 MULTIPART CHECKS FAILED"
exit "$FAILED"
