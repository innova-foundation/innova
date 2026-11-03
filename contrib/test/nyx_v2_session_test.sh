#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Nyx v2 1:1 sessions on three -nyxv2=1 regtest nodes: n0 is A (PQ), n1 and n2 are two devices of B.
# Checks the PQXDH handshake fanout to both devices, replies over the ratchet, a restart of n1
# mid-conversation, the frozen-pin refusal and its recovery, and the classical downgrade refusal.
# Usage: IV5_TEST_PORT_BASE=auto contrib/test/nyx_v2_session_test.sh   (INNOVAD=..., KEEP=1)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init nyx_v2_session || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="$(iv5_test_dir "${TMPDIR:-/tmp}/nyx_v2_session")"
N=3

[ -x "$INNOVAD" ] || { echo "FAIL: $INNOVAD not found"; exit 1; }

P2P=() RPCP=()
for i in $(seq 0 $((N - 1))); do
    P2P+=( "$(iv5_port "$i" $((29950 + i)))" )
    RPCP+=( "$(iv5_port $((N + i)) $((29960 + i)))" )
done

RPC() {
    local i="$1"; shift
    "$INNOVAD" -datadir="$TEST_DIR/n$i" -regtest -rpcuser=nyx -rpcpassword=nyxsesspass -rpcport="${RPCP[$i]}" "$@" 2>&1
}

FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
pass() { echo "PASS: $*"; }
field() { sed -n "s/.*\"$1\" : \"\{0,1\}\([^\",]*\)\"\{0,1\}.*/\1/p" | head -1; }

cleanup() {
    for i in $(seq 0 $((N - 1))); do RPC "$i" stop >/dev/null 2>&1 || true; done
    sleep 3
    iv5_kill_daemons "$TEST_DIR" KILL
    [ "${KEEP:-0}" = 1 ] || rm -rf "$TEST_DIR"
    iv5_ports_release
}
trap cleanup EXIT

start() {
    "$INNOVAD" -datadir="$TEST_DIR/n$1" -regtest -daemon
    for _ in $(seq 1 60); do RPC "$1" getinfo >/dev/null 2>&1 && return 0; sleep 1; done
    return 1
}

rm -rf "$TEST_DIR"
for i in $(seq 0 $((N - 1))); do
    mkdir -p "$TEST_DIR/n$i"
    {
        echo "regtest=1"; echo "server=1"; echo "daemon=1"; echo "rpcuser=nyx"; echo "rpcpassword=nyxsesspass"
        echo "rpcport=${RPCP[$i]}"; echo "port=${P2P[$i]}"; echo "listen=1"; echo "dnsseed=0"; echo "idns=0"
        echo "listenonion=0"; echo "staking=0"; echo "smsg=1"; echo "nyx=1"; echo "nyxv2=1"; echo "printtoconsole=0"
        for j in $(seq 0 $((N - 1))); do [ "$j" != "$i" ] && echo "addnode=127.0.0.1:${P2P[$j]}"; done
    } > "$TEST_DIR/n$i/innova.conf"
done
for i in $(seq 0 $((N - 1))); do start "$i" || fail "node $i did not start"; done
sleep 15

A=$(RPC 0 getnewaddress)
B=$(RPC 1 getnewaddress)
RPC 2 importprivkey "$(RPC 1 dumpprivkey "$B")" nyxb false >/dev/null
# An imported key joins the SMSG receive list when smsg.ini is rebuilt from the wallet.
RPC 2 stop >/dev/null; sleep 8
rm -f "$TEST_DIR/n2/regtest/smsg.ini"
start 2 || fail "n2 restart"
RPC 2 smsglocalkeys recv + "$B" | grep -q "not found" && fail "n2 does not receive for B"
sleep 10

# Polls node $1 with the remaining arguments until the output matches $2.
until_match() {
    local node="$1" want="$2" out=""; shift 2
    for _ in $(seq 1 120); do
        out=$(RPC "$node" "$@")
        if echo "$out" | tr -d '\n' | grep -q "$want"; then echo "$out"; return 0; fi
        sleep 2
    done
    echo "$out"
    return 1
}

echo "=== identities ==="
RPC 0 nyx keyring init "$A" pq | grep -q '"seq" : 1' || fail "A keyring init"
RPC 1 nyx keyring init "$B" pq | grep -q '"seq" : 1' || fail "B keyring init"
REQ=$(RPC 2 nyx device pair "$B" | field request)
CERT=$(until_match 1 '"cert"' nyx device approve "$B" "$REQ" "$(RPC 2 nyx device code "$REQ" | field pairing_code)" | field cert)
RPC 2 nyx device install "$B" "$CERT" | grep -q '"device"' || fail "B second device install"
OUT=$(until_match 0 '"seq" : 2' nyx keyring contact "$B")
[ "$(echo "$OUT" | grep -c '"device" :')" = 2 ] && pass "A pinned B with two devices" || fail "A pin of B: $OUT"
until_match 1 '"pinned" : true' nyx keyring contact "$A" >/dev/null || fail "B pin of A"
until_match 2 '"pinned" : true' nyx keyring contact "$A" >/dev/null || fail "B2 pin of A"

echo "=== PQXDH handshake fanout ==="
OUT=$(until_match 0 '"msgids"' nyx session send "$A" "$B" "hello from A")
[ "$(echo "$OUT" | grep -c '"handshake" : true')" = 2 ] && echo "$OUT" | grep -q '"mode" : "pq"' \
    && pass "handshake sent to both devices of B" || fail "send: $OUT"
until_match 1 'hello from A' nyx session messages "$B" "$A" >/dev/null && pass "B device 1 decrypted" || fail "n1 receive"
until_match 2 'hello from A' nyx session messages "$B" "$A" >/dev/null && pass "B device 2 decrypted" || fail "n2 receive"
OUT=$(RPC 1 nyx session list "$B")
echo "$OUT" | grep -q '"suite" : "PQXDH ML-KEM-768' && echo "$OUT" | grep -q '"opk" : true' \
    && pass "B session is PQXDH with a one-time prekey" || fail "B session list: $OUT"

echo "=== replies over the ratchet ==="
OUT=$(RPC 1 nyx session send "$B" "$A" "hi from B1")
echo "$OUT" | grep -q '"handshake" : false' && pass "B1 replied on the responder session" || fail "B1 reply: $OUT"
until_match 0 'hi from B1' nyx session messages "$A" "$B" >/dev/null && pass "A decrypted B1's reply" || fail "A receive"
OUT=$(RPC 0 nyx session send "$A" "$B" "second from A")
echo "$OUT" | grep -q '"handshake" : false' && echo "$OUT" | grep -q '"handshake" : true' \
    && pass "acked device gets 0x11, unacked device keeps the handshake" || fail "second send: $OUT"
until_match 1 'second from A' nyx session messages "$B" >/dev/null || fail "n1 second"
until_match 2 'second from A' nyx session messages "$B" >/dev/null || fail "n2 second"

echo "=== restart B1 mid-conversation ==="
RPC 1 stop >/dev/null; sleep 8
start 1 || fail "n1 restart"
for _ in $(seq 1 60); do [ "$(RPC 1 getconnectioncount)" -ge 2 ] 2>/dev/null && break; sleep 1; done
sleep 30
OUT=$(until_match 0 '"msgids"' nyx session send "$A" "$B" "after restart")
until_match 1 'after restart' nyx session messages "$B" >/dev/null && pass "B1 decrypted after restart" || fail "post-restart"
RPC 1 nyx session send "$B" "$A" "B1 back" | grep -q '"msgids"' || fail "B1 send after restart"
[ "$(RPC 1 nyx session messages "$B" "$A" | grep -c '"text" : "hello from A"')" = 1 ] \
    && pass "inbox holds each message once" || fail "duplicate inbox records"

echo "=== frozen pin refuses sends ==="
RPC 1 nyx keyring confirm "$B" > "$TEST_DIR/c1.out" &
RPC 2 nyx keyring confirm "$B" > "$TEST_DIR/c2.out" &
wait
until_match 0 '"frozen" : true' nyx keyring contact "$B" >/dev/null || fail "A did not freeze"
OUT=$(RPC 0 nyx session send "$A" "$B" "while frozen")
echo "$OUT" | grep -q "frozen" && pass "send refused while frozen" || fail "frozen send: $OUT"
sleep 5
RPC 1 nyx keyring confirm "$B" | grep -q '"seq" : 4' || fail "owner confirm"
until_match 0 '"frozen" : false' nyx keyring contact "$B" >/dev/null || fail "A did not unfreeze"
OUT=$(until_match 0 '"msgids"' nyx session send "$A" "$B" "after unfreeze")
until_match 1 'after unfreeze' nyx session messages "$B" >/dev/null && pass "sessions continue after unfreeze" || fail "unfreeze: $OUT"

echo "=== downgrade refused ==="
C=$(RPC 0 getnewaddress)
RPC 0 nyx keyring init "$C" classical | grep -q '"seq" : 1' || fail "C keyring init"
OUT=$(until_match 0 'classical-only' nyx session send "$A" "$C" "downgrade?")
echo "$OUT" | grep -q "refusing to downgrade" && pass "PQ device refuses a classical-only peer" || fail "downgrade: $OUT"

echo "=== B1's post-restart reply reached A ==="
until_match 0 'B1 back' nyx session messages "$A" >/dev/null && pass "A decrypted B1 after its restart" || fail "A post-restart"

echo "=== delete ==="
RPC 0 nyx session delete "$A" "$B" | grep -q '"deleted" : 2' && pass "session state erased" || fail "delete"

for i in $(seq 0 $((N - 1))); do
    if grep -q "Misbehaving.*smsg" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null; then fail "node$i penalised a peer for smsg"; fi
done

[ "$FAILED" = 0 ] && echo "ALL NYX V2 SESSION CHECKS PASSED" || echo "NYX V2 SESSION CHECKS FAILED"
exit "$FAILED"
