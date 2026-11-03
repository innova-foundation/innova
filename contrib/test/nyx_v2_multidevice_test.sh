#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Nyx v2 multi-device on four -nyxv2=1 regtest nodes: n0/n1 are devices A1/A2 of A, n2/n3 are B1/B2 of B.
# Checks recipient fanout plus sent-sync to own devices, a device added mid-conversation, replies
# synced across both identities, and revocation (no copy to the revoked device, its sessions erased).
# Usage: IV5_TEST_PORT_BASE=auto contrib/test/nyx_v2_multidevice_test.sh   (INNOVAD=..., KEEP=1)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init nyx_v2_multidevice || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="$(iv5_test_dir "${TMPDIR:-/tmp}/nyx_v2_multidevice")"
N=4

[ -x "$INNOVAD" ] || { echo "FAIL: $INNOVAD not found"; exit 1; }

P2P=() RPCP=()
for i in $(seq 0 $((N - 1))); do
    P2P+=( "$(iv5_port "$i" $((29970 + i)))" )
    RPCP+=( "$(iv5_port $((N + i)) $((29980 + i)))" )
done

RPC() {
    local i="$1"; shift
    "$INNOVAD" -datadir="$TEST_DIR/n$i" -regtest -rpcuser=nyx -rpcpassword=nyxmdpass -rpcport="${RPCP[$i]}" "$@" 2>&1
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

# Sends from node $1 until the reply matches $2, at most 12 tries 15 s apart (each try is a real message).
send_until() {
    local node="$1" want="$2" out=""; shift 2
    for _ in $(seq 1 12); do
        out=$(RPC "$node" nyx session send "$@")
        if echo "$out" | tr -d '\n' | grep -q "$want"; then echo "$out"; return 0; fi
        sleep 15
    done
    echo "$out"
    return 1
}

# Copies the key of $2 from node $1 into node $3 and makes $3 receive for it.
share_key() {
    RPC "$3" importprivkey "$(RPC "$1" dumpprivkey "$2")" nyx false >/dev/null
    RPC "$3" stop >/dev/null; sleep 8
    rm -f "$TEST_DIR/n$3/regtest/smsg.ini"
    start "$3" || fail "n$3 restart"
    RPC "$3" smsglocalkeys recv + "$2" | grep -q "not found" && fail "n$3 does not receive for $2"
}

# Pairs node $2 as a new device of $3, approved by node $1; prints the device id.
pair() {
    local req cert
    req=$(RPC "$2" nyx device pair "$3" | field request)
    cert=$(until_match "$1" '"cert"' nyx device approve "$3" "$req" | field cert)
    RPC "$2" nyx device install "$3" "$cert" | field device
}

rm -rf "$TEST_DIR"
for i in $(seq 0 $((N - 1))); do
    mkdir -p "$TEST_DIR/n$i"
    {
        echo "regtest=1"; echo "server=1"; echo "daemon=1"; echo "rpcuser=nyx"; echo "rpcpassword=nyxmdpass"
        echo "rpcport=${RPCP[$i]}"; echo "port=${P2P[$i]}"; echo "listen=1"; echo "dnsseed=0"; echo "idns=0"
        echo "listenonion=0"; echo "staking=0"; echo "smsg=1"; echo "nyx=1"; echo "nyxv2=1"; echo "printtoconsole=0"
        for j in $(seq 0 $((N - 1))); do [ "$j" != "$i" ] && echo "addnode=127.0.0.1:${P2P[$j]}"; done
    } > "$TEST_DIR/n$i/innova.conf"
done
for i in $(seq 0 $((N - 1))); do start "$i" || fail "node $i did not start"; done
sleep 15

A=$(RPC 0 getnewaddress)
B=$(RPC 2 getnewaddress)
share_key 0 "$A" 1
share_key 2 "$B" 3
sleep 10

echo "=== identities: A with two devices, B with one ==="
RPC 0 nyx keyring init "$A" pq | grep -q '"seq" : 1' || fail "A keyring init"
RPC 2 nyx keyring init "$B" pq | grep -q '"seq" : 1' || fail "B keyring init"
A2=$(pair 0 1 "$A")
[ -n "$A2" ] && pass "A2 paired" || fail "A2 pair"
until_match 2 '"seq" : 2' nyx keyring contact "$A" >/dev/null || fail "B pin of A at seq 2"
until_match 0 '"pinned" : true' nyx keyring contact "$B" >/dev/null || fail "A pin of B"
until_match 1 '"pinned" : true' nyx keyring contact "$B" >/dev/null || fail "A2 pin of B"
until_match 0 "$A2" nyx devices "$A" >/dev/null || fail "A1 sees A2"

echo "=== fanout + sent-sync ==="
OUT=$(send_until 0 '"copies" : 2' "$A" "$B" "one")
echo "$OUT" | grep -q '"own" : true' && echo "$OUT" | grep -q '"sync_msgids"' \
    && pass "A1 sent to B1 and a sync copy to A2" || fail "send one: $OUT"
until_match 2 '"text" : "one"' nyx session messages "$B" "$A" >/dev/null && pass "B1 received" || fail "B1 receive"
OUT=$(until_match 1 '"text" : "one"' nyx session messages "$A" "$B")
echo "$OUT" | grep -q '"direction" : "out"' && pass "A2 stored the sync as outgoing to B" || fail "A2 sync: $OUT"

echo "=== B adds a device mid-conversation ==="
B2=$(pair 2 3 "$B")
[ -n "$B2" ] && pass "B2 paired" || fail "B2 pair"
until_match 0 '"seq" : 2' nyx keyring contact "$B" >/dev/null || fail "A pin of B at seq 2"
until_match 3 '"pinned" : true' nyx keyring contact "$A" >/dev/null || fail "B2 pin of A"
OUT=$(send_until 0 '"copies" : 3' "$A" "$B" "two")
echo "$OUT" | tr -d '\n' | grep -q "\"device\" : \"$B2\"[^}]*\"handshake\" : true" \
    && pass "the new device B2 got a handshake" || fail "send two: $OUT"
until_match 3 '"text" : "two"' nyx session messages "$B" "$A" >/dev/null && pass "B2 received" || fail "B2 receive"
until_match 2 '"text" : "two"' nyx session messages "$B" "$A" >/dev/null || fail "B1 receive two"
until_match 1 '"text" : "two"' nyx session messages "$A" "$B" >/dev/null || fail "A2 sync two"

echo "=== reply from B2 syncs to B1, reaches A1 and A2 ==="
OUT=$(send_until 3 '"copies" : 3' "$B" "$A" "reply")
echo "$OUT" | grep -q '"own" : true' || fail "B2 reply: $OUT"
until_match 0 '"text" : "reply"' nyx session messages "$A" "$B" >/dev/null && pass "A1 received the reply" || fail "A1 reply"
until_match 1 '"text" : "reply"' nyx session messages "$A" "$B" >/dev/null && pass "A2 received the reply" || fail "A2 reply"
OUT=$(until_match 2 '"text" : "reply"' nyx session messages "$B" "$A")
echo "$OUT" | tr -d '\n' | grep -q '"direction" : "out"[^}]*"text" : "reply"' \
    && pass "B1 holds B2's reply as outgoing" || fail "B1 sync: $OUT"
N0=$(RPC 0 nyx session messages "$A" "$B" | grep -c '"text" : "two"')
N1=$(RPC 1 nyx session messages "$A" "$B" | grep -c '"text" : "two"')
[ "$N0" = "$N1" ] && pass "each logical message stored once ($N1)" || fail "A1 has $N0 records of two, A2 $N1"

echo "=== A revokes A2 ==="
OUT=$(RPC 0 nyx device revoke "$A" "$A2")
echo "$OUT" | grep -q '"seq" : 3' && echo "$OUT" | grep -q '"sessions_erased" : [1-9]' \
    && pass "revoked A2 and erased its sessions" || fail "revoke: $OUT"
OUT=$(RPC 0 nyx session send "$A" "$B" "after revoke")
echo "$OUT" | grep -q '"copies" : 2' && ! echo "$OUT" | grep -q "\"device\" : \"$A2\"" \
    && pass "no copy to the revoked device" || fail "post-revoke send: $OUT"
until_match 2 '"text" : "after revoke"' nyx session messages "$B" "$A" >/dev/null || fail "B1 after revoke"
until_match 2 '"seq" : 3' nyx keyring contact "$A" >/dev/null || fail "B pin of A at seq 3"
OUT=$(send_until 2 '"copies" : 2' "$B" "$A" "to A1 only")
! echo "$OUT" | grep -q "\"device\" : \"$A2\"" && pass "B leaves out the revoked A2" || fail "B send: $OUT"
sleep 20
if RPC 1 nyx session messages "$A" "$B" | grep -q "after revoke\|to A1 only"; then
    fail "revoked A2 decrypted later traffic"
else
    pass "revoked A2 got nothing new"
fi
OUT=$(RPC 1 nyx session send "$A" "$B" "from revoked")
echo "$OUT" | grep -q "not live\|was revoked" && pass "revoked A2 cannot send" || fail "revoked A2 send: $OUT"

for i in $(seq 0 $((N - 1))); do
    if grep -q "Misbehaving.*smsg" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null; then fail "node$i penalised a peer for smsg"; fi
    ALARM=$(grep "clone alarm" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null | grep -v "this device was revoked")
    [ -n "$ALARM" ] && fail "node$i raised a clone alarm: $ALARM"
done

[ "$FAILED" = 0 ] && echo "ALL NYX V2 MULTIDEVICE CHECKS PASSED" || echo "NYX V2 MULTIDEVICE CHECKS FAILED"
exit "$FAILED"
