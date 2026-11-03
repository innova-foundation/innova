#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Nyx v2 groups over sessions on four -nyxv2=1 regtest nodes: n0/n1 are devices A1/A2 of A, n2 is B, n3 is C.
# Checks create, fanout to every member device with sent-sync, removal (the removed member gets no later
# message from anyone and cannot send), and a later add.
# Usage: IV5_TEST_PORT_BASE=auto contrib/test/nyx_v2_group_test.sh   (INNOVAD=..., KEEP=1)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init nyx_v2_group || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="$(iv5_test_dir "${TMPDIR:-/tmp}/nyx_v2_group")"
N=4

[ -x "$INNOVAD" ] || { echo "FAIL: $INNOVAD not found"; exit 1; }

P2P=() RPCP=()
for i in $(seq 0 $((N - 1))); do
    P2P+=( "$(iv5_port "$i" $((29990 + i)))" )
    RPCP+=( "$(iv5_port $((N + i)) $((30000 + i)))" )
done

RPC() {
    local i="$1"; shift
    "$INNOVAD" -datadir="$TEST_DIR/n$i" -regtest -rpcuser=nyx -rpcpassword=nyxgrpass -rpcport="${RPCP[$i]}" "$@" 2>&1
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
    local req code cert
    req=$(RPC "$2" nyx device pair "$3")
    code=$(echo "$req" | field pairing_code)
    req=$(echo "$req" | field request)
    cert=$(until_match "$1" '"cert"' nyx device approve "$3" "$req" "$code" | field cert)
    RPC "$2" nyx device install "$3" "$cert" | field device
}

rm -rf "$TEST_DIR"
for i in $(seq 0 $((N - 1))); do
    mkdir -p "$TEST_DIR/n$i"
    {
        echo "regtest=1"; echo "server=1"; echo "daemon=1"; echo "rpcuser=nyx"; echo "rpcpassword=nyxgrpass"
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

A=$(RPC 0 getnewaddress)
B=$(RPC 2 getnewaddress)
C=$(RPC 3 getnewaddress)
share_key 0 "$A" 1
sleep 10

echo "=== identities: A with two devices, B and C with one ==="
RPC 0 nyx keyring init "$A" pq | grep -q '"seq" : 1' || fail "A keyring init"
RPC 2 nyx keyring init "$B" pq | grep -q '"seq" : 1' || fail "B keyring init"
RPC 3 nyx keyring init "$C" pq | grep -q '"seq" : 1' || fail "C keyring init"
A2=$(pair 0 1 "$A")
[ -n "$A2" ] && pass "A2 paired" || fail "A2 pair"
for n in 0 1; do
    until_match "$n" '"pinned" : true' nyx keyring contact "$B" >/dev/null || fail "n$n pin of B"
    until_match "$n" '"pinned" : true' nyx keyring contact "$C" >/dev/null || fail "n$n pin of C"
done
for n in 2 3; do until_match "$n" '"seq" : 2' nyx keyring contact "$A" >/dev/null || fail "n$n pin of A"; done
until_match 2 '"pinned" : true' nyx keyring contact "$C" >/dev/null || fail "B pin of C"
until_match 3 '"pinned" : true' nyx keyring contact "$B" >/dev/null || fail "C pin of B"
until_match 0 "$A2" nyx devices "$A" >/dev/null || fail "A1 sees A2"
# Bundles reach every node before the group starts: one 1:1 message on each pair.
send_until 0 '"copies" : 2' "$A" "$B" "hi b" >/dev/null || fail "A to B warm-up"
send_until 0 '"copies" : 2' "$A" "$C" "hi c" >/dev/null || fail "A to C warm-up"
send_until 2 '"copies" : 1' "$B" "$C" "hi" >/dev/null || fail "B to C warm-up"

group() { local n="$1"; shift; RPC "$n" nyx session "$@"; }
gsend_until() {
    local node="$1" want="$2" out=""; shift 2
    for _ in $(seq 1 12); do
        out=$(group "$node" groupsend "$@")
        if echo "$out" | tr -d '\n' | grep -q "$want"; then echo "$out"; return 0; fi
        sleep 15
    done
    echo "$out"
    return 1
}

echo "=== create ==="
OUT=$(group 0 groupcreate "$A" "team" "$B" "$C")
GID=$(echo "$OUT" | field gid)
[ -n "$GID" ] && pass "A created the group ($(echo "$OUT" | field copies) copies)" || fail "create: $OUT"
for n in 1 2 3; do
    until_match "$n" "\"gid\" : \"$GID\"" nyx session grouplist "$([ $n = 1 ] && echo "$A" || ([ $n = 2 ] && echo "$B" || echo "$C"))" \
        >/dev/null && pass "n$n knows the group" || fail "n$n grouplist"
done

echo "=== messages reach every member device ==="
OUT=$(gsend_until 0 '"copies" : 3' "$A" "$GID" "hello all")
echo "$OUT" | grep -q '"own" : true' && pass "A1 sent to B, C and a sync copy to A2" || fail "send: $OUT"
until_match 2 '"text" : "hello all"' nyx session groupmessages "$B" "$GID" >/dev/null && pass "B received" || fail "B receive"
until_match 3 '"text" : "hello all"' nyx session groupmessages "$C" "$GID" >/dev/null && pass "C received" || fail "C receive"
OUT=$(until_match 1 '"text" : "hello all"' nyx session groupmessages "$A" "$GID")
echo "$OUT" | tr -d '\n' | grep -q '"direction" : "out"[^}]*"text" : "hello all"' \
    && pass "A2 holds A1's message as outgoing" || fail "A2 sync: $OUT"
gsend_until 2 '"copies" : 3' "$B" "$GID" "from B" >/dev/null || fail "B send"
until_match 0 '"text" : "from B"' nyx session groupmessages "$A" "$GID" >/dev/null && pass "A1 got B's message" || fail "A1 from B"
until_match 1 '"text" : "from B"' nyx session groupmessages "$A" "$GID" >/dev/null && pass "A2 got B's message" || fail "A2 from B"
until_match 3 '"text" : "from B"' nyx session groupmessages "$C" "$GID" >/dev/null && pass "C got B's message" || fail "C from B"

echo "=== A removes C ==="
OUT=$(group 0 groupremove "$A" "$GID" "$C")
echo "$OUT" | grep -q '"epoch" : 1' && pass "remove op at epoch 1" || fail "remove: $OUT"
until_match 3 '"member" : false' nyx session grouplist "$C" >/dev/null && pass "C learned its removal" || fail "C removal"
until_match 2 '"epoch" : 1' nyx session grouplist "$B" >/dev/null || fail "B at epoch 1"
until_match 1 '"epoch" : 1' nyx session grouplist "$A" >/dev/null || fail "A2 at epoch 1"
OUT=$(gsend_until 0 '"copies" : 2' "$A" "$GID" "after remove")
echo "$OUT" | grep -q "\"member\" : \"$C\"" && fail "A still sends to C: $OUT" || pass "A sends to B and A2 only"
until_match 2 '"text" : "after remove"' nyx session groupmessages "$B" "$GID" >/dev/null || fail "B after remove"
OUT=$(gsend_until 2 '"copies" : 2' "$B" "$GID" "B after remove")
echo "$OUT" | grep -q "\"member\" : \"$C\"" && fail "B still sends to C: $OUT" || pass "B leaves out C"
until_match 0 '"text" : "B after remove"' nyx session groupmessages "$A" "$GID" >/dev/null || fail "A1 B after remove"
OUT=$(group 3 groupsend "$C" "$GID" "from removed C")
echo "$OUT" | grep -q "not a member" && pass "removed C cannot send" || fail "C send: $OUT"
sleep 20
if RPC 3 nyx session groupmessages "$C" "$GID" | grep -q "after remove"; then
    fail "removed C read a later message"
else
    pass "removed C got nothing after its removal"
fi

echo "=== A adds C back ==="
OUT=$(group 0 groupadd "$A" "$GID" "$C")
echo "$OUT" | grep -q '"epoch" : 2' && pass "add op at epoch 2" || fail "add: $OUT"
until_match 3 '"member" : true' nyx session grouplist "$C" >/dev/null && pass "C is a member again" || fail "C re-add"
until_match 2 '"epoch" : 2' nyx session grouplist "$B" >/dev/null || fail "B at epoch 2"
gsend_until 2 '"copies" : 3' "$B" "$GID" "welcome back" >/dev/null || fail "B send after add"
until_match 3 '"text" : "welcome back"' nyx session groupmessages "$C" "$GID" >/dev/null && pass "C reads after re-add" || fail "C after add"
until_match 1 '"epoch" : 2' nyx session grouplist "$A" >/dev/null && pass "A2 synced the add (two seals in one batch)" || fail "A2 at epoch 2"
until_match 1 '"text" : "welcome back"' nyx session groupmessages "$A" "$GID" >/dev/null && pass "A2 reads after the add" || fail "A2 after add"
OUT=$(RPC 0 nyx session groupmessages "$A" "$GID")
[ "$(echo "$OUT" | grep -c '"text" : "removed ')" = 1 ] && pass "the removal shows once" || fail "removal rows: $OUT"

for i in $(seq 0 $((N - 1))); do
    if grep -q "Misbehaving.*smsg" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null; then fail "node$i penalised a peer for smsg"; fi
    ALARM=$(grep "clone alarm" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null)
    [ -n "$ALARM" ] && fail "node$i raised a clone alarm: $ALARM"
done

[ "$FAILED" = 0 ] && echo "ALL NYX V2 GROUP CHECKS PASSED" || echo "NYX V2 GROUP CHECKS FAILED"
exit "$FAILED"
