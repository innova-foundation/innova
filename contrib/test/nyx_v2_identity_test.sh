#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Nyx v2 identity on four -nyxv2=1 regtest nodes: n0 and n1 are two devices of one address,
# n2 is a contact, n3 holds only the address key. Checks the PQ pin, pairing, a same-seq
# conflict freeze and its confirmation, revocation, and an address-key-only identity reset
# that the contact must accept.
# Usage: IV5_TEST_PORT_BASE=auto contrib/test/nyx_v2_identity_test.sh   (INNOVAD=..., KEEP=1)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init nyx_v2_identity || exit 1
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
TEST_DIR="$(iv5_test_dir "${TMPDIR:-/tmp}/nyx_v2_identity")"
N=4

[ -x "$INNOVAD" ] || { echo "FAIL: $INNOVAD not found"; exit 1; }

P2P=() RPCP=()
for i in $(seq 0 $((N - 1))); do
    P2P+=( "$(iv5_port "$i" $((29810 + i)))" )
    RPCP+=( "$(iv5_port $((N + i)) $((29820 + i)))" )
done

RPC() {
    local i="$1"; shift
    "$INNOVAD" -datadir="$TEST_DIR/n$i" -regtest -rpcuser=nyx -rpcpassword=nyxidpass -rpcport="${RPCP[$i]}" "$@" 2>&1
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

rm -rf "$TEST_DIR"
for i in $(seq 0 $((N - 1))); do
    mkdir -p "$TEST_DIR/n$i"
    {
        echo "regtest=1"; echo "server=1"; echo "daemon=1"; echo "rpcuser=nyx"; echo "rpcpassword=nyxidpass"
        echo "rpcport=${RPCP[$i]}"; echo "port=${P2P[$i]}"; echo "listen=1"; echo "dnsseed=0"; echo "idns=0"
        echo "listenonion=0"; echo "staking=0"; echo "smsg=1"; echo "nyx=1"; echo "nyxv2=1"; echo "printtoconsole=0"
        for j in $(seq 0 $((i - 1))); do echo "connect=127.0.0.1:${P2P[$j]}"; done
    } > "$TEST_DIR/n$i/innova.conf"
done
for i in $(seq 0 $((N - 1))); do "$INNOVAD" -datadir="$TEST_DIR/n$i" -regtest -daemon; done
for i in $(seq 0 $((N - 1))); do
    for _ in $(seq 1 60); do RPC "$i" getinfo >/dev/null 2>&1 && break; sleep 1; done
done
sleep 15

ADDR=$(RPC 0 getnewaddress)
KEY=$(RPC 0 dumpprivkey "$ADDR")
for i in 1 3; do RPC "$i" importprivkey "$KEY" "" false >/dev/null; done

# Polls the contact until the pin reaches the wanted epoch and seq (or a flag appears).
contact_until() {
    local want="$1" out=""
    for _ in $(seq 1 45); do
        out=$(RPC 2 nyx keyring contact "$ADDR")
        if echo "$out" | tr -d '\n' | grep -q "$want"; then echo "$out"; return 0; fi
        sleep 2
    done
    echo "$out"
    return 1
}

echo "=== first device, PQ ==="
OUT=$(RPC 0 nyx keyring init "$ADDR" pq)
echo "$OUT" | grep -q '"seq" : 1' && pass "keyring init seq 1" || fail "keyring init: $OUT"
OUT=$(contact_until '"seq" : 1')
echo "$OUT" | grep -q '"pinned" : true' && echo "$OUT" | grep -q '"pq_seen" : true' \
    && pass "contact pinned a PQ keyring" || fail "contact pin: $OUT"
SN1=$(echo "$OUT" | field safety_number)

echo "=== second device by pairing ==="
PAIR=$(RPC 1 nyx device pair "$ADDR")
REQ=$(echo "$PAIR" | field request)
CODE=$(echo "$PAIR" | field pairing_code)
[ "$(RPC 0 nyx device code "$REQ" | field pairing_code)" = "$CODE" ] && pass "approver derives the new device's code" \
    || fail "pairing code mismatch"
OUT=$(RPC 0 nyx device approve "$ADDR" "$REQ" 00 2>&1)
echo "$OUT" | grep -q "Pairing code does not match" && pass "approve refuses a wrong code" || fail "wrong code: $OUT"
CERT=$(RPC 0 nyx device approve "$ADDR" "$REQ" "$CODE" | field cert)
[ -n "$CERT" ] || fail "approve returned no cert"
RPC 1 nyx device install "$ADDR" "$CERT" | grep -q '"device"' || fail "install failed"
OUT=$(contact_until '"seq" : 2')
[ "$(echo "$OUT" | grep -c '"device" :')" = 2 ] && pass "contact sees two devices at seq 2" || fail "two devices: $OUT"

echo "=== address key alone cannot add a device ==="
OUT=$(RPC 3 nyx keyring init "$ADDR")
echo "$OUT" | grep -q "already has a keyring" && pass "n3 refused to start a second chain" || fail "n3 init: $OUT"

echo "=== same-seq conflict freezes the contact ==="
RPC 0 nyx keyring confirm "$ADDR" > "$TEST_DIR/c0.out" &
RPC 1 nyx keyring confirm "$ADDR" > "$TEST_DIR/c1.out" &
wait
OUT=$(contact_until '"frozen" : true')
echo "$OUT" | grep -q '"can_send" : false' && pass "contact froze on two seq-3 keyrings" || fail "freeze: $OUT"
sleep 5
OUT=$(RPC 0 nyx keyring confirm "$ADDR")
echo "$OUT" | grep -q '"seq" : 4' || fail "owner confirm: $OUT"
OUT=$(contact_until '"seq" : 4')
echo "$OUT" | grep -q '"frozen" : false' && echo "$OUT" | grep -q '"can_send" : true' \
    && pass "owner confirmation on one device unfroze the contact" || fail "unfreeze: $OUT"

echo "=== revocation ==="
DEV1=$(RPC 1 nyx keyring show "$ADDR" | field device)
OUT=$(RPC 0 nyx device revoke "$ADDR" "$DEV1")
echo "$OUT" | grep -q '"seq" : 5' || fail "revoke: $OUT"
OUT=$(contact_until '"seq" : 5')
[ "$(echo "$OUT" | grep -c '"device" :')" = 1 ] && ! echo "$OUT" | grep -q "$DEV1" \
    && pass "revoked device is gone from the contact's pin" || fail "revocation: $OUT"

echo "=== address-key-only identity reset ==="
OUT=$(RPC 3 nyx keyring reset "$ADDR")
echo "$OUT" | grep -q '"epoch" : 2' || fail "reset: $OUT"
OUT=$(contact_until '"reset_pending" : true')
echo "$OUT" | grep -q '"can_send" : false' && echo "$OUT" | grep -q "stolen wallet key" \
    && echo "$OUT" | grep -q '"new_safety_number"' && pass "reset held behind a warning" || fail "reset warning: $OUT"
RHASH=$(echo "$OUT" | grep -A8 '"reset" :' | field keyring_hash)
OLDH=$(echo "$OUT" | field keyring_hash)
OUT=$(RPC 2 nyx keyring accept "$ADDR" "$OLDH" 2>&1)
echo "$OUT" | grep -q "not the one shown" && pass "accept refuses a reset other than the one shown" || fail "wrong hash: $OUT"
OUT=$(RPC 2 nyx keyring accept "$ADDR" "$RHASH")
echo "$OUT" | grep -q '"epoch" : 2' && echo "$OUT" | grep -q '"can_send" : true' \
    && pass "one-click accept pinned epoch 2" || fail "accept: $OUT"
SN2=$(echo "$OUT" | field safety_number)
[ -n "$SN1" ] && [ "$SN1" != "$SN2" ] && pass "safety number changed" || fail "safety number $SN1 / $SN2"

for i in $(seq 0 $((N - 1))); do
    if grep -q "Misbehaving.*smsg" "$TEST_DIR/n$i/regtest/debug.log" 2>/dev/null; then fail "node$i penalised a peer for smsg"; fi
done

[ "$FAILED" = 0 ] && echo "ALL NYX V2 IDENTITY CHECKS PASSED" || echo "NYX V2 IDENTITY CHECKS FAILED"
exit "$FAILED"
