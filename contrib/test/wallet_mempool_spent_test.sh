#!/usr/bin/env bash
# Copyright (c) 2026 The Innova developers
# Regtest: listunspent must not clear spent flags set by a shield tx still in the mempool.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init wallet_mempool_spent
INNOVAD=${INNOVAD:-$SCRIPT_DIR/../../src/innovad}
D=${WMS_DATADIR:-$HOME/innova-local-test/wallet-mempool-spent}/node
P=$(iv5_port 0 39410)
rm -rf "$D"; mkdir -p "$D"
cat > "$D/innova.conf" <<C
regtest=1
server=1
rpcuser=u
rpcpassword=p
rpcport=$P
port=$(iv5_port 1 39411)
idnsport=$(iv5_port 2 39412)
listen=0
dnsseed=0
stakingmode=0
nofinalityvoting=1
regtestboundaryb=311
regtestiv5rehearsal=1
C
rpc() { "$INNOVAD" -datadir="$D" -regtest -rpcuser=u -rpcpassword=p -rpcport=$P "$@" 2>&1; }
h() { rpc getblockcount | tr -d '"[:space:]'; }
mine_to() { for _ in $(seq 1 200); do c=$(h); [ "$c" -ge "$1" ] 2>/dev/null && return 0; rpc setgenerate true $(( $1 - ${c:-0} )) >/dev/null; sleep 2; done; return 1; }
start() { "$INNOVAD" -datadir="$D" -regtest -daemon >/dev/null 2>&1; for _ in $(seq 1 90); do rpc getinfo >/dev/null && return 0; sleep 1; done; return 1; }
fail() { echo "FAIL: $*"; exit 1; }
trap 'rpc stop >/dev/null; iv5_wait_daemons_gone "-datadir=$D" 30 >/dev/null 2>&1' EXIT

start || fail "daemon start"
mine_to 340 || fail "mine"
rpc encryptwallet pw >/dev/null
iv5_wait_daemons_gone "-datadir=$D" 60 >/dev/null 2>&1
start || fail "daemon restart"
rpc walletpassphrase pw 36000 >/dev/null
rpc z_createiv5seed | grep -qi error && fail "z_createiv5seed"
X=$(rpc getnewaddress mig >/dev/null; rpc getnewaddress mig | tr -d '"[:space:]')
echo "X=$X"
T1=$(rpc sendtoaddress "$X" 5 | tr -d '"[:space:]')
T2=$(rpc sendtoaddress "$X" 7 | tr -d '"[:space:]')
mine_to $(( $(h) + 2 )) || fail "mine"
U=$(rpc listunspent 1 9999999 "[\"$X\"]"); [ "$(echo "$U" | grep -c txid)" -eq 2 ] || fail "funding not confirmed: $U"

R=$(rpc z_migratetopool 20)
echo "$R" | grep -q "\"address\" : \"$X\"" || fail "no shield built for X: $R"
echo "$R" | grep -q '"inputs" : 2' || fail "shield did not take both outputs"

# Shield is unmined; listunspent runs the spent-flag repair and must leave both outputs spent.
N=$(rpc listunspent 0 9999999 "[\"$X\"]" | grep -c txid)
[ "$N" -eq 0 ] || fail "listunspent lists $N output(s) spent by a mempool shield"
R2=$(rpc z_migratetopool 20)
echo "$R2" | grep -q "\"address\" : \"$X\"" && fail "second migrate rebuilt a double-spend of X"
rpc getrawmempool | grep -q . || fail "mempool empty"

mine_to $(( $(h) + 2 )) || fail "mine"
N=$(rpc listunspent 0 9999999 "[\"$X\"]" | grep -c txid)
[ "$N" -eq 0 ] || fail "after mining, $N output(s) of X still listed"
echo "PASS"
