#!/bin/bash
# Does a 24-word phrase actually recover money?
#
# Everything below the phrase is pinned by unit cases -- bip39_tests and hdroot_tests fix
# the wordlist, the encoding and the derivation -- but none of them can show that a wallet
# rebuilt from those words sees the notes the original held. This drives a real node to
# find out: fund a wallet, move value into the IV5 pool, write the phrase down, DELETE THE
# WALLET FILE, restore from the words alone, and require the notes and their value back.
#
# Usage:  contrib/test/recovery_phrase_restore.sh [path-to-innovad]
# Regtest only. It creates and destroys /home/user/hdr (or $HDR_DIR) and touches nothing
# else; it starts a node on ports 29951/29961, so nothing else may be using them.
#
# Two things that will look like failures and are not:
#   - spendable balance is 0 throughout. Spendability waits on finality and one node can
#     never advance it, so the value to compare across the wipe is the unconfirmed total.
#   - z_listaddresses is empty afterwards. That lists LEGACY shielded addresses; the IV5
#     ones come from z_getnewiv5address.
#
# Result 2026-09-12 (48-core Linux, regtest, Boundary B 311): 120 notes and 12,304.94 INN
# restored from the words alone, matching the chain's pool value exactly.

set -u
BIN=${1:-$(dirname "$0")/../../src/innovad}
D=${HDR_DIR:-/home/user/hdr}/node
PASS=hdrpass2026
R="$BIN -datadir=$D -regtest -rpcport=29951 -rpcuser=hdr -rpcpassword=hdrpass"

up () {
  $BIN -datadir=$D -regtest >/dev/null 2>&1
  for i in $(seq 1 120); do $R getinfo >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
down () { $R stop >/dev/null 2>&1; sleep 6; }
iv5bal () { $R z_getshieldedinfo 2>/dev/null | sed -n 's/.*"privacy_vnext_balance" *: *\([0-9.]*\).*/\1/p'; }
iv5notes () { $R z_getshieldedinfo 2>/dev/null | sed -n 's/.*"privacy_vnext_note_count" *: *\([0-9]*\).*/\1/p'; }
# Spendable value is zero on one node whatever the wallet holds -- spendability waits on
# finality and a single node can never advance it -- so the value that can be compared
# across the wipe is the unconfirmed total.
iv5unconf () { $R z_getshieldedinfo 2>/dev/null | sed -n 's/.*"privacy_vnext_unconfirmed_balance" *: *\([0-9.]*\).*/\1/p'; }
mine_to () {
  local t=$1
  $R setgenerate true $(( t + 5 )) >/dev/null 2>&1
  for i in $(seq 1 900); do
    local h=$($R getblockcount 2>/dev/null)
    [ -n "$h" ] && [ "$h" -ge "$t" ] && { $R setgenerate false >/dev/null 2>&1; return 0; }
    sleep 2
  done
  $R setgenerate false >/dev/null 2>&1; return 1
}
conf () {
  mkdir -p $D
  cat > $D/innova.conf <<CONF
regtest=1
server=1
daemon=1
rpcuser=hdr
rpcpassword=hdrpass
rpcport=29951
port=29961
bind=127.0.0.1
listen=1
dnsseed=0
nobootstrap=1
nosmsg=1
upnp=0
listenonion=0
idnsport=29971
maxconnections=125
staking=0
regtestboundaryb=311
regtestiv5rehearsal=1
CONF
}

rm -rf ${HDR_DIR:-/home/user/hdr}; conf
up || { echo "FAIL: node did not start"; exit 1; }
mine_to 420
echo "STEP height=$($R getblockcount) balance=$($R getbalance)"

$R encryptwallet "$PASS" >/dev/null 2>&1; sleep 8
up || { echo "FAIL: no restart after encryptwallet"; exit 1; }
$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
$R z_createiv5seed >/dev/null 2>&1
ADDR=$($R z_getnewiv5address 2>/dev/null | sed -n 's/.*"address" *: *"\([^"]*\)".*/\1/p')
echo "STEP iv5 address: ${ADDR:0:24}..."

PHRASE=$($R z_exportphrase 2>/dev/null | sed -n 's/.*"phrase" *: *"\([^"]*\)".*/\1/p')
WORDS=$(echo "$PHRASE" | wc -w)
echo "STEP phrase words=$WORDS"
[ "$WORDS" -eq 24 ] || { echo "FAIL: phrase is not 24 words"; down; exit 1; }

for r in 1 2 3 4 5 6; do
  $R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
  out=$($R z_migratetopool 10 4 2>/dev/null)
  s=$(echo "$out" | grep -o "\"sent\" : [0-9]*" | grep -o "[0-9]*$")
  [ -z "$s" ] && break
  mine_to $(( $($R getblockcount) + 2 ))
  [ "$s" -eq 0 ] && break
done
mine_to $(( $($R getblockcount) + 5 ))
POOL_BEFORE=$($R z_getshieldedinfo 2>/dev/null | grep privacy_vnext_pool_value | grep -o "[0-9.]*")
ZBAL_BEFORE=$(iv5bal)
NOTES_BEFORE=$(iv5notes)
UNCONF_BEFORE=$(iv5unconf)
HEIGHT=$($R getblockcount)
echo "STEP before wipe: height=$HEIGHT pool=$POOL_BEFORE notes=$NOTES_BEFORE unconfirmed=$UNCONF_BEFORE spendable=$ZBAL_BEFORE"
down

# The destruction: the wallet file, and nothing else. A user who lost their wallet still
# has the chain; taking the blocks away as well only adds a way for this to fail that has
# nothing to do with the phrase.
rm -f $D/regtest/wallet.dat
up || { echo "FAIL: node did not start on a fresh wallet"; exit 1; }
echo "STEP after wipe: height=$($R getblockcount) iv5_balance=$(iv5bal) notes=$(iv5notes)"

$R encryptwallet "$PASS" >/dev/null 2>&1; sleep 8
up || { echo "FAIL: no restart after second encryptwallet"; exit 1; }
$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
IMP=$($R z_importphrase "$PHRASE" 2>&1 | head -5)
echo "STEP importphrase: $(echo "$IMP" | head -2 | tr "\n" " ")"
$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
$R z_rescaniv5 2>&1 | head -3
sleep 10
ZBAL_AFTER=$(iv5bal)
NOTES_AFTER=$(iv5notes)
UNCONF_AFTER=$(iv5unconf)
echo "RESULT notes_before=$NOTES_BEFORE notes_after=$NOTES_AFTER unconfirmed_before=$UNCONF_BEFORE unconfirmed_after=$UNCONF_AFTER spendable=$ZBAL_AFTER pool=$POOL_BEFORE"
# Spendable value is not the test here and never could be: it is zero on one node before
# the wipe as well, because spendability waits on a finality this chain cannot reach. What
# the phrase has to bring back is the notes and the value in them.
if [ -n "$NOTES_AFTER" ] && [ "$NOTES_AFTER" = "$NOTES_BEFORE" ] && [ "$NOTES_AFTER" != "0" ] \
   && [ "$UNCONF_AFTER" = "$UNCONF_BEFORE" ] && [ "$UNCONF_AFTER" != "0.00000000" ]; then
  echo "RESTORE: PASS -- $NOTES_AFTER notes and $UNCONF_AFTER INN came back from the words alone"
else
  echo "RESTORE: FAIL -- notes $NOTES_BEFORE->$NOTES_AFTER value $UNCONF_BEFORE->$UNCONF_AFTER"
fi
$R z_listaddresses 2>/dev/null | head -4
down
