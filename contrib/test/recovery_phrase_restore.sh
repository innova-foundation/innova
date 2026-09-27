#!/bin/bash
# Restores a wallet from its 24-word phrase and requires its IV5 notes back, unlocked and locked.
# Usage: contrib/test/recovery_phrase_restore.sh [path-to-innovad]  (or INNOVAD=<path>)
# Regtest only; creates and destroys $HDR_DIR. Compares the unconfirmed total (spendable stays 0).

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init recovery_phrase_restore || exit 1
BIN=${1:-${INNOVAD:-$SCRIPT_DIR/../../src/innovad}}
ROOT_DIR=$(iv5_test_dir "${HDR_DIR:-${TMPDIR:-/tmp}/innova_hdr}")
D=$ROOT_DIR/node
RPC_PORT=$(iv5_port 0 29951)
P2P_PORT=$(iv5_port 1 29961)
IDNS_PORT=$(iv5_port 2 29971)
PASS=hdrpass2026
R="$BIN -datadir=$D -regtest -rpcport=$RPC_PORT -rpcuser=hdr -rpcpassword=hdrpass"
RC=0

cleanup () {
  $R stop >/dev/null 2>&1
  iv5_stop_daemons "-datadir=$D" 20 >/dev/null 2>&1
  iv5_ports_release
  [ "${KEEP_DIR:-0}" = "1" ] || [ "$RC" -ne 0 ] || rm -rf "$ROOT_DIR"
}
trap cleanup EXIT
[ -x "$BIN" ] || { echo "FAIL: innovad not found at $BIN"; RC=1; exit 1; }

up () {
  $BIN -datadir=$D -regtest >/dev/null 2>&1
  for i in $(seq 1 120); do $R getinfo >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
down () {
  $R stop >/dev/null 2>&1
  for i in $(seq 1 60); do [ -z "$(iv5_daemon_pids "-datadir=$D")" ] && return 0; sleep 1; done
  iv5_stop_daemons "-datadir=$D" 20 >/dev/null 2>&1
}
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
rpcport=$RPC_PORT
port=$P2P_PORT
bind=127.0.0.1
listen=1
dnsseed=0
nobootstrap=1
nosmsg=1
upnp=0
listenonion=0
idnsport=$IDNS_PORT
maxconnections=125
staking=0
regtestboundaryb=311
regtestiv5rehearsal=1
CONF
}

rm -rf "$ROOT_DIR"; conf
iv5_require_free_ports "$RPC_PORT" "$P2P_PORT" "$IDNS_PORT" || { RC=1; exit 1; }
up || { echo "FAIL: node did not start"; RC=1; exit 1; }
mine_to 420
echo "STEP height=$($R getblockcount) balance=$($R getbalance)"

$R encryptwallet "$PASS" >/dev/null 2>&1; down
up || { echo "FAIL: no restart after encryptwallet"; RC=1; exit 1; }
$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
$R z_createiv5seed >/dev/null 2>&1
ADDR=$($R z_getnewiv5address 2>/dev/null | sed -n 's/.*"address" *: *"\([^"]*\)".*/\1/p')
echo "STEP iv5 address: ${ADDR:0:24}..."

PHRASE=$($R z_exportphrase 2>/dev/null | sed -n 's/.*"phrase" *: *"\([^"]*\)".*/\1/p')
SEEDJSON=$($R z_exportiv5seed 2>/dev/null)
SEEDHEX=$(echo "$SEEDJSON" | sed -n 's/.*"seed" *: *"\([0-9a-f]*\)".*/\1/p')
SEEDCOUNT=$(echo "$SEEDJSON" | sed -n 's/.*"address_index_count" *: *\([0-9]*\).*/\1/p')
echo "STEP hex seed chars=${#SEEDHEX} address_index_count=$SEEDCOUNT"
[ "${#SEEDHEX}" -eq 64 ] || { echo "FAIL: z_exportiv5seed returned no seed"; RC=1; exit 1; }
WORDS=$(echo "$PHRASE" | wc -w)
echo "STEP phrase words=$WORDS"
[ "$WORDS" -eq 24 ] || { echo "FAIL: phrase is not 24 words"; RC=1; down; exit 1; }

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
up || { echo "FAIL: node did not start on a fresh wallet"; RC=1; exit 1; }
echo "STEP after wipe: height=$($R getblockcount) iv5_balance=$(iv5bal) notes=$(iv5notes)"

$R encryptwallet "$PASS" >/dev/null 2>&1; down
up || { echo "FAIL: no restart after second encryptwallet"; RC=1; exit 1; }
$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
IMP=$($R z_importphrase "$PHRASE" 0 true 2>&1 | head -5)
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
  RC=1
fi
$R z_listaddresses 2>/dev/null | head -4

# ---------------------------------------------------------------------------
# Restore while LOCKED: the rescan records a scan gap, refuses spends over it, closes on unlock.
# ---------------------------------------------------------------------------
echo "STEP --- locked restore ---"
gap ()   { $R z_getshieldedinfo 2>/dev/null | sed -n 's/.*"privacy_vnext_scan_gap_height" *: *\(-*[0-9]*\).*/\1/p'; }
gapdur() { $R z_getshieldedinfo 2>/dev/null | sed -n 's/.*"privacy_vnext_scan_gap_persisted" *: *\([a-z]*\).*/\1/p'; }

down
rm -f $D/regtest/wallet.dat
up || { echo "FAIL: node did not start for the locked arm"; RC=1; exit 1; }
$R encryptwallet "$PASS" >/dev/null 2>&1; down
up || { echo "FAIL: no restart after encryptwallet (locked arm)"; RC=1; exit 1; }
$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
# This arm restores from the hex seed, with the optional arguments, so both restore
# paths and their argument conversion are covered.
IMPHEX=$($R z_importiv5seed "$SEEDHEX" "${SEEDCOUNT:-0}" false 2>&1)
echo "$IMPHEX" | grep -q '"imported" *: *true' || { echo "FAIL: z_importiv5seed: $(echo "$IMPHEX" | head -2 | tr '\n' ' ')"; RC=1; exit 1; }
$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
RESCAN=$($R z_rescaniv5 0 2>&1)
echo "$RESCAN" | grep -q '"from_height" *: *0' || { echo "FAIL: z_rescaniv5 0: $(echo "$RESCAN" | head -2 | tr '\n' ' ')"; RC=1; exit 1; }
sleep 8
echo "STEP unlocked restore: notes=$(iv5notes) gap=$(gap) persisted=$(gapdur)"

# Now restart with the wallet LOCKED and see what the node says about its own view.
$R walletlock >/dev/null 2>&1
down
up || { echo "FAIL: node did not restart locked"; RC=1; exit 1; }
LOCKED_NOTES=$(iv5notes); LOCKED_GAP=$(gap); LOCKED_DUR=$(gapdur)
echo "STEP restarted LOCKED: notes=$LOCKED_NOTES gap=$LOCKED_GAP persisted=$LOCKED_DUR"

# A locked wallet must refuse to spend over a view it knows is incomplete.
SPEND=$($R z_iv5transfer "$ADDR" 1.0 2>&1 | head -2 | tr "\n" " ")
echo "STEP locked spend attempt: $SPEND"

$R walletpassphrase "$PASS" 36000 >/dev/null 2>&1
sleep 10
UNLOCKED_NOTES=$(iv5notes); UNLOCKED_GAP=$(gap)
echo "STEP after unlock: notes=$UNLOCKED_NOTES gap=$UNLOCKED_GAP"

if [ "$LOCKED_GAP" != "-1" ] && [ "$UNLOCKED_GAP" = "-1" ] && [ "$UNLOCKED_NOTES" = "$NOTES_BEFORE" ]; then
  echo "LOCKED: PASS -- a locked restart declared its view incomplete (gap $LOCKED_GAP) and closed it on unlock"
elif [ "$LOCKED_GAP" = "-1" ] && [ "$LOCKED_NOTES" = "$NOTES_BEFORE" ]; then
  echo "LOCKED: PASS -- the locked restart kept a complete view, so there was no gap to declare"
else
  echo "LOCKED: FAIL -- locked gap=$LOCKED_GAP notes=$LOCKED_NOTES / unlocked gap=$UNLOCKED_GAP notes=$UNLOCKED_NOTES (expected $NOTES_BEFORE)"
  RC=1
fi
down
exit $RC
