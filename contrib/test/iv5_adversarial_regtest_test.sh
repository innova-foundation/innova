#!/bin/bash
# Copyright (c) 2026 The Innova developers
# IV5 adversarial regtest: shield real value, then replay, reorg under the pool and
# restart mid-flight. The value-balance rejection is in privacy_vnext_builder_tests.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_ADV_TEST_DIR:-/tmp/innova_iv5_adversarial_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${IV5_ADV_PORT:-27845}"
RPC="${IV5_ADV_RPC:-27900}"
IDNS="${IV5_ADV_IDNS:-7865}"
RPCUSER="iv5adv"
RPCPASS="iv5advpass"
WALLETPASS="iv5walletpass"

# Boundary B must not precede the schema-V3 epoch height (311 on regtest): a shield
# before it confirms but its notes never reach the tree.
BOUNDARY_B=311
FUND_HEIGHT=340
EPOCH_HEIGHT=630

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() { "$INNOVAD" -datadir="$NODE_DIR" -regtest -rpcuser=$RPCUSER \
        -rpcpassword=$RPCPASS -rpcport=$RPC "$@" 2>&1; }

height()   { rpc getblockcount 2>/dev/null | tr -d '"[:space:]'; }
jnum()     { echo "$1" | grep -oE "\"$2\" *: *-?[0-9.]+" | grep -oE '\-?[0-9.]+$' | head -1; }
jstr()     { echo "$1" | sed -n "s/.*\"$2\" *: *\"\([^\"]*\)\".*/\1/p" | head -1; }
is_int()   { echo "$1" | grep -qE '^[0-9]+$'; }

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    # Match the daemon's exact argv. A bare datadir match also catches the
    # short-lived rpc helper processes, which share that fragment, so the node
    # never looks gone and the restart is skipped entirely.
    for _ in $(seq 1 180); do
        pgrep -f -- "-datadir=$NODE_DIR -regtest -daemon" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

start_node() {
    "$INNOVAD" -datadir="$NODE_DIR" -regtest -daemon >/dev/null 2>&1
    for _ in $(seq 1 90); do
        rpc getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

mine_to() {
    local target="$1" h
    for _ in $(seq 1 90); do
        h="$(height)"
        is_int "$h" && [ "$h" -ge "$target" ] && return 0
        rpc setgenerate true $(( target - ${h:-0} )) >/dev/null 2>&1
        sleep 4
    done
    return 1
}

cleanup() {
    stop_node || pkill -f "datadir=$NODE_DIR" 2>/dev/null || true
    [ "${IV5_ADV_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 adversarial regtest"

rm -rf "$TEST_DIR"; mkdir -p "$NODE_DIR"
cat > "$NODE_DIR/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPC
port=$PORT
listen=1
idnsport=$IDNS
dnsseed=0
stakingmode=0
nofinalityvoting=1
maxconnections=125
regtestboundaryb=$BOUNDARY_B
regtestiv5rehearsal=1
EOF

start_node || { fail "node did not start"; exit 1; }
success "node started with Boundary B at $BOUNDARY_B and IV5 rehearsal enabled"

# ============================================================
header "1. IV5 activates and reports itself ready"
# ============================================================

mine_to "$FUND_HEIGHT" || { fail "could not mine to $FUND_HEIGHT"; exit 1; }
INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
# Check whether consensus accepts an IV5 payload; the ABI's consensus-active flag
# stays zero until separately reviewed.
ACCEPTED="$(echo "$INFO" | grep -o '"privacy_vnext_transactions_accepted" *: *[a-z]*' | grep -o '[a-z]*$')"
ACTIVE="$(echo "$INFO" | grep -o '"boundary_b_active" *: *[a-z]*' | grep -o '[a-z]*$')"
if [ "$ACCEPTED" = "true" ] && [ "$ACTIVE" = "true" ]; then
    success "Boundary B active and consensus accepts IV5 transactions"
else
    fail "IV5 not accepting (boundary_b_active=$ACTIVE transactions_accepted=$ACCEPTED)"
    exit 1
fi

# ============================================================
header "2. A shield puts real value into the pool"
# ============================================================

# The IV5 seed is spend authority for every note the wallet will own, so it is only
# created into an encrypted wallet. Encrypting stops the daemon, so restart and unlock.
rpc encryptwallet "$WALLETPASS" >/dev/null 2>&1
for _ in $(seq 1 60); do
    pgrep -f "datadir=$NODE_DIR" >/dev/null 2>&1 || break
    sleep 1
done
start_node || { fail "node did not restart after encrypting the wallet"; exit 1; }
success "wallet encrypted and node restarted"

UNLOCK="$(rpc walletpassphrase "$WALLETPASS" 3600 2>&1)"
if echo "$UNLOCK" | grep -qiE "error"; then
    fail "could not unlock the wallet: $(echo "$UNLOCK" | head -2)"
    exit 1
fi

SEED="$(rpc z_createiv5seed 2>&1)"
if echo "$SEED" | grep -q '"created"'; then
    success "IV5 seed created into the encrypted wallet"
else
    fail "z_createiv5seed failed: $(echo "$SEED" | head -2)"
    exit 1
fi

BAL_BEFORE="$(jnum "$(rpc z_getshieldedinfo 2>/dev/null)" privacy_vnext_balance)"
TREE_BEFORE="$(jnum "$(rpc z_getshieldedinfo 2>/dev/null)" privacy_vnext_tree_size)"

SHIELD="$(rpc z_shieldall 2>&1)"
TXID="$(jstr "$SHIELD" txid)"
SHIELDED="$(jnum "$SHIELD" shielded)"
INPUTS="$(jnum "$SHIELD" inputs)"
if [ -n "$TXID" ] && [ ${#TXID} -eq 64 ]; then
    success "shield built and accepted: $INPUTS input(s), $SHIELDED INN, txid ${TXID:0:16}"
else
    fail "z_shieldall failed: $(echo "$SHIELD" | head -3)"
    exit 1
fi

# It must reach a block, not merely the mempool.
mine_to $(( $(height) + 3 )) || true
CONF="$(rpc gettransaction "$TXID" 2>&1)"
# gettransaction reports confirmations 0 in the mempool; require real depth and a
# block hash so a miner that drops IV5 transactions fails.
CONFIRMATIONS="$(jnum "$CONF" confirmations)"
CONFBLOCK="$(jstr "$CONF" blockhash)"
if [ -n "$CONFIRMATIONS" ] && [ "$CONFIRMATIONS" -ge 1 ] && [ ${#CONFBLOCK} -eq 64 ]; then
    success "shield confirmed in a block ($CONFIRMATIONS confirmation(s))"
else
    fail "shield did not confirm: confirmations='$CONFIRMATIONS' blockhash='$CONFBLOCK'"
fi

# ============================================================
header "3. Replaying the shield is refused"
# ============================================================

RAW="$(rpc getrawtransaction "$TXID" 2>/dev/null | tr -d '"[:space:]')"
if [ -n "$RAW" ] && [ ${#RAW} -gt 100 ]; then
    REPLAY="$(rpc sendrawtransaction "$RAW" 2>&1)"
    if echo "$REPLAY" | grep -qiE "already|error|denied|exists"; then
        success "resubmitting the confirmed shield is refused"
    else
        fail "the chain accepted a replay of an already-confirmed shield: $REPLAY"
    fi
else
    warn "could not fetch the raw shield; replay case skipped"
fi

# ============================================================
header "4. The tree and the store move together"
# ============================================================

mine_to "$EPOCH_HEIGHT" || { fail "could not mine to $EPOCH_HEIGHT"; exit 1; }
INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
TREE_AFTER="$(jnum "$INFO" privacy_vnext_tree_size)"
STORE_AFTER="$(jnum "$INFO" privacy_vnext_tree_store_size)"
BAL_AFTER="$(jnum "$INFO" privacy_vnext_balance)"

if is_int "$TREE_AFTER" && [ "$TREE_AFTER" -gt "${TREE_BEFORE:-0}" ]; then
    success "tree grew from ${TREE_BEFORE:-0} to $TREE_AFTER leaves"
else
    fail "tree did not grow (before=${TREE_BEFORE:-?} after=${TREE_AFTER:-?})"
fi

if [ "$TREE_AFTER" = "$STORE_AFTER" ]; then
    success "node-local store is level with the epoch tree at $STORE_AFTER"
else
    fail "store ($STORE_AFTER) disagrees with the epoch tree ($TREE_AFTER)"
fi

# The wallet must be able to see what it shielded. Value that reaches the tree
# but never reaches the owner's wallet is value the owner cannot spend, so this
# is a failure and not a warning.
NOTES_AFTER="$(jnum "$INFO" privacy_vnext_note_count)"
if [ "${NOTES_AFTER:-0}" -ge 1 ] 2>/dev/null; then
    success "wallet detected its own shielded output(s): $NOTES_AFTER note(s)"
else
    fail "wallet detected no shielded notes (note_count=${NOTES_AFTER:-?})"
fi
if [ "$(echo "$BAL_AFTER > ${BAL_BEFORE:-0}" | bc -l 2>/dev/null)" = "1" ]; then
    success "wallet reports the shielded balance: $BAL_AFTER INN"
else
    fail "wallet shielded balance did not increase (before=${BAL_BEFORE:-?} after=${BAL_AFTER:-?})"
fi

# ============================================================
header "5. Shielding does not create supply"
# ============================================================

# The pool is a value counterparty: coins it absorbs are not also spendable as
# fee. If they are, the block that carried the shield pays its miner the whole
# shielded amount on top of the subsidy.
coinbase_value() {
    local bh cb
    bh="$(rpc getblockhash "$1" 2>/dev/null | tr -d '"[:space:]')"
    [ -n "$bh" ] || return 1
    cb="$(rpc getblock "$bh" 2>/dev/null | sed -n '/"tx"/,/]/p' | grep -oE '[a-f0-9]{64}' | head -1)"
    [ -n "$cb" ] || return 1
    rpc getrawtransaction "$cb" 1 2>/dev/null |
        grep -oE '"value" : [0-9.]+' | grep -oE '[0-9.]+$' | paste -sd+ - | bc
}

SHIELD_HEIGHT="$(jnum "$(rpc getblock "$CONFBLOCK" 2>/dev/null)" height)"

if is_int "$SHIELD_HEIGHT"; then
    CB_SHIELD="$(coinbase_value "$SHIELD_HEIGHT")"
    CB_PLAIN="$(coinbase_value $(( SHIELD_HEIGHT - 1 )))"
    # The shield block's coinbase may exceed a plain one only by the fee.
    if [ -n "$CB_SHIELD" ] && [ -n "$CB_PLAIN" ] && \
       [ "$(echo "$CB_SHIELD - $CB_PLAIN < 1" | bc -l 2>/dev/null)" = "1" ]; then
        success "shield block coinbase is $CB_SHIELD against $CB_PLAIN for a plain block"
    else
        fail "shielded value was also paid out as fee: coinbase $CB_SHIELD vs $CB_PLAIN (shielded $SHIELDED)"
    fi
else
    warn "could not locate the shield block height; supply check skipped"
fi

# ============================================================
header "6. A transfer spends notes without touching transparent value"
# ============================================================

# A spend anchors to a finalized epoch state; a single regtest node cannot reach
# quorum, so spend sections do not apply here and the pool is deposit-only.
CUR_EPOCH=$(( ( $(height) - 11 ) / 300 + 1 ))
FIN_AS_OF="$(jnum "$(rpc getepochinfo $CUR_EPOCH 2>/dev/null)" finalized_height_as_of)"
CAN_SPEND=0
if is_int "$FIN_AS_OF" && [ "$FIN_AS_OF" -gt 0 ]; then
    CAN_SPEND=1
else
    warn "no finalized epoch state on this chain (finalized_height_as_of=$FIN_AS_OF);"
    warn "  spends cannot anchor, so sections 6-8 are skipped. Finality needs a"
    warn "  committee quorum, which one regtest node cannot form."
fi

if [ "$CAN_SPEND" = "1" ]; then

TO_ADDR="$(jstr "$(rpc z_getnewiv5address 2>&1)" address)"
[ -n "$TO_ADDR" ] || TO_ADDR="$(rpc z_getnewiv5address 2>&1 | grep -oE '[a-zA-Z0-9]{40,}' | head -1)"

XFER="$(rpc z_iv5transfer "$TO_ADDR" 100 2>&1)"
XFER_TXID="$(jstr "$XFER" txid)"
if [ ${#XFER_TXID} -eq 64 ]; then
    success "transfer built and accepted: 100 INN, txid ${XFER_TXID:0:16}"
else
    fail "z_iv5transfer failed: $(echo "$XFER" | head -3)"
fi

if [ ${#XFER_TXID} -eq 64 ]; then
    mine_to $(( $(height) + 3 )) || true
    XC="$(rpc gettransaction "$XFER_TXID" 2>&1)"
    XCONF="$(jnum "$XC" confirmations)"
    XRAW="$(rpc getrawtransaction "$XFER_TXID" 1 2>&1)"
    XVOUT="$(echo "$XRAW" | grep -cE '"value" : ')"
    if [ -n "$XCONF" ] && [ "$XCONF" -ge 1 ] 2>/dev/null; then
        success "transfer confirmed ($XCONF confirmation(s))"
    else
        fail "transfer did not confirm: confirmations='$XCONF'"
    fi
    # A transfer is entirely inside the pool: no transparent output may appear.
    if [ "$XVOUT" -eq 0 ]; then
        success "transfer carries no transparent output"
    else
        fail "transfer leaked $XVOUT transparent output(s)"
    fi
fi

# ============================================================
header "7. An unshield releases pool value to a transparent address"
# ============================================================

T_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
UNSH="$(rpc z_iv5unshield "$T_ADDR" 50 2>&1)"
UNSH_TXID="$(jstr "$UNSH" txid)"
if [ ${#UNSH_TXID} -eq 64 ]; then
    success "unshield built and accepted: 50 INN to $T_ADDR, txid ${UNSH_TXID:0:16}"
else
    fail "z_iv5unshield failed: $(echo "$UNSH" | head -3)"
fi

if [ ${#UNSH_TXID} -eq 64 ]; then
    mine_to $(( $(height) + 3 )) || true
    UC="$(rpc gettransaction "$UNSH_TXID" 2>&1)"
    UCONF="$(jnum "$UC" confirmations)"
    if [ -n "$UCONF" ] && [ "$UCONF" -ge 1 ] 2>/dev/null; then
        success "unshield confirmed ($UCONF confirmation(s))"
    else
        fail "unshield did not confirm: confirmations='$UCONF'"
    fi
    URAW="$(rpc getrawtransaction "$UNSH_TXID" 1 2>&1)"
    UVAL="$(echo "$URAW" | grep -oE '"value" : [0-9.]+' | grep -oE '[0-9.]+$' | head -1)"
    if [ "$(echo "$UVAL == 50" | bc -l 2>/dev/null)" = "1" ]; then
        success "unshield paid exactly 50.00000000 INN to the transparent output"
    else
        fail "unshield transparent output is $UVAL, expected 50"
    fi
    # The released value has to come out of the pool, not out of thin air.
    UB="$(coinbase_value "$(jnum "$(rpc getblock "$(jstr "$UC" blockhash)" 2>/dev/null)" height)")"
    if [ -n "$UB" ] && [ "$(echo "$UB < 100" | bc -l 2>/dev/null)" = "1" ]; then
        success "unshield block coinbase stayed at $UB"
    else
        fail "unshield inflated its block's coinbase to $UB"
    fi
fi

# ============================================================
header "8. A spent note cannot be spent twice"
# ============================================================

if [ ${#XFER_TXID} -eq 64 ]; then
    XR="$(rpc getrawtransaction "$XFER_TXID" 2>/dev/null | tr -d '"[:space:]')"
    if [ -n "$XR" ] && [ ${#XR} -gt 100 ]; then
        DBL="$(rpc sendrawtransaction "$XR" 2>&1)"
        if echo "$DBL" | grep -qiE "already|error|denied|exists|consumed"; then
            success "replaying a confirmed transfer is refused"
        else
            fail "the chain accepted a replay of a confirmed transfer: $DBL"
        fi
    else
        warn "could not fetch the raw transfer; double-spend case skipped"
    fi
fi

fi   # CAN_SPEND

# ============================================================
header "9. A reorg takes the pool back with it"
# ============================================================

REORG_FROM=$(( $(height) - 8 ))
ROLLBACK_HASH="$(rpc getblockhash "$REORG_FROM" 2>/dev/null | tr -d '"[:space:]')"
if [ -z "$ROLLBACK_HASH" ]; then
    fail "could not read a block hash to invalidate"
else
    rpc invalidateblock "$ROLLBACK_HASH" >/dev/null 2>&1
    sleep 5
    REORG_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
    REORG_TREE="$(jnum "$REORG_INFO" privacy_vnext_tree_size)"
    REORG_STORE="$(jnum "$REORG_INFO" privacy_vnext_tree_store_size)"
    if [ "$REORG_TREE" = "$REORG_STORE" ]; then
        success "store stayed level with the tree across the rollback ($REORG_STORE)"
    else
        fail "after rollback the store ($REORG_STORE) and tree ($REORG_TREE) disagree"
    fi

    rpc reconsiderblock "$ROLLBACK_HASH" >/dev/null 2>&1
    sleep 5
    mine_to $(( REORG_FROM + 12 )) || true
    BACK_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
    BACK_TREE="$(jnum "$BACK_INFO" privacy_vnext_tree_size)"
    BACK_STORE="$(jnum "$BACK_INFO" privacy_vnext_tree_store_size)"
    if [ "$BACK_TREE" = "$BACK_STORE" ] && is_int "$BACK_TREE" && [ "$BACK_TREE" -ge "$TREE_AFTER" ]; then
        success "chain recovered and the pool returned to $BACK_TREE leaves"
    else
        fail "after recovery tree=$BACK_TREE store=$BACK_STORE (expected >= $TREE_AFTER, equal)"
    fi
fi

# ============================================================
header "10. The pool survives a restart"
# ============================================================

PRE_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
PRE_TREE="$(jnum "$PRE_INFO" privacy_vnext_tree_size)"
PRE_STORE="$(jnum "$PRE_INFO" privacy_vnext_tree_store_size)"
PRE_ROOT="$(jstr "$PRE_INFO" privacy_vnext_tree_root)"

if stop_node && start_node; then
    rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
    POST_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
    POST_TREE="$(jnum "$POST_INFO" privacy_vnext_tree_size)"
    POST_STORE="$(jnum "$POST_INFO" privacy_vnext_tree_store_size)"
    POST_ROOT="$(jstr "$POST_INFO" privacy_vnext_tree_root)"
    if [ "$PRE_TREE" = "$POST_TREE" ] && [ "$PRE_STORE" = "$POST_STORE" ] && \
       [ "$PRE_ROOT" = "$POST_ROOT" ]; then
        success "tree, store and root all survived the restart unchanged"
    else
        fail "restart changed the pool: tree $PRE_TREE->$POST_TREE store $PRE_STORE->$POST_STORE root ${PRE_ROOT:0:12}->${POST_ROOT:0:12}"
    fi
    if rpc gettransaction "$TXID" 2>/dev/null | grep -q '"confirmations"'; then
        success "the shield is still known to the wallet after restart"
    else
        fail "the wallet lost the shield across a restart"
    fi
else
    fail "node did not come back after restart"
fi

# ============================================================
header "11. A payload that lands while the seed is locked is not lost"
# ============================================================

# A locked wallet cannot trial-decrypt and unshield is retired, so a missed note is
# recovered only by reprocessing its block. The node must stay up and recover on request.
rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
mine_to $(( $(height) + 25 )) || true
NOTES_BEFORE="$(jnum "$(rpc z_getshieldedinfo 2>/dev/null)" privacy_vnext_note_count)"
SHIELD2="$(rpc z_shieldall 2>&1)"
TXID2="$(jstr "$SHIELD2" txid)"
if [ ${#TXID2} -ne 64 ]; then
    warn "no second shield could be built; locked-wallet case skipped"
else
    rpc walletlock >/dev/null 2>&1
    mine_to $(( $(height) + 4 )) || true

    if rpc getinfo >/dev/null 2>&1; then
        success "the node stayed up while a payload confirmed against a locked seed"
    else
        fail "the node went down when a payload confirmed against a locked seed"
    fi

    LOCKED_INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
    GAP="$(jnum "$LOCKED_INFO" privacy_vnext_scan_gap_height)"
    NOTES_LOCKED="$(jnum "$LOCKED_INFO" privacy_vnext_note_count)"
    if is_int "$GAP" && [ "$GAP" -ge 0 ]; then
        success "the skipped block was recorded as a scan gap at height $GAP"
    else
        fail "a block went unscanned with no gap recorded (scan_gap_height=$GAP)"
    fi
    if [ "$NOTES_LOCKED" = "$NOTES_BEFORE" ]; then
        success "the note was not credited while the seed was locked ($NOTES_LOCKED)"
    else
        warn "note count moved while locked ($NOTES_BEFORE -> $NOTES_LOCKED)"
    fi

    rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
    RESCAN="$(rpc z_rescaniv5 2>&1)"
    NOTES_AFTER="$(jnum "$RESCAN" notes_after)"
    GAP_AFTER="$(jnum "$(rpc z_getshieldedinfo 2>/dev/null)" privacy_vnext_scan_gap_height)"
    if is_int "$NOTES_AFTER" && is_int "$NOTES_BEFORE" && \
       [ "$NOTES_AFTER" -gt "$NOTES_BEFORE" ]; then
        success "z_rescaniv5 recovered the missed note ($NOTES_BEFORE -> $NOTES_AFTER)"
    else
        fail "z_rescaniv5 did not recover the missed note: $(echo "$RESCAN" | head -3)"
    fi
    if [ "$GAP_AFTER" = "-1" ]; then
        success "the scan gap cleared once the blocks were reprocessed"
    else
        fail "the scan gap survived the rescan (scan_gap_height=$GAP_AFTER)"
    fi
fi

# ============================================================
header "12. The seed can be backed up and cannot be overwritten"
# ============================================================

EXPORT="$(rpc z_exportiv5seed 2>&1)"
SEEDHEX="$(jstr "$EXPORT" seed)"
if [ ${#SEEDHEX} -eq 64 ] && echo "$SEEDHEX" | grep -qE '^[0-9a-f]+$'; then
    success "z_exportiv5seed returned a 32-byte seed"
else
    fail "z_exportiv5seed did not return a seed: $(echo "$EXPORT" | head -2)"
fi

# Importing over a live seed would leave every note already recorded unspendable
# material under a seed that cannot derive it.
OVERWRITE="$(rpc z_importiv5seed "${SEEDHEX:-00}" 2>&1)"
if echo "$OVERWRITE" | grep -qi "already holds"; then
    success "importing over an existing seed is refused"
else
    fail "a seed import over a live seed was not refused: $(echo "$OVERWRITE" | head -2)"
fi

# ============================================================
header "13. An output owner already on chain cannot be issued again"
# ============================================================

# I = Hp(O): two leaves with one owner key share a key image, so spending one burns
# the other. Case: copy a confirmed shield's payload into a second transaction funded
# by other coins, re-issuing the same output owners.

# hex byte-order reversal, for the internal (little-endian) form of a txid
rev_hex() { echo "$1" | sed 's/../& /g' | awk '{for(i=NF;i>0;i--) printf "%s",$i}'; }
le32()    { printf '%08x' "$1" | sed 's/../& /g' | awk '{for(i=NF;i>0;i--) printf "%s",$i}'; }

rpc walletpassphrase "$WALLETPASS" 3600 >/dev/null 2>&1
mine_to $(( $(height) + 25 )) || true

# A small, self-contained shield: one address, one input, so the payload declares a
# balance a single fresh output can cover again.
VICTIM_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
rpc sendtoaddress "$VICTIM_ADDR" 40 >/dev/null 2>&1
mine_to $(( $(height) + 3 )) || true
SH="$(rpc z_shieldall "$VICTIM_ADDR" 1 2>&1)"
SH_TXID="$(jstr "$SH" txid)"
SH_AMOUNT="$(jnum "$SH" shielded)"
if [ ${#SH_TXID} -eq 64 ]; then
    success "single-input shield built: $SH_AMOUNT INN, txid ${SH_TXID:0:16}"
else
    fail "could not build the single-input shield: $(echo "$SH" | head -3)"
fi

REISSUE_DONE=0
if [ ${#SH_TXID} -eq 64 ]; then
    mine_to $(( $(height) + 3 )) || true
    SH_CONF="$(jnum "$(rpc gettransaction "$SH_TXID" 2>&1)" confirmations)"
    if [ -n "$SH_CONF" ] && [ "$SH_CONF" -ge 1 ] 2>/dev/null; then
        success "the shield whose owners will be re-issued is confirmed"
    else
        fail "the single-input shield did not confirm (confirmations='$SH_CONF')"
    fi

    # Fund the replay from a different address, with enough to cover the balance the
    # copied payload declares: short of it the transaction is refused for its value
    # rather than for the owner, which would prove nothing.
    ATTACK_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
    ATTACK_FUND="$(echo "${SH_AMOUNT:-0} + 5" | bc -l 2>/dev/null)"
    rpc sendtoaddress "$ATTACK_ADDR" "$ATTACK_FUND" >/dev/null 2>&1
    mine_to $(( $(height) + 3 )) || true
    UTXO="$(rpc listunspent 1 9999999 "[\"$ATTACK_ADDR\"]" 2>/dev/null)"
    FUND_TXID="$(echo "$UTXO" | grep -oE '"txid" *: *"[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}' | head -1)"
    FUND_VOUT="$(echo "$UTXO" | grep -oE '"vout" *: *[0-9]+' | grep -oE '[0-9]+$' | head -1)"

    SH_RAW="$(rpc getrawtransaction "$SH_TXID" 2>/dev/null | tr -d '"[:space:]')"
    # vout count 0, nLockTime 0, then the 0xff "IV5P" marker and schema 1.
    ENV_OFF="$(awk -v s="$SH_RAW" 'BEGIN{print index(s, "0000000000ff495635500100")}')"
    if [ -n "$FUND_TXID" ] && [ -n "$FUND_VOUT" ] && [ "${ENV_OFF:-0}" -gt 0 ] 2>/dev/null; then
        ENVELOPE="${SH_RAW:$(( ENV_OFF - 1 + 10 ))}"
        REISSUE_RAW="d8070000$(le32 "$(date +%s)")01$(rev_hex "$FUND_TXID")$(le32 "$FUND_VOUT")00ffffffff0000000000$ENVELOPE"
        SIGNED="$(rpc signrawtransaction "$REISSUE_RAW" 2>&1)"
        SIGNED_HEX="$(jstr "$SIGNED" hex)"
        COMPLETE="$(echo "$SIGNED" | grep -o '"complete" *: *[a-z]*' | grep -o '[a-z]*$')"
        if [ ${#SIGNED_HEX} -gt 100 ] && [ "$COMPLETE" = "true" ]; then
            success "a second transaction carrying the same payload was assembled and signed"
            REISSUE_DONE=1
        else
            fail "could not sign the re-issue transaction: $(echo "$SIGNED" | head -3)"
        fi
    else
        fail "could not locate the payload envelope or a funding output (offset=$ENV_OFF utxo=$FUND_TXID:$FUND_VOUT)"
    fi
fi

if [ "$REISSUE_DONE" = "1" ]; then
    # Decide on the chain, not on the submitting RPC's reply: the transaction id is
    # known before submission, so whether it reached a block is a direct question.
    EXPECT_TXID="$(python3 -c 'import hashlib,sys; b=bytes.fromhex(sys.argv[1]); print(hashlib.sha256(hashlib.sha256(b).digest()).digest()[::-1].hex())' "$SIGNED_HEX" 2>/dev/null)"
    # sendrawtransaction reports every rejection as a bare "TX rejected", so the reason
    # has to be read off the node. Anchor the search at the current end of the log.
    LOG_MARK="$(wc -l < "$NODE_DIR/regtest/debug.log" 2>/dev/null || echo 0)"
    rpc sendrawtransaction "$SIGNED_HEX" >/dev/null 2>&1
    # Either the transparent binding (input prevouts) or the owner rule may refuse it;
    # both are named refusals. A bare non-confirmation still fails.
    REASON="$(tail -n +$(( LOG_MARK + 1 )) "$NODE_DIR/regtest/debug.log" 2>/dev/null |
              grep -aE "IV5 output owner .* was already issued by|does not bind this transaction" | head -1)"
    mine_to $(( $(height) + 3 )) || true
    RCONF="$(jnum "$(rpc gettransaction "$EXPECT_TXID" 2>&1)" confirmations)"

    if [ -n "$RCONF" ] && [ "$RCONF" -ge 1 ] 2>/dev/null; then
        fail "consensus accepted a second issue of an on-chain output owner: txid ${EXPECT_TXID:0:16} confirmed $RCONF deep"
    elif [ -n "$REASON" ]; then
        success "the re-issue was refused by a named rule: ${REASON##*ERROR: }"
    else
        fail "the re-issue never confirmed, but no rule named it -- it may have been dropped for an unrelated reason"
        tail -n +$(( LOG_MARK + 1 )) "$NODE_DIR/regtest/debug.log" 2>/dev/null | tail -12
    fi
fi

# ============================================================
header "14. The node reports no errors"
# ============================================================

ERRORS="$(jstr "$(rpc getinfo 2>/dev/null)" errors)"
if [ -z "$ERRORS" ]; then
    success "getinfo reports no errors"
else
    fail "node reports errors: $ERRORS"
fi

if grep -qiE "IV5 pool balance|takes more from the pool|does not validate" \
        "$NODE_DIR/regtest/debug.log" 2>/dev/null; then
    fail "the log carries an IV5 pool or validation complaint"
    grep -iE "IV5 pool balance|takes more from the pool|does not validate" \
        "$NODE_DIR/regtest/debug.log" | tail -3
else
    success "no IV5 pool or validation complaints in the log"
fi

# ============================================================
header "Results"
# ============================================================
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
