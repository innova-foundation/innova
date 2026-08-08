#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Migrates a whole wallet into the pool: completion, remainder, residue, interruption.
# No transaction may spend from two addresses (section 7 is the positive control).

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${IV5_MIGRATE_TEST_DIR:-/tmp/innova_iv5_migration_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${IV5_MIGRATE_PORT:-29300}"
RPC="${IV5_MIGRATE_RPC:-29301}"
IDNS="${IV5_MIGRATE_IDNS:-29302}"
RPCUSER="iv5mig"
RPCPASS="iv5migpass"
WALLETPASS="iv5migwalletpass"

# Boundary B must not precede the schema-V3 epoch height (DAG fork + 300 = 311 on
# regtest); before it the epoch build carries no IV5 state.
BOUNDARY_B=311
FUND_HEIGHT=340
# One epoch has to complete before notes take a tree position and count as
# spendable pool balance, which is what the accounting section reads.
EPOCH_HEIGHT=630

# The flat shield fee, in satoshi. The two addresses funded either side of it are
# what make the fee test discriminate rather than merely pass.
SHIELD_FEE_SAT=100000
DUST_INN="0.0005"     # below the fee: can never be shielded
NEAR_INN="0.002"      # above it by a hair: must be shielded

# Transactions per call. Bounded work, several calls, so the loop is what finishes.
PER_CALL=10
# A run that will not terminate is the failure this bound exists to catch.
MAX_CALLS=60

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
# The per-transaction objects repeat some of the outer field names, so a total has
# to be read at the outer indentation or it picks up the first transaction's copy.
jtop()     { echo "$1" | grep -oE "^    \"$2\" *: *-?[0-9.]+" | grep -oE '\-?[0-9.]+$' | head -1; }
jstr()     { echo "$1" | sed -n "s/.*\"$2\" *: *\"\([^\"]*\)\".*/\1/p" | head -1; }
jbool()    { echo "$1" | grep -oE "\"$2\" *: *(true|false)" | grep -oE '(true|false)$' | head -1; }
is_int()   { echo "$1" | grep -qE '^[0-9]+$'; }
# Money arrives as a decimal string; compare in satoshi so no rounding creeps in.
to_sat()   { echo "${1:-0}" | awk '{printf "%.0f", $1 * 100000000}'; }

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    # Match the daemon's exact argv: a bare datadir match also catches the
    # short-lived rpc helpers, so the node would never look gone.
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

unlock() { rpc walletpassphrase "$WALLETPASS" 36000 >/dev/null 2>&1; }

mine_to() {
    local target="$1" h
    for _ in $(seq 1 150); do
        h="$(height)"
        is_int "$h" && [ "$h" -ge "$target" ] && return 0
        rpc setgenerate true $(( target - ${h:-0} )) >/dev/null 2>&1
        sleep 4
    done
    return 1
}

cleanup() {
    stop_node || true
    [ "${IV5_MIGRATE_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "IV5 whole-wallet migration regtest"

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
success "node started with Boundary B at $BOUNDARY_B"

# ============================================================
header "1. Boundary B is judged at the height the transaction would occupy"
# ============================================================

# The gate uses the inclusion height, not the tip: at tip B-1 the next block is the
# boundary and the transaction must be accepted.
mine_to $(( BOUNDARY_B - 2 )) || { fail "could not mine to $(( BOUNDARY_B - 2 ))"; exit 1; }
if rpc z_migratetopool 1 2>&1 | grep -qi "not active"; then
    success "at tip $(height) the next block is below the boundary and the call is refused"
else
    fail "the boundary gate did not refuse at tip $(height)"
fi

mine_to $(( BOUNDARY_B - 1 )) || { fail "could not mine to $(( BOUNDARY_B - 1 ))"; exit 1; }
AT_B="$(rpc z_migratetopool 1 2>&1)"
if echo "$AT_B" | grep -qi "not active"; then
    fail "at tip $(height) the next block is the boundary itself but the call was still refused: the gate is reading the tip"
elif echo "$AT_B" | grep -qi "IV5 seed"; then
    # Past the boundary gate, the missing seed is the next precondition in line,
    # which is also what proves that check runs before any transaction is built.
    success "at tip $(height) the gate passes and a wallet with no IV5 seed is refused"
else
    fail "unexpected reply one block below the boundary: $(echo "$AT_B" | head -2)"
fi

mine_to "$FUND_HEIGHT" || { fail "could not mine to $FUND_HEIGHT"; exit 1; }

# The seed is spend authority for every note the wallet will hold, so it is only
# created into an encrypted wallet. Encrypting stops the daemon.
rpc encryptwallet "$WALLETPASS" >/dev/null 2>&1
for _ in $(seq 1 60); do
    pgrep -f "datadir=$NODE_DIR" >/dev/null 2>&1 || break
    sleep 1
done
start_node || { fail "node did not restart after encrypting the wallet"; exit 1; }
unlock
if rpc z_createiv5seed 2>&1 | grep -q '"created"'; then
    success "IV5 seed created into the encrypted wallet"
else
    fail "z_createiv5seed failed"; exit 1
fi

# ============================================================
header "2. Preconditions are refused before any work is done"
# ============================================================

rpc walletlock >/dev/null 2>&1
LOCKED="$(rpc z_migratetopool 1 2>&1)"
if echo "$LOCKED" | grep -qiE "passphrase|locked|unlock"; then
    success "a locked wallet is refused"
else
    fail "a locked wallet was not refused: $(echo "$LOCKED" | head -2)"
fi
unlock

if rpc z_migratetopool 0 2>&1 | grep -qi "at least one"; then
    success "maxtransactions below one is refused"
else
    fail "maxtransactions=0 was not refused"
fi

if rpc z_migratetopool 100000 2>&1 | grep -qi "capped"; then
    success "an unbounded maxtransactions is refused, so one call stays bounded"
else
    fail "maxtransactions=100000 was not capped"
fi

# ============================================================
header "3. Fund several addresses with many outputs each"
# ============================================================

# All the mined coins sit at one address, which alone holds far more outputs than
# a single shield can carry: chunking is forced by the wallet's own shape and not
# only by what this section builds.
MINE_ADDR="$(rpc listunspent 1 9999999 2>/dev/null |
             grep -oE '"address" : "[a-zA-Z0-9]+"' | grep -oE '[a-zA-Z0-9]{25,}' | head -1)"
MINE_OUTPUTS="$(rpc listunspent 1 9999999 2>/dev/null | grep -c '"txid"')"
if [ -n "$MINE_ADDR" ] && is_int "$MINE_OUTPUTS" && [ "$MINE_OUTPUTS" -gt 50 ]; then
    success "the mining address holds $MINE_OUTPUTS outputs, more than one shield can carry"
else
    fail "unexpected starting wallet shape (address=$MINE_ADDR outputs=$MINE_OUTPUTS)"
    exit 1
fi

A_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
B_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
C_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
DUST_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
NEAR_ADDR="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"

# The wallet hands out keys from a pool the miner also draws on. If a funded
# address were the mining address, the sections below would be measuring one
# address while claiming to measure two.
DISTINCT="$(printf '%s\n' "$MINE_ADDR" "$A_ADDR" "$B_ADDR" "$C_ADDR" "$DUST_ADDR" "$NEAR_ADDR" | sort -u | wc -l | tr -d ' ')"
if [ "$DISTINCT" = "6" ]; then
    success "six distinct addresses to migrate from"
else
    fail "the funded addresses are not distinct from each other or from the mining address"
    exit 1
fi

log "funding A (60 outputs), B (12), C (5), dust $DUST_INN, near-fee $NEAR_INN"
for _ in $(seq 1 60); do rpc sendtoaddress "$A_ADDR" 1 >/dev/null 2>&1; done
for _ in $(seq 1 12); do rpc sendtoaddress "$B_ADDR" 2 >/dev/null 2>&1; done
for _ in $(seq 1 5);  do rpc sendtoaddress "$C_ADDR" 3 >/dev/null 2>&1; done
rpc sendtoaddress "$DUST_ADDR" "$DUST_INN" >/dev/null 2>&1
rpc sendtoaddress "$NEAR_ADDR" "$NEAR_INN" >/dev/null 2>&1
mine_to $(( $(height) + 3 )) || true

count_outputs() { rpc listunspent 1 9999999 "[\"$1\"]" 2>/dev/null | grep -c '"txid"'; }
value_at() {
    rpc listunspent 1 9999999 "[\"$1\"]" 2>/dev/null |
        grep -oE '"amount" : [0-9.]+' | grep -oE '[0-9.]+$' | paste -sd+ - | bc
}

A_N="$(count_outputs "$A_ADDR")"; B_N="$(count_outputs "$B_ADDR")"; C_N="$(count_outputs "$C_ADDR")"
D_V="$(value_at "$DUST_ADDR")";   N_V="$(value_at "$NEAR_ADDR")"
D_SAT="$(to_sat "$D_V")";         N_SAT="$(to_sat "$N_V")"

if [ "${A_N:-0}" -ge 51 ] && [ "${B_N:-0}" -ge 10 ] && [ "${C_N:-0}" -ge 4 ]; then
    success "funded A=$A_N B=$B_N C=$C_N outputs"
else
    fail "funding did not land as expected (A=$A_N B=$B_N C=$C_N)"; exit 1
fi

# The pair either side of the fee is what turns "the dust was skipped" from an
# observation into a discriminating test.
if [ "$D_SAT" -le "$SHIELD_FEE_SAT" ] && [ "$N_SAT" -gt "$SHIELD_FEE_SAT" ] 2>/dev/null; then
    success "one address at $D_V INN (under the fee) and one at $N_V INN (over it)"
else
    fail "the fee-boundary pair did not land (dust=$D_V near=$N_V fee=$SHIELD_FEE_SAT sat)"; exit 1
fi

# Every spendable satoshi here except the dust must end up in the pool. Coinbase
# outputs that mature later are not in this snapshot, and no block is mined again
# until the migration is over, so the set does not move underneath the run.
SNAP="$TEST_DIR/snapshot.json"
rpc listunspent 1 9999999 > "$SNAP" 2>/dev/null
SPENDABLE_SAT="$(grep -oE '"amount" : [0-9.]+' "$SNAP" | grep -oE '[0-9.]+$' |
                 awk '{s += $1} END {printf "%.0f", s * 100000000}')"
SPENDABLE_OUTPUTS="$(grep -c '"txid"' "$SNAP")"
SPENDABLE_ADDRS="$(grep -oE '"address" : "[a-zA-Z0-9]+"' "$SNAP" | sort -u | wc -l | tr -d ' ')"
log "starting point: $SPENDABLE_OUTPUTS outputs over $SPENDABLE_ADDRS addresses, $SPENDABLE_SAT sat"

# Outpoint -> address, read once off the snapshot. Every input the migration can
# possibly spend is in here, so resolving an input costs no further RPC and the
# per-shield check below stays affordable at several thousand inputs.
OUTPOINT_MAP="$TEST_DIR/outpoint_map"
grep -E '"(txid|vout|address)" *:' "$SNAP" |
    sed -e 's/.*"txid" *: *"\([a-f0-9]*\)".*/T \1/' \
        -e 's/.*"vout" *: *\([0-9]*\).*/V \1/' \
        -e 's/.*"address" *: *"\([^"]*\)".*/A \1/' |
    awk '$1=="T"{t=$2} $1=="V"{v=$2} $1=="A"{print t":"v, $2}' > "$OUTPOINT_MAP"
if [ "$(wc -l < "$OUTPOINT_MAP" | tr -d ' ')" = "$SPENDABLE_OUTPUTS" ]; then
    success "resolved all $SPENDABLE_OUTPUTS spendable outputs to their addresses"
else
    fail "outpoint map has $(wc -l < "$OUTPOINT_MAP") entries for $SPENDABLE_OUTPUTS outputs"; exit 1
fi

# ============================================================
header "4. A two-address transaction, built only as a control"
# ============================================================

# Assembled here, while coins from two addresses still exist, and never broadcast.
# It exists so section 6 can hand section 5's resolver a transaction that really
# does spend from two addresses and watch it say so.
pick_outpoint() { grep " $1\$" "$OUTPOINT_MAP" | head -1 | awk '{print $1}'; }
A_OP="$(pick_outpoint "$A_ADDR")"
B_OP="$(pick_outpoint "$B_ADDR")"
MIXED_HEX=""
if [ -n "$A_OP" ] && [ -n "$B_OP" ]; then
    SINK="$(rpc getnewaddress 2>&1 | tr -d '"[:space:]')"
    MIXED_HEX="$(rpc createrawtransaction \
        "[{\"txid\":\"${A_OP%%:*}\",\"vout\":${A_OP##*:}},{\"txid\":\"${B_OP%%:*}\",\"vout\":${B_OP##*:}}]" \
        "{\"$SINK\":2.5}" 2>&1 | tr -d '"[:space:]')"
fi
if [ ${#MIXED_HEX} -gt 100 ]; then
    success "assembled a two-address control transaction (never broadcast)"
else
    fail "could not assemble the control transaction"
fi

# ============================================================
header "5. Migrate the whole wallet in bounded calls"
# ============================================================

TX_ADDR_FILE="$TEST_DIR/migration_tx_addresses"   # "txid reported_address"
: > "$TX_ADDR_FILE"

record_call() {
    # Every transaction object gives its txid before its address, and the skipped
    # entries carry an address with no txid, so pairing on that order picks out the
    # transactions and nothing else.
    echo "$1" |
        sed -e 's/.*"txid" *: *"\([a-f0-9]*\)".*/T \1/' \
            -e 's/.*"address" *: *"\([^"]*\)".*/A \1/' |
        awk '$1 == "T" && NF == 2 { t = $2; next }
             $1 == "A" && NF == 2 && t != "" { print t, $2; t = "" }' >> "$TX_ADDR_FILE"
}

TOTAL_SENT=0
TOTAL_SHIELDED_SAT=0
TOTAL_FEES_SAT=0
CALLS=0
RESTARTED=0
LAST_OUT=""
FIRST_CALL_MEMPOOL=0
FIRST_CALL_SENT=0

while : ; do
    CALLS=$((CALLS + 1))
    if [ "$CALLS" -gt "$MAX_CALLS" ]; then
        fail "the migration did not terminate within $MAX_CALLS calls"
        break
    fi

    OUT="$(rpc z_migratetopool $PER_CALL 2>&1)"
    LAST_OUT="$OUT"
    SENT="$(jtop "$OUT" sent)"
    if ! is_int "$SENT"; then
        fail "z_migratetopool returned no usable result: $(echo "$OUT" | head -5)"
        break
    fi

    TOTAL_SENT=$(( TOTAL_SENT + SENT ))
    TOTAL_SHIELDED_SAT=$(( TOTAL_SHIELDED_SAT + $(to_sat "$(jtop "$OUT" shielded)") ))
    TOTAL_FEES_SAT=$(( TOTAL_FEES_SAT + $(to_sat "$(jtop "$OUT" fees)") ))
    record_call "$OUT"

    if [ "$CALLS" = "1" ]; then
        FIRST_CALL_SENT="$SENT"
        # Read before anything is mined and before the restart clears it.
        FIRST_CALL_MEMPOOL="$(rpc getrawmempool 2>/dev/null | grep -c '[a-f0-9]\{64\}')"
    fi

    [ "$(jbool "$OUT" more)" = "true" ] || break

    # Interrupt once, part way in. Nothing is written down between calls, so a
    # restart must cost nothing but the time to come back.
    if [ "$RESTARTED" = "0" ] && [ "$CALLS" -ge 2 ]; then
        MID_REMAINING="$(jtop "$OUT" outputs_remaining)"
        if stop_node && start_node; then
            unlock
            RESTARTED=1
            RESUME_OUT="$(rpc z_migratetopool 1 2>&1)"
            RESUME_SENT="$(jtop "$RESUME_OUT" sent)"
            RESUME_REMAINING="$(jtop "$RESUME_OUT" outputs_remaining)"
            if [ "${RESUME_SENT:-0}" -ge 1 ] 2>/dev/null; then
                success "migration resumed after a restart with no recovery step (sent $RESUME_SENT)"
            else
                fail "migration did not resume after a restart: $(echo "$RESUME_OUT" | head -5)"
            fi
            # Resuming must continue, not restart: the work left has to have shrunk
            # by what that call did, not reverted to what it was before the stop.
            if is_int "$MID_REMAINING" && is_int "$RESUME_REMAINING" && \
               [ "$RESUME_REMAINING" -lt "$MID_REMAINING" ]; then
                success "the restart lost no progress ($MID_REMAINING -> $RESUME_REMAINING outputs left)"
            else
                fail "progress did not carry across the restart ($MID_REMAINING -> $RESUME_REMAINING)"
            fi
            TOTAL_SENT=$(( TOTAL_SENT + ${RESUME_SENT:-0} ))
            TOTAL_SHIELDED_SAT=$(( TOTAL_SHIELDED_SAT + $(to_sat "$(jtop "$RESUME_OUT" shielded)") ))
            TOTAL_FEES_SAT=$(( TOTAL_FEES_SAT + $(to_sat "$(jtop "$RESUME_OUT" fees)") ))
            record_call "$RESUME_OUT"
        else
            fail "node did not come back for the resumability check"
        fi
    fi
done

RECORDED="$(wc -l < "$TX_ADDR_FILE" | tr -d ' ')"
if [ "$TOTAL_SENT" -gt 0 ] && [ "$RECORDED" = "$TOTAL_SENT" ]; then
    success "migration sent $TOTAL_SENT transaction(s) over $CALLS bounded call(s)"
else
    fail "sent count $TOTAL_SENT does not match the $RECORDED transactions reported"
fi

# Chunking has to be real, not just the one-transaction case.
CHUNKED="$(awk '{print $2}' "$TX_ADDR_FILE" | sort | uniq -c | sort -rn | head -1)"
CHUNKED_N="$(echo "$CHUNKED" | awk '{print $1}')"
CHUNKED_ADDR="$(echo "$CHUNKED" | awk '{print $2}')"
if is_int "$CHUNKED_N" && [ "$CHUNKED_N" -ge 2 ]; then
    success "one address needed $CHUNKED_N transactions (${CHUNKED_ADDR:0:12}): chunking was exercised"
else
    fail "no address needed more than one transaction; chunking was never exercised"
fi

# The chunks in the very first call were built back to back with no block between
# them. If a chunk had to wait for its predecessor to confirm, they could not all
# be sitting unconfirmed together.
if [ "${FIRST_CALL_SENT:-0}" -ge 2 ] && [ "${FIRST_CALL_MEMPOOL:-0}" -ge "$FIRST_CALL_SENT" ]; then
    success "$FIRST_CALL_SENT chunks from one call are unconfirmed together in the mempool"
else
    fail "chunks did not chain unconfirmed (sent=$FIRST_CALL_SENT mempool=$FIRST_CALL_MEMPOOL)"
fi

# ============================================================
header "6. No transaction spends from two addresses"
# ============================================================

# Outpoints spent by a transaction, from its verbose JSON. The range stops at the
# outputs array, so the "vout" index inside each input is not confused with it.
vin_outpoints() {
    echo "$1" | sed -n '/"vin"/,/"vout" *: *\[/p' |
        grep -E '"(txid|vout)" *:' |
        sed -e 's/.*"txid" *: *"\([a-f0-9]*\)".*/T \1/' \
            -e 's/.*"vout" *: *\([0-9]*\).*/V \1/' |
        awk '$1=="T"{t=$2} $1=="V" && t!=""{print t":"$2; t=""}'
}

PAIRS="$TEST_DIR/shield_inputs"      # "shield_txid outpoint"
: > "$PAIRS"
READ_FAIL=0
while read -r TXID ADDR; do
    [ ${#TXID} -eq 64 ] || continue
    VERBOSE="$(rpc getrawtransaction "$TXID" 1 2>/dev/null)"
    OPS="$(vin_outpoints "$VERBOSE")"
    if [ -z "$OPS" ]; then
        fail "could not read the inputs of shield ${TXID:0:16}"
        READ_FAIL=$((READ_FAIL + 1))
        continue
    fi
    echo "$OPS" | while read -r op; do echo "$TXID $op" >> "$PAIRS"; done
done < "$TX_ADDR_FILE"

TOTAL_INPUTS="$(wc -l < "$PAIRS" | tr -d ' ')"

# Every input must resolve, and every input of a transaction must resolve to the
# same address. An unresolvable input means the migration spent something outside
# the snapshot, which is itself a failure rather than something to skip over.
RESOLVED="$TEST_DIR/shield_input_addresses"
awk 'NR==FNR {m[$1] = $2; next}
     {print $1, ($2 in m ? m[$2] : "UNRESOLVED")}' "$OUTPOINT_MAP" "$PAIRS" > "$RESOLVED"

UNRESOLVED="$(grep -c 'UNRESOLVED$' "$RESOLVED")"
if [ "$UNRESOLVED" = "0" ]; then
    success "all $TOTAL_INPUTS shield inputs resolve to a known funding address"
else
    fail "$UNRESOLVED shield input(s) came from outside the snapshot"
fi

# Reuse of an outpoint across two shields would be a double spend that chaining
# without confirmations was supposed to make impossible.
DUP_INPUTS="$(awk '{print $2}' "$PAIRS" | sort | uniq -d | wc -l | tr -d ' ')"
if [ "$DUP_INPUTS" = "0" ]; then
    success "no outpoint was selected twice across $TOTAL_INPUTS inputs"
else
    fail "$DUP_INPUTS outpoint(s) were selected by two different shields"
fi

MIXED_FOUND=0
CHECKED=0
while read -r TXID ADDR; do
    [ ${#TXID} -eq 64 ] || continue
    N="$(awk -v t="$TXID" '$1 == t {print $2}' "$RESOLVED" | sort -u | wc -l | tr -d ' ')"
    SEEN="$(awk -v t="$TXID" '$1 == t {print $2}' "$RESOLVED" | sort -u | tr '\n' ' ')"
    CHECKED=$((CHECKED + 1))
    if [ "$N" != "1" ]; then
        fail "shield ${TXID:0:16} spends from $N addresses: $SEEN"
        MIXED_FOUND=$((MIXED_FOUND + 1))
    elif [ "$(echo "$SEEN" | tr -d ' ')" != "$ADDR" ]; then
        fail "shield ${TXID:0:16} spends $SEEN but was reported as $ADDR"
        MIXED_FOUND=$((MIXED_FOUND + 1))
    fi
done < "$TX_ADDR_FILE"

if [ "$CHECKED" -gt 0 ] && [ "$MIXED_FOUND" -eq 0 ] && [ "$READ_FAIL" -eq 0 ]; then
    success "all $CHECKED shields spend from exactly one address, the one reported"
elif [ "$CHECKED" -eq 0 ]; then
    fail "no shield could be checked for mixed inputs"
fi

# ============================================================
header "7. The one-address check can actually fail"
# ============================================================

if [ ${#MIXED_HEX} -gt 100 ]; then
    CTRL="$(rpc decoderawtransaction "$MIXED_HEX" 2>/dev/null)"
    CTRL_ADDRS="$(vin_outpoints "$CTRL" |
        awk 'NR==FNR {m[$1] = $2; next} {print ($1 in m ? m[$1] : "UNRESOLVED")}' "$OUTPOINT_MAP" - |
        sort -u)"
    CTRL_N="$(echo "$CTRL_ADDRS" | grep -c '[a-zA-Z0-9]')"
    if [ "$CTRL_N" = "2" ]; then
        success "the same resolver reports 2 addresses for a deliberately mixed transaction"
    else
        fail "the resolver saw $CTRL_N address(es) in a transaction built from two: it does not discriminate"
        echo "$CTRL_ADDRS"
    fi
else
    fail "no control transaction was built, so the one-address check is unproven"
fi

# ============================================================
header "8. The run terminates, and names what it could not move"
# ============================================================

FINAL_MORE="$(jbool "$LAST_OUT" more)"
FINAL_COMPLETE="$(jbool "$LAST_OUT" complete)"
FINAL_REMAINING="$(jtop "$LAST_OUT" addresses_remaining)"
FINAL_STUCK="$(jtop "$LAST_OUT" unsweepable_addresses)"

if [ "$CALLS" -le "$MAX_CALLS" ] && [ "$FINAL_MORE" = "false" ]; then
    success "the loop ended on more=false after $CALLS call(s), with a dust address present"
else
    fail "the loop did not end cleanly (calls=$CALLS more=$FINAL_MORE)"
fi

if [ "${FINAL_REMAINING:-1}" = "0" ]; then
    success "nothing sweepable is left: addresses_remaining=0"
else
    fail "the run stopped with $FINAL_REMAINING sweepable address(es) still to do"
fi

# "complete" must not be claimed while the dust is still sitting there: a caller
# that trusted it would believe the wallet was fully migrated.
if [ "$FINAL_COMPLETE" = "false" ] && [ "${FINAL_STUCK:-0}" -ge 1 ] 2>/dev/null; then
    success "finished-but-not-complete is reported distinctly ($FINAL_STUCK unsweepable address(es))"
else
    fail "the dust was not reported distinctly (complete=$FINAL_COMPLETE unsweepable=$FINAL_STUCK)"
fi

if echo "$LAST_OUT" | grep -q "$DUST_ADDR" && echo "$LAST_OUT" | grep -qi "does not cover"; then
    success "the dust address is named in the report, with the fee as its reason"
else
    fail "the dust address is not named with a reason in the final report"
    echo "$LAST_OUT" | tail -25
fi

# The discriminator. The two addresses differ only in sitting either side of the
# fee: if the near-fee one had also been skipped, "skipped the dust" would be
# saying nothing about value at all.
if grep -q " $NEAR_ADDR\$" "$TX_ADDR_FILE"; then
    success "the address just above the fee was swept, the one just below was not"
else
    fail "the address at $N_V INN was not swept, so the fee test does not discriminate"
fi

if grep -q " $DUST_ADDR\$" "$TX_ADDR_FILE"; then
    fail "the dust address was swept even though its value cannot cover the fee"
else
    success "no transaction was built for the address under the fee"
fi

# ============================================================
header "9. The value reached the pool"
# ============================================================

# Everything spendable at the snapshot had to end in the pool except the dust and
# the fees. The control transaction was never broadcast, so nothing left the
# wallet another way and the two figures must agree exactly.
EXPECT_MOVED_SAT=$(( SPENDABLE_SAT - D_SAT ))
ACCOUNTED_SAT=$(( TOTAL_SHIELDED_SAT + TOTAL_FEES_SAT ))
if [ "$ACCOUNTED_SAT" -eq "$EXPECT_MOVED_SAT" ]; then
    success "shielded + fees accounts for every spendable satoshi: $ACCOUNTED_SAT"
else
    fail "value went missing: shielded+fees=$ACCOUNTED_SAT expected=$EXPECT_MOVED_SAT (dust $D_SAT)"
fi

mine_to "$EPOCH_HEIGHT" || { fail "could not mine to $EPOCH_HEIGHT"; exit 1; }
unlock

UNCONFIRMED=0
while read -r TXID ADDR; do
    [ ${#TXID} -eq 64 ] || continue
    G="$(rpc gettransaction "$TXID" 2>&1)"
    C="$(jnum "$G" confirmations)"
    BH="$(jstr "$G" blockhash)"
    # confirmations reads 0 for a transaction still in the mempool, so the block
    # hash is what proves it was mined.
    if ! { [ -n "$C" ] && [ "$C" -ge 1 ] 2>/dev/null && [ ${#BH} -eq 64 ]; }; then
        UNCONFIRMED=$((UNCONFIRMED + 1))
    fi
done < "$TX_ADDR_FILE"
if [ "$UNCONFIRMED" -eq 0 ]; then
    success "all $TOTAL_SENT migration transactions reached a block"
else
    fail "$UNCONFIRMED migration transaction(s) never reached a block"
fi

INFO="$(rpc z_getshieldedinfo 2>/dev/null)"
POOL_SAT="$(to_sat "$(jnum "$INFO" privacy_vnext_balance)")"
PENDING_SAT="$(to_sat "$(jnum "$INFO" privacy_vnext_unconfirmed_balance)")"
NOTES="$(jnum "$INFO" privacy_vnext_note_count)"

if [ "$(( POOL_SAT + PENDING_SAT ))" -eq "$TOTAL_SHIELDED_SAT" ]; then
    success "the wallet holds exactly what it shielded: $TOTAL_SHIELDED_SAT sat"
else
    fail "pool holdings $(( POOL_SAT + PENDING_SAT )) sat do not match the $TOTAL_SHIELDED_SAT sat moved"
fi

if [ "$POOL_SAT" -eq "$TOTAL_SHIELDED_SAT" ]; then
    success "all of it is spendable pool balance after the epoch completed"
else
    fail "spendable pool balance is $POOL_SAT sat of $TOTAL_SHIELDED_SAT sat moved"
fi

# Every shield writes two notes. A shortfall is value that reached the tree but
# never reached its owner, which is unspendable value however the balance reads.
if [ "${NOTES:-0}" -eq "$(( TOTAL_SENT * 2 ))" ] 2>/dev/null; then
    success "the wallet detected all $NOTES notes, two for each of $TOTAL_SENT shields"
else
    fail "note count is $NOTES, expected $(( TOTAL_SENT * 2 ))"
fi

TRANSPARENT_LEFT="$(rpc z_migratetopool 1 2>&1)"
if [ "$(jtop "$TRANSPARENT_LEFT" unsweepable_outputs)" -ge 1 ] 2>/dev/null; then
    success "the dust output is still there and still reported, not quietly dropped"
else
    fail "the dust output stopped being reported"
fi

# ============================================================
header "10. The node reports no errors"
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
