#!/bin/bash
# Focused FCMP spendability regression for z_send privacy modes.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${FCMP_MODES_TEST_DIR:-/tmp/innova_fcmp_modes_$$}"
BASE_PORT="${FCMP_MODES_BASE_PORT:-28640}"
BASE_RPC="${FCMP_MODES_BASE_RPC:-29640}"
BASE_IDNS="${FCMP_MODES_BASE_IDNS:-8660}"
NUM_NODES=3
FUNDING_HEIGHT=9
RPCUSER="${FCMP_MODES_RPCUSER:-fcmpmodes}"
RPCPASS="${FCMP_MODES_RPCPASS:-fcmpmodespass}"

PASSED=0
FAILED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

node_dir() { echo "$TEST_DIR/node$1"; }
node_port() { echo $((BASE_PORT + $1)); }
node_rpc() { echo $((BASE_RPC + $1)); }
node_idns() { echo $((BASE_IDNS + $1)); }

rpc() {
    local node="$1"
    shift
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest \
        -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$(node_rpc "$node")" "$@" 2>&1
}

height() {
    rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'
}

is_int() {
    echo "$1" | grep -qE '^[0-9]+$'
}

wait_rpc() {
    local node="$1"
    local attempt
    for ((attempt=0; attempt<60; attempt++)); do
        rpc "$node" getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

wait_rpc_down() {
    local node="$1"
    local attempt
    for ((attempt=0; attempt<45; attempt++)); do
        if ! rpc "$node" getinfo >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

peer_count() {
    rpc "$1" getpeerinfo 2>/dev/null | python3 -c '
import json
import sys
try:
    peers = json.load(sys.stdin)
    print(len(peers) if isinstance(peers, list) else 0)
except Exception:
    print(0)
'
}

wait_peer_count() {
    local node="$1"
    local target="$2"
    local attempt count
    for ((attempt=0; attempt<45; attempt++)); do
        count="$(peer_count "$node")"
        if is_int "$count" && [ "$count" -ge "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

connect_mesh() {
    local node peer
    for ((node=0; node<NUM_NODES; node++)); do
        for ((peer=0; peer<NUM_NODES; peer++)); do
            [ "$node" -eq "$peer" ] && continue
            [ "$node" -gt "$peer" ] && continue
            rpc "$node" addnode "127.0.0.1:$(node_port "$peer")" onetry >/dev/null 2>&1 || true
        done
    done
}

wait_all_height() {
    local target="$1"
    local attempt node h ready
    for ((attempt=0; attempt<90; attempt++)); do
        ready=1
        for ((node=0; node<NUM_NODES; node++)); do
            h="$(height "$node")"
            if ! is_int "$h" || [ "$h" -lt "$target" ]; then
                ready=0
                break
            fi
        done
        [ "$ready" -eq 1 ] && return 0
        sleep 1
    done
    return 1
}

mine_one() {
    local node="$1"
    local before after attempt
    before="$(height "$node")"
    is_int "$before" || return 1

    rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1
    for ((attempt=0; attempt<180; attempt++)); do
        after="$(height "$node")"
        if is_int "$after" && [ "$after" -gt "$before" ]; then
            rpc "$node" setgenerate false 0 >/dev/null 2>&1 || true
            wait_all_height "$after" || return 1
            return 0
        fi
        sleep 0.25
    done
    rpc "$node" setgenerate false 0 >/dev/null 2>&1 || true
    return 1
}

mine_until_height_synced() {
    local node="$1"
    local target="$2"
    local h
    h="$(height "$node")"
    is_int "$h" || return 1
    while [ "$h" -lt "$target" ]; do
        mine_one "$node" || return 1
        h="$(height "$node")"
        is_int "$h" || return 1
        if [ $((h % 5)) -eq 0 ] || [ "$h" -eq "$target" ]; then
            log "  ...height $h/$target"
        fi
    done
}

write_config() {
    local node="$1"
    local dir
    dir="$(node_dir "$node")"
    mkdir -p "$dir"
    {
        echo "regtest=1"
        echo "server=1"
        echo "rpcuser=$RPCUSER"
        echo "rpcpassword=$RPCPASS"
        echo "rpcport=$(node_rpc "$node")"
        echo "port=$(node_port "$node")"
        echo "bind=127.0.0.1"
        echo "listen=1"
        echo "dnsseed=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "idnsport=$(node_idns "$node")"
        echo "debug=1"
        echo "staking=0"
        echo "nofinalityvoting=1"
        echo "getdatablockbatch=128"
        echo "maxconnections=32"
    } > "$dir/innova.conf"
}

start_node() {
    local node="$1"
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -daemon \
        -pid="$(node_dir "$node")/fcmp_modes.pid" >/dev/null 2>&1
}

z_spendable_balance() {
    local node="$1"
    local zaddr="$2"
    local notes
    notes="$(rpc "$node" z_listunspent 2>/dev/null)"
    NOTES="$notes" ZADDR="$zaddr" python3 - <<'PY'
import json
import os
from decimal import Decimal

try:
    notes = json.loads(os.environ.get("NOTES", "[]"))
except Exception:
    print("0")
    raise SystemExit

total = Decimal("0")
for note in notes:
    if note.get("address") == os.environ.get("ZADDR") and note.get("spendable") is True:
        total += Decimal(str(note.get("amount", "0")))
print(total)
PY
}

amount_ge() {
    python3 - "$1" "$2" <<'PY'
import sys
from decimal import Decimal

raise SystemExit(0 if Decimal(sys.argv[1]) >= Decimal(sys.argv[2]) else 1)
PY
}

wait_sources_spendable() {
    local max_blocks="${1:-80}"
    local mined=0
    local mode spendable ready current

    while [ "$mined" -le "$max_blocks" ]; do
        ready=1
        for mode in $MODE_LIST; do
            spendable="$(z_spendable_balance "${NODES[$mode]}" "${SOURCES[$mode]}")"
            if ! amount_ge "$spendable" "$NOTE_AMOUNT"; then
                ready=0
                break
            fi
        done

        if [ "$ready" -eq 1 ]; then
            return 0
        fi

        if [ $((mined % 5)) -eq 0 ]; then
            current="$(height 0)"
            log "  ...waiting for FCMP spendability at height ${current:-unknown}; mode $mode spendable=$spendable"
        fi

        mine_one 0 || return 1
        mined=$((mined + 1))
    done

    return 1
}

mempool_count() {
    rpc "$1" getrawmempool 2>/dev/null | python3 -c '
import json
import sys
try:
    pool = json.load(sys.stdin)
    print(len(pool) if isinstance(pool, list) else 0)
except Exception:
    print(-1)
'
}

extract_txid() {
    TX_JSON="$1" python3 - <<'PY'
import json
import os

try:
    print(json.loads(os.environ["TX_JSON"])["txid"])
except Exception:
    raise SystemExit(1)
PY
}

assert_mode_privacy_shape() {
    local mode="$1"
    local decoded="$2"

    MODE="$mode" TX_JSON="$decoded" python3 - <<'PY'
import json
import os
import sys

mode = int(os.environ["MODE"])
tx = json.loads(os.environ["TX_JSON"])

hide_sender = bool(mode & 1)
hide_receiver = bool(mode & 2)
hide_amount = bool(mode & 4)

def fail(msg):
    print(msg)
    raise SystemExit(1)

if tx.get("privacy_mode") != mode:
    fail(f"privacy_mode mismatch: got {tx.get('privacy_mode')} expected {mode}")
if bool(tx.get("hide_sender")) != hide_sender:
    fail("hide_sender bit mismatch")
if bool(tx.get("hide_receiver")) != hide_receiver:
    fail("hide_receiver bit mismatch")
if bool(tx.get("hide_amount")) != hide_amount:
    fail("hide_amount bit mismatch")

spends = tx.get("shielded_spends") or []
outputs = tx.get("shielded_outputs") or []
if not spends:
    fail("missing shielded spend")
if not outputs:
    fail("missing shielded output")

for idx, spend in enumerate(spends):
    if int(spend.get("fcmp_proof_size", 0)) <= 0:
        fail(f"spend {idx} missing FCMP proof")

    lelantus_size = int(spend.get("lelantus_proof_size", 0))
    anonset_size = int(spend.get("anonset_size", 0))
    if hide_sender:
        if lelantus_size <= 0 or anonset_size <= 0:
            fail(f"spend {idx} missing sender-hiding proof")
    else:
        if lelantus_size != 0 or anonset_size != 0:
            fail(f"spend {idx} leaks sender-hiding proof in public-sender mode")

    plaintext_value = spend.get("plaintext_value")
    blind_size = int(spend.get("plaintext_blind_size", 0))
    range_size = int(spend.get("range_proof_size", 0))
    if hide_amount:
        if plaintext_value != -1 or blind_size != 0 or range_size <= 0:
            fail(f"spend {idx} does not hide amount")
    else:
        if plaintext_value == -1 or blind_size != 32 or range_size != 0:
            fail(f"spend {idx} does not expose public amount opening")

recipient_markers = 0
for idx, output in enumerate(outputs):
    plaintext_value = output.get("plaintext_value")
    blind_size = int(output.get("plaintext_blind_size", 0))
    range_size = int(output.get("range_proof_size", 0))
    enc_size = int(output.get("enc_ciphertext_size", 0))
    out_size = int(output.get("out_ciphertext_size", 0))
    recipient_size = int(output.get("recipient_script_size", 0))

    if enc_size <= 0 or out_size <= 0:
        fail(f"output {idx} missing encrypted note payload")

    if hide_amount:
        if plaintext_value != -1 or blind_size != 0 or range_size <= 0:
            fail(f"output {idx} does not hide amount")
    else:
        if plaintext_value == -1 or blind_size != 32 or range_size != 0:
            fail(f"output {idx} does not expose public amount opening")

    if hide_receiver and recipient_size != 0:
        fail(f"output {idx} has public recipient marker in hidden-receiver mode")
    if recipient_size > 0:
        recipient_markers += 1

if not hide_receiver and recipient_markers == 0:
    fail("public-receiver mode has no public recipient marker")

print("ok")
PY
}

cleanup() {
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        rpc "$node" stop >/dev/null 2>&1 || true
    done
    for ((node=0; node<NUM_NODES; node++)); do
        wait_rpc_down "$node" >/dev/null 2>&1 || true
    done
    pkill -f "innovad.*${TEST_DIR}" 2>/dev/null || true
    if [ "$FAILED" -gt 0 ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

NULLSEND_SMOKE=0
if [ "${1:-}" = "--nullsend-smoke" ]; then
    NULLSEND_SMOKE=1
fi

MODE_LIST="0 1 2 3 4 5 6 7"
if [ "$NULLSEND_SMOKE" -eq 1 ]; then
    MODE_LIST="7"
fi
NOTE_AMOUNT="3.0"

if [ "$NULLSEND_SMOKE" -eq 1 ]; then
    header "FCMP z_nullsend Smoke"
else
    header "FCMP z_send Modes 0..7"
fi

if [ ! -x "$INNOVAD" ]; then
    fail "innovad not found at $INNOVAD"
    exit 1
fi

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

for ((node=0; node<NUM_NODES; node++)); do
    write_config "$node"
done

for ((node=0; node<NUM_NODES; node++)); do
    start_node "$node"
    sleep 1
done

for ((node=0; node<NUM_NODES; node++)); do
    if wait_rpc "$node"; then
        success "node$node RPC ready"
    else
        fail "node$node RPC did not become ready"
        exit 1
    fi
done

connect_mesh
for ((node=0; node<NUM_NODES; node++)); do
    if wait_peer_count "$node" 2; then
        success "node$node connected to peers"
    else
        fail "node$node did not connect to peers"
        exit 1
    fi
done

log "Mining spendable funding"
mine_until_height_synced 0 "$FUNDING_HEIGHT" || { fail "funding mining failed"; exit 1; }

SOURCES=()
DESTS=()
NODES=()
TXIDS=()

log "Creating one epoch-0 shielded note per mode"
for mode in $MODE_LIST; do
    node=0
    NODES[$mode]="$node"
    SOURCES[$mode]="$(rpc "$node" z_getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    DESTS[$mode]="$(rpc "$node" z_getnewaddress 2>/dev/null | tr -d '"[:space:]')"
    if [ -z "${SOURCES[$mode]}" ] || [ -z "${DESTS[$mode]}" ]; then
        fail "mode $mode address creation failed"
        exit 1
    fi

    shield="$(rpc "$node" z_shield "*" "$NOTE_AMOUNT" "${SOURCES[$mode]}" 2>&1)"
    if echo "$shield" | grep -q '"txid"'; then
        success "mode $mode source note shield tx accepted"
    else
        fail "mode $mode z_shield failed: $shield"
        exit 1
    fi
done

mine_one 0 || { fail "failed to confirm shielded notes"; exit 1; }
success "shielded notes confirmed"

log "Mining to epoch-root FCMP boundary and spend depth"
wait_sources_spendable 80 || { fail "source notes did not become FCMP-spendable"; exit 1; }

for mode in $MODE_LIST; do
    spendable="$(z_spendable_balance "${NODES[$mode]}" "${SOURCES[$mode]}")"
    if amount_ge "$spendable" "$NOTE_AMOUNT"; then
        success "mode $mode source note is FCMP-spendable"
    else
        fail "mode $mode source note is not FCMP-spendable: spendable=$spendable"
        exit 1
    fi
done

if [ "$NULLSEND_SMOKE" -eq 1 ]; then
    mode=7
    tx="$(rpc "${NODES[$mode]}" z_nullsend "${SOURCES[$mode]}" 1.0 "$mode" 2 30 2>&1)"
    if echo "$tx" | grep -q "commitment not found in curve tree"; then
        fail "z_nullsend hit old curve-tree commitment error: $tx"
        exit 1
    fi
    if echo "$tx" | grep -q '"txid"'; then
        txid="$(extract_txid "$tx")" || { fail "z_nullsend txid extraction failed: $tx"; exit 1; }
        success "z_nullsend mode 7 accepted"
    else
        fail "z_nullsend mode 7 failed: $tx"
        exit 1
    fi

    mine_one 0 || { fail "failed to mine z_nullsend mode 7"; exit 1; }

    conf="$(rpc "${NODES[$mode]}" gettransaction "$txid" 2>/dev/null | python3 -c 'import json,sys
try:
    print(int(json.load(sys.stdin).get("confirmations", 0)))
except Exception:
    print(-1)' 2>/dev/null)"
    if is_int "$conf" && [ "$conf" -ge 1 ]; then
        success "z_nullsend mode 7 confirmed in block (confirmations=$conf)"
    else
        fail "z_nullsend tx did not confirm after mining (confirmations=$conf): rejected by mempool/consensus"
        exit 1
    fi

    raw="$(rpc "${NODES[$mode]}" getrawtransaction "$txid" 1 2>&1)"
    if ! echo "$raw" | grep -q '"privacy_mode"'; then
        raw="$(rpc "${NODES[$mode]}" gettransaction "$txid" 2>&1)"
    fi
    if echo "$raw" | grep -q '"privacy_mode"'; then
        privacy_check="$(assert_mode_privacy_shape "$mode" "$raw" 2>&1)"
        if [ "$privacy_check" = "ok" ]; then
            success "z_nullsend mode 7 privacy fields match mode bits"
        else
            fail "z_nullsend mode 7 privacy field assertion failed: $privacy_check"
            exit 1
        fi
    else
        fail "z_nullsend mode 7 raw decode missing shielded privacy fields: $raw"
        exit 1
    fi

    POOL_TOTAL=0
    for ((node=0; node<NUM_NODES; node++)); do
        count="$(mempool_count "$node")"
        if ! is_int "$count"; then
            fail "node$node mempool query failed"
            exit 1
        fi
        POOL_TOTAL=$((POOL_TOTAL + count))
    done

    if [ "$POOL_TOTAL" -eq 0 ]; then
        success "z_nullsend mode 7 mined and mempools are empty"
    else
        fail "mempools not empty after mining z_nullsend: aggregate=$POOL_TOTAL"
    fi

    header "Summary"
    echo "Passed: $PASSED"
    echo "Failed: $FAILED"

    if [ "$FAILED" -eq 0 ]; then
        success "FCMP z_nullsend smoke regression passed"
        exit 0
    fi

    exit 1
fi

for mode in $MODE_LIST; do
    tx="$(rpc "${NODES[$mode]}" z_send "${SOURCES[$mode]}" "${DESTS[$mode]}" 1.0 "$mode" 2>&1)"
    if echo "$tx" | grep -q "commitment not found in curve tree"; then
        fail "mode $mode hit old curve-tree commitment error: $tx"
        exit 1
    fi
    if echo "$tx" | grep -q '"txid"'; then
        txid="$(extract_txid "$tx")" || { fail "mode $mode txid extraction failed: $tx"; exit 1; }
        TXIDS[$mode]="$txid"
        success "z_send mode $mode accepted"
    else
        fail "z_send mode $mode failed: $tx"
        exit 1
    fi

    raw="$(rpc "${NODES[$mode]}" gettransaction "${TXIDS[$mode]}" 2>&1)"
    if echo "$raw" | grep -q '"privacy_mode"'; then
        privacy_check="$(assert_mode_privacy_shape "$mode" "$raw" 2>&1)"
        if [ "$privacy_check" = "ok" ]; then
            success "z_send mode $mode privacy fields match mode bits"
        else
            fail "z_send mode $mode privacy field assertion failed: $privacy_check"
            exit 1
        fi
    else
        fail "z_send mode $mode raw decode missing shielded privacy fields: $raw"
        exit 1
    fi
done

mine_one 0 || { fail "failed to mine z_send modes"; exit 1; }

POOL_TOTAL=0
for ((node=0; node<NUM_NODES; node++)); do
    count="$(mempool_count "$node")"
    if ! is_int "$count"; then
        fail "node$node mempool query failed"
        exit 1
    fi
    POOL_TOTAL=$((POOL_TOTAL + count))
done

if [ "$POOL_TOTAL" -eq 0 ]; then
    success "all z_send mode transactions mined and mempools are empty"
else
    fail "mempools not empty after mining z_send modes: aggregate=$POOL_TOTAL"
fi

header "Summary"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ "$FAILED" -eq 0 ]; then
    success "FCMP z_send modes 0..7 regression passed"
    exit 0
fi

exit 1
