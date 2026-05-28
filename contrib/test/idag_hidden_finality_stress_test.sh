#!/bin/bash
# IDAG hidden-finality stress coverage
# Exercises the post-DAG PoW boundary, epoch-root persistence, and public
# hidden-finality RPC gates on a local regtest cluster.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="$INNOVA_ROOT/src/innovad"

TEST_DIR="${IDAG_HIDDEN_TEST_DIR:-/tmp/innova_hidden_finality_clean_$$}"
NUM_NODES="${IDAG_HIDDEN_NODES:-3}"
TARGET_BLOCKS="${IDAG_HIDDEN_BLOCKS:-60}"
KEEP_DIR="${IDAG_HIDDEN_KEEP_DIR:-0}"
PORT_OFFSET="${IDAG_HIDDEN_PORT_OFFSET:-0}"
BASE_PORT="${IDAG_HIDDEN_BASE_PORT:-18122}"
BASE_RPC="${IDAG_HIDDEN_BASE_RPC:-19172}"
BASE_IDNS="${IDAG_HIDDEN_BASE_IDNS:-8342}"
RPCUSER="hiddenfinality"
RPCPASS="stresspass"

PASSED=0
FAILED=0
SKIPPED=0

log()     { echo -e "${BLUE}[TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
skip()    { echo -e "${CYAN}[SKIP]${NC} $1"; ((SKIPPED++)) || true; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

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

json_field() {
    local json="$1"
    local field="$2"
    FIELD="$field" python3 -c '
import json
import os
import sys
try:
    value = json.load(sys.stdin).get(os.environ["FIELD"], "")
    if isinstance(value, bool):
        print(str(value).lower())
    elif value is None:
        print("")
    else:
        print(value)
except Exception:
    pass
' <<< "$json" 2>/dev/null
}

get_height() {
    rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'
}

get_block_json() {
    local node="$1"
    local height="$2"
    local hash
    hash=$(rpc "$node" getblockhash "$height" 2>/dev/null | tr -d '"[:space:]')
    [ -n "$hash" ] || return 1
    rpc "$node" getblock "$hash" 2>/dev/null
}

mine_blocks() {
    local node="$1"
    local count="$2"
    local idx
    for ((idx=0; idx<count; idx++)); do
        rpc "$node" setgenerate true 1 >/dev/null 2>&1 || return 1
        sleep 0.15
    done
    return 0
}

wait_for_height() {
    local node="$1"
    local target="$2"
    local attempt
    local height
    for ((attempt=0; attempt<80; attempt++)); do
        height=$(get_height "$node")
        if [ -n "$height" ] && [ "$height" -ge "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_rpc_down() {
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

cleanup() {
    local node
    for ((node=0; node<NUM_NODES; node++)); do
        rpc "$node" stop >/dev/null 2>&1 || true
    done
    pkill -f "innovad.*${TEST_DIR}" 2>/dev/null || true
    sleep 2
    if [ "$KEEP_DIR" = "1" ]; then
        log "Preserving $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

start_node() {
    local node="$1"
    "$INNOVAD" -datadir="$(node_dir "$node")" -regtest -daemon \
        -pid="$(node_dir "$node")/hidden_finality.pid" >/dev/null 2>&1
}

setup_nodes() {
    cleanup
    mkdir -p "$TEST_DIR"

    local node
    local peer
    local attempt
    for ((node=0; node<NUM_NODES; node++)); do
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
            echo "listen=1"
            echo "dnsseed=0"
            echo "idnsport=$(node_idns "$node")"
            echo "debug=1"
            echo "staking=1"
            echo "nofinalityvoting=0"
            echo "finalityvotemode=auto"
            for ((peer=0; peer<NUM_NODES; peer++)); do
                [ "$node" -eq "$peer" ] && continue
                echo "addnode=127.0.0.1:$(node_port "$peer")"
            done
        } > "$dir/innova.conf"
    done

    log "Starting $NUM_NODES local nodes"
    for ((node=0; node<NUM_NODES; node++)); do
        start_node "$node"
        sleep 1
    done

    for ((attempt=0; attempt<60; attempt++)); do
        local ready=1
        for ((node=0; node<NUM_NODES; node++)); do
            rpc "$node" getinfo >/dev/null 2>&1 || ready=0
        done
        [ "$ready" -eq 1 ] && return 0
        sleep 1
    done

    fail "nodes failed to start"
    return 1
}

restart_node_zero() {
    rpc 0 stop >/dev/null 2>&1 || true
    wait_for_rpc_down 0 || return 1
    sleep 2
    start_node 0
    local attempt
    for ((attempt=0; attempt<60; attempt++)); do
        rpc 0 getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

trap cleanup EXIT

header "IDAG Hidden Finality Stress"

if [ ! -x "$INNOVAD" ]; then
    fail "innovad not found at $INNOVAD"
    exit 1
fi

setup_nodes || exit 1

header "Mine Through IDAG Activation"

log "Mining $TARGET_BLOCKS blocks on node0"
mine_blocks 0 "$TARGET_BLOCKS" || fail "mining failed"
node=0
for ((node=0; node<NUM_NODES; node++)); do
    if wait_for_height "$node" "$TARGET_BLOCKS"; then
        success "node$node synced to height >= $TARGET_BLOCKS"
    else
        fail "node$node did not sync to height $TARGET_BLOCKS"
    fi
done

DAGINFO=$(rpc 0 getdaginfo 2>/dev/null)
DAG_ACTIVE=$(json_field "$DAGINFO" "dag_active")
DK_ACTIVE=$(json_field "$DAGINFO" "dagknight_active")
DAG_PRODUCER=$(json_field "$DAGINFO" "dag_block_producer")
POS_PRODUCTION=$(json_field "$DAGINFO" "pos_block_production")

[ "$DAG_ACTIVE" = "true" ] && success "DAG active" || fail "DAG not active"
[ "$DK_ACTIVE" = "true" ] && success "DAGKNIGHT active" || fail "DAGKNIGHT not active"
[ "$DAG_PRODUCER" = "pow" ] && success "DAG producer is PoW" || fail "unexpected DAG producer: $DAG_PRODUCER"
[ "$POS_PRODUCTION" = "false" ] && success "PoS block production disabled" || fail "PoS production still enabled"

header "Finality And Hidden-Weight Gates"

FININFO=$(rpc 0 getfinalityinfo 2>/dev/null)
FORK_ACTIVE=$(json_field "$FININFO" "fork_active")
MODEL=$(json_field "$FININFO" "finality_model")
ABS_FLOOR=$(json_field "$FININFO" "absolute_stake_floor")
PRIVATE_MODE=$(json_field "$FININFO" "private_finality_mode")
TALLY_REQUIRED=$(json_field "$FININFO" "tally_certificate_required_for_private_votes")
PRIVATE_PROMOTION=$(json_field "$FININFO" "private_promotion_enabled")
TALLY_THRESHOLD_VALID=$(json_field "$FININFO" "tally_threshold_valid")
TALLY_CERT_PRODUCTION=$(json_field "$FININFO" "tally_certificate_production_enabled")
PRIVATE_VOTES=$(json_field "$FININFO" "private_votes")

[ "$FORK_ACTIVE" = "true" ] && success "finality fork active" || fail "finality fork inactive"
[ "$MODEL" = "active-epoch-committed-weight" ] && success "dynamic finality model reported" || fail "unexpected finality model: $MODEL"
[ "$ABS_FLOOR" = "false" ] && success "absolute stake floor disabled" || fail "absolute stake floor not disabled"
[ "$PRIVATE_MODE" = "hidden-weight-nullstake" ] && success "hidden finality mode reported" || fail "unexpected private finality mode: $PRIVATE_MODE"
[ "$TALLY_REQUIRED" = "true" ] && success "private votes require tally certificates" || fail "private tally gate not reported"
[ "$PRIVATE_PROMOTION" = "false" ] && success "private promotion disabled without committee config" || fail "private promotion unexpectedly enabled"
[ "$TALLY_THRESHOLD_VALID" = "false" ] && success "missing tally threshold reported invalid" || fail "missing tally threshold not reported invalid"
[ "$TALLY_CERT_PRODUCTION" = "false" ] && success "tally cert production disabled without committee keys" || fail "tally cert production unexpectedly enabled"
[ -n "$PRIVATE_VOTES" ] && success "private vote counter exposed" || fail "private vote counter missing"

FSTAKING=$(rpc 0 getfinalitystakinginfo 2>/dev/null)
F_ENABLED=$(json_field "$FSTAKING" "enabled")
F_DAG=$(json_field "$FSTAKING" "dag_active")
F_POS=$(json_field "$FSTAKING" "pos_block_production")
F_TALLY=$(json_field "$FSTAKING" "tally_certificate_required_for_private_votes")
F_PROMOTION=$(json_field "$FSTAKING" "private_promotion_enabled")

[ "$F_ENABLED" = "true" ] && success "finality voter enabled" || fail "finality voter disabled"
[ "$F_DAG" = "true" ] && success "finality staking sees DAG" || fail "finality staking does not see DAG"
[ "$F_POS" = "false" ] && success "finality staking reports no PoS blocks" || fail "finality staking reports PoS production"
[ "$F_TALLY" = "true" ] && success "finality staking reports private tally gate" || fail "finality staking missing private tally gate"
[ "$F_PROMOTION" = "false" ] && success "finality staking blocks private promotion without tally config" || fail "finality staking unexpectedly enables private promotion"

BAD_SHARE=$(rpc 0 submitfinalitytallyshare 00 2>/dev/null || true)
echo "$BAD_SHARE" | grep -qi "tally share" && success "malformed manual tally share rejected" || fail "malformed tally share was not rejected as expected"

header "Epoch Roots And Restart Persistence"

EPOCH0=$(rpc 0 getepochinfo 0 2>/dev/null)
CURVE_ROOT=$(json_field "$EPOCH0" "curve_root")
NULLIFIER_ROOT=$(json_field "$EPOCH0" "nullifier_root")
ZERO_ROOT="0000000000000000000000000000000000000000000000000000000000000000"

if [ -n "$CURVE_ROOT" ]; then
    if [ "$CURVE_ROOT" = "$ZERO_ROOT" ]; then
        warn "epoch 0 curve root is empty because no shielded outputs were created"
    fi
    success "epoch 0 curve root field available"
else
    fail "epoch 0 curve root field missing"
fi

if [ -n "$NULLIFIER_ROOT" ] && [ "$NULLIFIER_ROOT" != "$ZERO_ROOT" ]; then
    success "epoch 0 nullifier root available"
else
    fail "epoch 0 nullifier root missing"
fi

if restart_node_zero; then
    success "node0 restarted"
else
    fail "node0 restart failed"
fi

EPOCH0_AFTER=$(rpc 0 getepochinfo 0 2>/dev/null)
CURVE_ROOT_AFTER=$(json_field "$EPOCH0_AFTER" "curve_root")
NULLIFIER_ROOT_AFTER=$(json_field "$EPOCH0_AFTER" "nullifier_root")

[ "$CURVE_ROOT_AFTER" = "$CURVE_ROOT" ] && success "epoch curve root persisted across restart" || fail "epoch curve root changed after restart"
[ "$NULLIFIER_ROOT_AFTER" = "$NULLIFIER_ROOT" ] && success "epoch nullifier root persisted across restart" || fail "epoch nullifier root changed after restart"

header "Post-DAG Block Producer Boundary"

START_HEIGHT=$(get_height 0)
mine_blocks 0 8 || fail "post-DAG mining failed"
END_HEIGHT=$(get_height 0)
POS_FOUND=0
for ((h=START_HEIGHT + 1; h<=END_HEIGHT; h++)); do
    BLOCK=$(get_block_json 0 "$h")
    FLAGS=$(json_field "$BLOCK" "flags")
    PRODUCER=$(json_field "$BLOCK" "dag_block_producer")
    BLOCK_POS=$(json_field "$BLOCK" "pos_block_production")
    echo "$FLAGS" | grep -qi "proof-of-stake" && POS_FOUND=$((POS_FOUND + 1))
    [ "$PRODUCER" = "pow" ] || fail "block $h missing pow producer"
    [ "$BLOCK_POS" = "false" ] || fail "block $h reports PoS production"
done

[ "$POS_FOUND" -eq 0 ] && success "no PoS blocks mined after DAG activation" || fail "found $POS_FOUND PoS blocks after DAG activation"

header "Summary"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Skipped: $SKIPPED"

if [ "$FAILED" -eq 0 ]; then
    success "IDAG hidden-finality stress passed"
    exit 0
fi

exit 1
