#!/usr/bin/env bash
# Local depth policy, retained side branches, mergesets and sync.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init w10_fork_test
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
TEST_DIR="${W10_TEST_DIR:-$(mktemp -d /tmp/innova-w10.XXXXXX)}"
BASE_PORT="${W10_BASE_PORT:-$(iv5_port 0 28900)}"
BASE_RPC="${W10_BASE_RPC:-$(iv5_port 16 28920)}"
BASE_IDNS="${W10_BASE_IDNS:-$(iv5_port 32 8990)}"
MERGESET=311
MAX_DEPTH=1440

die() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
dir() { echo "$TEST_DIR/node$1"; }
rpc() {
    local node="$1"; shift
    "$INNOVAD" -datadir="$(dir "$node")" -regtest -rpcuser=w10 -rpcpassword=w10pass \
        -rpcport="$((BASE_RPC + node))" "$@"
}
field() {
    python3 -c 'import json,sys; v=json.load(sys.stdin)[sys.argv[1]]; print(str(v).lower() if isinstance(v,bool) else v)' "$1"
}
height() { rpc "$1" getblockcount | tr -d '"[:space:]'; }
hash_at() { rpc "$1" getblockhash "$2" | tr -d '"[:space:]'; }
best() { rpc "$1" getbestblockhash | tr -d '"[:space:]'; }

start() {
    local node="$1" depth="${2:-}" d i
    d="$(dir "$node")"
    mkdir -p "$d"
    cat > "$d/innova.conf" <<EOF
regtest=1
server=1
rpcuser=w10
rpcpassword=w10pass
rpcport=$((BASE_RPC + node))
port=$((BASE_PORT + node))
idnsport=$((BASE_IDNS + node))
listen=1
bind=127.0.0.1
connect=0
dnsseed=0
nobootstrap=1
nosmsg=1
upnp=0
listenonion=0
stakingmode=0
nofinalityvoting=1
regtestboundaryb=311
regtestiv5rehearsal=1
regtestmergeset=$MERGESET
dagheaderssync=1
EOF
    if [ -n "$depth" ]; then echo "maxreorgdepth=$depth" >> "$d/innova.conf"; fi
    "$INNOVAD" -datadir="$d" -regtest -daemon >/dev/null
    for ((i=0; i<120; ++i)); do
        if rpc "$node" getinfo >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    die "node $node failed to start ($d/regtest/debug.log)"
}

stop() {
    local node="$1" i
    rpc "$node" stop >/dev/null 2>&1 || true
    for ((i=0; i<120; ++i)); do
        if ! pgrep -f -- "-datadir=$(dir "$node") -regtest -daemon" >/dev/null; then return 0; fi
        sleep 1
    done
    return 1
}

cleanup() {
    local node
    for node in 0 1 2; do stop "$node" || true; done
    if [ "${KEEP_DIR:-0}" = 1 ]; then
        echo "Kept $TEST_DIR"
    else
        # Remove only the node directories created by this script.
        for node in 0 1 2; do rm -rf "$(dir "$node")"; done
        rmdir "$TEST_DIR" 2>/dev/null || true
    fi
}

mine_to() {
    local node="$1" target="$2" h i
    h="$(height "$node")"
    if [ "$h" -ge "$target" ]; then return 0; fi
    rpc "$node" setgenerate true "$((target - h))" >/dev/null
    for ((i=0; i<7200; ++i)); do
        h="$(height "$node")"
        if [ "$h" -ge "$target" ]; then
            rpc "$node" setgenerate false >/dev/null
            [ "$h" = "$target" ] || die "node $node mined past $target to $h"
            return 0
        fi
        sleep 1
    done
    die "node $node did not reach $target"
}

submit_height() {
    local from="$1" to="$2" h="$3" raw result
    raw="$(rpc "$from" getblock "$(hash_at "$from" "$h")" 0 | tr -d '"[:space:]')"
    result="$(rpc "$to" submitblock "$raw" 2>&1)" || return 1
    case "$result" in ''|null) return 0 ;; *) echo "$result" >&2; return 1 ;; esac
}

relay() {
    local from="$1" to="$2" first="$3" last="$4" h
    for ((h=first; h<=last; ++h)); do
        submit_height "$from" "$to" "$h" || die "relay $from -> $to failed at $h"
    done
}

same_tip() { [ "$(best "$1")" = "$(best "$2")" ] || die "nodes $1 and $2 disagree"; }

[ -x "$INNOVAD" ] || die "no executable at $INNOVAD"
command -v python3 >/dev/null || die "python3 required"
for node in 0 1 2; do
    [ ! -e "$(dir "$node")" ] || die "datadir already exists: $(dir "$node")"
    iv5_require_free_ports "$((BASE_PORT + node))" "$((BASE_RPC + node))" "$((BASE_IDNS + node))"
done
trap cleanup EXIT
assert_side_block() {
    local node="$1" hash="$2"
    rpc "$node" getblock "$hash" | python3 -c 'import json,sys
b=json.load(sys.stdin)
assert "failreason" not in b, b
assert b["confirmations"] <= 0, b
assert b.get("dagparents"), b
' || die "block $hash is not a retained DAG side block on node $node"
}

wait_same_tip() {
    local a="$1" b="$2" i
    for ((i=0; i<7200; ++i)); do
        if [ "$(best "$a")" = "$(best "$b")" ]; then return 0; fi
        sleep 1
    done
    die "nodes $a and $b did not converge"
}

start 0
start 1
[ "$(rpc 0 getinfo | field max_reorg_depth)" = "$MAX_DEPTH" ] || die "wrong default depth"
rpc 0 getforkinfo | python3 -c 'import json,sys
assert not any("w10" in k for k in json.load(sys.stdin))
' || die "depth policy exposed as a fork"

mine_to 0 330
relay 0 1 1 330
same_tip 0 1

# An old sibling remains mergeable even with a two-block local limit.
stop 0 || die "node 0 did not stop"
start 0 2
[ "$(rpc 0 getinfo | field max_reorg_depth)" = 2 ] || die "custom depth ignored"
mine_to 1 331
sibling="$(best 1)"
mine_to 0 333
before_merge="$(best 0)"
submit_height 1 0 331 || die "side sibling refused"
[ "$(best 0)" = "$before_merge" ] || die "side sibling reorganized the chain"
assert_side_block 0 "$sibling"
mine_to 0 334
rpc 0 getblock "$(best 0)" | python3 -c 'import json,sys
b=json.load(sys.stdin)
assert b["selected_parent"] == sys.argv[1], b
assert sys.argv[2] in b["dagparents"], b
assert sys.argv[2] in b["mergedblocks"], b
' "$before_merge" "$sibling" || die "sibling was not merged by a direct extension"
relay 0 1 331 334
same_tip 0 1
pass "side sibling and mergeset accepted without reorganizing"

stop 0 || die "node 0 did not stop"
start 0
[ "$(rpc 0 getinfo | field max_reorg_depth)" = "$MAX_DEPTH" ] || die "default depth not restored"

# Exactly the limit is allowed, without a separate activation height.
fork="$(height 0)"
mine_to 0 "$((fork + MAX_DEPTH))"
mine_to 1 "$((fork + MAX_DEPTH + 8))"
relay 1 0 "$((fork + 1))" "$(height 1)"
same_tip 0 1
pass "reorganization at exactly 1440 blocks allowed"

fork="$(height 0)"
mine_to 0 "$((fork + MAX_DEPTH + 1))"
tip="$(best 0)"
mine_to 1 "$((fork + MAX_DEPTH + 9))"
root="$(hash_at 1 "$((fork + 1))")"
branch_tip="$(best 1)"
branch_height="$(height 1)"
# Every body, including heavier descendants, is accepted and stored.
relay 1 0 "$((fork + 1))" "$branch_height"
[ "$(best 0)" = "$tip" ] || die "deep branch moved the tip"
assert_side_block 0 "$root"
assert_side_block 0 "$branch_tip"
grep -q 'Reorg depth policy: refused candidate' "$(dir 0)/regtest/debug.log" || die "refusal not logged"
pass "deep branch stored successfully while chain switch refused"

stop 0 || die "node 0 did not stop"
start 0
[ "$(best 0)" = "$tip" ] || die "tip changed after restart"
assert_side_block 0 "$root"
assert_side_block 0 "$branch_tip"
rpc 0 reconsiderblock "$root" >/dev/null || die "valid branch could not be reconsidered"
[ "$(best 0)" = "$tip" ] || die "reconsider bypassed the configured depth limit"
pass "retained branch survives restart and remains reconsiderable"

# Sync an empty datadir, including the selected chain's merge parents.
start 2
rpc 2 addnode "127.0.0.1:$BASE_PORT" onetry >/dev/null
wait_same_tip 0 2
stop 2 || die "node 2 did not stop"
start 2
same_tip 0 2
pass "fresh-node sync from genesis and restart unaffected"

# Disabling policy adopts the already stored branch without resubmission.
stop 0 || die "node 0 did not stop"
start 0 0
[ "$(rpc 0 getinfo | field max_reorg_depth)" = 0 ] || die "depth limit not disabled"
rpc 0 reconsiderblock "$root" >/dev/null || die "disabled-policy reselection failed"
same_tip 0 1
[ "$(best 0)" = "$branch_tip" ] || die "stored branch was not adopted"
pass "maxreorgdepth=0 permits adoption of the retained branch"

# A nonempty node far behind checked headers can switch during catchup.
mine_to 1 "$((branch_height + MAX_DEPTH + 10))"
rpc 2 addnode "127.0.0.1:$((BASE_PORT + 1))" onetry >/dev/null
wait_same_tip 1 2
[ "$(rpc 2 getinfo | field max_reorg_depth)" = "$MAX_DEPTH" ] || die "catchup disabled the depth limit"
stop 2 || die "node 2 did not stop"
start 2
same_tip 1 2
pass "lagging node follows the heavier branch during header sync and survives restart"
