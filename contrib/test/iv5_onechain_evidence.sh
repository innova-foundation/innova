#!/usr/bin/env bash
# Copyright (c) 2026 The Innova developers
# Evidence pass over a live multi-host IV5 chain: per v5 feature, the block or tx that
# exercised it, read from bytes and every node. Usage: discover | run | rpc <node> <args>.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DECODE="$SCRIPT_DIR/iv5_onechain_evidence.py"

PRIMARY_SSH="${PRIMARY_SSH:-user@linux-host}"
OUT_DIR="${IV5_EVIDENCE_DIR:-$HOME/iv5-onechain-evidence}"
INVENTORY="${IV5_EVIDENCE_INVENTORY:-$OUT_DIR/inventory.tsv}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

mkdir -p "$OUT_DIR"

PASSED=0; FAILED=0; SKIPPED=0
FEATURE_ROWS="$OUT_DIR/features.tsv"

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }
skip()  { echo -e "${YELLOW}[SKIP]${NC} $*"; SKIPPED=$((SKIPPED+1)); }
info()  { echo -e "${CYAN}  ..${NC} $*"; }
header(){ echo; echo -e "${BLUE}=== $* ===${NC}"; }

# One row per feature: name, verdict, the block or transaction that did it, why.
# Verdicts: EXERCISED, CONFIGURED-ONLY, BLOCKED.
feature() {
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$FEATURE_ROWS"
    case "$2" in
        EXERCISED)       echo -e "${GREEN}FEATURE${NC} $1: ${GREEN}$2${NC} [$3] $4" ;;
        CONFIGURED-ONLY) echo -e "${YELLOW}FEATURE${NC} $1: ${YELLOW}$2${NC} [$3] $4" ;;
        *)               echo -e "${RED}FEATURE${NC} $1: ${RED}$2${NC} [$3] $4" ;;
    esac
}

is_int() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

# ---------------------------------------------------------------------------
# Inventory, read off the running fleet rather than harness defaults.
# ---------------------------------------------------------------------------
NODE_NAMES=(); NODE_HOSTS=(); NODE_DIRS=(); NODE_PORTS=()
NODE_USERS=(); NODE_PASSES=(); NODE_BINS=()

load_inventory() {
    local f="${1:-$INVENTORY}"
    [ -r "$f" ] || { echo "no inventory at $f" >&2; return 1; }
    NODE_NAMES=(); NODE_HOSTS=(); NODE_DIRS=(); NODE_PORTS=()
    NODE_USERS=(); NODE_PASSES=(); NODE_BINS=()
    local name host dir port user pass bin
    while IFS=$'\t' read -r name host dir port user pass bin; do
        case "$name" in ''|'#'*) continue ;; esac
        NODE_NAMES+=("$name"); NODE_HOSTS+=("$host"); NODE_DIRS+=("$dir")
        NODE_PORTS+=("$port"); NODE_USERS+=("$user"); NODE_PASSES+=("$pass")
        NODE_BINS+=("$bin")
    done < "$f"
    [ "${#NODE_NAMES[@]}" -gt 0 ]
}

node_index() {
    local want="$1" i
    for i in "${!NODE_NAMES[@]}"; do
        [ "${NODE_NAMES[$i]}" = "$want" ] && { echo "$i"; return 0; }
    done
    return 1
}

on_host() {
    local host="$1"; shift
    if [ "$host" = "primary" ]; then
        ssh -o ConnectTimeout=10 -o BatchMode=yes "$PRIMARY_SSH" "$@"
    else
        bash -c "$@"
    fi
}

rpc() {
    local n="$1"; shift
    local i; i="$(node_index "$n")" || { echo "unknown node $n" >&2; return 1; }
    on_host "${NODE_HOSTS[$i]}" \
        "${NODE_BINS[$i]} -datadir=${NODE_DIRS[$i]} -regtest -rpcuser=${NODE_USERS[$i]} -rpcpassword=${NODE_PASSES[$i]} -rpcport=${NODE_PORTS[$i]} $* 2>&1"
}

# Read a fleet's node config off disk. Base holds one directory per node.
discover_host() {
    local host="$1" base="$2" bin="$3"
    local listing
    listing="$(on_host "$host" "for d in $base/*/; do [ -f \"\$d/innova.conf\" ] || continue; n=\$(basename \"\$d\"); p=\$(sed -n 's/^rpcport=//p' \"\$d/innova.conf\" | head -1); u=\$(sed -n 's/^rpcuser=//p' \"\$d/innova.conf\" | head -1); w=\$(sed -n 's/^rpcpassword=//p' \"\$d/innova.conf\" | head -1); echo \"\$n \$d \$p \$u \$w\"; done" 2>/dev/null)"
    local n d p u w
    while read -r n d p u w; do
        [ -n "${n:-}" ] || continue
        [ -n "${p:-}" ] || continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$n" "$host" "${d%/}" "$p" "$u" "$w" "$bin"
    done <<< "$listing"
}

cmd_discover() {
    local secondarybase="${1:-}" primarybase="${2:-}"
    local secondarybin="${SECONDARY_BIN:-$INNOVA_ROOT/src/innovad}"
    local primarybin="${PRIMARY_BIN:-}"
    : > "$INVENTORY.tmp"
    if [ -n "$secondarybase" ]; then
        discover_host secondary "$secondarybase" "$secondarybin" >> "$INVENTORY.tmp"
    fi
    if [ -n "$primarybase" ]; then
        if [ -z "$primarybin" ]; then
            # The binary the live daemon is actually running, off its command line.
            primarybin="$(on_host primary "ps -eo args= | grep -m1 -- '-datadir=$primarybase' | awk '{print \$1}'" 2>/dev/null)"
        fi
        [ -n "$primarybin" ] || { echo "set PRIMARY_BIN: no running daemon under $primarybase" >&2; return 1; }
        discover_host primary "$primarybase" "$primarybin" >> "$INVENTORY.tmp"
    fi
    mv "$INVENTORY.tmp" "$INVENTORY"
    echo "inventory -> $INVENTORY"
    cat "$INVENTORY"
}

# ---------------------------------------------------------------------------
# JSON helpers (python3, so nested same-named keys are not misread).
# ---------------------------------------------------------------------------
jq_path() {
    python3 -c '
import json, sys
try:
    v = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
for k in sys.argv[1:]:
    try:
        v = v[int(k)] if isinstance(v, list) else v[k]
    except Exception:
        sys.exit(0)
if isinstance(v, bool):
    print("true" if v else "false")
elif isinstance(v, (dict, list)):
    print(json.dumps(v))
else:
    print(v)
' "$@"
}

jget()  { printf '%s' "$1" | jq_path "${@:2}"; }
jlen()  { printf '%s' "$1" | python3 -c '
import json,sys
try: v=json.loads(sys.stdin.read())
except Exception: sys.exit(0)
for k in sys.argv[1:]:
    try: v = v[int(k)] if isinstance(v,list) else v[k]
    except Exception: sys.exit(0)
print(len(v))
' "${@:2}"; }

height()      { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
block_hash()  { rpc "$1" getblockhash "$2" 2>/dev/null | tr -d '"[:space:]'; }
get_block()   { rpc "$1" getblock "$(block_hash "$1" "$2")" 2>/dev/null; }
raw_tx()      { rpc "$1" getrawtransaction "$2" 2>/dev/null | tr -d '"[:space:]'; }
coinbase_txid() { jget "$(get_block "$1" "$2")" tx 0 | tr -d '"[:space:]'; }
coinbase_raw()  { local c; c="$(coinbase_txid "$1" "$2")"; [ ${#c} -eq 64 ] || return 1; raw_tx "$1" "$c"; }

# ---------------------------------------------------------------------------
# Cross-node agreement: a value every node reports identically, or the disagreement.
# ---------------------------------------------------------------------------
AGREE_VALUE=""; AGREE_WHY=""; AGREE_ABSENT=0
agree_on() {
    local label="$1"; shift
    local n v first="" ok=1 detail="" empty=0 seen=0
    for n in "${NODE_NAMES[@]}"; do
        v="$("$@" "$n")"
        seen=$((seen+1))
        [ -z "$v" ] && empty=$((empty+1))
        # A long value (an epoch's whole block ordering, say) is compared in
        # full but reported as a digest, so one disagreement cannot bury the
        # report in the value it disagreed about.
        local shown="$v"
        if [ ${#v} -gt 72 ]; then
            shown="sha256:$(printf '%s' "$v" | shasum -a 256 2>/dev/null | cut -c1-16)(${#v}B)"
        fi
        detail="$detail $n=${shown:-<empty>}"
        if [ "$seen" -eq 1 ]; then first="$v"
        elif [ "$v" != "$first" ]; then ok=0; fi
    done
    AGREE_VALUE="$first"; AGREE_WHY="$detail"
    AGREE_ABSENT=0
    if [ "$empty" -eq "$seen" ]; then
        # Every node is silent about this field. That is a field this chain does
        # not carry, not a disagreement between nodes.
        AGREE_ABSENT=1
        fail "$label: no node reports this field ($detail)"
        return 1
    fi
    if [ -z "$first" ] || [ "$empty" -gt 0 ]; then
        fail "$label: some nodes report the field and some do not:$detail"
        return 1
    fi
    if [ "$ok" -eq 1 ]; then
        local shown="$first"
        if [ ${#first} -gt 72 ]; then
            shown="sha256:$(printf '%s' "$first" | shasum -a 256 2>/dev/null | cut -c1-16) over ${#first} bytes"
        fi
        AGREE_SHORT="$shown"
        pass "$label: all ${#NODE_NAMES[@]} nodes agree ($shown)"
        return 0
    fi
    fail "$label: the fleet disagrees:$detail"
    return 1
}
AGREE_SHORT=""

# Field readers shaped for agree_on: they take the node name last.
r_finalized_height() { jget "$(rpc "$1" getfinalityinfo 2>/dev/null)" finalized_height; }
r_finalized_hash()   { jget "$(rpc "$1" getfinalityinfo 2>/dev/null)" finalized_hash; }
r_money_supply()     { jget "$(rpc "$1" getfinalityinfo 2>/dev/null)" money_supply; }
r_epoch_null_root()  { jget "$(rpc "$1" getfinalityinfo 2>/dev/null)" epoch_nullifier_root; }
r_epoch_curve_root() { jget "$(rpc "$1" getfinalityinfo 2>/dev/null)" epoch_curve_root; }

EPOCH_Q=0
r_epoch_digest()   { jget "$(rpc "$1" getepochinfo "$EPOCH_Q" 2>/dev/null)" epoch_state_digest; }
r_epoch_treeroot() { jget "$(rpc "$1" getepochinfo "$EPOCH_Q" 2>/dev/null)" iv5_tree_root; }
r_epoch_nullroot() { jget "$(rpc "$1" getepochinfo "$EPOCH_Q" 2>/dev/null)" nullifier_root; }
r_epoch_notevotes(){ jget "$(rpc "$1" getepochinfo "$EPOCH_Q" 2>/dev/null)" note_votes_counted; }
r_epoch_ordering() { jget "$(rpc "$1" getepochinfo "$EPOCH_Q" 2>/dev/null)" blocks; }

BLOCK_Q=0
r_block_hash()    { block_hash "$1" "$BLOCK_Q"; }
r_block_entropy() { jget "$(get_block "$1" "$BLOCK_Q")" entropy; }
r_block_dagparents() { jget "$(get_block "$1" "$BLOCK_Q")" dagparents; }
r_coinbase_idag() { local raw; raw="$(coinbase_raw "$1" "$BLOCK_Q")" || return 0
                    [ -n "$raw" ] || return 0
                    python3 "$DECODE" coinbase "$raw" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for r in d.get("op_returns",[]):
    if r.get("tag")=="IDAG":
        print("%d:%s" % (r["count"], ",".join(r["parents"]))); break
'; }
r_coinbase_imts() { local raw; raw="$(coinbase_raw "$1" "$BLOCK_Q")" || return 0
                    [ -n "$raw" ] || return 0
                    python3 "$DECODE" coinbase "$raw" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for r in d.get("op_returns",[]):
    if r.get("tag")=="IMTS":
        print(r["offset_ms"]); break
'; }
r_coinbase_version() { local raw; raw="$(coinbase_raw "$1" "$BLOCK_Q")" || return 0
                       [ -n "$raw" ] || return 0
                       python3 "$DECODE" coinbase "$raw" 2>/dev/null | jq_path version; }

TX_Q=""
r_tx_mask()  { python3 "$DECODE" iv5 "$(raw_tx "$1" "$TX_Q")" 2>/dev/null | jq_path disclosure_mask; }
r_tx_size()  { python3 "$DECODE" iv5 "$(raw_tx "$1" "$TX_Q")" 2>/dev/null | jq_path payload_size; }
r_tx_seen()  { local b; b="$(jget "$(rpc "$1" gettransaction "$TX_Q" 2>/dev/null)" blockhash)"; echo "${b:-none}"; }


cmd_run() {
    load_inventory "${1:-$INVENTORY}" || return 1
    : > "$FEATURE_ROWS"
    echo "nodes: ${NODE_NAMES[*]}"
    echo "evidence -> $OUT_DIR"
    echo "ONECHAIN EVIDENCE PASS  $(date -u +%FT%TZ)"
    # The individual feature sections live in the companion files so this one
    # stays readable; sourcing keeps them in the same shell and same helpers.
    . "$SCRIPT_DIR/iv5_onechain_sweep.sh"
    . "$SCRIPT_DIR/iv5_onechain_checks.sh"
    run_all_checks
    header "Totals"
    echo "checks: $PASSED passed, $FAILED failed, $SKIPPED skipped"
    echo
    echo "per-feature verdicts:"
    column -t -s $'\t' "$FEATURE_ROWS" 2>/dev/null || cat "$FEATURE_ROWS"
    [ "$FAILED" -eq 0 ]
}

case "${1:-}" in
    discover) shift; cmd_discover "$@" ;;
    run)      shift; cmd_run "$@" ;;
    rpc)      shift; load_inventory >/dev/null && rpc "$@" ;;
    *) echo "usage: $0 {discover <secondary-base> [primary-base]|run [inventory]|rpc <node> <args...>}"; exit 1 ;;
esac
