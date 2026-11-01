#!/usr/bin/env bash
# Reindex the same blk*.dat with two innovad binaries in fresh datadirs, dump a
# state digest every INTERVAL heights and at the tip, and diff the dumps.
# usage: replay_compare.sh BIN_A BIN_B BLOCKS_DIR OUT_DIR
# env:   INTERVAL (10000) PORT_BASE (29600) MAX_FILES (all) KEEP_DATA (0)
# Prepare BLOCKS_DIR once, e.g. a fresh datadir started with -getbootstrap.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
[ $# -eq 4 ] || { sed -n 2,6p "$0"; exit 2; }
BIN_A=$(readlink -f "$1"); BIN_B=$(readlink -f "$2"); BLOCKS=$(readlink -f "$3"); OUT=$4
INTERVAL=${INTERVAL:-10000}; PORT_BASE=${PORT_BASE:-29600}
mkdir -p "$OUT"; OUT=$(readlink -f "$OUT")
FILES=$(fnd_blk_files "$BLOCKS" "${MAX_FILES:-100000}")
[ -n "$FILES" ] || { echo "no blk*.dat in $BLOCKS" >&2; exit 2; }
LOADARGS=$(for f in $FILES; do printf -- '-loadblock=%s ' "$f"; done)

run_one() {
    local tag=$1 bin=$2 port=$3 dd="$OUT/$1-data"
    rm -rf "$dd"; fnd_conf "$dd" "$port" $((port + 1))
    rm -f "$OUT/$tag.jsonl"
    local t0=$(date +%s)
    # shellcheck disable=SC2086
    "$bin" $(fnd_flags "$dd" $((port + 2))) -statedigestinterval="$INTERVAL" \
        -statedigestfile="$OUT/$tag.jsonl" $LOADARGS > "$OUT/$tag.stdout" 2>&1
    local rc=$?
    echo "$tag exit=$rc wall_s=$(( $(date +%s) - t0 ))" > "$OUT/$tag.status"
    cp "$dd/debug.log" "$OUT/$tag.debug.log" 2>/dev/null
}

run_one a "$BIN_A" "$PORT_BASE" & PA=$!
run_one b "$BIN_B" $((PORT_BASE + 10)) & PB=$!
echo "$PA $PB" > "$OUT/pids"
wait $PA $PB
cat "$OUT/a.status" "$OUT/b.status"

python3 "$HERE/digest_diff.py" "$OUT/a.jsonl" "$OUT/b.jsonl" --strict > "$OUT/diff.json"
RC=$?
grep -q 'exit=0' "$OUT/a.status" && grep -q 'exit=0' "$OUT/b.status" || RC=1
python3 - "$OUT" "$RC" <<'PY'
import json, sys
out, rc = sys.argv[1], int(sys.argv[2])
d = json.load(open(out + "/diff.json"))
st = {t: open(f"{out}/{t}.status").read().split() for t in "ab"}
tips = {}
for t in "ab":
    lines = [l for l in open(f"{out}/{t}.jsonl") if l.strip()]
    tips[t] = json.loads(lines[-1]) if lines else {}
print(json.dumps({"pass": rc == 0, "status": st,
                  "tip_a": {k: tips["a"].get(k) for k in ("height", "hash", "db_digest")},
                  "tip_b": {k: tips["b"].get(k) for k in ("height", "hash", "db_digest")},
                  "common_heights": d["common_heights"], "diff_count": d["diff_count"],
                  "first_diffs": d["diffs"][:5]}, indent=1))
PY
[ "${KEEP_DATA:-0}" = 1 ] || rm -rf "$OUT/a-data" "$OUT/b-data"
exit $RC
