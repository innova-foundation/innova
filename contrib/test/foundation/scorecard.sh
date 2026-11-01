#!/usr/bin/env bash
# Performance and crash-recovery scorecard for one innovad binary. Linux only.
# usage: scorecard.sh BIN BLOCKS_DIR WORK_DIR OUT_JSON
# env:   PORT_BASE (29640) KILLS (20) KILL_MIN_S (60) KILL_MAX_S (600)
#        KILL_FILES (2: blk files fed to the kill run) STEADY_S (600)
#        INTERVAL (10000: digest interval of the kill run) REF_JSONL (optional
#        replay_compare digest file; kill-run digests are diffed against it)
#        PHASES ("reindex restart kill")
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
[ $# -eq 4 ] || { sed -n 2,9p "$0"; exit 2; }
BIN=$(readlink -f "$1"); BLOCKS=$(readlink -f "$2"); WORK=$3; OUT_JSON=$4
PORT_BASE=${PORT_BASE:-29640}; KILLS=${KILLS:-20}
KILL_MIN_S=${KILL_MIN_S:-60}; KILL_MAX_S=${KILL_MAX_S:-600}; KILL_FILES=${KILL_FILES:-2}
STEADY_S=${STEADY_S:-600}; INTERVAL=${INTERVAL:-10000}; PHASES=${PHASES:-reindex restart kill}
mkdir -p "$WORK"; WORK=$(readlink -f "$WORK"); R="$WORK/results"; mkdir -p "$R"
loadargs() { for f in $(fnd_blk_files "$BLOCKS" "${1:-100000}"); do printf -- '-loadblock=%s ' "$f"; done; }
log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$R/progress.log"; }

# Gaps >120 s between consecutive tip updates in a timestamped debug.log.
stalls() {
    python3 - "$1" <<'PY'
import sys, re, datetime, json
prev, gaps = None, []
for line in open(sys.argv[1], errors="replace"):
    if "SetBestChain: new best" not in line: continue
    m = re.match(r"(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)", line)
    if not m: continue
    t = datetime.datetime.fromisoformat(m.group(1).replace(" ", "T"))
    h = re.search(r"height=(\d+)", line)
    if prev and (t - prev[0]).total_seconds() > 120:
        gaps.append({"after_height": prev[1], "gap_s": (t - prev[0]).total_seconds()})
    prev = (t, int(h.group(1)) if h else None)
print(json.dumps({"count": len(gaps), "gaps": gaps[:20]}))
PY
}
rss_summary() {
    python3 - "$1" "${2:-0}" <<'PY'
import sys, json
rows = [list(map(int, l.split())) for l in open(sys.argv[1]) if l.strip()]
tail = int(sys.argv[2])
if not rows: print("{}"); sys.exit()
if tail:
    t_end = rows[-1][0]; rows_t = [r for r in rows if r[0] >= t_end - tail] or rows
else:
    rows_t = rows
print(json.dumps({"peak_hwm_kb": max(r[2] for r in rows), "max_rss_kb": max(r[1] for r in rows),
                  "mean_rss_kb_window": sum(r[1] for r in rows_t) // len(rows_t), "samples": len(rows)}))
PY
}

D="$WORK/reindex-data"
if [[ " $PHASES " == *" reindex "* ]]; then
    log "reindex start"
    rm -rf "$D"; fnd_conf "$D" "$PORT_BASE" $((PORT_BASE + 1)); : > "$R/reindex.rss"
    t0=$(date +%s.%N)
    # shellcheck disable=SC2086
    "$BIN" $(fnd_flags "$D" $((PORT_BASE + 2))) $(loadargs) > "$R/reindex.stdout" 2>&1 & PID=$!
    echo $PID > "$R/reindex.pid"
    fnd_sample_rss $PID "$R/reindex.rss" 5 & SPID=$!
    wait $PID; rc=$?; wait $SPID
    wall=$(echo "$(date +%s.%N) - $t0" | bc)
    tip=$(grep 'SetBestChain: new best' "$D/debug.log" | tail -1 | sed -n 's/.*best=\([0-9a-f]*\).*height=\([0-9]*\).*/\2 \1/p')
    printf '{"exit":%d,"wall_s":%s,"tip_height":%s,"tip_hash_prefix":"%s","rss":%s,"stalls_gt120s":%s}\n' \
        $rc "$wall" "${tip%% *}" "${tip##* }" "$(rss_summary "$R/reindex.rss")" "$(stalls "$D/debug.log")" > "$R/reindex.json"
    cp "$D/debug.log" "$R/reindex.debug.log"
    log "reindex done: $(cat "$R/reindex.json")"
fi

if [[ " $PHASES " == *" restart "* ]]; then
    log "restart start"
    : > "$D/debug.log"; : > "$R/steady.rss"
    t0=$(date +%s.%N)
    # shellcheck disable=SC2086
    "$BIN" $(fnd_flags "$D" $((PORT_BASE + 2))) > "$R/restart.stdout" 2>&1 & PID=$!
    ready=$(fnd_wait_rpc "$BIN" "$D" $PID 7200) || ready=null
    height=$(fnd_rpc "$BIN" "$D" getblockcount || echo null)
    vms=$(sed -n 's/.* block index *\([0-9]*\)ms.*/\1/p' "$D/debug.log" | tail -1)
    fnd_sample_rss $PID "$R/steady.rss" 5 & SPID=$!
    sleep "$STEADY_S"
    t1=$(date +%s.%N); fnd_stop "$BIN" "$D" $PID; stop_s=$(echo "$(date +%s.%N) - $t1" | bc)
    wait $SPID 2>/dev/null
    printf '{"rpc_ready_s":%s,"height":%s,"block_index_load_verify_ms":%s,"shutdown_s":%s,"steady_window_s":%s,"rss":%s}\n' \
        "$ready" "$height" "${vms:-null}" "$stop_s" "$STEADY_S" "$(rss_summary "$R/steady.rss" 300)" > "$R/restart.json"
    log "restart done: $(cat "$R/restart.json")"
fi
[ "${KEEP_DATA:-0}" = 1 ] || rm -rf "$D"

if [[ " $PHASES " == *" kill "* ]]; then
    K="$WORK/kill-data"; rm -rf "$K"; fnd_conf "$K" $((PORT_BASE + 20)) $((PORT_BASE + 21))
    KDIG="$R/kill.jsonl"; rm -f "$KDIG" "$R/kill.rows"
    KARGS="-statedigestinterval=$INTERVAL -statedigestfile=$KDIG"
    for i in $(seq 1 "$KILLS"); do
        # shellcheck disable=SC2086
        "$BIN" $(fnd_flags "$K" $((PORT_BASE + 22))) $KARGS $(loadargs "$KILL_FILES") >> "$R/kill.stdout" 2>&1 & PID=$!
        s=$(( KILL_MIN_S + RANDOM % (KILL_MAX_S - KILL_MIN_S + 1) )); sleep "$s"
        if ! kill -0 $PID 2>/dev/null; then log "kill $i: import finished before kill"; wait $PID; break; fi
        pre=$(grep 'SetBestChain: new best' "$K/debug.log" | tail -1 | sed -n 's/.*height=\([0-9]*\).*/\1/p')
        kill -9 $PID; wait $PID 2>/dev/null
        nrep0=$(grep -c 'Block data repair mode' "$K/debug.log")
        # shellcheck disable=SC2086
        "$BIN" $(fnd_flags "$K" $((PORT_BASE + 22))) $KARGS >> "$R/kill.stdout" 2>&1 & PID=$!
        ready=$(fnd_wait_rpc "$BIN" "$K" $PID 3600) || ready=null
        post=$(fnd_rpc "$BIN" "$K" getblockcount || echo null)
        alive=1; kill -0 $PID 2>/dev/null || alive=0
        [ $alive = 1 ] && fnd_stop "$BIN" "$K" $PID; wait $PID 2>/dev/null
        nrep=$(( $(grep -c 'Block data repair mode' "$K/debug.log") - nrep0 ))
        ok=false; [ "$post" != null ] && [ -n "$pre" ] && [ "$post" -ge "$pre" ] && ok=true
        printf '{"kill":%d,"after_s":%d,"pre_height":%s,"post_height":%s,"rpc_ready_s":%s,"repair_mode":%d,"recovered":%s}\n' \
            "$i" "$s" "${pre:-null}" "$post" "$ready" "$nrep" "$ok" | tee -a "$R/kill.rows"
    done
    log "kill run: finishing import"
    # shellcheck disable=SC2086
    "$BIN" $(fnd_flags "$K" $((PORT_BASE + 22))) $KARGS $(loadargs "$KILL_FILES") >> "$R/kill.stdout" 2>&1; frc=$?
    final=$(grep 'SetBestChain: new best' "$K/debug.log" | tail -1 | sed -n 's/.*height=\([0-9]*\).*/\1/p')
    cmp=null
    if [ -n "${REF_JSONL:-}" ] && [ -s "${REF_JSONL:-}" ]; then
        cmp=$(python3 "$HERE/digest_diff.py" "$REF_JSONL" "$KDIG" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(json.dumps({k:d[k] for k in ("common_heights","max_common_height","diff_count","diffs")}))')
    fi
    python3 - "$R/kill.rows" "$frc" "${final:-null}" "$cmp" > "$R/kill.json" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
print(json.dumps({"kills": len(rows), "recovered": sum(1 for r in rows if r["recovered"]),
                  "repair_mode_runs": sum(1 for r in rows if r["repair_mode"]),
                  "final_import_exit": int(sys.argv[2]), "final_height": json.loads(sys.argv[3]),
                  "ref_compare": json.loads(sys.argv[4]), "rows": rows}))
PY
    log "kill done"
    [ "${KEEP_DATA:-0}" = 1 ] || rm -rf "$K"
fi

python3 - "$R" "$BIN" "$OUT_JSON" <<'PY'
import json, sys, os, hashlib
r, binp, out = sys.argv[1:]
def j(n):
    p = os.path.join(r, n + ".json")
    return json.load(open(p)) if os.path.exists(p) else None
h = hashlib.sha256(open(binp, "rb").read()).hexdigest()
json.dump({"binary": binp, "binary_sha256": h, "reindex": j("reindex"),
           "restart": j("restart"), "kill": j("kill")}, open(out, "w"), indent=1)
print(open(out).read())
PY
