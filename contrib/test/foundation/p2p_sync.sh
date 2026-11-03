#!/bin/bash
# P2P sync timing: a fresh node syncs from one local source node for a fixed window.
# usage: p2p_sync.sh <source-bin> <source-datadir> <sink-bin> <work-dir> <out.json>
# The source datadir must hold an imported chain. Env: PORT_BASE, SYNC_S (window, seconds),
# TARGET_HEIGHT (stop once reached; default the source height).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
[ $# -eq 5 ] || { sed -n 2,5p "$0"; exit 2; }
SBIN=$(readlink -f "$1"); SDIR=$(readlink -f "$2"); BIN=$(readlink -f "$3"); WORK=$4; OUT_JSON=$5
PORT_BASE=${PORT_BASE:-29840}; SYNC_S=${SYNC_S:-1200}
mkdir -p "$WORK"; WORK=$(readlink -f "$WORK"); R="$WORK/results"; mkdir -p "$R"

SPORT=$PORT_BASE
sed -i -e "s/^port=.*/port=$SPORT/" -e "s/^listen=.*/listen=1/" -e "s/^rpcport=.*/rpcport=$((PORT_BASE + 1))/" "$SDIR/innova.conf"
"$SBIN" -datadir="$SDIR" -listen=1 -bind=127.0.0.1 -connect=127.0.0.1:$((PORT_BASE + 9)) -nobootstrap \
    -dnsseed=0 -checkblocks=0 -printtoconsole=0 > "$R/source.stdout" 2>&1 & SPID=$!
fnd_wait_rpc "$SBIN" "$SDIR" $SPID 3600 > /dev/null || { echo "source did not start"; kill $SPID; exit 1; }
SRC_H=$(fnd_rpc "$SBIN" "$SDIR" getblockcount)
STOP_H=${TARGET_HEIGHT:-$SRC_H}

D="$WORK/sink"; rm -rf "$D"; fnd_conf "$D" $((PORT_BASE + 2)) $((PORT_BASE + 3))
: > "$R/sink.rss"
"$BIN" $(fnd_flags "$D" "$SPORT") > "$R/sink.stdout" 2>&1 & PID=$!
fnd_sample_rss $PID "$R/sink.rss" 5 & RPID=$!
fnd_wait_rpc "$BIN" "$D" $PID 600 > /dev/null
t0=$(date +%s); h0=$(fnd_rpc "$BIN" "$D" getblockcount || echo 0)
: > "$R/sink.heights"
while [ $(( $(date +%s) - t0 )) -lt "$SYNC_S" ]; do
    sleep 10
    h=$(fnd_rpc "$BIN" "$D" getblockcount || echo -1)
    echo "$(( $(date +%s) - t0 )) $h" >> "$R/sink.heights"
    [ "$h" -ge "$STOP_H" ] && break
done
t1=$(date +%s); h1=$(fnd_rpc "$BIN" "$D" getblockcount || echo 0)
fnd_stop "$BIN" "$D" $PID; wait $RPID 2>/dev/null
fnd_stop "$SBIN" "$SDIR" $SPID
gb=$(grep -c 'getblocks' "$D/debug.log")
python3 - "$R/sink.rss" "$h0" "$h1" "$t0" "$t1" "$SRC_H" "$gb" "$OUT_JSON" <<'PY'
import json, sys
rows = [list(map(int, l.split())) for l in open(sys.argv[1]) if l.strip()]
h0, h1, t0, t1, src, gb = map(int, sys.argv[2:8])
tail = [r for r in rows if r[0] >= rows[-1][0] - 300] if rows else []
out = {"start_height": h0, "end_height": h1, "source_height": src, "seconds": t1 - t0,
       "blocks_per_s": round((h1 - h0) / max(1, t1 - t0), 2), "getblocks_log_lines": gb,
       "peak_hwm_kb": max((r[2] for r in rows), default=0),
       "mean_rss_kb_last300s": (sum(r[1] for r in tail) // len(tail)) if tail else 0}
json.dump(out, open(sys.argv[8], "w")); print(json.dumps(out))
PY
[ "${KEEP_DATA:-0}" = 1 ] || rm -rf "$D"
