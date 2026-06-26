#!/bin/sh
set -eu

RUN_ID="${1:-gate7_soak_$(date -u +%Y%m%dT%H%M%SZ)}"
SCRIPT="${GATE7_SCRIPT:-/root/gate7_soak_runner.py}"
BASE="${GATE7_BASE:-/root/testnet_metrics}"
OUT_DIR="$BASE/$RUN_ID"
PID_FILE="$OUT_DIR/runner.pid"
LOG_FILE="$OUT_DIR/runner.log"

mkdir -p "$OUT_DIR"

if [ -f "$PID_FILE" ]; then
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
        echo "already-running run_id=$RUN_ID pid=$old_pid output_dir=$OUT_DIR"
        exit 0
    fi
fi

nohup python3 -u "$SCRIPT" \
    --run-id "$RUN_ID" \
    --output-dir "$OUT_DIR" \
    --duration 259200 \
    --traffic-interval 1800 \
    --txs-per-pulse 2 \
    --seed-visibility-min 5 \
    --min-seed-peers 4 \
    --min-traffic-peers 4 \
    --yes-live-traffic \
    > "$LOG_FILE" 2>&1 &

pid="$!"
echo "$pid" > "$PID_FILE"
printf 'started run_id=%s pid=%s output_dir=%s log=%s\n' "$RUN_ID" "$pid" "$OUT_DIR" "$LOG_FILE"
