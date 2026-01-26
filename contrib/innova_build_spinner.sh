#!/bin/sh
set -e

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <command> [args...]" >&2
    exit 2
fi

if [ ! -t 2 ]; then
    exec "$@"
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ASCII_FILE="$SCRIPT_DIR/../src/qt/res/icons/innova_ascii.txt"
SPINNER_MS=97

cleanup() {
    if [ -n "${spinner_pid:-}" ]; then
        kill "$spinner_pid" >/dev/null 2>&1 || true
        wait "$spinner_pid" >/dev/null 2>&1 || true
        printf "\r\033[2K\n" >&2
    fi
}

spinner_loop() {
    if command -v python3 >/dev/null 2>&1 && [ -f "$ASCII_FILE" ]; then
        exec python3 "$SCRIPT_DIR/spin_ascii.py" "$ASCII_FILE" \
            --ms "$SPINNER_MS" \
            --stderr \
            --toggle-key i \
            --tty /dev/tty \
            --scroll-region \
            --output-lines 5 \
            --min-output 5 \
            --max-output 15
    fi
}

spinner_loop &
spinner_pid=$!

trap cleanup INT TERM EXIT

"$@"
status=$?
cleanup
exit "$status"
