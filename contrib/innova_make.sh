#!/bin/sh
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SPINNER="$SCRIPT_DIR/innova_build_spinner.sh"

if [ -x "$SPINNER" ]; then
    exec "$SPINNER" make "$@"
fi

exec make "$@"
