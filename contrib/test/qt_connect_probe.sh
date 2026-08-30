#!/bin/bash
# Builds the wallet's widget tree offscreen and fails on any connection Qt could not
# resolve by name.
# usage: qt_connect_probe.sh <wallet-binary> <datadir> [stderr-log]
set -u

BIN="${1:?usage: qt_connect_probe.sh <wallet-binary> <datadir> [stderr-log]}"
DD="${2:?usage: qt_connect_probe.sh <wallet-binary> <datadir> [stderr-log]}"
OUT="${3:-$DD.stderr.log}"
WAIT="${QT_CONNECT_PROBE_WAIT:-90}"

# Warnings not this tree's to fix: Qt's own QPlatformNativeInterface plumbing, and
# managenamespage.h slots for widgets in no .ui file.
ALLOWED='QPlatformNativeInterface|on_cbMyNames_stateChanged|on_cbOtherNames_stateChanged|on_cbExpired_stateChanged'

# A connect that failed to resolve, in either of Qt's two spellings.
FAILURE='No such signal|No such slot|No matching signal'

[ -x "$BIN" ] || { echo "probe: $BIN is not an executable" >&2; exit 2; }

rm -rf "$DD"
mkdir -p "$DD" || exit 2
cat > "$DD/innova.conf" <<EOF
dnsseed=0
listen=0
irc=0
upnp=0
nativetor=0
idns=0
connect=127.0.0.1:1
EOF

QT_QPA_PLATFORM=offscreen "$BIN" -datadir="$DD" > "$OUT" 2>&1 &
PID=$!

# MintingTableModel logs the marker after every page is built; its presence proves
# the connects under test ran.
MARKER='refreshWallet'
ready=0
for _ in $(seq 1 "$WAIT"); do
    sleep 1
    grep -q "$MARKER" "$DD/debug.log" 2>/dev/null && { ready=1; break; }
    kill -0 "$PID" 2>/dev/null || break
done
[ "$ready" = "1" ] && sleep 3

kill -TERM "$PID" 2>/dev/null
for _ in $(seq 1 30); do sleep 1; kill -0 "$PID" 2>/dev/null || break; done
kill -KILL "$PID" 2>/dev/null
wait "$PID" 2>/dev/null

if [ "$ready" != "1" ]; then
    echo "probe: the wallet never reached $MARKER, so no connect was exercised" >&2
    tail -20 "$OUT" >&2
    exit 1
fi

found="$(cat "$OUT" "$DD/debug.log" 2>/dev/null \
         | grep -E "$FAILURE" | grep -Ev "$ALLOWED" | sort -u)"

echo "probe: widget tree built (saw $MARKER)"
if [ -n "$found" ]; then
    echo "probe: unresolved connections:"
    printf '%s\n' "$found"
    exit 1
fi
echo "probe: no unresolved connections"
exit 0
