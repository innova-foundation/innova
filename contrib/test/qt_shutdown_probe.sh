#!/bin/bash
# The wallet must stop on SIGTERM and the stop RPC, even inside the terms dialog's modal loop.
# usage: qt_shutdown_probe.sh <wallet-binary> <workdir>
# Cases: A agreed datadir + SIGTERM, B fresh datadir + SIGTERM, C fresh datadir + stop RPC.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"

BIN="${1:?usage: qt_shutdown_probe.sh <wallet-binary> <workdir>}"
WORK="${2:?usage: qt_shutdown_probe.sh <wallet-binary> <workdir>}"
INNOVAD="${INNOVAD:-$(dirname "$BIN")/innovad}"
# Seconds allowed to reach the dialog, and seconds allowed to exit afterwards.
READY_WAIT="${QT_SHUTDOWN_READY_WAIT:-120}"
EXIT_WAIT="${QT_SHUTDOWN_EXIT_WAIT:-90}"

iv5_ports_init qt_shutdown_probe || exit 2
RPC_PORT=$(iv5_port 0 29781)
trap 'iv5_ports_release' EXIT
iv5_require_free_ports "$RPC_PORT" || exit 2

DIALOG_MARK='First run: showing the terms-of-use dialog'
CLOSE_MARK='Shutdown requested: closing the terms-of-use dialog'
# Logged by MintingTableModel once the wallet model is built, which is the last
# thing before checkTOU. Reaching it means the GUI is up.
READY_MARK='refreshWallet'

[ -x "$BIN" ] || { echo "probe: $BIN is not an executable" >&2; exit 2; }

FAILED=0
pass() { echo "probe: PASS $*"; }
fail() { echo "probe: FAIL $*"; FAILED=1; }

# $1 datadir, $2 "agreed"|"fresh", $3 "sigterm"|"stop"
run_case() {
    local dd="$1" mode="$2" stopby="$3" pid ready=0 waited=0 status
    rm -rf "$dd"
    mkdir -p "$dd" || return 2
    cat > "$dd/innova.conf" <<EOF
rpcuser=qtshutdownuser
rpcpassword=qtshutdownpass
server=1
rpcport=$RPC_PORT
dnsseed=0
listen=0
irc=0
upnp=0
nativetor=0
idns=0
staking=0
connect=127.0.0.1:1
EOF
    [ "$mode" = agreed ] && echo "I Agree!" > "$dd/.agreed_to_tou"

    QT_QPA_PLATFORM=offscreen "$BIN" -datadir="$dd" > "$dd/stderr.log" 2>&1 &
    pid=$!

    for _ in $(seq 1 "$READY_WAIT"); do
        sleep 1
        grep -q "$READY_MARK" "$dd/debug.log" 2>/dev/null && { ready=1; break; }
        kill -0 "$pid" 2>/dev/null || break
    done
    if [ "$ready" != 1 ]; then
        kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        fail "$mode/$stopby: the wallet never came up, so nothing was exercised"
        tail -10 "$dd/stderr.log" >&2
        return 1
    fi
    # checkTOU runs immediately after the marker; give it the moment.
    sleep 3

    if [ "$stopby" = sigterm ]; then
        kill -TERM "$pid" 2>/dev/null
    else
        "$INNOVAD" -datadir="$dd" stop > /dev/null 2>&1
    fi

    for _ in $(seq 1 "$EXIT_WAIT"); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        fail "$mode/$stopby: still running after ${EXIT_WAIT}s; had to be killed"
        return 1
    fi
    wait "$pid"
    status=$?

    if [ "$mode" = fresh ]; then
        grep -q "$DIALOG_MARK" "$dd/debug.log" 2>/dev/null \
            || { fail "$mode/$stopby: the terms dialog never opened; this case proves nothing"; return 1; }
        grep -q "$CLOSE_MARK" "$dd/debug.log" 2>/dev/null \
            || { fail "$mode/$stopby: the dialog was never closed by the shutdown path"; return 1; }
        [ -e "$dd/.agreed_to_tou" ] \
            && { fail "$mode/$stopby: a stop wrote the agreement file"; return 1; }
    else
        grep -q "$DIALOG_MARK" "$dd/debug.log" 2>/dev/null \
            && { fail "$mode/$stopby: the dialog opened on an already-agreed datadir"; return 1; }
    fi

    [ "$status" -eq 0 ] || { fail "$mode/$stopby: exited $status"; return 1; }
    pass "$mode/$stopby: exited 0 after ${waited}s"
    return 0
}

run_case "$WORK/agreed-sigterm" agreed sigterm
run_case "$WORK/fresh-sigterm"  fresh  sigterm
run_case "$WORK/fresh-stoprpc"  fresh  stop

[ "$FAILED" -eq 0 ] || { echo "probe: the wallet does not stop cleanly in every case"; exit 1; }
echo "probe: the wallet stops on SIGTERM and on the stop RPC, dialog or no dialog"
exit 0
