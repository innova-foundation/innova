#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Repeats `stop` and fails on the first non-zero exit; the run is rejected unless the
# finality voter thread started and logged its stop.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib/testports.sh"

INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
ITERATIONS="${SHUTDOWN_ITERATIONS:-3}"

iv5_ports_init shutdown_clean_exit || exit 1
RPCPORT=$(iv5_port 0 29740)
RPCPORT_B=$(iv5_port 1 29741)
P2PPORT_A=$(iv5_port 2 29742)
P2PPORT_B=$(iv5_port 3 29743)

WORKROOT="$(iv5_test_dir "${TMPDIR:-/tmp}/innova-shutdown-clean-exit")"
rm -rf "$WORKROOT"
mkdir -p "$WORKROOT"

NODE_PID=""
PID_A=""
PID_B=""
PID_AFTER=""
cleanup() {
    local p
    # By pid, never by name: other harnesses run their own daemons on this host.
    for p in "$NODE_PID" "$PID_A" "$PID_B" "$PID_AFTER"; do
        if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
            kill -KILL "$p" 2>/dev/null
        fi
    done
    iv5_ports_release
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

[ -x "$INNOVAD" ] || fail "no innovad at $INNOVAD (set INNOVAD)"
iv5_require_free_ports "$RPCPORT" "$RPCPORT_B" "$P2PPORT_A" "$P2PPORT_B" || exit 1

for i in $(seq 1 "$ITERATIONS"); do
    DATADIR="$WORKROOT/n$i"
    rm -rf "$DATADIR"
    mkdir -p "$DATADIR"
    {
        echo "rpcuser=shutdownuser"
        echo "rpcpassword=shutdownpass"
        echo "server=1"
        echo "listen=0"
        echo "dnsseed=0"
        echo "idns=0"
        echo "rpcport=$RPCPORT"
    } > "$DATADIR/innova.conf"

    "$INNOVAD" -datadir="$DATADIR" > "$DATADIR/node.out" 2>&1 &
    NODE_PID=$!

    up=0
    for _ in $(seq 1 60); do
        if "$INNOVAD" -datadir="$DATADIR" getinfo > /dev/null 2>&1; then
            up=1
            break
        fi
        kill -0 "$NODE_PID" 2>/dev/null || break
        sleep 2
    done
    [ "$up" = 1 ] || fail "iteration $i: the node never answered RPC"

    # The voter registers on the condition variable a few polls in; stopping
    # before it has slept once would not exercise the path at all.
    sleep 10

    "$INNOVAD" -datadir="$DATADIR" stop > /dev/null 2>&1
    wait "$NODE_PID"
    STATUS=$?
    NODE_PID=""

    LOG="$DATADIR/debug.log"
    [ -f "$LOG" ] || fail "iteration $i: no debug.log"

    grep -q "ThreadFinalityVoter started" "$LOG" \
        || fail "iteration $i: the voter thread never started; this run proves nothing"

    ORDER=$(awk '/ThreadFinalityVoter stopped/{v=NR} /Innova exited/{e=NR}
                 END{print (v>0 && e>0 && v<e) ? "ok" : "bad"}' "$LOG")

    if [ "$STATUS" -ne 0 ]; then
        echo "--- tail of $LOG"
        tail -15 "$LOG"
        echo "--- stderr"
        tail -5 "$DATADIR/node.out"
        fail "iteration $i: stop exited $STATUS (134 is the condition-variable abort)"
    fi
    [ "$ORDER" = ok ] \
        || fail "iteration $i: the voter did not report stopping before the process exited"

    echo "iteration $i: exit 0, voter stopped before exit"
done

echo "phase 1: $ITERATIONS clean shutdowns, voter drained on every one"

# ---------------------------------------------------------------------------
# Phase 2: peers connected, same datadir reused; abort damage shows on the next start.
# ---------------------------------------------------------------------------
rpc_a() { "$INNOVAD" -datadir="$WORKROOT/peer-a" -regtest -rpcport="$RPCPORT" "$@"; }
rpc_b() { "$INNOVAD" -datadir="$WORKROOT/peer-b" -regtest -rpcport="$RPCPORT_B" "$@"; }

write_peer_conf() {
    local dir="$1" rpcport="$2" p2pport="$3" peer="$4"
    mkdir -p "$dir"
    {
        echo "regtest=1"
        echo "rpcuser=shutdownuser"
        echo "rpcpassword=shutdownpass"
        echo "server=1"
        echo "listen=1"
        echo "dnsseed=0"
        echo "idns=0"
        echo "nobootstrap=1"
        echo "nosmsg=1"
        echo "upnp=0"
        echo "listenonion=0"
        echo "staking=0"
        echo "rpcport=$rpcport"
        echo "port=$p2pport"
        [ -n "$peer" ] && echo "addnode=127.0.0.1:$peer"
    } > "$dir/innova.conf"
}

write_peer_conf "$WORKROOT/peer-a" "$RPCPORT" "$P2PPORT_A" ""
write_peer_conf "$WORKROOT/peer-b" "$RPCPORT_B" "$P2PPORT_B" "$P2PPORT_A"

PEER_CYCLES="${SHUTDOWN_PEER_CYCLES:-3}"
LAST_HEIGHT=0
SAW_PEER=0
for c in $(seq 1 "$PEER_CYCLES"); do
    "$INNOVAD" -datadir="$WORKROOT/peer-a" -regtest > "$WORKROOT/peer-a/node.out" 2>&1 &
    PID_A=$!
    "$INNOVAD" -datadir="$WORKROOT/peer-b" -regtest > "$WORKROOT/peer-b/node.out" 2>&1 &
    PID_B=$!

    for _ in $(seq 1 60); do
        rpc_a getblockcount > /dev/null 2>&1 && rpc_b getblockcount > /dev/null 2>&1 && break
        sleep 2
    done
    rpc_a getblockcount > /dev/null 2>&1 || fail "cycle $c: node A never answered RPC"
    rpc_b getblockcount > /dev/null 2>&1 || fail "cycle $c: node B never answered RPC"

    # The datadir must carry forward, so give this cycle blocks to write and the
    # next one an index to load.
    rpc_a setgenerate true 2 1 > /dev/null 2>&1 || true
    sleep 3
    rpc_a setgenerate false 0 > /dev/null 2>&1 || true

    CONNS=$(rpc_a getconnectioncount 2>/dev/null | tr -d '"[:space:]')
    case "$CONNS" in ''|*[!0-9]*) CONNS=0;; esac
    [ "$CONNS" -ge 1 ] && SAW_PEER=1

    HEIGHT=$(rpc_a getblockcount 2>/dev/null | tr -d '"[:space:]')
    case "$HEIGHT" in ''|*[!0-9]*) fail "cycle $c: node A reported no height";; esac
    [ "$HEIGHT" -ge "$LAST_HEIGHT" ] \
        || fail "cycle $c: node A came back at height $HEIGHT, below the $LAST_HEIGHT it stopped at"
    LAST_HEIGHT="$HEIGHT"

    rpc_b stop > /dev/null 2>&1
    wait "$PID_B"; STATUS_B=$?
    rpc_a stop > /dev/null 2>&1
    wait "$PID_A"; STATUS_A=$?

    [ "$STATUS_A" -eq 0 ] || { tail -20 "$WORKROOT/peer-a/node.out"; fail "cycle $c: node A stop exited $STATUS_A ($CONNS peer(s) connected)"; }
    [ "$STATUS_B" -eq 0 ] || { tail -20 "$WORKROOT/peer-b/node.out"; fail "cycle $c: node B stop exited $STATUS_B"; }
    grep -qiE 'assertion|terminate called|segmentation fault' "$WORKROOT/peer-a/node.out" \
        && { tail -20 "$WORKROOT/peer-a/node.out"; fail "cycle $c: node A aborted during teardown"; }

    echo "cycle $c: both nodes exited 0 at height $HEIGHT with $CONNS peer(s) connected"
done
[ "$SAW_PEER" -eq 1 ] || fail "no cycle ever had a peer connected; this phase proved nothing"

# The damage an abort does is to the directory, so the reading is the reload.
"$INNOVAD" -datadir="$WORKROOT/peer-a" -regtest > "$WORKROOT/peer-a/node.out" 2>&1 &
PID_A=$!
RELOADED=""
for _ in $(seq 1 60); do
    RELOADED=$(rpc_a getblockcount 2>/dev/null | tr -d '"[:space:]')
    case "$RELOADED" in ''|*[!0-9]*) ;; *) break;; esac
    sleep 2
done
case "$RELOADED" in ''|*[!0-9]*) fail "node A did not reload the directory the cycles left";; esac
[ "$RELOADED" -eq "$LAST_HEIGHT" ] \
    || fail "node A reloaded at height $RELOADED, not the $LAST_HEIGHT it stopped at"
rpc_a stop > /dev/null 2>&1
wait "$PID_A" 2>/dev/null
echo "phase 2: $PEER_CYCLES peered cycles, directory reloaded at height $RELOADED"

# ---------------------------------------------------------------------------
# Phase 3: a start refused the datadir must not close unopened DBs or remove the pid file.
# ---------------------------------------------------------------------------
LOCKDIR="$WORKROOT/locked"
write_peer_conf "$LOCKDIR" "$RPCPORT" "$P2PPORT_A" ""
rpc_l() { "$INNOVAD" -datadir="$LOCKDIR" -regtest -rpcport="$RPCPORT" "$@"; }

"$INNOVAD" -datadir="$LOCKDIR" -regtest -daemon > "$LOCKDIR/daemon.out" 2>&1
for _ in $(seq 1 60); do
    rpc_l getblockcount > /dev/null 2>&1 && break
    sleep 2
done
rpc_l getblockcount > /dev/null 2>&1 || fail "the daemon under test never answered RPC"

PIDFILE="$LOCKDIR/regtest/innovad.pid"
[ -f "$PIDFILE" ] || PIDFILE="$LOCKDIR/innovad.pid"
[ -f "$PIDFILE" ] || fail "the daemon wrote no pid file; phase 3 cannot test what happens to it"
PID_BEFORE="$(tr -d '[:space:]' < "$PIDFILE")"

"$INNOVAD" -datadir="$LOCKDIR" -regtest -daemon > "$LOCKDIR/second.out" 2>&1
SECOND_STATUS=$?
[ "$SECOND_STATUS" -ne 0 ] || fail "a second start on a held directory reported success"
grep -qiE 'already running|cannot obtain a lock' "$LOCKDIR/second.out" \
    || { cat "$LOCKDIR/second.out"; fail "the second start failed for some other reason than the directory being held"; }

[ -f "$PIDFILE" ] || fail "the refused start deleted the running node's pid file"
PID_AFTER="$(tr -d '[:space:]' < "$PIDFILE")"
[ "$PID_AFTER" = "$PID_BEFORE" ] \
    || fail "the refused start rewrote the pid file: $PID_BEFORE became $PID_AFTER"
kill -0 "$PID_AFTER" 2>/dev/null || fail "the pid file names $PID_AFTER, which is not running"
rpc_l getblockcount > /dev/null 2>&1 || fail "the running node stopped answering after the refused start"
echo "phase 3: the refused start left pid $PID_AFTER and its directory alone"

# ---------------------------------------------------------------------------
# Phase 4: an idle RPC client; the handler wait must be bounded so the datadir lock is released.
# ---------------------------------------------------------------------------
exec 9<>"/dev/tcp/127.0.0.1/$RPCPORT" 2>/dev/null \
    || fail "could not open an idle connection to the RPC port"
sleep 2

STOP_START=$(date +%s)
rpc_l stop > /dev/null 2>&1
GONE=0
for _ in $(seq 1 90); do
    kill -0 "$PID_AFTER" 2>/dev/null || { GONE=1; break; }
    sleep 1
done
STOP_SECS=$(( $(date +%s) - STOP_START ))
exec 9<&- 2>/dev/null
exec 9>&- 2>/dev/null

[ "$GONE" -eq 1 ] || fail "the node was still running ${STOP_SECS}s after stop with an idle RPC client attached"
[ -f "$PIDFILE" ] && fail "the node exited but left its pid file behind"
echo "phase 4: stopped in ${STOP_SECS}s with an idle RPC client attached"

echo "PASS: clean exits, peered teardown, a refused start, and a stop under an idle RPC client"
