#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Port allocation and daemon teardown for harnesses (sourced). IV5_TEST_PORT_BASE unset
# keeps literals, <n> binds <n>+slot, auto locks a free window; use iv5_port <slot> <default>.

# Guard against double-sourcing.
if [ -n "${IV5_TESTPORTS_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
IV5_TESTPORTS_SOURCED=1

# Slots reserved per harness when a base is in effect. Wide enough for the
# largest fleet a harness builds (nodes x {p2p, rpc, idns}) plus headroom.
IV5_TEST_PORT_WINDOW="${IV5_TEST_PORT_WINDOW:-64}"

# Auto-allocation searches above every historical literal (highest is 29xxx) and
# below the ephemeral range most kernels hand out.
IV5_TEST_PORT_AUTO_MIN="${IV5_TEST_PORT_AUTO_MIN:-40000}"
IV5_TEST_PORT_AUTO_MAX="${IV5_TEST_PORT_AUTO_MAX:-59000}"

IV5_TEST_PORT_LOCKROOT="${IV5_TEST_PORT_LOCKROOT:-${TMPDIR:-/tmp}/innova-testports}"

# Resolved by iv5_ports_init. Empty means "use the historical literals".
IV5_PORT_BASE_RESOLVED=""
IV5_PORT_LOCK=""
IV5_PORT_HARNESS=""

iv5_ports_log() { echo "[ports] $*" >&2; }

# True when something is listening on 127.0.0.1:$1.
# /dev/tcp is a bash builtin, so this needs no lsof, nc or ss.
iv5_port_listening() {
    local port="$1"
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || return 1
    exec 3<&- 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    return 0
}

# Best-effort description of who holds a port. Advisory only.
iv5_port_holder() {
    local port="$1"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | tail -n +2 | head -1
    fi
}

# Fail the harness with the real reason rather than letting it time out waiting
# for an RPC that will never answer.
iv5_require_free_ports() {
    local port held=0 holder
    for port in "$@"; do
        [ -n "$port" ] || continue
        if iv5_port_listening "$port"; then
            holder="$(iv5_port_holder "$port")"
            iv5_ports_log "port $port is already in use${holder:+ by: $holder}"
            held=1
        fi
    done
    if [ "$held" -ne 0 ]; then
        iv5_ports_log "refusing to start: ${IV5_PORT_HARNESS:-harness} needs the ports above."
        iv5_ports_log "run with IV5_TEST_PORT_BASE=auto to take a free window instead."
        return 1
    fi
    return 0
}

iv5_window_free() {
    local base="$1" k
    for ((k = 0; k < IV5_TEST_PORT_WINDOW; k++)); do
        iv5_port_listening $((base + k)) && return 1
    done
    return 0
}

# Claim a free window. The claim is a lock directory holding the claimant pid,
# so a crashed harness releases its window without any trap running.
iv5_alloc_window() {
    local base owner
    mkdir -p "$IV5_TEST_PORT_LOCKROOT" 2>/dev/null || true
    for ((base = IV5_TEST_PORT_AUTO_MIN;
          base + IV5_TEST_PORT_WINDOW <= IV5_TEST_PORT_AUTO_MAX;
          base += IV5_TEST_PORT_WINDOW)); do
        if [ -d "$IV5_TEST_PORT_LOCKROOT/$base" ]; then
            owner="$(cat "$IV5_TEST_PORT_LOCKROOT/$base/pid" 2>/dev/null || true)"
            if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
                continue
            fi
            rm -rf "$IV5_TEST_PORT_LOCKROOT/$base" 2>/dev/null || true
        fi
        mkdir "$IV5_TEST_PORT_LOCKROOT/$base" 2>/dev/null || continue
        echo "$$" > "$IV5_TEST_PORT_LOCKROOT/$base/pid"
        echo "${IV5_PORT_HARNESS:-unknown}" > "$IV5_TEST_PORT_LOCKROOT/$base/harness"
        if iv5_window_free "$base"; then
            IV5_PORT_BASE_RESOLVED="$base"
            IV5_PORT_LOCK="$IV5_TEST_PORT_LOCKROOT/$base"
            return 0
        fi
        rm -rf "$IV5_TEST_PORT_LOCKROOT/$base" 2>/dev/null || true
    done
    return 1
}

iv5_ports_release() {
    [ -n "$IV5_PORT_LOCK" ] || return 0
    rm -rf "$IV5_PORT_LOCK" 2>/dev/null || true
    IV5_PORT_LOCK=""
}

# iv5_ports_init <harness-name>
# Resolves the port base once. Safe to call more than once.
iv5_ports_init() {
    IV5_PORT_HARNESS="${1:-harness}"
    local requested="${IV5_TEST_PORT_BASE:-}"
    case "$requested" in
        "")
            IV5_PORT_BASE_RESOLVED=""
            ;;
        auto|AUTO)
            if iv5_alloc_window; then
                iv5_ports_log "$IV5_PORT_HARNESS: allocated port window $IV5_PORT_BASE_RESOLVED-$((IV5_PORT_BASE_RESOLVED + IV5_TEST_PORT_WINDOW - 1))"
            else
                iv5_ports_log "$IV5_PORT_HARNESS: no free port window in $IV5_TEST_PORT_AUTO_MIN-$IV5_TEST_PORT_AUTO_MAX"
                return 1
            fi
            ;;
        *[!0-9]*)
            iv5_ports_log "IV5_TEST_PORT_BASE must be a number or 'auto', got: $requested"
            return 1
            ;;
        *)
            IV5_PORT_BASE_RESOLVED="$requested"
            iv5_ports_log "$IV5_PORT_HARNESS: using port window $IV5_PORT_BASE_RESOLVED-$((IV5_PORT_BASE_RESOLVED + IV5_TEST_PORT_WINDOW - 1))"
            ;;
    esac
    return 0
}

# iv5_port <slot> <historical-default>
# The historical default is what the harness bound before this library existed;
# with no base configured it is returned unchanged, so behaviour is unchanged.
iv5_port() {
    local slot="$1" legacy="$2"
    if [ -z "$IV5_PORT_BASE_RESOLVED" ]; then
        echo "$legacy"
        return 0
    fi
    if [ "$slot" -ge "$IV5_TEST_PORT_WINDOW" ] 2>/dev/null; then
        iv5_ports_log "slot $slot exceeds IV5_TEST_PORT_WINDOW=$IV5_TEST_PORT_WINDOW"
        return 1
    fi
    echo $((IV5_PORT_BASE_RESOLVED + slot))
}

# A per-run scratch root, so two concurrent runs never share a datadir either.
# Unset base keeps the caller's historical path.
iv5_test_dir() {
    local legacy="$1"
    if [ -z "$IV5_PORT_BASE_RESOLVED" ]; then
        echo "$legacy"
    else
        echo "${legacy}_p${IV5_PORT_BASE_RESOLVED}"
    fi
}

# ---------------------------------------------------------------------------
# Daemon teardown: match on the process image, not pkill -f, which also matches
# runners like `env INNOVAD=... bash <name>_test.sh`.
iv5_daemon_pids() {
    local needle="$1" pid comm
    for pid in $(pgrep -f -- "$needle" 2>/dev/null); do
        [ "$pid" = "$$" ] && continue
        comm="$(ps -o comm= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
        case "${comm##*/}" in
            innovad|innovad.exe|innova-qt) echo "$pid" ;;
        esac
    done
}

# iv5_kill_daemons <argv-substring> [signal]
iv5_kill_daemons() {
    local needle="$1" sig="${2:-TERM}" pid
    for pid in $(iv5_daemon_pids "$needle"); do
        kill "-$sig" "$pid" 2>/dev/null || true
    done
    return 0
}

# iv5_wait_daemons_gone <argv-substring> [seconds]
iv5_wait_daemons_gone() {
    local needle="$1" limit="${2:-60}" i
    for ((i = 0; i < limit; i++)); do
        [ -z "$(iv5_daemon_pids "$needle")" ] && return 0
        sleep 1
    done
    return 1
}

# iv5_stop_daemons <argv-substring> [grace-seconds]
# TERM, wait, then KILL. The common teardown every harness wants.
iv5_stop_daemons() {
    local needle="$1" grace="${2:-20}"
    iv5_kill_daemons "$needle" TERM
    iv5_wait_daemons_gone "$needle" "$grace" && return 0
    iv5_kill_daemons "$needle" KILL
    iv5_wait_daemons_gone "$needle" 10
}
