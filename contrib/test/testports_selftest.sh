#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Self-test for contrib/test/lib/testports.sh. Every check has a negative control
# that must fail if the mechanism is absent.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"

PASSED=0
FAILED=0
pass() { echo "[PASS] $*"; PASSED=$((PASSED + 1)); }
fail() { echo "[FAIL] $*"; FAILED=$((FAILED + 1)); }

HOLDERS=()
SLEEPERS=()

cleanup() {
    local pid
    for pid in "${HOLDERS[@]:-}" "${SLEEPERS[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    iv5_ports_release
    rm -rf "$LOCKROOT" 2>/dev/null || true
}
trap cleanup EXIT

LOCKROOT="$(mktemp -d "${TMPDIR:-/tmp}/testports-selftest.XXXXXX")"
IV5_TEST_PORT_LOCKROOT="$LOCKROOT"

# Hold a TCP listener on a port until killed. Sets HOLD_PID.
# Both stdio ends are detached: a background child that keeps the write end of a
# command-substitution pipe open would block the caller until it exits.
hold_port() {
    local port="$1"
    # Accept and drop in a loop, the way a real daemon does. A listener that
    # never accepts fills its backlog after the first probe and then looks
    # closed to every probe after it.
    python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $port))
s.listen(64)
s.settimeout(600)
while True:
    try:
        c, _ = s.accept()
        c.close()
    except OSError:
        break
" >/dev/null 2>&1 &
    HOLD_PID=$!
    HOLDERS+=("$HOLD_PID")
    local i
    for ((i = 0; i < 50; i++)); do
        iv5_port_listening "$port" && return 0
        sleep 0.1
    done
    kill -9 "$HOLD_PID" 2>/dev/null
    HOLD_PID=""
    return 1
}

echo "=== 1. unset base preserves historical literals ==="
unset IV5_TEST_PORT_BASE
iv5_ports_init selftest_legacy >/dev/null 2>&1
[ "$(iv5_port 0 27445)" = "27445" ] && pass "slot 0 returns its historical default" \
    || fail "slot 0 changed with no base set: $(iv5_port 0 27445)"
[ "$(iv5_port 3 27448)" = "27448" ] && pass "slot 3 returns its historical default" \
    || fail "slot 3 changed with no base set"
# Negative control: the same call must NOT return the default once a base is set.
IV5_TEST_PORT_BASE=41000 iv5_ports_init x >/dev/null 2>&1
IV5_TEST_PORT_BASE=41000
iv5_ports_init selftest_explicit >/dev/null 2>&1
[ "$(iv5_port 0 27445)" != "27445" ] && pass "negative control: default is NOT returned once a base is set" \
    || fail "negative control failed: base was ignored, defaults still returned"

echo
echo "=== 2. explicit base is honoured exactly ==="
[ "$(iv5_port 0 27445)" = "41000" ] && pass "slot 0 -> base+0" || fail "slot 0 -> $(iv5_port 0 27445), want 41000"
[ "$(iv5_port 7 27445)" = "41007" ] && pass "slot 7 -> base+7" || fail "slot 7 -> $(iv5_port 7 27445), want 41007"
iv5_port 999 27445 >/dev/null 2>&1 && fail "a slot past the window was accepted" \
    || pass "negative control: a slot past the window is rejected"

echo
echo "=== 3. auto allocation takes a free window ==="
unset IV5_TEST_PORT_BASE
IV5_TEST_PORT_BASE=auto
IV5_TEST_PORT_AUTO_MIN=45000
IV5_TEST_PORT_AUTO_MAX=46000
iv5_ports_init selftest_auto >/dev/null 2>&1
FIRST_BASE="$IV5_PORT_BASE_RESOLVED"
[ -n "$FIRST_BASE" ] && pass "auto resolved a base ($FIRST_BASE)" || fail "auto resolved no base"
[ -d "$IV5_PORT_LOCK" ] && pass "auto took a lock directory" || fail "auto took no lock"

echo
echo "=== 4. auto skips a window that is actually occupied ==="
# Occupy the first candidate window, then re-run auto in a clean lock root and
# assert it lands somewhere else. Without the liveness probe it would return the
# occupied base.
iv5_ports_release
rm -rf "$LOCKROOT"; mkdir -p "$LOCKROOT"
HOLD_PID=""
hold_port 45000
if [ -n "$HOLD_PID" ]; then
    pass "held 45000 with a real listener"
    iv5_ports_init selftest_auto_skip >/dev/null 2>&1
    if [ -n "$IV5_PORT_BASE_RESOLVED" ] && [ "$IV5_PORT_BASE_RESOLVED" != "45000" ]; then
        pass "auto skipped the occupied window (chose $IV5_PORT_BASE_RESOLVED)"
    else
        fail "auto handed out an occupied window: $IV5_PORT_BASE_RESOLVED"
    fi
else
    fail "could not hold a port for the negative control"
fi

echo
echo "=== 5. a held port is reported as held, not as a node that failed to start ==="
if iv5_require_free_ports 45000 >/dev/null 2>&1; then
    fail "require_free_ports passed on a port with a live listener"
else
    pass "negative control: require_free_ports fails on a held port"
fi
if iv5_require_free_ports "$((IV5_PORT_BASE_RESOLVED + 1))" >/dev/null 2>&1; then
    pass "require_free_ports passes on a free port"
else
    fail "require_free_ports failed on a free port"
fi

echo
echo "=== 6. two concurrent allocations never share a window ==="
iv5_ports_release
rm -rf "$LOCKROOT"; mkdir -p "$LOCKROOT"
claim_window() {
    # Claims a window and holds it while its pid stays alive, writing the base
    # to $1. Runs detached so the two claimants overlap in time.
    local out="$1"
    bash -c "
        source '$SCRIPT_DIR/lib/testports.sh'
        IV5_TEST_PORT_LOCKROOT='$LOCKROOT'
        IV5_TEST_PORT_BASE=auto
        IV5_TEST_PORT_AUTO_MIN=47000
        IV5_TEST_PORT_AUTO_MAX=48000
        iv5_ports_init claimant >/dev/null 2>&1
        echo \$IV5_PORT_BASE_RESOLVED > '$out'
        sleep 6
    " >/dev/null 2>&1 &
    SLEEPERS+=("$!")
}

claim_window "$LOCKROOT/../a.base"
claim_window "$LOCKROOT/../b.base"
for _ in $(seq 1 40); do
    [ -s "$LOCKROOT/../a.base" ] && [ -s "$LOCKROOT/../b.base" ] && break
    sleep 0.25
done
A_BASE="$(cat "$LOCKROOT/../a.base" 2>/dev/null || true)"
B_BASE="$(cat "$LOCKROOT/../b.base" 2>/dev/null || true)"
if [ -n "$A_BASE" ] && [ -n "$B_BASE" ] && [ "$A_BASE" != "$B_BASE" ]; then
    pass "concurrent runs claimed distinct windows ($A_BASE, $B_BASE)"
else
    fail "concurrent runs claimed '$A_BASE' and '$B_BASE'; they would collide"
fi
rm -f "$LOCKROOT/../a.base" "$LOCKROOT/../b.base" 2>/dev/null || true

echo
echo "=== 7. teardown never signals a non-daemon that matches the pattern ==="
# Regression: a runner whose argv carries both 'innovad' and the harness name must not be
# killed by teardown. The decoy has that argv shape; teardown matches by image.
DECOY_TAG="selftest_milestone_$$"
bash -c "exec -a 'env INNOVAD=/opt/innova/src/innovad bash /opt/t/${DECOY_TAG}.sh' sleep 300" &
DECOY=$!
SLEEPERS+=("$DECOY")
sleep 1
if ! kill -0 "$DECOY" 2>/dev/null; then
    fail "could not stand up the decoy process"
else
    iv5_kill_daemons "innovad.*${DECOY_TAG}" TERM
    sleep 1
    if kill -0 "$DECOY" 2>/dev/null; then
        pass "iv5_kill_daemons left the non-daemon runner alive"
    else
        fail "iv5_kill_daemons killed a process that is not innovad"
    fi
    # Negative control: the pattern really does match, so the old pkill would
    # have hit it. If pgrep finds nothing the check above proves nothing.
    if pgrep -f -- "innovad.*${DECOY_TAG}" >/dev/null 2>&1; then
        pass "negative control: the pattern does match the decoy (old pkill would have killed it)"
    else
        fail "negative control void: the decoy does not match the pattern"
    fi
    kill -9 "$DECOY" 2>/dev/null
fi

echo
echo "=== 8. iv5_test_dir separates scratch roots per window ==="
unset IV5_TEST_PORT_BASE
IV5_PORT_BASE_RESOLVED=""
[ "$(iv5_test_dir /tmp/x)" = "/tmp/x" ] && pass "unset base keeps the historical scratch path" \
    || fail "scratch path changed with no base set"
IV5_PORT_BASE_RESOLVED=41000
[ "$(iv5_test_dir /tmp/x)" = "/tmp/x_p41000" ] && pass "a base suffixes the scratch path" \
    || fail "scratch path not separated per window"

echo
echo "================================"
echo "  passed: $PASSED  failed: $FAILED"
echo "================================"
[ "$FAILED" -eq 0 ]
