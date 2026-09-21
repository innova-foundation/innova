#!/bin/bash
# Produces integration_sha256 by driving the release gate's integration phase, so the
# suites recorded are the suites the gate runs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin integration_sha256
evidence_reuse && exit 0

# No scratch copy: this builds nothing and has to use the daemon under test.
[ -x "$ROOT/src/innovad" ] || \
    evidence_die "build src/innovad before producing $EV_FIELD; the integration suites drive it"
# An unknown flag starts a node on the default datadir; --help prints the version and
# exits. Explicit datadir and a watchdog guard the probe.
VERSION_PROBE="$EV_DIR/.version-probe"
probe_version() {
    local pid i
    rm -rf "$VERSION_PROBE"
    mkdir -p "$VERSION_PROBE" || return 0
    "$ROOT/src/innovad" -datadir="$VERSION_PROBE" --help > "$VERSION_PROBE/version.txt" 2>/dev/null &
    pid=$!
    for i in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null || true
    head -1 "$VERSION_PROBE/version.txt" 2>/dev/null
}
evidence_toolchain "$(probe_version)"
evidence_observe innovad_sha256 \
    "$( { sha256sum "$ROOT/src/innovad" 2>/dev/null || shasum -a 256 "$ROOT/src/innovad"; } | awk '{print $1}')"

EXPECTED="$("$SCRIPT_DIR/v5_release_gate.sh" --print-suites | awk -F'\t' '$1=="executed" && $2=="integration"' | wc -l | tr -d ' ')"
[ "$EXPECTED" -gt 0 ] || evidence_die "the gate reports no integration suite to run"

evidence_run "release gate integration phase" "contrib/test/v5_release_gate.sh --integration"

RAN="$(evidence_log_count '^\[v5-release-gate\] running ')"
evidence_observe suites_expected "$EXPECTED"
evidence_observe suites_run "$RAN"
evidence_observe gate_passed "$(evidence_log_count 'integration gate passed')"

# The gate stops at the first failing suite, so a pass that ran fewer suites than
# the gate lists means the list and the run disagree.
[ "$RAN" = "$EXPECTED" ] || \
    evidence_finish fail "the gate ran $RAN of $EXPECTED integration suites"
[ "$(evidence_log_count 'integration gate passed')" = "1" ] || \
    evidence_finish fail "the gate did not report its integration phase as passed"

# Suites report SKIP on unmet preconditions and still pass, so count the skips.
SKIPPED="$(evidence_log_count '\[SKIP\]')"
evidence_observe assertions_skipped "$SKIPPED"
[ "$SKIPPED" = "0" ] || \
    evidence_finish fail "the integration phase skipped $SKIPPED assertion(s); \
the evidence would record a pass for cases that never ran"

evidence_pass
