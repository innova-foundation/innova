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
evidence_toolchain "$("$ROOT/src/innovad" --version 2>/dev/null | head -1 || echo 'innovad (version unavailable)')"
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

evidence_pass
