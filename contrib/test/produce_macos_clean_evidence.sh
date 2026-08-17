#!/bin/bash
# Produces macos_clean_sha256: a clean STRICT_WARNINGS makefile.osx build plus release-check,
# with binary digests. Darwin only; any other host fails and names the file to copy in.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin macos_clean_sha256
evidence_reuse && exit 0

evidence_require_kernel Darwin
evidence_require_command make
evidence_toolchain "$(${CXX:-clang++} --version 2>/dev/null | head -1)"
evidence_workdir

JOBS="${V5_EVIDENCE_JOBS:-$(sysctl -n hw.ncpu)}"
MAKE_ARGS="STRICT_WARNINGS=1 INNOVA_SPINNER=0 -f makefile.osx"

evidence_run "clean tree" "cd src && make $MAKE_ARGS clean"
evidence_run "daemon and test build" "cd src && make $MAKE_ARGS -j$JOBS innovad test_innova"
evidence_run "release-check aggregate" "cd src && make $MAKE_ARGS release-check"

CASES="$(grep -oE 'Running [0-9]+ test case' "$EV_LOG" | grep -oE '[0-9]+' | awk '{t+=$1} END{print t+0}')"
evidence_observe test_cases "$CASES"
evidence_observe aggregate_runs "$(evidence_log_count 'No errors detected')"
evidence_observe compiler_warnings "$(evidence_log_count 'warning:')"
evidence_observe jobs "$JOBS"
for binary in innovad test_innova; do
    [ -x "$EV_WORK/src/$binary" ] || evidence_finish fail "the build left no $binary"
    evidence_observe "${binary}_sha256" "$(shasum -a 256 "$EV_WORK/src/$binary" | awk '{print $1}')"
done

[ "$CASES" -gt 0 ] || evidence_finish fail "the aggregate reported no test cases"

evidence_pass
