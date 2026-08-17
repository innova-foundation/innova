#!/bin/bash
# Produces ubsan_sha256: a clean UBSan build and the full release-check aggregate.
# UBSan continues after a report, so the runtime-error count is the check, not exit status.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin ubsan_sha256
evidence_reuse && exit 0

evidence_require_kernel Linux
evidence_require_command make
evidence_toolchain "$(${CXX:-g++} --version 2>/dev/null | head -1)"
evidence_workdir

JOBS="${V5_EVIDENCE_JOBS:-$(nproc)}"
MAKE_ARGS="USE_NATIVETOR=- USE_IPFS=- INNOVA_SPINNER=0 -f makefile.unix"
SAN_ARGS="SANITIZE=undefined CXXFLAGS=\"-O1 -Werror=return-type -Werror=format\" CFLAGS=\"-O1 -Werror=return-type -Werror=format\""
SAN_ENV="UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"

evidence_run "clean tree" "cd src && make $MAKE_ARGS clean"
evidence_run "sanitizer build" "cd src && $SAN_ENV make $MAKE_ARGS $SAN_ARGS -j$JOBS innovad test_innova"
evidence_run "release-check aggregate" "cd src && $SAN_ENV make $MAKE_ARGS $SAN_ARGS release-check"

CASES="$(grep -oE 'Running [0-9]+ test case' "$EV_LOG" | grep -oE '[0-9]+' | awk '{t+=$1} END{print t+0}')"
FINDINGS="$(evidence_log_count 'runtime error:|SUMMARY: UndefinedBehaviorSanitizer')"
evidence_observe test_cases "$CASES"
evidence_observe sanitizer_findings "$FINDINGS"
evidence_observe aggregate_runs "$(evidence_log_count 'No errors detected')"
evidence_observe sanitizer "undefined"
evidence_observe jobs "$JOBS"

evidence_require_zero "undefined-behaviour diagnostics" "$FINDINGS"
[ "$CASES" -gt 0 ] || evidence_finish fail "the aggregate reported no test cases"

evidence_pass
