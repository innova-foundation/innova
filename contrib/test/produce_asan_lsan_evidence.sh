#!/bin/bash
# Produces asan_lsan_sha256: a clean ASan/LSan build and the full release-check
# aggregate with zero sanitizer findings, using the CI sanitizer leg's commands.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin asan_lsan_sha256
evidence_reuse && exit 0

evidence_require_kernel Linux
evidence_require_command make
evidence_toolchain "$(${CXX:-g++} --version 2>/dev/null | head -1)"
evidence_workdir

JOBS="${V5_EVIDENCE_JOBS:-$(nproc)}"
MAKE_ARGS="USE_NATIVETOR=- USE_IPFS=- INNOVA_SPINNER=0 -f makefile.unix"
SAN_ARGS="SANITIZE=address CXXFLAGS=\"-O1 -Werror=return-type -Werror=format\" CFLAGS=\"-O1 -Werror=return-type -Werror=format\""
# halt_on_error/abort_on_error make a finding kill the run instead of being
# reported and survived, which is the only way `make` sees it.
SAN_ENV="ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1"

evidence_run "clean tree" "cd src && make $MAKE_ARGS clean"
evidence_run "sanitizer build" "cd src && $SAN_ENV make $MAKE_ARGS $SAN_ARGS -j$JOBS innovad test_innova"
evidence_run "release-check aggregate" "cd src && $SAN_ENV make $MAKE_ARGS $SAN_ARGS release-check"

CASES="$(grep -oE 'Running [0-9]+ test case' "$EV_LOG" | grep -oE '[0-9]+' | awk '{t+=$1} END{print t+0}')"
FINDINGS="$(evidence_log_count 'ERROR: (Address|Leak)Sanitizer|SUMMARY: (Address|Leak)Sanitizer|detected memory leaks')"
evidence_observe test_cases "$CASES"
evidence_observe sanitizer_findings "$FINDINGS"
evidence_observe aggregate_runs "$(evidence_log_count 'No errors detected')"
evidence_observe sanitizer "address+leak"
evidence_observe jobs "$JOBS"

evidence_require_zero "sanitizer findings" "$FINDINGS"
# A green aggregate that ran no case is the failure mode a pass/fail status hides.
[ "$CASES" -gt 0 ] || evidence_finish fail "the aggregate reported no test cases"

evidence_pass
