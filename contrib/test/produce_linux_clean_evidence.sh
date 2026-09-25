#!/bin/bash
# Produces linux_clean_sha256: a clean Linux build of the daemon and the test
# binary under the network-input warning gates, plus the full release-check
# aggregate, and the digests of the two binaries it produced.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin linux_clean_sha256
evidence_reuse && exit 0

evidence_require_kernel Linux
evidence_require_command make
evidence_toolchain "$(${CXX:-g++} --version 2>/dev/null | head -1)"
evidence_workdir

JOBS="${V5_EVIDENCE_JOBS:-$(nproc)}"
MAKE_ARGS="USE_NATIVETOR=- INNOVA_SPINNER=0 -f makefile.unix"
WARN_ARGS="CXXFLAGS=\"-Werror=return-type -Werror=format\" CFLAGS=\"-Werror=return-type -Werror=format\""

evidence_run "clean tree" "cd src && make $MAKE_ARGS clean"
evidence_run "daemon and test build" "cd src && make $MAKE_ARGS $WARN_ARGS -j$JOBS innovad test_innova"
evidence_run "release-check aggregate" "cd src && make $MAKE_ARGS $WARN_ARGS release-check"

CASES="$(grep -oE 'Running [0-9]+ test case' "$EV_LOG" | grep -oE '[0-9]+' | awk '{t+=$1} END{print t+0}')"
evidence_observe test_cases "$CASES"
evidence_observe aggregate_runs "$(evidence_log_count 'No errors detected')"
evidence_observe compiler_warnings "$(evidence_log_count 'warning:')"
evidence_observe jobs "$JOBS"
for binary in innovad test_innova; do
    [ -x "$EV_WORK/src/$binary" ] || evidence_finish fail "the build left no $binary"
    evidence_observe "${binary}_sha256" "$(sha256sum "$EV_WORK/src/$binary" | awk '{print $1}')"
    evidence_observe "${binary}_build_desc" \
        "$(LC_ALL=C grep -a -o -m1 '[0-9a-f]\{6,16\}-commit-[0-9a-f]\{40\}\(-dirty\)\{0,1\}' \
            "$EV_WORK/src/$binary" || echo unreadable)"
done

[ "$CASES" -gt 0 ] || evidence_finish fail "the aggregate reported no test cases"

evidence_pass
