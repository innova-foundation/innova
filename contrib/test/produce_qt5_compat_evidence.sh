#!/bin/bash
# Produces qt5_compat_sha256: the Qt5 wallet still configures, compiles and passes
# its own test binary at the release's compatibility Qt version.
#
# The Qt version is read from qmake and recorded; a qmake that answers Qt6 is
# rejected rather than quietly producing a document titled qt5.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin qt5_compat_sha256
evidence_reuse && exit 0

QMAKE="${V5_QT5_QMAKE:-qmake}"
evidence_require_command make
evidence_require_command "$QMAKE" "set V5_QT5_QMAKE to the Qt5 qmake"
QT_VERSION="$("$QMAKE" -query QT_VERSION 2>/dev/null || echo unknown)"
case "$QT_VERSION" in
    5.*) ;;
    *) evidence_die "$QMAKE answers Qt $QT_VERSION; qt5_compat_sha256 needs a Qt5 qmake (V5_QT5_QMAKE)" ;;
esac
evidence_toolchain "$QMAKE $QT_VERSION, $(${CXX:-g++} --version 2>/dev/null | head -1)"
evidence_workdir

JOBS="${V5_EVIDENCE_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

# The shipped .pro carries the win32 link line; the Linux legs drop the
# cross-build libraries before configuring, exactly as .github/workflows/ci.yml does.
evidence_run "drop win32-only link libraries" \
    "sed -i.bak 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx\$\$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx\$\$BDB_LIB_SUFFIX/' innova-qt.pro && rm -f innova-qt.pro.bak"
evidence_run "configure the Qt test project" "$QMAKE -o Makefile.qt-tests innova-qt-test.pro"
evidence_run "build the Qt test binary" "make -f Makefile.qt-tests -j$JOBS"
evidence_run "run the Qt test binary" "./test_innova_qt"
evidence_run "configure the wallet" \
    "$QMAKE -o Makefile.qt-app USE_UPNP=1 USE_QRCODE=1 USE_NATIVETOR=- STRICT_WARNINGS=1 innova-qt.pro"
evidence_run "build the wallet" "make -f Makefile.qt-app -j$JOBS"

# The policy compares the manifest's declared Qt version, not the one this
# build actually used. Refuse to record evidence for a different toolchain,
# so a manifest cannot claim a version it was not built against.
PINNED_QT=$(sed -n 's/^COMPAT_QT_VERSION = "\(.*\)"/\1/p' \
    "$(dirname "$0")/check_v5_release_policy.py")
evidence_run "the toolchain matches the pinned Qt version" \
    "test \"$QT_VERSION\" = \"$PINNED_QT\""

evidence_observe qt_version "$QT_VERSION"
evidence_observe qmake "$QMAKE"
evidence_observe compiler_warnings "$(evidence_log_count 'warning:')"
evidence_observe qt_test_totals "$(evidence_log_count 'Totals:')"
evidence_observe qt_test_failures "$(evidence_log_count 'FAIL!')"
evidence_observe jobs "$JOBS"

evidence_require_zero "Qt test failures" "$(evidence_log_count 'FAIL!')"
[ -x "$EV_WORK/test_innova_qt" ] || evidence_finish fail "the Qt test binary is not where the build left it"

evidence_pass
