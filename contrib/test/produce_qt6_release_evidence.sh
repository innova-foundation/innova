#!/bin/bash
# Produces qt6_release_sha256: a Qt6 USE_NATIVETOR=1 release build, rejecting a Qt5 qmake,
# run offscreen so an unresolved SIGNAL()/connectSlotsByName connection fails the run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin qt6_release_sha256
evidence_reuse && exit 0

QMAKE="${V5_QT6_QMAKE:-qmake6}"
evidence_require_command make
evidence_require_command nm "the linked binary is checked with nm, not with exit status"
evidence_require_command "$QMAKE" "set V5_QT6_QMAKE to the Qt6 qmake"
QT_VERSION="$("$QMAKE" -query QT_VERSION 2>/dev/null || echo unknown)"
case "$QT_VERSION" in
    6.*) ;;
    *) evidence_die "$QMAKE answers Qt $QT_VERSION; qt6_release_sha256 needs a Qt6 qmake (V5_QT6_QMAKE)" ;;
esac
evidence_toolchain "$QMAKE $QT_VERSION, $(${CXX:-g++} --version 2>/dev/null | head -1)"
evidence_workdir

JOBS="${V5_EVIDENCE_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

# Static first: it names the file and line, which the runtime probe cannot.
evidence_run "reject Qt6 removed-signal connections" \
    "python3 contrib/test/check_qt6_removed_signals.py ."

# The shipped .pro carries the win32 link line; the Linux legs drop the
# cross-build libraries before configuring, exactly as .github/workflows/ci.yml does.
evidence_run "drop win32-only link libraries" \
    "sed -i.bak 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx\$\$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx\$\$BDB_LIB_SUFFIX/' innova-qt.pro && rm -f innova-qt.pro.bak"
evidence_run "configure the Qt test project" "$QMAKE -o Makefile.qt-tests innova-qt-test.pro"
evidence_run "build the Qt test binary" "make -f Makefile.qt-tests -j$JOBS"
evidence_run "run the Qt test binary" "QT_QPA_PLATFORM=offscreen ./test_innova_qt"
evidence_run "configure the wallet with the bundled Tor" \
    "$QMAKE -o Makefile.qt-app USE_UPNP=1 USE_QRCODE=1 USE_NATIVETOR=1 STRICT_WARNINGS=1 innova-qt.pro"

# A Makefile that mentions Qt5 configured against the wrong toolchain, whatever
# qmake answered.
evidence_run "refuse a Qt5 reference in the generated makefile" \
    "! grep -q 'Qt5' Makefile.qt-app"
evidence_run "build the wallet" "make -f Makefile.qt-app -j$JOBS"
evidence_run "the wallet links Qt6 and no Qt5" \
    "ldd ./Innova | grep -q libQt6Core && ! ldd ./Innova | grep -q libQt5"
# USE_NATIVETOR=1 must actually link Tor symbols, not just be selected.
evidence_run "the wallet carries the bundled Tor" \
    "test \"\$(nm -C ./Innova | grep -c -E ' (T|t) (tor_main|tor_tls_)')\" -gt 0"
evidence_run "build the widget tree and resolve every connection" \
    "contrib/test/qt_connect_probe.sh ./Innova \"\$PWD/qt-connect-probe\" \"\$PWD/qt-connect-probe.stderr.log\""

# The policy checks the manifest's declared Qt version, so refuse evidence from
# any other toolchain version.
PINNED_QT=$(sed -n 's/^RELEASE_QT_VERSION = "\(.*\)"/\1/p' \
    "$(dirname "$0")/check_v5_release_policy.py")
evidence_run "the toolchain matches the pinned Qt version" \
    "test \"$QT_VERSION\" = \"$PINNED_QT\""

evidence_observe qt_version "$QT_VERSION"
evidence_observe qmake "$QMAKE"
evidence_observe native_tor "1"
evidence_observe tor_symbols "$(nm -C "$EV_WORK/Innova" 2>/dev/null | grep -c -E ' (T|t) (tor_main|tor_tls_)' || echo 0)"
evidence_observe wallet_sha256 "$( (sha256sum "$EV_WORK/Innova" 2>/dev/null || shasum -a 256 "$EV_WORK/Innova") | cut -d' ' -f1)"
evidence_observe wallet_bytes "$(wc -c < "$EV_WORK/Innova" | tr -d ' ')"
evidence_observe compiler_warnings "$(evidence_log_count 'warning:')"
evidence_observe qt_test_totals "$(evidence_log_count 'Totals:')"
evidence_observe qt_test_failures "$(evidence_log_count 'FAIL!')"
evidence_observe unresolved_connections "$(evidence_log_count 'No such signal|No such slot|No matching signal')"
evidence_observe jobs "$JOBS"

evidence_require_zero "Qt test failures" "$(evidence_log_count 'FAIL!')"
[ -x "$EV_WORK/Innova" ] || evidence_finish fail "the wallet is not where the build left it"
[ -x "$EV_WORK/test_innova_qt" ] || evidence_finish fail "the Qt test binary is not where the build left it"

evidence_pass
