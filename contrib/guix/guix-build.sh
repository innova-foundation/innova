#!/usr/bin/env bash
# Copyright (c) 2019-2026 The Innova developers
# Guix Reproducible Build Script
#
# Builds Innova daemon (and optionally Qt wallet) in a reproducible
# Guix environment. All dependencies come from the manifest, ensuring
# identical output across machines.
#
# Usage:
#   ./contrib/guix/guix-build.sh [targets...]
#   Targets: linux-x86_64 (default), linux-aarch64, linux-armhf, all
#
# Prerequisites:
#   - GNU Guix installed (https://guix.gnu.org/manual/en/html_node/Installation.html)
#   - guix-daemon running
#
# Environment:
#   SOURCE_DATE_EPOCH — override timestamp for deterministic builds (default: git commit time)
#   JOBS              — parallel build jobs (default: nproc)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$SCRIPT_DIR/manifest.scm"
OUTPUT_DIR="$INNOVA_ROOT/output"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

# Reproducible timestamp: use git commit time or epoch 0
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$INNOVA_ROOT" log -1 --format=%ct 2>/dev/null || echo 0)
fi
export SOURCE_DATE_EPOCH

echo "=== Innova Guix Reproducible Build ==="
echo "Source root:        $INNOVA_ROOT"
echo "Manifest:           $MANIFEST"
echo "SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH"
echo "Parallel jobs:      $JOBS"
echo ""

# Parse targets
TARGETS="${*:-linux-x86_64}"
if [ "$TARGETS" = "all" ]; then
    TARGETS="linux-x86_64"
    # Future: linux-aarch64 linux-armhf win64 macos-arm64
fi

mkdir -p "$OUTPUT_DIR"

build_linux_x86_64() {
    echo "=== Building: linux-x86_64 daemon ==="
    guix shell --manifest="$MANIFEST" --container --network \
        --share="$INNOVA_ROOT"=/build \
        -- bash -c "
            set -e
            cd /build/src

            # Ensure deterministic build
            export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
            export TZ=UTC
            export LC_ALL=C

            # Clean previous build
            make -f makefile.unix clean 2>/dev/null || true

            # Build daemon
            make USE_NATIVETOR=- USE_IPFS=- -f makefile.unix -j$JOBS

            echo 'Daemon build complete.'
        "

    # Copy output
    cp "$INNOVA_ROOT/src/innovad" "$OUTPUT_DIR/innovad-linux-x86_64"
    strip "$OUTPUT_DIR/innovad-linux-x86_64" 2>/dev/null || true
    echo "Output: $OUTPUT_DIR/innovad-linux-x86_64"

    echo ""
    echo "=== Building: linux-x86_64 Qt wallet ==="
    guix shell --manifest="$MANIFEST" --container --network \
        --share="$INNOVA_ROOT"=/build \
        -- bash -c "
            set -e
            cd /build

            export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
            export TZ=UTC
            export LC_ALL=C

            # Fix Linux-specific link flags
            sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx\$\$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx\$\$BDB_LIB_SUFFIX/' innova-qt.pro 2>/dev/null || true

            # Build Qt wallet
            qmake USE_UPNP=1 USE_QRCODE=1 USE_NATIVETOR=- USE_IPFS=- innova-qt.pro
            make -j$JOBS

            echo 'Qt wallet build complete.'
        " || echo "WARN: Qt wallet build failed (may need Qt5 in manifest)"

    # Copy Qt output if it exists
    if [ -f "$INNOVA_ROOT/Innova" ]; then
        cp "$INNOVA_ROOT/Innova" "$OUTPUT_DIR/Innova-linux-x86_64"
        strip "$OUTPUT_DIR/Innova-linux-x86_64" 2>/dev/null || true
        echo "Output: $OUTPUT_DIR/Innova-linux-x86_64"
    fi
}

# Build each target
for TARGET in $TARGETS; do
    case "$TARGET" in
        linux-x86_64)
            build_linux_x86_64
            ;;
        linux-aarch64)
            echo "WARN: linux-aarch64 cross-compilation not yet implemented in Guix"
            echo "      Requires cross-toolchain packages in manifest.scm"
            ;;
        linux-armhf)
            echo "WARN: linux-armhf cross-compilation not yet implemented in Guix"
            echo "      Requires cross-toolchain packages in manifest.scm"
            ;;
        win64)
            echo "WARN: Windows cross-compilation not yet implemented in Guix"
            echo "      Requires mingw-w64 toolchain and Windows SDK in manifest"
            ;;
        macos-arm64)
            echo "WARN: macOS cross-compilation not yet implemented in Guix"
            echo "      Requires macOS SDK and cross-toolchain in manifest"
            ;;
        *)
            echo "ERROR: Unknown target: $TARGET"
            echo "Valid targets: linux-x86_64, linux-aarch64, linux-armhf, win64, macos-arm64, all"
            exit 1
            ;;
    esac
done

# Generate SHA256SUMS
echo ""
echo "=== Generating SHA256SUMS ==="
cd "$OUTPUT_DIR"
if [ -n "$(ls 2>/dev/null)" ]; then
    sha256sum * > SHA256SUMS 2>/dev/null || shasum -a 256 * > SHA256SUMS
    echo ""
    cat SHA256SUMS
    echo ""
    echo "=== Reproducible build complete ==="
    echo "Output directory: $OUTPUT_DIR"
    echo ""
    echo "To verify reproducibility, run this script again and compare SHA256SUMS."
    echo "Identical hashes confirm deterministic builds."
else
    echo "No output files generated."
    exit 1
fi
