#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DAEMON=1
BUILD_WALLET=1
CLEAN=0
JOBS=8

while [[ $# -gt 0 ]]; do
    case $1 in
        --jobs)         JOBS="$2"; shift 2 ;;
        --clean)        CLEAN=1; shift ;;
        --daemon-only)  BUILD_WALLET=0; shift ;;
        --wallet-only)  BUILD_DAEMON=0; shift ;;
        -h|--help)
            head -18 "$0" | tail -16
            exit 0 ;;
        *)
            echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ "$MSYSTEM" != "MINGW64" && -z "$MINGW_PREFIX" ]]; then
    echo "ERROR: This script must be run from an MSYS2 MINGW64 shell."
    echo ""
    echo "Open MSYS2 MINGW64 (not MSYS2 MSYS or UCRT64) and run:"
    echo "  cd $(cygpath -u "$SCRIPT_DIR" 2>/dev/null || echo "$SCRIPT_DIR")"
    echo "  ./build-portable-win64.sh"
    exit 1
fi

PREFIX="${MINGW_PREFIX:-/mingw64}"
QT5_STATIC="$PREFIX/qt5-static"
RELEASE_DIR="$SCRIPT_DIR/release-portable"

echo "============================================"
echo " Innova Portable Windows Build"
echo "============================================"
echo " Platform:    MSYS2 MINGW64"
echo " Compiler:    $(gcc --version | head -1)"
echo " Prefix:      $PREFIX"
echo " Jobs:        $JOBS"
echo " Build dir:   $SCRIPT_DIR"
echo "============================================"
echo ""

echo ">> [1/6] Checking and installing dependencies..."

PACKAGES=(
    mingw-w64-x86_64-toolchain
    mingw-w64-x86_64-boost
    mingw-w64-x86_64-openssl
    mingw-w64-x86_64-db
    mingw-w64-x86_64-miniupnpc
    mingw-w64-x86_64-libevent
    mingw-w64-x86_64-curl
    mingw-w64-x86_64-gmp
    mingw-w64-x86_64-protobuf
    mingw-w64-x86_64-qt5-static
    make
    git
)

pacman -S --needed --noconfirm "${PACKAGES[@]}" || {
    echo "WARNING: pacman install had issues. Continuing anyway..."
}

echo "   Dependencies OK."

if [[ $CLEAN -eq 1 ]]; then
    echo ">> Cleaning previous build..."
    cd "$SCRIPT_DIR/src/leveldb" && make clean 2>/dev/null || true
    cd "$SCRIPT_DIR/src" && rm -f innovad.exe obj/*.o obj/*.P obj/*.d obj/minizip/*.o 2>/dev/null || true
    cd "$SCRIPT_DIR" && rm -rf build/ Makefile Makefile.Release Makefile.Debug .qmake.stash release/Innova.exe 2>/dev/null || true
    rm -rf "$RELEASE_DIR"
    echo "   Clean done."
fi

echo ">> [2/6] Building LevelDB..."

cd "$SCRIPT_DIR/src/leveldb"
if [[ ! -f libleveldb.a || ! -f libmemenv.a || $CLEAN -eq 1 ]]; then
    TARGET_OS=NATIVE_WINDOWS make libleveldb.a libmemenv.a -j"$JOBS"
    echo "   LevelDB built."
else
    echo "   LevelDB already built, skipping. Use --clean to rebuild."
fi

echo ">> [3/6] Detecting Boost library suffix..."

BOOST_LIB=$(find "$PREFIX/lib" -maxdepth 1 -name "libboost_system*.a" ! -name "*.dll.a" -print -quit 2>/dev/null)
if [[ -n "$BOOST_LIB" ]]; then
    BOOST_SUFFIX=$(basename "$BOOST_LIB" | sed 's/^libboost_system//; s/\.a$//')
    echo "   Boost suffix: '$BOOST_SUFFIX'"
else
    BOOST_SUFFIX="-mt"
    echo "   Boost suffix fallback: '$BOOST_SUFFIX'"
fi

if [[ $BUILD_DAEMON -eq 1 ]]; then
    echo ">> [4/6] Building innovad (daemon)..."

    cd "$SCRIPT_DIR/src"
    mkdir -p obj obj/minizip

    make -f makefile.mingw \
        BOOST_ROOT="$PREFIX" \
        BDB_ROOT="$PREFIX" \
        OPENSSL_ROOT="$PREFIX" \
        LIBEVENT_ROOT="$PREFIX" \
        CURL_ROOT="$PREFIX" \
        MINIUPNPC_ROOT="$PREFIX" \
        BOOST_LIB_SUFFIX="$BOOST_SUFFIX" \
        BDB_LIB_SUFFIX="-6.0" \
        STATIC=1 \
        LDFLAGS="-static -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va" \
        USE_NATIVETOR=- \
        USE_IPFS=1 \
        INNOVA_SPINNER=0 \
        -j"$JOBS"

    echo "   innovad.exe built."
else
    echo ">> [4/6] Skipping daemon build."
fi

if [[ $BUILD_WALLET -eq 1 ]]; then
    echo ">> [5/6] Building Innova Qt wallet (static)..."

    cd "$SCRIPT_DIR"

    QMAKE="$QT5_STATIC/bin/qmake"
    if [[ ! -x "$QMAKE" ]]; then
        echo "ERROR: Static Qt5 not found at $QT5_STATIC"
        echo "Install it with: pacman -S mingw-w64-x86_64-qt5-static"
        exit 1
    fi
    echo "   Using static Qt5: $($QMAKE -query QT_VERSION)"

    rm -rf build/ Makefile Makefile.Release Makefile.Debug .qmake.stash

    "$QMAKE" \
        "BOOST_LIB_SUFFIX=$BOOST_SUFFIX" \
        "BOOST_THREAD_LIB_SUFFIX=$BOOST_SUFFIX" \
        "BDB_LIB_SUFFIX=-6.0" \
        "STATIC_LINK=1" \
        "USE_UPNP=1" \
        "USE_NATIVETOR=-" \
        innova-qt.pro

    make -j"$JOBS"

    echo "   Innova.exe built."
else
    echo ">> [5/6] Skipping Qt wallet build."
fi

echo ">> [6/6] Packaging portable release..."

rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

if [[ $BUILD_DAEMON -eq 1 && -f "$SCRIPT_DIR/src/innovad.exe" ]]; then
    cp "$SCRIPT_DIR/src/innovad.exe" "$RELEASE_DIR/"
fi

if [[ $BUILD_WALLET -eq 1 ]]; then
    if [[ -f "$SCRIPT_DIR/release/Innova.exe" ]]; then
        cp "$SCRIPT_DIR/release/Innova.exe" "$RELEASE_DIR/"
    elif [[ -f "$SCRIPT_DIR/Innova.exe" ]]; then
        cp "$SCRIPT_DIR/Innova.exe" "$RELEASE_DIR/"
    fi
fi

strip "$RELEASE_DIR"/*.exe 2>/dev/null || true

cd "$RELEASE_DIR"
sha256sum *.exe > checksums.txt 2>/dev/null || true

echo ""
echo "============================================"
echo " Build Complete!"
echo "============================================"
echo ""
echo " Output directory: $RELEASE_DIR"
echo ""
ls -lh "$RELEASE_DIR/"
echo ""

TOTAL_SIZE=$(du -sh "$RELEASE_DIR" | cut -f1)
FILE_COUNT=$(ls -1 "$RELEASE_DIR" | wc -l)
echo " Total: $TOTAL_SIZE in $FILE_COUNT files"
echo ""
echo " FULLY STATIC build - no DLLs needed."
echo " Copy these .exe files to any Windows x64 machine and they will run."
echo ""
echo " To create a zip for distribution:"
echo "   cd $RELEASE_DIR && 7z a ../innova-win64-portable.zip *"
echo "============================================"
