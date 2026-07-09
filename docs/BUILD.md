# Building Innova

This document describes how to build Innova [INN] from source on Linux, macOS,
and Windows. It replaces the older per-platform notes (`doc/build-unix.txt`,
`doc/build-osx.txt`, `doc/build-msw.txt`, and `doc/readme-qt.rst`).

Innova is a Tribus-algorithm Proof-of-Work / Proof-of-Stake hybrid chain. From
the v5 series onward it also carries the IDAG DAG-ordering and epoch-finality
layer. The codebase descends from the Bitcoin / PPCoin / Denarius 0.x C++
lineage and builds with GNU Make (daemon) and qmake (GUI wallet).

> **The reference build is CI.** The GitHub Actions workflow at
> `.github/workflows/build.yml` builds every released platform on a clean image
> and is the authoritative source for exact package names, compiler flags, and
> per-distro quirks. If anything in this document drifts from that workflow, the
> workflow wins. Use this document to build locally; use the workflow to
> reproduce a release.

---

## Overview

Innova produces two independent binaries. You can build either one alone, or
both.

| Target | Build system | Output | What it is |
| --- | --- | --- | --- |
| `innovad` | `make -f makefile.<platform>` in `src/` | `src/innovad` (`innovad.exe` on Windows) | The headless daemon and RPC server. Runs full validation, staking / finality voting, and the wallet backend. This is what you run on a node or seed. |
| `Innova` (Qt) | `qmake innova-qt.pro && make` in the repo root | `Innova` / `Innova.app` / `release/Innova.exe` | The Qt 5 desktop wallet GUI. Wraps the same consensus/wallet code with a graphical interface, block/DAG browser, staking and privacy pages. |

Both link the same consensus and wallet code, so their dependency sets overlap
heavily. The Qt wallet additionally needs Qt 5, and (optionally) `qrencode` for
QR codes and `protobuf` for payment-request handling.

### Common dependencies

Across all platforms the daemon links, at minimum:

- **Berkeley DB (C++)** — wallet database (`libdb_cxx`). Version 4.8 or 5.x.
- **Boost** — `filesystem`, `program_options`, `thread`, `chrono`.
- **OpenSSL** — `libssl` / `libcrypto`. OpenSSL 3.x is the norm; note the Native
  Tor caveat below.
- **libcurl** — HTTP client (market data, IPFS gateway, etc.).
- **libevent** — networking event loop.
- **libgmp** — big-number arithmetic used by the privacy / ZK primitives.
- **zlib** — compression (also pulled in by minizip and LevelDB).
- **LevelDB** — block/transaction index. Vendored under `src/leveldb` and built
  automatically by the makefiles; no system package required.

Optional, controlled by the `USE_*` flags (see the table further below):

- **miniupnpc** — UPnP port mapping (`USE_UPNP`).
- **Native Tor** — vendored under `src/tor` (`USE_NATIVETOR`). Requires
  OpenSSL 1.x and is **incompatible with OpenSSL 3.x**.
- **IPFS** — vendored C library under `src/ipfs` (`USE_IPFS`).

The Qt wallet adds:

- **Qt 5** — `core gui network widgets concurrent printsupport` (and `dbus` on
  Linux for desktop notifications).
- **qrencode** — QR-code rendering (`USE_QRCODE`).
- **protobuf** — payment-protocol support.

The build embeds git revision info via `share/genbuild.sh`, so build from a git
checkout (a shallow tarball works but yields less version detail).

---

## Linux

Tested distributions (all built in CI): Ubuntu 22.04 / 24.04 / 26.04,
Debian 11 / 12, Fedora 40 / 41, and Arch Linux. aarch64 and armhf are
cross/emulated-built in CI as well.

### 1. Install dependencies

**Debian / Ubuntu (22.04, 24.04, Debian 11/12):**

```sh
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
  libssl-dev libevent-dev bsdmainutils libboost-all-dev libdb++-dev \
  libminiupnpc-dev libqrencode-dev libcurl4-openssl-dev libgmp-dev \
  libsecp256k1-dev \
  libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools \
  libprotobuf-dev protobuf-compiler
```

**Ubuntu 26.04** ships a renamed Berkeley DB C++ package. Use `libdb5.3++-dev`
instead of `libdb++-dev`, and replace `bsdmainutils` with `bsdextrautils`:

```sh
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
  libssl-dev libevent-dev bsdextrautils libboost-all-dev libdb5.3++-dev \
  libminiupnpc-dev libqrencode-dev libcurl4-openssl-dev libgmp-dev \
  libsecp256k1-dev \
  libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools \
  libprotobuf-dev protobuf-compiler
```

On 26.04 the Berkeley DB headers/libs are versioned, so the makefile needs to be
told where they live and what suffix the library carries. The CI workflow probes
this automatically; locally you can pass, for example:

```sh
make USE_NATIVETOR=- \
  BDB_INCLUDE_PATH=/usr/include \
  BDB_LIB_PATH=/usr/lib/x86_64-linux-gnu \
  BDB_LIB_SUFFIX=-5.3 \
  -f makefile.unix -j$(nproc)
```

(Adjust the paths/suffix to match your system; `find /usr -name 'libdb_cxx*'`
will show what is installed.)

**Fedora (40 / 41):**

```sh
sudo dnf install -y gcc-c++ make libtool automake pkgconfig \
  openssl-devel libevent-devel boost-devel libdb-cxx-devel \
  miniupnpc-devel qrencode-devel libcurl-devel gmp-devel zlib-devel \
  qt5-qtbase-devel qt5-qttools-devel \
  protobuf-devel protobuf-compiler git
```

**Arch Linux:**

```sh
sudo pacman -Syu --noconfirm base-devel boost boost-libs openssl libevent db \
  miniupnpc qrencode curl gmp qt5-base qt5-tools protobuf git
```

On Arch, `boost_system` is header-only and no longer ships a link library.
Remove the stray link flags before building:

```sh
sed -i '/-l boost_system/d' src/makefile.unix
sed -i '/-lboost_system/d' innova-qt.pro
```

### 2. Build the daemon

```sh
cd src
make USE_NATIVETOR=- -f makefile.unix -j$(nproc)
```

This produces `src/innovad`. The vendored LevelDB is compiled on first build.

`USE_NATIVETOR=-` disables the bundled Tor client because virtually every current
distro ships OpenSSL 3.x, with which Native Tor does not compile. (The makefile
also auto-disables Native Tor when it detects OpenSSL 3 via `pkg-config`, so on
most systems you can omit the flag — passing it explicitly just makes the intent
clear.)

### 3. Build the Qt wallet (optional)

From the repository root:

```sh
qmake USE_UPNP=1 USE_QRCODE=1 USE_NATIVETOR=- innova-qt.pro
make -j$(nproc)
```

This produces the `Innova` GUI binary. On Fedora the qmake binary is
`qmake-qt5`.

Two environment notes that CI applies and you may need locally:

- The `innova-qt.pro` LIBS line carries some Windows-only link flags. On Linux
  CI strips them with an in-place `sed`; if your linker complains about missing
  `-lcrypt32` / `-lssh2` / etc., trim the LIBS line to just
  `-lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX`.
- Some prebuilt Qt5 packages carry an ABI-tag note that trips the linker; CI runs
  `strip --remove-section=.note.ABI-tag` on `libQt5Core.so.5` as a workaround.

---

## macOS (Apple Silicon)

CI builds macOS on `macos-14` (arm64). Intel Macs use the same makefile; only the
Homebrew prefix differs (`/usr/local` vs `/opt/homebrew`), which the makefile
detects automatically.

### 1. Install dependencies (Homebrew)

```sh
brew install boost openssl@3 berkeley-db@5 miniupnpc libevent qt@5 qrencode \
  curl gmp secp256k1
```

`makefile.osx` looks for these under the Homebrew prefix, including the
keg-only formulae `berkeley-db@5`, `openssl@3`, `libevent`, and `curl` via their
`opt/<formula>` paths.

### 2. Build the daemon

```sh
cd src
make -f makefile.osx -j$(sysctl -n hw.ncpu)
```

This produces `src/innovad`. On macOS, Native Tor is **off by default**
(`USE_NATIVETOR:=-` in `makefile.osx`) because Homebrew provides OpenSSL 3.x.
Pass `RELEASE=1` for `-O3` and `STATIC=1` to statically link the Homebrew
dependencies into a redistributable binary.

### 3. Build the Qt wallet and .dmg (optional)

```sh
/opt/homebrew/opt/qt@5/bin/qmake USE_UPNP=1 USE_QRCODE=1 innova-qt.pro
make -j$(sysctl -n hw.ncpu)
```

This produces `Innova.app`. The `.pro` file targets a macOS 12.0 deployment
minimum and ad-hoc code-signs the bundle on link (recent macOS refuses to run
unsigned `.app` bundles). To assemble the distributable disk image that CI
publishes, stage `innovad` and `Innova.app` into a folder and run `hdiutil`:

```sh
mkdir -p dmg_contents
cp src/innovad dmg_contents/
cp -R Innova.app dmg_contents/
hdiutil create -volname "Innova" -srcfolder dmg_contents \
  -ov -format UDZO innova-<version>-macOS-arm64.dmg
```

> The macOS toolchain builds the daemon and wallet, but the Boost unit-test
> binary `test_innova` is not run on macOS; run the test suite on Linux.

---

## Windows (MSYS2 / MINGW64)

Windows binaries are built with the MSYS2 MINGW64 toolchain and linked **fully
static** so the released `.exe` runs without extra runtime DLLs.

### 1. Install MSYS2 and packages

Install [MSYS2](https://www.msys2.org/), open a **MINGW64** shell, and install:

```sh
pacman -Syu   # then reopen the shell if it asks you to
pacman -S --needed \
  mingw-w64-x86_64-toolchain \
  mingw-w64-x86_64-boost \
  mingw-w64-x86_64-openssl \
  mingw-w64-x86_64-db \
  mingw-w64-x86_64-miniupnpc \
  mingw-w64-x86_64-libevent \
  mingw-w64-x86_64-curl \
  mingw-w64-x86_64-gmp \
  mingw-w64-x86_64-qt5-static \
  mingw-w64-x86_64-protobuf \
  make git
```

### 2. Pre-build LevelDB

On Windows the vendored LevelDB must be built explicitly with the native-Windows
target before linking the daemon:

```sh
cd src/leveldb
TARGET_OS=NATIVE_WINDOWS make libleveldb.a libmemenv.a -j$(nproc)
cd ../..
```

### 3. Build the daemon (static)

Boost and Berkeley DB library filenames carry a toolchain-specific suffix under
MSYS2 (e.g. `-mt`). Point the makefile at `/mingw64` and pass the detected
suffixes. `makefile.mingw` defaults `USE_UPNP=0`; enable it if you installed
miniupnpc.

```sh
cd src
make -f makefile.mingw \
  BOOST_ROOT=/mingw64 \
  BDB_ROOT=/mingw64 \
  OPENSSL_ROOT=/mingw64 \
  LIBEVENT_ROOT=/mingw64 \
  CURL_ROOT=/mingw64 \
  MINIUPNPC_ROOT=/mingw64 \
  BOOST_LIB_SUFFIX=-mt \
  BDB_LIB_SUFFIX= \
  USE_UPNP=1 \
  USE_IPFS=1 \
  STATIC=1 \
  LDFLAGS="-static -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va" \
  -j$(nproc)
```

This produces `src/innovad.exe`. `STATIC=1` pulls in the full static curl
dependency chain (ssh2, brotli, nghttp2/3, ngtcp2, idn2, etc.); those libraries
come from the MSYS2 packages above. To confirm the exact suffixes on your
install, list `/mingw64/lib/libboost_filesystem*` and `/mingw64/lib/libdb_cxx*`.

### 4. Build the Qt wallet (static)

Use the static Qt from `mingw-w64-x86_64-qt5-static`:

```sh
/mingw64/qt5-static/bin/qmake \
  "BOOST_LIB_SUFFIX=-mt" \
  "BOOST_THREAD_LIB_SUFFIX=-mt" \
  "BDB_LIB_SUFFIX=" \
  "STATIC_LINK=1" \
  "USE_UPNP=1" \
  "USE_NATIVETOR=-" \
  innova-qt.pro
make -j$(nproc)
```

`innova-qt.pro` auto-detects an MSYS2 MINGW64 layout under `$MINGW_PREFIX`
(falling back to `C:/msys64/mingw64`) and enables Windows ASLR/DEP linker flags.
The GUI executable is emitted as `release/Innova.exe`.

---

## Build flags (`USE_*`)

The makefiles and `innova-qt.pro` share a set of feature toggles. A flag is set
to `1` to enable, `0` to disable (where the option supports being off), or `-` to
compile the feature out entirely. Defaults differ per makefile, as noted.

| Flag | Default | Effect |
| --- | --- | --- |
| `USE_LEVELDB` | `1` | Use the vendored LevelDB block/transaction index (`src/leveldb`). Set to `-`/`0` to fall back to the Berkeley-DB transaction index (`txdb-bdb`) instead. LevelDB is the supported default. |
| `USE_UPNP` | `1` (unix/osx), `0` (mingw) | Link miniupnpc for automatic UPnP port mapping. `-` compiles it out. |
| `USE_NATIVETOR` | `1` (unix), `-` (osx/mingw) | Compile the bundled Tor client (`src/tor`) for built-in onion routing. **Requires OpenSSL 1.x** — `makefile.unix` auto-disables it when it detects OpenSSL 3.x, and macOS disables it by default. On any OpenSSL 3 system, build with `USE_NATIVETOR=-`. |
| `USE_IPFS` | `1` | Compile the vendored IPFS C library (`src/ipfs`) for hyperfile / content-addressed storage features. `-` builds without it. |
| `USE_QRCODE` | off unless set | (Qt only) Build QR-code display/scan support via libqrencode. CI passes `USE_QRCODE=1`. |
| `USE_DBUS` | `1` on Linux | (Qt only) Freedesktop desktop-notification support via D-Bus. |
| `USE_IPV6` | `1` | Enable IPv6 networking. `-` builds IPv4-only. |
| `STATIC` / `STATIC_LINK` | off | Statically link dependencies for a redistributable binary. `STATIC` is used by `makefile.osx`/`makefile.mingw`; `STATIC_LINK=1` is the qmake equivalent for the Windows wallet. |
| `RELEASE` | off | (makefile.osx / qmake) Optimize for release (`-O3`, dynamic-relink of C/C++ runtime on Linux, macOS deployment-target pinning). |

Additional makefile knobs: `PIE` (position-independent executable + `-pie`),
`SANITIZE=<checks>` (build with `-fsanitize=...`), `INNOVA_SPINNER=0` (disable the
build-progress spinner), and the `BOOST_*` / `BDB_*` / `OPENSSL_*` /
`*_ROOT` / `*_PATH` / `*_LIB_SUFFIX` variables for pointing at
non-standard dependency locations.

---

## Running the test suite

The Boost unit tests build into a separate `test_innova` binary (Linux/Unix
makefiles). The consensus-critical suites are wired as individual `make` targets:

```sh
cd src
make -f makefile.unix release-check      # builds innovad + runs the core test suites
# or run individual suites:
make -f makefile.unix check-finality-tally
make -f makefile.unix check-idag-validation
make -f makefile.unix check-coinstake-guard
# ...see the check-* targets in makefile.unix for the full list
```

`release-check` builds the daemon and runs the bulletproof, finality-tally,
FCMP-root, IDAG-validation, nullifier-binding, vote-binding, NullSend-binding,
coinstake-guard, and committee-signature suites. Run the tests on Linux; the
macOS makefile does not build `test_innova`.

---

## Continuous integration and releases

`.github/workflows/build.yml` is the canonical build definition. On a `v*` tag
push (or a manual dispatch with `publish_release` set) it runs a 13-target
matrix:

- Ubuntu 22.04 / 24.04 / 26.04 (daemon + Qt)
- Debian 11 / 12 (daemon + Qt)
- Fedora 40 / 41 (daemon + Qt)
- Arch Linux (daemon + Qt)
- Linux aarch64 (daemon), aarch64-Qt (daemon + Qt, via QEMU), armhf/armv7
  (daemon, via QEMU)
- macOS arm64 (daemon + Qt, `.dmg`)
- Windows x86_64 (static daemon + Qt, `.zip`, via MSYS2)

Each job packages its binaries with a `SHA256SUMS.txt`, and the final `release`
job collects every artifact, generates a combined `SHA256SUMS.txt`, and publishes
a GitHub release via `softprops/action-gh-release`. The release version comes
from the tag (`v<version>`) or from `release-version` in `build.properties`.

If you are reproducing a specific release build, read the matching job in
`build.yml` for the exact package list and flags — it is kept current, and this
document intentionally tracks it rather than duplicating every detail.