# Building Innova

This document describes how to build Innova [INN] from source on Linux, macOS,
and Windows. It replaces the older per-platform build notes.

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
| `Innova` (Qt) | `qmake6 innova-qt.pro && make` (Linux/Windows) or CMake with Qt 6 (macOS) | `Innova` / `Innova.app` / `release/Innova.exe` | The desktop wallet GUI. Wraps the same consensus/wallet code with a graphical interface, block/DAG browser, staking and privacy pages. |

Both link the same consensus and wallet code, so their dependency sets overlap
heavily. The Qt wallet additionally needs Qt (see below), and (optionally) `qrencode` for
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

- **Qt** — `core gui network widgets concurrent printsupport` (and `dbus` on
  Linux for desktop notifications).
- **qrencode** — QR-code rendering (`USE_QRCODE`).
- **protobuf** — payment-protocol support.

The tree builds against both Qt 5.15 and Qt 6. Most Linux release builds and
Windows use Qt 6 (`qmake6`); Fedora still builds against Qt 5
(`qmake-qt5`). macOS builds Qt 6 with CMake (`CMakeLists.txt`), because
Homebrew's Qt 6 ships no qmake platform mkspec.

The build embeds git revision info via `share/genbuild.sh`, so build from a git
checkout (a shallow tarball works but yields less version detail).

---

## Rust toolchain (required)

The IV5 privacy layer (`src/privacy_vnext/`) wraps the upstream monero-oxide
FCMP++ implementation. FCMP++ has no C++ implementation — Monero's own C++ daemon
calls the same Rust code over FFI — so a Rust toolchain is required to build the
daemon or the test binary.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
rustup toolchain install 1.94.1 --profile minimal -c rustfmt -c clippy
```

The exact version is pinned by `src/privacy_vnext/rust/rust-toolchain.toml`;
rustup selects it automatically inside that directory.

### Restore the vendored crates (once per clone)

`src/privacy_vnext/rust/vendor/` is not tracked in git. It holds third-party
crates.io dependencies, which `cargo vendor` reproduces exactly from the versions
and SHA-256 checksums pinned in `Cargo.lock`. The pinned monero-oxide sources
under `rust/upstream/` *are* tracked, because they are path dependencies with no
crates.io equivalent.

```sh
cd src/privacy_vnext/rust
CARGO_NET_OFFLINE=false cargo vendor --locked --versioned-dirs \
  --sync upstream/Cargo.toml > /dev/null     # needs network, once
cargo build --locked --offline
```

`.cargo/config.toml` sets `offline = true`, so a plain `cargo vendor` cannot fetch
anything on a fresh machine; `CARGO_NET_OFFLINE=false` allows this one networked
step. `--sync upstream/Cargo.toml` restores the full crate set the pinned upstream
lock names (the wrapper alone resolves fewer crates, and the provenance check in
`release-check` refuses that set). Every later build is offline and reproducible.

For an air-gapped build, each release also ships
`innova-<version>-rust-vendor.tar.zst`; unpack it in place of `cargo vendor`:

```sh
cd src/privacy_vnext/rust
zstd -dc /path/to/innova-<version>-rust-vendor.tar.zst | tar -xf -
```

## Linux

Tested distributions (all built in CI): Ubuntu 22.04 / 24.04 / 26.04,
Debian 12 / 13, Fedora 40 / 41, and Arch Linux. aarch64 (daemon, and
daemon+Qt) is also built in CI, on native arm runners.

### 1. Install dependencies

**Debian / Ubuntu (22.04, 24.04, Debian 12):**

```sh
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
  libssl-dev libevent-dev bsdmainutils libboost-all-dev libdb++-dev \
  libminiupnpc-dev libqrencode-dev libcurl4-openssl-dev libgmp-dev \
  libsecp256k1-dev \
  qt6-base-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools libgl1-mesa-dev \
  libprotobuf-dev protobuf-compiler
```

**Debian 13** uses the same list with `libdb5.3++-dev` in place of `libdb++-dev`
(there `libdb++-dev` installs only the C library). Its headers and library sit on
the default paths, so no further settings are needed.

**Ubuntu 26.04** ships a renamed Berkeley DB C++ package. Use `libdb5.3++-dev`
instead of `libdb++-dev`, and replace `bsdmainutils` with `bsdextrautils`:

```sh
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
  libssl-dev libevent-dev bsdextrautils libboost-all-dev libdb5.3++-dev \
  libminiupnpc-dev libqrencode-dev libcurl4-openssl-dev libgmp-dev \
  libsecp256k1-dev \
  qt6-base-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools libgl1-mesa-dev \
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
  miniupnpc qrencode curl gmp qt6-base qt6-tools protobuf git
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
qmake6 USE_UPNP=1 USE_QRCODE=1 USE_NATIVETOR=- innova-qt.pro
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
brew install boost openssl@3 berkeley-db@5 miniupnpc libevent qrencode \
  curl gmp secp256k1
```

`makefile.osx` looks for these under the Homebrew prefix, including the
keg-only formulae `berkeley-db@5`, `openssl@3`, `libevent`, and `curl` via their
`opt/<formula>` paths.

### 2. Build the daemon

```sh
cd src
make STRICT_WARNINGS=1 -f makefile.osx -j$(sysctl -n hw.ncpu)
```

This produces `src/innovad`. On macOS, Native Tor is **off by default**
(`USE_NATIVETOR:=-` in `makefile.osx`) because Homebrew provides OpenSSL 3.x.
Pass `RELEASE=1` for `-O3` and `STATIC=1` to statically link the Homebrew
dependencies into a redistributable binary.

### 3. Build the Qt wallet and .dmg (optional)

Build `innovad` first (step 2): it produces the Rust IV5 library and LevelDB that
the GUI links. Then, with `brew install qt qttools`:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
make -C build -j$(sysctl -n hw.ncpu)
```

This produces `build/Innova.app`. The build compiles the translations with
`lrelease` (from `qttools`) and ad-hoc code-signs the bundle on link (recent macOS refuses to run
unsigned `.app` bundles). To assemble the distributable disk image that CI
publishes, stage `innovad` and `Innova.app` into a folder and run `hdiutil`:

```sh
mkdir -p dmg_contents
cp src/innovad dmg_contents/
cp -R build/Innova.app dmg_contents/
hdiutil create -volname "Innova" -srcfolder dmg_contents \
  -ov -format UDZO innova-<version>-macOS-arm64.dmg
```

> Release CI builds and runs `test_innova` on macOS as well as Linux. The
> `STRICT_WARNINGS=1` gate promotes return-type and format diagnostics to errors
> so platform-specific varargs ABI mistakes cannot be hidden.

---

## Windows (MSYS2 / UCRT64)

Windows binaries are built with the MSYS2 UCRT64 toolchain and linked **fully
static** so the released `.exe` runs without extra runtime DLLs.

### 1. Install MSYS2 and packages

Install [MSYS2](https://www.msys2.org/), open a **UCRT64** shell, and install:

```sh
pacman -Syu   # then reopen the shell if it asks you to
pacman -S --needed \
  mingw-w64-ucrt-x86_64-toolchain \
  mingw-w64-ucrt-x86_64-boost \
  mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-db \
  mingw-w64-ucrt-x86_64-miniupnpc \
  mingw-w64-ucrt-x86_64-libevent \
  mingw-w64-ucrt-x86_64-curl \
  mingw-w64-ucrt-x86_64-gmp \
  mingw-w64-ucrt-x86_64-qt6-static \
  mingw-w64-ucrt-x86_64-freetype \
  mingw-w64-ucrt-x86_64-harfbuzz \
  mingw-w64-ucrt-x86_64-graphite2 \
  mingw-w64-ucrt-x86_64-libpng \
  mingw-w64-ucrt-x86_64-libjpeg-turbo \
  mingw-w64-ucrt-x86_64-jbigkit \
  mingw-w64-ucrt-x86_64-lerc \
  mingw-w64-ucrt-x86_64-libdeflate \
  mingw-w64-ucrt-x86_64-glib2 \
  mingw-w64-ucrt-x86_64-libtiff \
  mingw-w64-ucrt-x86_64-libwebp \
  mingw-w64-ucrt-x86_64-protobuf \
  make git
```

### 2. Rust toolchain and the IV5 library

Install Rust for Windows with [rustup](https://rustup.rs/) (`rustup-init.exe`).
The Windows build links the GNU-ABI archive, so add that target, then make
`cargo` visible inside the UCRT64 shell (MSYS2 does not inherit the Windows
`PATH`) and point it at that target:

```sh
export PATH="$(cygpath -u "$USERPROFILE")/.cargo/bin:$PATH"
export CARGO_BUILD_TARGET=x86_64-pc-windows-gnu

cd src/privacy_vnext/rust
rustup toolchain install          # reads rust-toolchain.toml (1.94.1)
rustup target add x86_64-pc-windows-gnu
CARGO_NET_OFFLINE=false cargo vendor --locked --versioned-dirs \
  --sync upstream/Cargo.toml > /dev/null
cargo build --locked --offline --release
mkdir -p target/release
cp target/x86_64-pc-windows-gnu/release/libinnova_privacy_vnext.a target/release/
cd ../../..
```

Keep both `export` lines set in the shell you build in: `makefile.mingw` and
`innova-qt.pro` re-run `cargo` to confirm the library is current. Clone with
Git for Windows as usual; `.gitattributes` keeps the files the IV5 startup check
hashes byte-exact.

### 3. Pre-build LevelDB

On Windows the vendored LevelDB must be built explicitly with the native-Windows
target before linking the daemon:

```sh
cd src/leveldb
TARGET_OS=NATIVE_WINDOWS make libleveldb.a libmemenv.a -j$(nproc)
cd ../..
```

### 4. Build the daemon (static)

Boost and Berkeley DB library filenames carry a toolchain-specific suffix under
MSYS2 (e.g. `-mt`). Point the makefile at `/ucrt64` and pass the detected
suffixes. `makefile.mingw` defaults `USE_UPNP=0`; enable it if you installed
miniupnpc.

```sh
cd src
make -f makefile.mingw \
  BOOST_ROOT=/ucrt64 \
  BDB_ROOT=/ucrt64 \
  OPENSSL_ROOT=/ucrt64 \
  LIBEVENT_ROOT=/ucrt64 \
  CURL_ROOT=/ucrt64 \
  MINIUPNPC_ROOT=/ucrt64 \
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
install, list `/ucrt64/lib/libboost_filesystem*` and `/ucrt64/lib/libdb_cxx*`.

### 5. Build the Qt wallet (static)

Use the static Qt from `mingw-w64-ucrt-x86_64-qt6-static`:

```sh
/ucrt64/qt6-static/bin/qmake \
  "BOOST_LIB_SUFFIX=-mt" \
  "BOOST_THREAD_LIB_SUFFIX=-mt" \
  "BDB_LIB_SUFFIX=" \
  "STATIC_LINK=1" \
  "USE_UPNP=1" \
  "USE_NATIVETOR=-" \
  innova-qt.pro
make -j$(nproc)
```

`innova-qt.pro` auto-detects the MSYS2 layout via the `$MINGW_PREFIX`
environment variable (`/ucrt64` in a UCRT64 shell; falls back to
`C:/msys64/mingw64` if unset) and enables Windows ASLR/DEP linker flags. The
GUI executable is emitted as `release/Innova.exe`.

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
`SANITIZE=<checks>` (build with `-fsanitize=...`), `STRICT_WARNINGS=1` on macOS
(fail on return-type/format warnings), `INNOVA_SPINNER=0` (disable the
build-progress spinner), and the `BOOST_*` / `BDB_*` / `OPENSSL_*` /
`*_ROOT` / `*_PATH` / `*_LIB_SUFFIX` variables for pointing at
non-standard dependency locations.

---

## Running the test suite

The Boost unit tests build into a separate `test_innova` binary on Linux and
macOS. The consensus-critical suites are wired as individual `make` targets:

```sh
cd src
make -f makefile.unix release-check      # builds innovad + runs all 131 test translation units
# or run individual suites:
make -f makefile.unix check-finality-tally
make -f makefile.unix check-idag-validation
make -f makefile.unix check-coinstake-guard
make -f makefile.unix check-finality-committee-sig
make -f makefile.unix check-halfagg-stake
make -f makefile.unix check-epoch-state-determinism
# ...see the check-* targets in makefile.unix for the full list
```

`release-check` builds the daemon, runs the full `test_innova` binary unfiltered
(`check-all`, covering all of the repository's 131 Boost test translation
units), and additionally runs roughly 60 named consensus-critical `check-*`
targets (bulletproof, finality-tally, FCMP-root, IDAG-validation,
nullifier-binding, vote-binding, NullSend-binding, coinstake-guard,
committee-signature, half-aggregated NullStake authorization, epoch-state
determinism, and more) for explicit per-suite CI visibility — see the
`check-*` targets in `makefile.unix` for the full list. Isolated suite
invocations remain available for diagnosis.
`makefile.osx` builds the same test binary and exposes the same release-critical
targets, so both Linux and macOS run those mandatory suites. Both makefiles load
`obj/test/*.P`; this prevents stale test objects after consensus/proof headers
change. The vendored LevelDB sub-build retains its required include/platform
flags when audit or sanitizer flags are supplied by the parent, and any nested
build or clean failure stops the top-level build. Linux sanitizer flags are
passed into LevelDB itself, not only into the daemon objects that call it.

---

## Continuous integration and releases

`.github/workflows/build.yml` is the canonical build definition. It runs a
12-target matrix on every push to `master`, on a `v*` tag push, and on a manual
dispatch. A `master` push, a tag push, or a dispatch with `publish_release` set
publishes a GitHub release once the matrix and audit gates pass:

- Ubuntu 22.04 / 24.04 / 26.04 (daemon + Qt)
- Debian 12 / 13 (daemon + Qt)
- Fedora 40 / 41 (daemon + Qt)
- Arch Linux (daemon + Qt)
- Linux aarch64 (daemon), aarch64-Qt (daemon + Qt), on native arm runners
- macOS arm64 (daemon + Qt, `.dmg`)
- Windows x86_64 (static daemon + Qt, `.zip`, via MSYS2)

Each job requires its documented binaries and archive, uploads with missing-file
failure enabled, and includes a `SHA256SUMS.txt`. The final `release` job requires
exactly one of every named platform archive, plus three audit gates: the clean-Linux
unit/warning build (`audit-linux-clean`), the ASan/UBSan sanitizer runs
(`audit-linux-sanitizers`), and the Rust vendored-provenance/offline gate
(`audit-rust-vnext`). The multi-node regtest suites
(`contrib/test/v5_release_gate.sh --integration`) run locally, not in CI.
It generates a combined `SHA256SUMS.txt` and publishes a GitHub release via
`softprops/action-gh-release`. The version comes from
`contrib/versioning/next-version.sh`; see `docs/RELEASING.md`.

If you are reproducing a specific release build, read the matching job in
`build.yml` for the exact package list and flags — it is kept current, and this
document intentionally tracks it rather than duplicating every detail.
