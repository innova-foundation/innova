;; Innova Guix Build Environment Manifest
;; Defines ALL build dependencies with pinned versions for reproducible builds.
;; Usage: guix shell -m manifest.scm -- bash
;;        guix environment --manifest=manifest.scm

(specifications->manifest
  (list
    ;; Core toolchain
    "gcc-toolchain@12"
    "make"
    "pkg-config"
    "libtool"
    "automake"
    "autoconf"

    ;; Build dependencies
    "boost"
    "openssl"
    "libevent"
    "bdb"
    "miniupnpc"
    "qrencode"
    "curl"
    "gmp"
    "zlib"

    ;; Qt5 (for wallet GUI)
    "qtbase@5"
    "qttools@5"
    "protobuf"

    ;; Utilities
    "coreutils"
    "diffutils"
    "findutils"
    "gawk"
    "grep"
    "sed"
    "tar"
    "gzip"
    "bzip2"
    "xz"
    "patch"
    "binutils"
    "file"
    "which"

    ;; Source control (for build info)
    "git"

    ;; Cross-compilation support (uncomment as needed)
    ;; "gcc-cross-aarch64-linux-gnu-toolchain"
    ;; "gcc-cross-arm-linux-gnueabihf-toolchain"
    ))
