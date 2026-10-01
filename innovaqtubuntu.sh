#!/bin/bash
# Build the Innova Qt 6 wallet (v5) on Ubuntu 22.04 or later.
#   ./innovaqtubuntu.sh [install|update]
# INNOVA_REF picks the tag or branch (default v5.0.0.0); INNOVA_REPO the clone URL.
set -euo pipefail

INNOVA_REF="${INNOVA_REF:-v5.0.0.0}"
INNOVA_REPO="${INNOVA_REPO:-https://github.com/innova-foundation/innova}"
INNOVA_DIR="${INNOVA_DIR:-$HOME/innova}"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

mode="${1:-}"
if [ -z "$mode" ]; then
    mode=$(whiptail --title "Innova [INN]" --menu "Qt wallet (Ubuntu 22.04+):" 12 60 2 \
        install "Build the Qt wallet" update "Rebuild at $INNOVA_REF" 3>&1 1>&2 2>&3)
fi

install_deps() {
    $SUDO apt-get update -y
    $SUDO apt-get install -y git curl ca-certificates build-essential libtool autotools-dev \
        automake pkg-config bsdmainutils libssl-dev libevent-dev libboost-all-dev libdb++-dev \
        libminiupnpc-dev libqrencode-dev libcurl4-openssl-dev libgmp-dev libsecp256k1-dev \
        qt6-base-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools libgl1-mesa-dev \
        libprotobuf-dev protobuf-compiler
    if ! command -v cargo >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    fi
}

build() {
    export PATH="$HOME/.cargo/bin:$PATH"
    [ -d "$INNOVA_DIR/.git" ] || git clone "$INNOVA_REPO" "$INNOVA_DIR"
    cd "$INNOVA_DIR"
    git fetch --tags origin
    git checkout "$INNOVA_REF"
    git merge --ff-only "origin/$INNOVA_REF" 2>/dev/null || true
    # vendor/ is not in git; restore it from the checksums pinned in Cargo.lock.
    (cd src/privacy_vnext/rust && CARGO_NET_OFFLINE=false cargo vendor --locked \
        --versioned-dirs --sync upstream/Cargo.toml >/dev/null)
    qmake6 USE_UPNP=1 USE_QRCODE=1 USE_NATIVETOR=- innova-qt.pro
    make -j"$(nproc)"
    echo "Built $INNOVA_DIR/Innova"
}

case "$mode" in
    install|update)
        install_deps
        build
        ;;
    *)
        echo "usage: $0 [install|update]" >&2
        exit 1
        ;;
esac
