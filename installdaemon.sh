#!/bin/bash
# Build and install innovad (v5) on Ubuntu 22.04 or later.
#   ./installdaemon.sh [install|update]
# INNOVA_REF picks the tag or branch (default v5.0.0.0); INNOVA_REPO the clone URL.
# INNOVA_SKIP_HOST_SETUP=1 skips the firewall and swap steps.
set -euo pipefail

INNOVA_REF="${INNOVA_REF:-v5.0.0.0}"
INNOVA_REPO="${INNOVA_REPO:-https://github.com/innova-foundation/innova}"
INNOVA_DIR="${INNOVA_DIR:-$HOME/innova}"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

mode="${1:-}"
if [ -z "$mode" ]; then
    mode=$(whiptail --title "Innova [INN]" --menu "Daemon node (Ubuntu 22.04+):" 12 60 2 \
        install "Build and install innovad" update "Rebuild innovad at $INNOVA_REF" 3>&1 1>&2 2>&3)
fi

install_deps() {
    $SUDO apt-get update -y
    $SUDO apt-get install -y git curl ca-certificates build-essential libtool autotools-dev \
        automake pkg-config bsdmainutils libssl-dev libevent-dev libboost-all-dev libdb++-dev \
        libminiupnpc-dev libqrencode-dev libcurl4-openssl-dev libgmp-dev libsecp256k1-dev
    if ! command -v cargo >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    fi
}

host_setup() {
    [ "${INNOVA_SKIP_HOST_SETUP:-0}" = 1 ] && return
    $SUDO apt-get install -y ufw
    $SUDO ufw allow ssh
    $SUDO ufw limit ssh/tcp
    $SUDO ufw allow 14530/tcp
    $SUDO ufw allow 14531/tcp
    $SUDO ufw allow 14539/tcp
    $SUDO ufw default allow outgoing
    $SUDO ufw --force enable
    if ! swapon --show | grep -q /swapfile; then
        $SUDO fallocate -l 8G /swapfile
        $SUDO chmod 600 /swapfile
        $SUDO mkswap /swapfile
        $SUDO swapon /swapfile
        grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab
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
    make -C src -f makefile.unix -j"$(nproc)" USE_NATIVETOR=- innovad
    $SUDO cp -f src/innovad /usr/bin/
    echo "innovad installed to /usr/bin"
}

case "$mode" in
    install)
        install_deps
        host_setup
        build
        mkdir -p "$HOME/.innova"
        echo "Optional: run $INNOVA_DIR/bootstrap.sh to fetch chain data."
        ;;
    update)
        install_deps
        build
        ;;
    *)
        echo "usage: $0 [install|update]" >&2
        exit 1
        ;;
esac
