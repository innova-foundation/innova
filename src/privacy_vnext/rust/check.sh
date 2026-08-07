#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

if [ ! -d vendor ]; then
    echo "privacy-vNext: vendor/ is absent, so nothing can be checked against it." >&2
    echo "  restore it first, syncing upstream so the set matches what this gate" >&2
    echo "  compares against -- the wrapper lock alone resolves far fewer crates:" >&2
    echo "    CARGO_NET_OFFLINE=false cargo vendor --locked --versioned-dirs \\" >&2
    echo "      --sync upstream/Cargo.toml" >&2
    exit 1
fi

python3 tools/verify_provenance.py

actual_rustc=$(rustc --version)
case "$actual_rustc" in
    "rustc 1.94.1 "*) ;;
    *)
        echo "privacy-vNext: Rust 1.94.1 required, found: $actual_rustc" >&2
        exit 1
        ;;
esac

cc -std=c11 -Wall -Wextra -Werror -Iinclude -fsyntax-only tests/header_compile.c
rustfmt --edition 2021 --check src/lib.rs
cargo build --locked --offline
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
