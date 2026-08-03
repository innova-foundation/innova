#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

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
