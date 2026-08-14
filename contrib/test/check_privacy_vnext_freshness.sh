#!/usr/bin/env bash
# Fail when the linked IV5 archive is older than any source compiled into it.
# Compares mtimes directly rather than reading the make dependency graph, so a
# wrong prerequisite list cannot hide staleness.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
rust="$root/src/privacy_vnext/rust"

profile=${PRIVACY_VNEXT_RUST_PROFILE:-release}
archive="$rust/target/$profile/libinnova_privacy_vnext.a"

fail() { printf 'IV5 freshness: ERROR: %s\n' "$1" >&2; exit 1; }

[ -d "$rust" ] || fail "no Rust crate at $rust"

if [ ! -f "$archive" ]; then
    printf 'IV5 freshness: no archive at %s yet; nothing to be stale\n' "$archive"
    exit 0
fi

# Everything the archive is compiled from: the wrapper crate, the pinned upstream tree,
# the vendored registry, the manifests it include_bytes!, and the protocol contract.
newer=$(
    find "$rust/src" "$rust/include" "$rust/abi" "$rust/tests" \
         "$rust/upstream" "$rust/vendor" "$root/src/privacy_vnext/contract" \
         "$rust/Cargo.toml" "$rust/Cargo.lock" "$rust/rust-toolchain.toml" \
         "$rust/provenance.json" \
         -name target -prune -o \
         -type f -newer "$archive" -print 2>/dev/null | head -20
)

if [ -n "$newer" ]; then
    printf 'IV5 freshness: ERROR: sources are newer than the linked archive\n' >&2
    printf '  archive: %s\n' "$archive" >&2
    printf '  newer:\n' >&2
    printf '%s\n' "$newer" | sed 's|^|    |' >&2
    printf '  the archive did not rebuild; run cargo build in %s\n' "$rust" >&2
    exit 1
fi

printf 'IV5 freshness: archive is at least as new as every source compiled into it\n'
