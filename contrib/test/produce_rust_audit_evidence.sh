#!/bin/bash
# Produces rust_audit_sha256: verify_provenance.py (vendored set equals the pinned locks)
# plus cargo-deny over the upstream workspace. Metadata only: not a source review, and
# not the C++ side or FFI boundary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin rust_audit_sha256
evidence_reuse && exit 0

# No scratch copy: nothing is built and nothing is written into the tree, and
# copying a 158-crate vendored registry to read its manifests is pure cost.
RUST="$ROOT/src/privacy_vnext/rust"
UPSTREAM="$RUST/upstream"
[ -d "$RUST/vendor" ] || \
    evidence_die "no vendored registry at $RUST/vendor; restore it before producing $EV_FIELD"
[ -f "$UPSTREAM/deny.toml" ] || \
    evidence_die "no $UPSTREAM/deny.toml; the advisory and licence policy is that file"

evidence_require_command python3
evidence_require_command cargo
evidence_require_command rustc
evidence_require_command cargo-deny "install it with: cargo +1.94.1 install cargo-deny --version =0.19.0"

CARGO_DENY_VERSION="$(cargo-deny --version 2>/dev/null | head -1)"
RUSTC_VERSION="$(cd "$RUST" && rustc --version 2>/dev/null | head -1)"
evidence_toolchain "$CARGO_DENY_VERSION, $RUSTC_VERSION"

# The database cargo-deny resolves advisories against. Recorded by revision after
# the run: an advisories check with no database is a check against nothing.
ADVISORY_DB="${V5_RUST_ADVISORY_DB:-$HOME/.cargo/advisory-db}"

evidence_run "vendored source provenance" \
    "python3 src/privacy_vnext/rust/tools/verify_provenance.py"
# Run from the upstream directory so deny.toml and the pinned lock are the ones
# in effect, and so .cargo/config.toml's source replacement still applies.
evidence_run "advisory, licence, ban and source audit" \
    "cd src/privacy_vnext/rust/upstream && cargo deny --log-level info --all-features \
     check advisories licenses bans sources"

UPSTREAM_PACKAGES="$( { grep -c '^\[\[package\]\]' "$UPSTREAM/Cargo.lock" || true; } | tr -dc '0-9')"
WRAPPER_PACKAGES="$( { grep -c '^\[\[package\]\]' "$RUST/Cargo.lock" || true; } | tr -dc '0-9')"
VENDORED="$(find "$RUST/vendor" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')"

evidence_observe cargo_deny "$CARGO_DENY_VERSION"
evidence_observe rustc "$RUSTC_VERSION"
evidence_observe upstream_lock_packages "${UPSTREAM_PACKAGES:-0}"
evidence_observe wrapper_lock_packages "${WRAPPER_PACKAGES:-0}"
evidence_observe vendored_crates "$VENDORED"
evidence_observe deny_checks "advisories licenses bans sources"
for file in "$UPSTREAM/Cargo.lock" "$RUST/Cargo.lock" "$UPSTREAM/deny.toml" "$RUST/provenance.json"; do
    evidence_observe "$(basename "$(dirname "$file")")_$(basename "$file" | tr '.' '_')_sha256" \
        "$( { sha256sum "$file" 2>/dev/null || shasum -a 256 "$file"; } | awk '{print $1}')"
done

# cargo-deny exits 0 over an empty graph as readily as over a clean one, so the
# graph it was pointed at is proved non-empty here rather than assumed.
[ "${UPSTREAM_PACKAGES:-0}" -gt 0 ] || \
    evidence_finish fail "the upstream lock resolves no package, so the audit covered nothing"
[ "$VENDORED" -gt 0 ] || \
    evidence_finish fail "the vendored registry is empty, so the audit covered nothing"

# An advisories check that fetched no database reports no advisory and exits 0.
DB_REVISION=""
DB_CHECKOUT="$(find "$ADVISORY_DB" -maxdepth 2 -type d -name .git 2>/dev/null | head -1)"
if [ -n "$DB_CHECKOUT" ]; then
    DB_REVISION="$(git -C "$(dirname "$DB_CHECKOUT")" rev-parse HEAD 2>/dev/null || true)"
fi
evidence_observe advisory_db "$ADVISORY_DB"
evidence_observe advisory_db_revision "${DB_REVISION:-none}"
[ -n "$DB_REVISION" ] || \
    evidence_finish fail "no advisory database under $ADVISORY_DB, so the advisories check compared against nothing; set V5_RUST_ADVISORY_DB or let cargo-deny fetch it"

evidence_pass
