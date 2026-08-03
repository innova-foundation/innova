#!/bin/bash
# Build exactly the Git index in an isolated work tree before preserving a
# recovery commit. Unstaged or untracked source is rejected so the tested bytes
# and the bytes about to be committed cannot silently diverge.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
MODE="${1:---all}"

case "$MODE" in
    --static|--unit|--all) ;;
    *)
        echo "usage: $0 [--static|--unit|--all]" >&2
        exit 2
        ;;
esac

if git -C "$ROOT" diff --quiet --ignore-submodules --; then
    :
else
    echo "build_staged_index: unstaged tracked changes remain" >&2
    exit 1
fi

untracked="$(git -C "$ROOT" ls-files --others --exclude-standard)"
if [ -n "$untracked" ]; then
    echo "build_staged_index: untracked files remain; stage or exclude them" >&2
    printf '%s\n' "$untracked" >&2
    exit 1
fi

if git -C "$ROOT" diff --cached --quiet --ignore-submodules --; then
    echo "build_staged_index: index has no changes to verify" >&2
    exit 1
fi
git -C "$ROOT" diff --cached --check

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/innova-staged-index.XXXXXX")"
cleanup() {
    rm -rf "$STAGE"
}
trap cleanup EXIT INT TERM

git -C "$ROOT" checkout-index --all --prefix="$STAGE/"

# Let build metadata inspect the original index while every source read comes
# from the isolated export. `git status` will intentionally mark the candidate
# as index-dirty until the matching commit is created.
export GIT_DIR="$(git -C "$ROOT" rev-parse --absolute-git-dir)"
export GIT_WORK_TREE="$STAGE"

case "$MODE" in
    --static)
        "$STAGE/contrib/test/v5_release_gate.sh" --static
        ;;
    --unit)
        "$STAGE/contrib/test/v5_release_gate.sh" --unit
        ;;
    --all)
        "$STAGE/contrib/test/v5_release_gate.sh" --static
        "$STAGE/contrib/test/v5_release_gate.sh" --unit
        ;;
esac

echo "build_staged_index: verified isolated index tree $(git -C "$ROOT" write-tree)"
