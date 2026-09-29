#!/bin/bash
# Decides the release version for a CI run and, when releasing, commits the stamped
# version and tags it. Bump level: [release:major|minor|patch|build|none] in the head
# commit message, else the dispatch input, else DEFAULT_BUMP. A release-version in
# build.properties above the latest tag is released as-is (first release of a line).
# Writes version, sha and release to $GITHUB_OUTPUT.
set -euo pipefail
cd "$(dirname "$0")/../.."
git fetch --tags --force -q origin || true
vsort() { sort -t. -k1,1n -k2,2n -k3,3n -k4,4n; }
base=$(grep '^release-version=' build.properties | cut -d= -f2)
latest=$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*.[0-9]*' | sed 's/^v//' | vsort | tail -1)
release=false; level=""; version="$base"

if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
    version="${GITHUB_REF#refs/tags/v}"; release=true
elif [ "${EVENT:-}" = workflow_dispatch ]; then
    level="${INPUT_BUMP:-build}"
    [ "${INPUT_PUBLISH:-false}" = true ] && release=true
else
    level=$(printf '%s' "${HEAD_MSG:-}" | grep -o -E '\[release:(major|minor|patch|build|none)\]' | tail -1 | sed -E 's/\[release:(.*)\]/\1/' || true)
    level="${level:-${DEFAULT_BUMP:-build}}"
    [ "$level" != none ] && release=true
fi

if [ -n "$level" ] && [ "$level" != none ]; then
    if [ -z "$latest" ] || { [ "$base" != "$latest" ] && [ "$(printf '%s\n%s\n' "$base" "$latest" | vsort | tail -1)" = "$base" ]; }; then
        version="$base"
    else
        IFS=. read -r A B C D <<< "$latest"
        case "$level" in
            major) A=$((A+1)); B=0; C=0; D=0 ;;
            minor) B=$((B+1)); C=0; D=0 ;;
            patch) C=$((C+1)); D=0 ;;
            build) D=$((D+1)) ;;
        esac
        version="$A.$B.$C.$D"
    fi
fi

if [ "$release" = true ] && [[ "${GITHUB_REF:-}" != refs/tags/v* ]]; then
    if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
        echo "tag v$version already exists" >&2; exit 1
    fi
    contrib/versioning/stamp-version.sh "$version"
    git config user.name "0xcircuitbreaker"
    git config user.email "0xcircuitbreaker@protonmail.com"
    if ! git diff --quiet; then
        git commit -q -am "release:[change] v$version [release:none]"
        git push -q origin "HEAD:${GITHUB_REF_NAME}"
    fi
    git tag -a "v$version" -m "Innova v$version"
    git push -q origin "v$version"
fi

sha=$(git rev-parse HEAD)
echo "version=$version release=$release level=${level:-tag} sha=$sha latest=${latest:-none}"
{ echo "version=$version"; echo "sha=$sha"; echo "release=$release"; } >> "${GITHUB_OUTPUT:-/dev/null}"
