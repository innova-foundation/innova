#!/bin/sh

if [ $# -gt 0 ]; then
    FILE="$1"
    shift
    if [ -f "$FILE" ]; then
        INFO="$(head -n 1 "$FILE")"
    fi
else
    echo "Usage: $0 <filename>"
    exit 1
fi

if command -v git >/dev/null 2>&1; then
    # clean 'dirty' status of touched files that haven't been modified
    git diff >/dev/null 2>/dev/null 

    # Bind RPC/release evidence to the complete source commit, not an
    # ambiguous abbreviated describe.  Preserve a human-friendly tag prefix
    # and make any tracked or untracked worktree change explicit.
    DESCRIBE="$(git describe --always --abbrev=12 2>/dev/null)"
    COMMIT="$(git rev-parse --verify HEAD 2>/dev/null)"
    DIRTY=""
    if [ -n "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
        DIRTY="-dirty"
    fi
    if [ -n "$DESCRIBE" ] && [ -n "$COMMIT" ]; then
        DESC="${DESCRIBE}-commit-${COMMIT}${DIRTY}"
    fi

    # get a string like "2012-04-10 16:27:19 +0200"
    TIME="$(git log -n 1 --format="%ci")"
fi

if [ -n "$DESC" ]; then
    NEWINFO="#define BUILD_DESC \"$DESC\""
else
    NEWINFO="// No build information available"
fi

# only update build.h if necessary
if [ "$INFO" != "$NEWINFO" ]; then
    echo "$NEWINFO" >"$FILE"
    echo "#define BUILD_DATE \"$TIME\"" >>"$FILE"
fi
