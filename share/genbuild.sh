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

DESC=""
TIME=""
COMMIT=""
DIRTY=0

if command -v git >/dev/null 2>&1 &&
   git rev-parse --git-dir >/dev/null 2>&1; then
    # clean 'dirty' status of touched files that haven't been modified
    git diff >/dev/null 2>/dev/null

    # Bind RPC/release evidence to the complete source commit, not an
    # ambiguous abbreviated describe.  Preserve a human-friendly tag prefix
    # and make any tracked or untracked worktree change explicit.
    DESCRIBE="$(git describe --always --abbrev=12 2>/dev/null)"
    COMMIT="$(git rev-parse --verify HEAD 2>/dev/null)"
    DIRTYSUFFIX=""
    # An untracked file still changes what was built, so it counts as dirty
    # here where git diff-index alone would call the tree clean.
    if [ -n "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
        DIRTYSUFFIX="-dirty"
        DIRTY=1
    fi
    if [ -n "$DESCRIBE" ] && [ -n "$COMMIT" ]; then
        DESC="${DESCRIBE}-commit-${COMMIT}${DIRTYSUFFIX}"
    fi

    # get a string like "2012-04-10 16:27:19 +0200"
    TIME="$(git log -n 1 --format="%ci" 2>/dev/null)"
fi

if [ -n "$COMMIT" ]; then
    if [ -n "$DESC" ]; then
        BUILD_DESC_LINE="#define BUILD_DESC \"$DESC\""
    else
        BUILD_DESC_LINE="// No build description available"
    fi
    NEWINFO="$BUILD_DESC_LINE
#define BUILD_COMMIT \"$COMMIT\"
#define BUILD_DIRTY $DIRTY
#define BUILD_DATE \"$TIME\""
else
    NEWINFO="// No build information available
#define BUILD_COMMIT \"unknown\"
#define BUILD_DIRTY 0"
fi

TMPFILE="$FILE.tmp.$$"
printf '%s\n' "$NEWINFO" >"$TMPFILE"
if [ ! -f "$FILE" ] || ! cmp -s "$TMPFILE" "$FILE"; then
    mv "$TMPFILE" "$FILE"
else
    rm -f "$TMPFILE"
fi
