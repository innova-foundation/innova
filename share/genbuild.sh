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
    DESC="$(git describe --dirty 2>/dev/null)"
    TIME="$(git log -n 1 --format="%ci" 2>/dev/null)"
    COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null)"
    if [ -n "$COMMIT" ] && git diff-index --quiet HEAD -- >/dev/null 2>&1; then
        DIRTY=0
    elif [ -n "$COMMIT" ]; then
        DIRTY=1
    fi
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
