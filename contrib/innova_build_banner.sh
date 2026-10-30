#!/usr/bin/env bash
# Usage: innova_build_banner.sh <command...>  (run from src/)
if [ ! -t 2 ]; then
    exec "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."

ver() { sed -n "s/^#define CLIENT_VERSION_$1 *\([0-9]*\).*/\1/p" "$ROOT/src/clientversion.h"; }
VERSION="$(ver MAJOR).$(ver MINOR).$(ver REVISION).$(ver BUILD)"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

TARGET="make"
prev=""
for a in "$@"; do
    [ "$prev" = "-f" ] && TARGET="$a"
    prev="$a"
done
JOBS="$(printf '%s\n' "$MAKEFLAGS" | sed -n 's/.*-j *\([0-9][0-9]*\).*/\1/p')"
if [ -z "$JOBS" ]; then
    case "$MAKEFLAGS" in *jobserver*) JOBS="auto" ;; *) JOBS=1 ;; esac
fi

case "${LC_ALL:-${LC_CTYPE:-$LANG}}" in
    *UTF-8*|*utf-8*|*UTF8*|*utf8*) UTF=1 ;;
    *) UTF=0 ;;
esac

if [ "$UTF" = 1 ]; then
    SQ="■"; H="─"; TR="┐"; BR="┘"; T="├"; DOT="·"; OK="✔"; FAIL="✘"
else
    SQ="#"; H="-"; TR="+"; BR="+"; T="+"; DOT="-"; OK="ok"; FAIL="FAILED"
fi

if [ -z "$NO_COLOR" ] && [ "$TERM" != "dumb" ]; then
    C="\033[38;5;37m"; D="\033[2m"; B="\033[1m"; R="\033[0m"
else
    C=""; D=""; B=""; R=""
fi

row() { printf "${C}%s${R}%*s%b\n" "$1" "$2" "" "$3" >&2; }
row "  $SQ$H$TR"                          17 "${B}Innova v$VERSION-$COMMIT${R} $DOT build"
row "     $T$H$SQ$H$TR"                   12 "${D}target${R}   $TARGET"
row "  $SQ$H$BR    $T$H$SQ$H$H$SQ"         7 "${D}jobs${R}     $JOBS"
row "  $SQ$H$H$H$H$H$H$BR"                12 "${D}commit${R}   $COMMIT"
row ""                                    22 "${D}output${R}   src/innovad $DOT src/innova-cli"
row "  I N N O V A $DOT IDAG"              2 "${D}next${R}     ./innovad $DOT ./innova-cli help"

START=$(date +%s)
"$@"
STATUS=$?
ELAPSED=$(( $(date +%s) - START ))

BINS=""
for b in innovad innova-cli innovad.exe innova-cli.exe; do
    if [ -f "$b" ]; then
        sz=$(wc -c < "$b" | tr -d ' ')
        BINS="$BINS $b $(( sz / 1048576 ))M"
    fi
done
TIME="$((ELAPSED / 60))m$((ELAPSED % 60))s"
if [ "$STATUS" -eq 0 ]; then
    printf "  ${C}%s${R} built%s $DOT %s\n" "$OK" "$BINS" "$TIME" >&2
else
    printf "  %s make exited %d $DOT %s\n" "$FAIL" "$STATUS" "$TIME" >&2
fi
exit "$STATUS"
