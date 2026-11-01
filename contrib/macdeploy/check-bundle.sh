#!/bin/bash
# Fail if any Mach-O in an app bundle or dir loads a library from outside it. Usage: check-bundle.sh App.app|dir...
set -uo pipefail

bad=0
for top in "$@"; do
    while read -r f; do
        file -b "$f" | grep -q 'Mach-O' || continue
        hits=$( { otool -L "$f" | tail -n +2 | awk '{print $1}'; otool -l "$f" | awk '/cmd LC_RPATH/{getline; getline; print $2}'; } |
               grep -E '^(/opt/homebrew|/usr/local)' )
        if [ -n "$hits" ]; then echo "$f:"; echo "$hits" | sed 's/^/    /'; bad=1; fi
    done < <(find "$top" -type f)
    qtconf="$top/Contents/Resources/qt.conf"
    if [ -f "$qtconf" ] && grep -qE '= */' "$qtconf"; then echo "$qtconf has an absolute path"; bad=1; fi
done
[ "$bad" = 0 ] && echo "bundle is self-contained: $*"
exit $bad
