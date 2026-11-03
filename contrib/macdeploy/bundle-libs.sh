#!/bin/bash
# Bundle every non-system library macdeployqt missed. Usage: bundle-libs.sh App.app|dir [libdir...]
set -euo pipefail

APP="$1"; shift
ROOT="$APP/Contents"; [ -d "$ROOT" ] || ROOT="$APP"
FW="$ROOT/Frameworks"
SEARCH=("$@" /opt/homebrew/lib /usr/local/lib)
mkdir -p "$FW"

machos() {
    # Qt frameworks copied flat have no extension and no exec bit
    find "$ROOT" -type f | while read -r f; do
        if file -b "$f" | grep -q 'Mach-O'; then echo "$f"; fi
    done
}

find_lib() {
    local name="$1" d
    for d in "${SEARCH[@]}" /opt/homebrew/opt/*/lib /usr/local/opt/*/lib; do
        [ -e "$d/$name" ] && { echo "$d/$name"; return 0; }
        for f in "$d/$name.framework/Versions/"*/"$name"; do
            [ -e "$f" ] && { echo "$f"; return 0; }
        done
    done
    return 1
}

target_of() {
    case "$2" in
        /opt/homebrew/*|/usr/local/*) echo "$FW/$(basename "$2")" ;;
        @rpath/*.framework/*)
            # flat copy unless macdeployqt already placed the framework
            if [ -e "$FW/${2#@rpath/}" ]; then echo "$FW/${2#@rpath/}"; else echo "$FW/$(basename "$2")"; fi ;;
        @rpath/*) echo "$FW/${2#@rpath/}" ;;
        @loader_path/*) echo "$(dirname "$1")/${2#@loader_path/}" ;;
        @executable_path/../Frameworks/*) echo "$FW/${2#@executable_path/../Frameworks/}" ;;
    esac
}

deps() {
    local id
    id=$(otool -D "$1" | tail -n +2)
    otool -L "$1" | tail -n +2 | awk '{print $1}' | { grep -vxF "$id" || true; }
}

unresolved() {
    machos | while read -r f; do
        deps "$f" | while read -r dep; do
            t=$(target_of "$f" "$dep")
            case "$dep" in /opt/homebrew/*|/usr/local/*|@rpath/*) echo "$f|$dep|$t"; continue ;; esac
            if [ -n "$t" ] && [ ! -e "$t" ]; then echo "$f|$dep|$t"; fi
        done
    done
}

finish() {
    machos | while read -r f; do
        otool -l "$f" | awk '/cmd LC_RPATH/{getline; getline; print $2}' | while read -r rp; do
            case "$rp" in /opt/homebrew/*|/usr/local/*) chmod u+w "$f"; install_name_tool -delete_rpath "$rp" "$f" ;; esac
        done
        # macdeployqt leaves plugin ids pointing at the Homebrew copy
        case "$(otool -D "$f" | tail -n +2)" in
            /opt/homebrew/*|/usr/local/*) chmod u+w "$f"; install_name_tool -id "@rpath/$(basename "$f")" "$f" ;;
        esac
    done
    qtconf="$ROOT/Resources/qt.conf"
    if [ -f "$qtconf" ] && grep -qE '= */' "$qtconf"; then
        printf '[Paths]\nPlugins = PlugIns\n' > "$qtconf"
    fi
    echo "all libraries resolve inside $APP"
}

for pass in 1 2 3 4 5 6 7 8; do
    todo=$(unresolved | sort -u)
    [ -z "$todo" ] && { finish; exit 0; }
    while IFS='|' read -r f dep t; do
        if [ ! -e "$t" ]; then
            case "$dep" in
                /opt/homebrew/*|/usr/local/*) src="$dep" ;;
                *) src=$(find_lib "$(basename "$dep")") || { echo "not found: $dep (needed by $f)" >&2; exit 1; } ;;
            esac
            mkdir -p "$(dirname "$t")"; cp -L "$src" "$t"; chmod u+w "$t"
            install_name_tool -id "@executable_path/../Frameworks/$(basename "$t")" "$t" 2>/dev/null || true
            echo "bundled $(basename "$t")"
        fi
        case "$dep" in
            /opt/homebrew/*|/usr/local/*|@rpath/*)
                chmod u+w "$f"; install_name_tool -change "$dep" "@executable_path/../Frameworks/${t#$FW/}" "$f" ;;
        esac
    done <<< "$todo"
done
echo "libraries still unresolved after 8 passes:" >&2; unresolved >&2; exit 1
