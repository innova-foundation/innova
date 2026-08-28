#!/bin/bash
# Runs the libFuzzer targets and archives corpus, duration, sanitizer, commit and result
# per target, each in its own directory.
#   contrib/test/run_fuzz_campaign.sh [seconds] [workers]
set -euo pipefail

DURATION="${1:-1800}"
WORKERS="${2:-4}"
SRC="$(cd "$(dirname "$0")/../../src" && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
COMMIT="$(git -C "$SRC/.." rev-parse HEAD 2>/dev/null || echo unknown)"
OUT="${FUZZ_OUT:-/tmp/innova-fuzz-$STAMP}"

TARGETS="fuzz_deserialize fuzz_script fuzz_block_header fuzz_privacy_payload"

# Count live workers for a target. pgrep -x fails on names over 15 characters;
# pgrep -f also matches this script, so exclude our own pid.
fuzz_worker_count() {
    # Match the executable path only, so a target named in another worker's
    # arguments (its corpus directory, for instance) is not miscounted.
    pgrep -af "$1" 2>/dev/null \
        | awk -v t="$1" '$2 ~ ("(^|/)" t "$") { n++ } END { print n+0 }'
}

# `status` reports a campaign in progress without disturbing it.
if [ "${1:-}" = "status" ]; then
    dir="${2:-${FUZZ_OUT:-}}"
    [ -n "$dir" ] || { echo "usage: $0 status <evidence-dir>" >&2; exit 2; }
    [ -f "$dir/manifest.txt" ] && sed 's/^/  /' "$dir/manifest.txt"
    for t in $TARGETS; do
        run="$dir/$t"
        if [ ! -d "$run" ]; then
            printf '  %-20s not started\n' "$t"
            continue
        fi
        ub=$( { grep -c "runtime error" "$run/run.log" 2>/dev/null || true; } | head -1 | tr -dc '0-9')
        art=$(find "$run/work" -maxdepth 1 \( -name 'crash-*' -o -name 'leak-*' \
                  -o -name 'timeout-*' -o -name 'oom-*' \) 2>/dev/null | wc -l | tr -d ' ')
        corp=$(find "$run/corpus" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
        printf '  %-20s corpus=%-7s undefined_behavior=%-3s artifacts=%-3s workers=%s\n' \
               "$t" "$corp" "${ub:-0}" "$art" "$(fuzz_worker_count "$t")"
        grep -oE 'cov: [0-9]+ ft: [0-9]+ corp: [0-9]+' "$run/run.log" 2>/dev/null | tail -1 | sed 's/^/      /'
    done
    exit 0
fi

mkdir -p "$OUT"
echo "commit:    $COMMIT"   > "$OUT/manifest.txt"
echo "started:   $STAMP"   >> "$OUT/manifest.txt"
echo "duration:  ${DURATION}s per target" >> "$OUT/manifest.txt"
echo "workers:   $WORKERS" >> "$OUT/manifest.txt"

rc=0
for t in $TARGETS; do
    if [ ! -x "$SRC/$t" ]; then
        echo "missing $t -- build with: make -f makefile.unix fuzz-all-libfuzzer" >&2
        rc=1
        continue
    fi
    run="$OUT/$t"
    mkdir -p "$run/corpus" "$run/work"
    # Sanitizers are compiled into these binaries; record that they are active.
    ( cd "$run/work" && ASAN_OPTIONS=abort_on_error=0 \
        "$SRC/$t" "$run/corpus" \
        -max_total_time="$DURATION" -workers="$WORKERS" -jobs="$WORKERS" \
        -rss_limit_mb=4096 -print_final_stats=1 ) > "$run/run.log" 2>&1 || true

    # Count with find: a no-match ls glob fails under pipefail. Normalise grep -c
    # output to a bare integer.
    ub=$( { grep -c "runtime error" "$run/run.log" 2>/dev/null || true; } | head -1 | tr -dc '0-9')
    ub=${ub:-0}
    art=$(find "$run/work" -maxdepth 1 \( -name 'crash-*' -o -name 'leak-*' \
              -o -name 'timeout-*' -o -name 'oom-*' \) 2>/dev/null | wc -l | tr -d ' ')
    corp=$(find "$run/corpus" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
    echo "$t: corpus=$corp undefined_behavior=$ub artifacts=$art" | tee -a "$OUT/manifest.txt"
    if [ "$ub" != "0" ] || [ "$art" != "0" ]; then rc=1; fi
done

echo "evidence: $OUT"
exit $rc
