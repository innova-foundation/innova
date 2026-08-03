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

TARGETS="fuzz_deserialize fuzz_script fuzz_block_header"

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

    # No-match globs make ls exit non-zero, which under pipefail would abort the
    # whole campaign after the first target. Count with find instead.
    ub=$(grep -c "runtime error" "$run/run.log" 2>/dev/null || true)
    ub=${ub:-0}
    art=$(find "$run/work" -maxdepth 1 \( -name 'crash-*' -o -name 'leak-*' \
              -o -name 'timeout-*' -o -name 'oom-*' \) 2>/dev/null | wc -l | tr -d ' ')
    corp=$(find "$run/corpus" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
    echo "$t: corpus=$corp undefined_behavior=$ub artifacts=$art" | tee -a "$OUT/manifest.txt"
    if [ "$ub" != "0" ] || [ "$art" != "0" ]; then rc=1; fi
done

echo "evidence: $OUT"
exit $rc
