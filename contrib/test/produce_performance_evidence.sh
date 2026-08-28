#!/bin/bash
# Produces performance_sha256: the regtest throughput measurement, compared against
# the reviewed baseline in contrib/test/performance_baseline.json. With no baseline
# it writes a candidate for review and fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin performance_sha256
evidence_reuse && exit 0

[ -x "$ROOT/src/innovad" ] || \
    evidence_die "build src/innovad before producing $EV_FIELD; the measurement drives it"
evidence_require_command python3
BASELINE="${V5_PERFORMANCE_BASELINE:-$ROOT/contrib/test/performance_baseline.json}"
TOLERANCE="${V5_PERFORMANCE_TOLERANCE:-0.20}"
evidence_toolchain "$("$ROOT/src/innovad" --version 2>/dev/null | head -1 || echo 'innovad (version unavailable)')"
evidence_observe innovad_sha256 \
    "$( { sha256sum "$ROOT/src/innovad" 2>/dev/null || shasum -a 256 "$ROOT/src/innovad"; } | awk '{print $1}')"
evidence_observe baseline "${BASELINE#$ROOT/}"
evidence_observe tolerance "$TOLERANCE"

evidence_run "regtest throughput measurement" \
    "INNOVAD='$ROOT/src/innovad' contrib/test/idag_tps_test.sh"

CANDIDATE="$EV_DIR/performance_baseline.candidate.json"
STATUS_FILE="$EV_DIR/performance_compare.txt"
set +e
python3 - "$EV_LOG" "$BASELINE" "$CANDIDATE" "$TOLERANCE" > "$STATUS_FILE" <<'PY'
import json, re, sys

log, baseline_path, candidate_path, tolerance = sys.argv[1:5]
tolerance = float(tolerance)
METRICS = ("rpc_submit_tps", "confirmed_wall_clock_tps", "block_capacity_tps")

text = open(log, encoding="utf-8", errors="ignore").read()
measured = {}
for name in METRICS:
    hits = re.findall(r"\b%s=([0-9]+(?:\.[0-9]+)?)" % name, text)
    if hits:
        measured[name] = float(hits[-1])

for name, value in sorted(measured.items()):
    print("OBSERVE %s %s" % (name, value))

absent = [name for name in METRICS if name not in measured]
if absent:
    print("STATUS unmeasured %s" % ",".join(absent))
    raise SystemExit(0)

try:
    baseline = json.load(open(baseline_path, encoding="utf-8"))
    floors = {name: float(entry["floor"]) for name, entry in baseline["metrics"].items()}
except (OSError, ValueError, KeyError, TypeError):
    floors = None

if floors is None:
    json.dump({
        "schema_version": 1,
        "note": "Candidate floors: each metric at %d%% of one measured run. Review, "
                "adjust and commit as contrib/test/performance_baseline.json." %
                round((1 - tolerance) * 100),
        "metrics": {name: {"floor": round(value * (1 - tolerance), 2),
                           "measured": value} for name, value in sorted(measured.items())},
    }, open(candidate_path, "w", encoding="utf-8"), indent=2, sort_keys=True)
    print("STATUS no_baseline %s" % candidate_path)
    raise SystemExit(0)

for name, floor in sorted(floors.items()):
    print("OBSERVE %s_floor %s" % (name, floor))
below = [name for name in METRICS
         if name in floors and measured[name] < floors[name]]
missing = [name for name in METRICS if name not in floors]
if missing:
    print("STATUS incomplete_baseline %s" % ",".join(missing))
elif below:
    print("STATUS regression %s" % ",".join(
        "%s %.2f<%.2f" % (name, measured[name], floors[name]) for name in below))
else:
    print("STATUS ok")
PY
COMPARE_STATUS=$?
set -e
[ "$COMPARE_STATUS" -eq 0 ] || evidence_finish fail "the measurement could not be compared (exit $COMPARE_STATUS)"
cat "$STATUS_FILE" >> "$EV_LOG"

while read -r keyword name value; do
    [ "$keyword" = "OBSERVE" ] || continue
    evidence_observe "$name" "$value"
done < "$STATUS_FILE"

VERDICT="$(awk '$1=="STATUS" {sub(/^STATUS /, ""); print; exit}' "$STATUS_FILE")"
evidence_observe comparison "${VERDICT%% *}"
case "$VERDICT" in
    ok) ;;
    no_baseline*) evidence_finish fail "no reviewed baseline at $BASELINE; a candidate is at ${VERDICT#no_baseline }" ;;
    *) evidence_finish fail "$VERDICT" ;;
esac

evidence_pass
