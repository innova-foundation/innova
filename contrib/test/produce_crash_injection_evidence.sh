#!/bin/bash
# Produces crash_injection_sha256 from crash_injection_test.sh, recomputing the digest from
# the manifest and refusing a run with no kill window or two empty states.
# `--check-manifest <file>` runs only those refusals over an existing manifest.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

manifest_matches() { { grep -c '^MATCH ' "$1" || true; } | tr -dc '0-9'; }
manifest_differs() { { grep -c '^DIFFER ' "$1" || true; } | tr -dc '0-9'; }
manifest_field()   { sed -n "s/^$2: *//p" "$1" | tail -1; }

# Every reason a manifest is refused, one per line; empty output is a pass.
# Checked independently of the harness exit status.
manifest_refusals() {
    local m="$1" v

    v="$(manifest_differs "$m")"
    [ "${v:-0}" = "0" ] || echo "recovered states that differed from the control: $v"
    v="$(manifest_field "$m" failed)"
    [ "${v:-0}" = "0" ] || echo "harness checks that failed: ${v:-unrecorded}"
    v="$(manifest_field "$m" passed)"
    [ "${v:-0}" -gt 0 ] 2>/dev/null || echo "the run recorded no passing check"
    v="$(manifest_matches "$m")"
    [ "${v:-0}" -ge 3 ] 2>/dev/null || echo "only ${v:-0} of the 3 state comparisons ran"

    case "$(manifest_field "$m" kill_connectblock_height)" in
        *"mid-connect"*) ;;
        *) echo "no mid-ConnectBlock kill window was reached" ;;
    esac
    case "$(manifest_field "$m" kill_nameindex_height)" in
        NONE*|"") echo "no mid-batch name-index kill window was reached" ;;
    esac
    case "$(manifest_field "$m" kill_reorg_height)" in
        *"mid-reorg"*) ;;
        *) echo "no mid-reorg kill window was reached" ;;
    esac
    [ -n "$(manifest_field "$m" kill_wallet_height)" ] || \
        echo "the wallet-locator phase recorded no kill"
    v="$(manifest_field "$m" notes_lost)"
    [ "${v:-unrecorded}" = "0" ] || \
        echo "the wallet-locator phase recorded notes_lost=${v:-unrecorded}"
    # Two empty indexes match trivially, so an empty one proves nothing.
    v="$(manifest_field "$m" nameidx_fields)"
    [ "${v:-0}" -gt 0 ] 2>/dev/null || \
        echo "the name index was empty, so its comparison proved nothing"

    # A run with no unscanned gap never exercised this phase.
    v="$(manifest_field "$m" scan_gaps_recorded)"
    [ "${v:-0}" -gt 0 ] 2>/dev/null || \
        echo "no IV5 scan gap was recorded anywhere in the run (${v:-none}), so the degraded path was never exercised"
    case "$(manifest_field "$m" locked_rescan_gap)" in
        ""|none|-*) echo "the locked-wallet rescan recorded no IV5 scan gap, so the degraded start was not exercised" ;;
    esac
    v="$(manifest_field "$m" locked_rescan_gap_after_unlock)"
    [ "${v:-none}" = "-1" ] || \
        echo "the IV5 scan gap survived the unlock (${v:-none})"
    v="$(manifest_field "$m" locked_rescan_gap_close_status)"
    [ "${v:-none}" = "complete" ] || \
        echo "the queued IV5 scan gap close did not report itself complete (${v:-none})"
    # The unlock must not be the thread that rescans; it runs under the RPC
    # dispatcher's lock on the chain and the wallet.
    v="$(manifest_field "$m" locked_rescan_unlock_seconds)"
    [ "${v:-999}" -le 10 ] 2>/dev/null || \
        echo "walletpassphrase took ${v}s, so the gap close is back on the unlock path"

    # Note reachability at the mid-reorg kill.
    v="$(manifest_field "$m" reorg_scan_gap_after_unlock)"
    [ "${v:-none}" = "-1" ] || \
        echo "an IV5 scan gap survived the unlock after the reorg kill (${v:-none})"
    v="$(manifest_field "$m" reorg_notes_lost)"
    [ "${v:-unrecorded}" = "0" ] || \
        echo "the reorg kill lost ${v:-an unrecorded number of} note field(s)"
    v="$(manifest_field "$m" reorg_note_count)"
    case "$v" in
        "") echo "the reorg kill recorded no note count, so reachability was not measured" ;;
        *"before=0"*) echo "the victim held no shielded notes going into the reorg kill" ;;
    esac
}

if [ "${1:-}" = "--check-manifest" ]; then
    [ -f "${2:-}" ] || { echo "usage: $0 --check-manifest <manifest.txt>" >&2; exit 2; }
    REASONS="$(manifest_refusals "$2")"
    if [ -n "$REASONS" ]; then
        echo "$REASONS"
        exit 1
    fi
    echo "manifest accepted"
    exit 0
fi

evidence_begin crash_injection_sha256
evidence_reuse && exit 0

# No scratch copy: this builds nothing and has to kill the daemon under test.
[ -x "$ROOT/src/innovad" ] || \
    evidence_die "build src/innovad before producing $EV_FIELD; the recovery run drives it"
# Every digest the harness compares comes from its own digest_of, which is
# sha256sum. Without it each comparison is empty against empty, and the harness
# spends the whole run to fail for a missing tool.
evidence_require_command sha256sum "crash_injection_test.sh computes every state digest with it"
evidence_require_command pgrep "the harness finds its own daemons by datadir"
# --version is unknown to the daemon and would start a node; use --help with an
# explicit datadir under a watchdog.
VERSION_PROBE="$EV_DIR/.version-probe"
probe_version() {
    local pid i
    rm -rf "$VERSION_PROBE"
    mkdir -p "$VERSION_PROBE" || return 0
    "$ROOT/src/innovad" -datadir="$VERSION_PROBE" --help > "$VERSION_PROBE/version.txt" 2>/dev/null &
    pid=$!
    for i in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null || true
    head -1 "$VERSION_PROBE/version.txt" 2>/dev/null
}
evidence_toolchain "$(probe_version)"
evidence_require_binary_commit "$EV_TOOLCHAIN"
evidence_observe innovad_sha256 \
    "$( { sha256sum "$ROOT/src/innovad" 2>/dev/null || shasum -a 256 "$ROOT/src/innovad"; } | awk '{print $1}')"

# Three regtest datadirs, kept beside the document: CRASH_EVIDENCE_DIR set is
# what stops the harness deleting the run it just described.
RUN_DIR="${V5_CRASH_RUN_DIR:-$EV_DIR/crash_injection.run}"
CRASH_EVIDENCE="$RUN_DIR/evidence"
# Well clear of the fleet and reproduction windows; slot n takes base+n,
# base+10+n and base+20+n.
CRASH_BASE="${V5_CRASH_PORT_BASE:-29320}"
rm -rf "$RUN_DIR"

evidence_observe port_base "$CRASH_BASE"
evidence_observe run_dir "$RUN_DIR"

evidence_run "crash-injection recovery run" \
    "INNOVAD='$ROOT/src/innovad' CRASH_TEST_DIR='$RUN_DIR' CRASH_EVIDENCE_DIR='$CRASH_EVIDENCE' \
     CRASH_PORT_BASE=$CRASH_BASE CRASH_RPC_BASE=$(( CRASH_BASE + 10 )) CRASH_IDNS_BASE=$(( CRASH_BASE + 20 )) \
     contrib/test/crash_injection_test.sh"

MANIFEST="$CRASH_EVIDENCE/manifest.txt"
[ -f "$MANIFEST" ] || evidence_finish fail "the run wrote no manifest at $MANIFEST"

manifest_value() { sed -n "s/^$1: *//p" "$MANIFEST" | tail -1; }

PRINTED="$(sed -n 's/^crash_injection_sha256: \([0-9a-f]\{64\}\)$/\1/p' "$EV_LOG" | tail -1)"
[ -n "$PRINTED" ] || evidence_finish fail "the run printed no crash_injection_sha256 digest"
RECOMPUTED="$( { sha256sum "$MANIFEST" 2>/dev/null || shasum -a 256 "$MANIFEST"; } | awk '{print $1}')"
# The digest is only evidence about the manifest if it is the manifest's digest.
[ "$PRINTED" = "$RECOMPUTED" ] || \
    evidence_finish fail "the printed digest $PRINTED is not the digest of $MANIFEST ($RECOMPUTED)"

evidence_observe manifest_sha256 "$PRINTED"
evidence_observe checks_passed "$(manifest_value passed)"
evidence_observe checks_failed "$(manifest_value failed)"
evidence_observe kill_connectblock_height "$(manifest_value kill_connectblock_height)"
evidence_observe kill_nameindex_height "$(manifest_value kill_nameindex_height)"
evidence_observe kill_wallet_height "$(manifest_value kill_wallet_height)"
evidence_observe kill_reorg_height "$(manifest_value kill_reorg_height)"
evidence_observe names_registered "$(manifest_value names_registered)"
evidence_observe nameidx_fields "$(manifest_value nameidx_fields)"
evidence_observe note_count "$(manifest_value note_count)"
evidence_observe notes_lost "$(manifest_value notes_lost)"
evidence_observe states_matched "$(manifest_matches "$MANIFEST")"
evidence_observe states_differed "$(manifest_differs "$MANIFEST")"
evidence_observe scan_gaps_recorded "$(manifest_value scan_gaps_recorded)"
evidence_observe locked_rescan_gap "$(manifest_value locked_rescan_gap)"
evidence_observe locked_rescan_gap_after_unlock "$(manifest_value locked_rescan_gap_after_unlock)"
evidence_observe locked_rescan_gap_close_status "$(manifest_value locked_rescan_gap_close_status)"
evidence_observe locked_rescan_unlock_seconds "$(manifest_value locked_rescan_unlock_seconds)"
evidence_observe locked_rescan_note_count "$(manifest_value locked_rescan_note_count)"
evidence_observe reorg_restart_scan_gap "$(manifest_value reorg_restart_scan_gap)"
evidence_observe reorg_scan_gap_after_unlock "$(manifest_value reorg_scan_gap_after_unlock)"
evidence_observe reorg_note_count "$(manifest_value reorg_note_count)"
evidence_observe reorg_notes_lost "$(manifest_value reorg_notes_lost)"
evidence_observe boundary_b "$(manifest_value boundary_b)"

REFUSALS="$(manifest_refusals "$MANIFEST")"
if [ -n "$REFUSALS" ]; then
    echo "$REFUSALS" | tail -n +2
    evidence_finish fail "$(echo "$REFUSALS" | head -1)"
fi

evidence_pass
