#!/bin/bash
# Produces crash_injection_sha256: the SIGKILL recovery run over the batched
# persistence points, and the digest that run computes over its own manifest.
#
# crash_injection_test.sh already kills a victim mid-ConnectBlock, mid-name-index
# batch, with the wallet locator lagging and mid-reorg, and prints
# "crash_injection_sha256: <sha>" over the manifest it leaves. Nothing keyed that
# digest to a commit, so the field had no producer. This drives the run, records
# the digest it printed, recomputes it from the manifest on disk, and refuses a
# run that reached no kill window or compared two empty states.
#
# What a pass covers: a victim killed with SIGKILL at each of the four batching
# points recovers to a tip and to per-epoch and name-index state byte-identical
# to a control that ran the same block stream uninterrupted, and loses no
# shielded note field across the kill.
# What it does not: the harness prints its own limits under WHAT THIS DOES NOT
# COVER, and they hold for this document. It is not a torn-write or power-loss
# test, the kill points are timing-driven rather than instrumented, and the
# comparison is over what RPC exposes, not a database byte-compare.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

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

PASSED="$(manifest_value passed)"
FAILED="$(manifest_value failed)"
KILL_CONNECT="$(manifest_value kill_connectblock_height)"
KILL_IDNS="$(manifest_value kill_nameindex_height)"
KILL_WALLET="$(manifest_value kill_wallet_height)"
KILL_REORG="$(manifest_value kill_reorg_height)"
NAMES="$(manifest_value names_registered)"
NAMEIDX="$(manifest_value nameidx_fields)"
NOTES_LOST="$(manifest_value notes_lost)"
NOTE_COUNT="$(manifest_value note_count)"
MATCHES="$( { grep -c '^MATCH ' "$MANIFEST" || true; } | tr -dc '0-9')"
DIFFERS="$( { grep -c '^DIFFER ' "$MANIFEST" || true; } | tr -dc '0-9')"

evidence_observe manifest_sha256 "$PRINTED"
evidence_observe checks_passed "${PASSED:-0}"
evidence_observe checks_failed "${FAILED:-0}"
evidence_observe kill_connectblock_height "${KILL_CONNECT:-none}"
evidence_observe kill_nameindex_height "${KILL_IDNS:-none}"
evidence_observe kill_wallet_height "${KILL_WALLET:-none}"
evidence_observe kill_reorg_height "${KILL_REORG:-none}"
evidence_observe names_registered "${NAMES:-0}"
evidence_observe nameidx_fields "${NAMEIDX:-0}"
evidence_observe note_count "${NOTE_COUNT:-none}"
evidence_observe notes_lost "${NOTES_LOST:-unrecorded}"
evidence_observe states_matched "${MATCHES:-0}"
evidence_observe states_differed "${DIFFERS:-0}"
evidence_observe boundary_b "$(manifest_value boundary_b)"

# The harness fails itself on each of these, so a violation here means its exit
# status and its manifest disagree. Both are checked: a producer that trusts
# only the status records whatever a later edit stops failing on.
evidence_require_zero "recovered states that differed from the control" "${DIFFERS:-0}"
evidence_require_zero "harness checks that failed" "${FAILED:-0}"
[ "${PASSED:-0}" -gt 0 ] || evidence_finish fail "the run recorded no passing check"
[ "${MATCHES:-0}" -ge 3 ] || \
    evidence_finish fail "only ${MATCHES:-0} of the 3 state comparisons ran"
case "$KILL_CONNECT" in
    *"mid-connect"*) ;;
    *) evidence_finish fail "no mid-ConnectBlock kill window was reached (${KILL_CONNECT:-none})" ;;
esac
case "$KILL_IDNS" in
    NONE*|"") evidence_finish fail "no mid-batch name-index kill window was reached" ;;
esac
case "$KILL_REORG" in
    *"mid-reorg"*) ;;
    *) evidence_finish fail "no mid-reorg kill window was reached (${KILL_REORG:-none})" ;;
esac
[ -n "$KILL_WALLET" ] || evidence_finish fail "the wallet-locator phase recorded no kill"
[ "${NOTES_LOST:-unrecorded}" = "0" ] || \
    evidence_finish fail "the wallet-locator phase recorded notes_lost=${NOTES_LOST:-unrecorded}"
# Two empty indexes match trivially. The harness says so too; this refuses the
# document rather than the run.
[ "${NAMEIDX:-0}" -gt 0 ] || evidence_finish fail "the name index was empty, so its comparison proved nothing"

evidence_pass
