#!/bin/bash
# Local macOS IDAG regtest gate runner.
#
# This script keeps the unblock narrow: it builds the current daemon, refreshes
# a Gatekeeper assessment rule for that exact binary, probes execution, then
# runs the local regtest propagation gates. It is not for live wallet validation.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"
SPCTL_LABEL="${SPCTL_LABEL:-InnovaRegtest}"
SPCTL_MODE="${SPCTL_MODE:-auto}"
MAKE_JOBS="${MAKE_JOBS:-4}"
AMFI_LOG_WINDOW="${AMFI_LOG_WINDOW:-10m}"
KEEP_DIR="${KEEP_DIR:-0}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$INNOVA_ROOT/testnet_metrics/local_regtest_gate_$RUN_ID}"

GATES=(
    "contrib/test/idag_1s_sync_regression_test.sh"
    "contrib/test/idag_tx_relay_test.sh"
    "contrib/test/idag_finality_relay_test.sh"
    "contrib/test/idag_block_propagation_test.sh"
    "contrib/test/idag_stress_test.sh"
    "contrib/test/idag_tps_test.sh"
)

log() {
    printf '[macos-idag-gate] %s\n' "$*"
}

fail() {
    printf '[macos-idag-gate] ERROR: %s\n' "$*" >&2
    exit 1
}

require_macos() {
    if [ "$(uname -s)" != "Darwin" ]; then
        fail "this runner is macOS-specific; use the individual regtest scripts on other hosts"
    fi
}

collect_security_log() {
    local reason="$1"
    local out="$ARTIFACT_DIR/${reason}_amfi_gatekeeper.log"

    mkdir -p "$ARTIFACT_DIR"
    if command -v log >/dev/null 2>&1; then
        /usr/bin/log show \
            --style syslog \
            --last "$AMFI_LOG_WINDOW" \
            --predicate 'process == "syspolicyd" || process == "amfid" || eventMessage CONTAINS[c] "AMFI" || eventMessage CONTAINS[c] "CMS" || eventMessage CONTAINS[c] "Unrecoverable CT signature" || eventMessage CONTAINS[c] "no CMS blob"' \
            > "$out" 2>&1 || true
        log "Security log window written to $out"
    else
        log "macOS log command not found; skipped AMFI/Gatekeeper log capture"
    fi
}

build_daemon() {
    log "Building $INNOVAD"
    make -j"$MAKE_JOBS" -C "$INNOVA_ROOT/src" -f makefile.unix innovad
    [ -x "$INNOVAD" ] || fail "built daemon is not executable at $INNOVAD"
}

verify_signature() {
    log "Verifying code signature for $INNOVAD"
    xattr -dr com.apple.quarantine "$INNOVAD" 2>/dev/null || true
    codesign --verify --strict --verbose=4 "$INNOVAD"
}

refresh_spctl_rule() {
    local spctl_output

    if [ "$SPCTL_MODE" = "skip" ]; then
        log "Skipping spctl label refresh because SPCTL_MODE=skip"
        return 0
    fi

    command -v spctl >/dev/null 2>&1 || fail "spctl not found"

    log "Refreshing Gatekeeper label '$SPCTL_LABEL' for $INNOVAD"
    spctl --remove --label "$SPCTL_LABEL" >/dev/null 2>&1 || true

    spctl_output="$(spctl --add --label "$SPCTL_LABEL" "$INNOVAD" 2>&1)"
    if [ "$?" -ne 0 ]; then
        printf '%s\n' "$spctl_output" >&2
        if printf '%s\n' "$spctl_output" | grep -qi "no longer supported"; then
            if [ "$SPCTL_MODE" = "auto" ]; then
                log "spctl label rules are not supported on this macOS; continuing with signature verification and execution probe"
                return 0
            fi
            cat >&2 <<EOF
This macOS spctl no longer supports label-based allow rules.
The selected unblock route was a narrow Gatekeeper label for this daemon, so
the local regtest gate cannot continue on this host without choosing a
different unblock route.

Do not use spctl --master-disable for this gate.
EOF
        else
            cat >&2 <<EOF
spctl could not add the narrow allow rule.
If this requires administrator authorization, run only this label/path operation:

  sudo spctl --remove --label "$SPCTL_LABEL"
  sudo spctl --add --label "$SPCTL_LABEL" "$INNOVAD"
  sudo spctl --enable --label "$SPCTL_LABEL"

Do not use spctl --master-disable for this gate.
EOF
        fi
        exit 1
    fi

    if ! spctl --enable --label "$SPCTL_LABEL"; then
        fail "spctl could not enable label '$SPCTL_LABEL'"
    fi

    spctl --assess --type execute --verbose=4 "$INNOVAD" || \
        log "spctl assessment still reports non-acceptance; execution probe is authoritative for this gate"
}

probe_daemon() {
    local out="$ARTIFACT_DIR/innovad_version.txt"

    mkdir -p "$ARTIFACT_DIR"
    log "Probing daemon execution with -?"
    "$INNOVAD" "-?" > "$out" 2>&1 || true
    if grep -q "Innova version" "$out"; then
        log "Version probe passed; output written to $out"
    else
        cat "$out" >&2 || true
        collect_security_log "version_probe_failed"
        fail "innovad -version failed after Gatekeeper allow rule"
    fi
}

run_gate() {
    local gate="$1"
    local path="$INNOVA_ROOT/$gate"

    [ -x "$path" ] || fail "gate script is not executable: $path"

    log "Running $gate"
    if KEEP_DIR="$KEEP_DIR" IDAG_RELAY_KEEP_DIR="$KEEP_DIR" INNOVAD="$INNOVAD" "$path"; then
        log "Passed $gate"
    else
        collect_security_log "$(basename "$gate" .sh)_failed"
        fail "failed gate: $gate"
    fi
}

main() {
    require_macos

    build_daemon
    verify_signature
    refresh_spctl_rule
    probe_daemon

    log "Running local IDAG gates in one shell session"
    local gate
    for gate in "${GATES[@]}"; do
        run_gate "$gate"
    done

    log "All local IDAG regtest gates passed"
}

main "$@"
