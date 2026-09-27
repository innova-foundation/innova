#!/bin/bash
# Local/CI orchestrator for the v5 internal release audit.
# The evidence gate is fail-closed: missing evidence fails it, and --selftest is not evidence.
# Evidence lives in V5_EVIDENCE_DIR, one document and one log per release-policy verification field.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODE="${1:---all}"

# Checked for the executable bit only. Presence here is not execution: the
# relay test is reached solely through idag_finality_2of3_test.sh.
STATIC_SHELL=(
    "$SCRIPT_DIR/audit_build_dependencies.sh"
    "$SCRIPT_DIR/idag_finality_relay_test.sh"
    "$SCRIPT_DIR/idag_finality_2of3_test.sh"
)

# The commands run_static actually executes. Kept as data so --print-suites
# reports what runs instead of a second list that can drift from it.
STATIC_COMMANDS=(
    "$SCRIPT_DIR/audit_build_dependencies.sh"
    "python3 $SCRIPT_DIR/idag_four_node_differential.py --selftest"
    "python3 $ROOT/contrib/testnet_tools/innova_testnet_tool.py selftest"
    "python3 $ROOT/contrib/testnet_tools/v5_testnet_rollout.py --selftest"
    "python3 $ROOT/contrib/testnet_tools/v5_mainnet_activation.py --selftest"
    "python3 $SCRIPT_DIR/check_v5_release_policy.py --selftest"
    "python3 $SCRIPT_DIR/v5_verification_evidence.py --selftest"
    "python3 $ROOT/src/privacy_vnext/rust/tools/verify_provenance.py"
)

# One producer per REQUIRED_VERIFICATION_FIELDS entry: produce_<obligation>_evidence.sh answers
# for <obligation>_sha256, so the field is read from the file name.
VERIFICATION_PRODUCERS=(
    "$SCRIPT_DIR/produce_asan_lsan_evidence.sh"
    "$SCRIPT_DIR/produce_crash_injection_evidence.sh"
    "$SCRIPT_DIR/produce_fuzz_corpora_evidence.sh"
    "$SCRIPT_DIR/produce_history_replay_evidence.sh"
    "$SCRIPT_DIR/produce_integration_evidence.sh"
    "$SCRIPT_DIR/produce_linux_clean_evidence.sh"
    "$SCRIPT_DIR/produce_macos_clean_evidence.sh"
    "$SCRIPT_DIR/produce_performance_evidence.sh"
    "$SCRIPT_DIR/produce_qt6_release_evidence.sh"
    "$SCRIPT_DIR/produce_rust_audit_evidence.sh"
    "$SCRIPT_DIR/produce_ubsan_evidence.sh"
)

EVIDENCE_TOOL="$SCRIPT_DIR/v5_verification_evidence.py"
EVIDENCE_DIR="${V5_EVIDENCE_DIR:-${TMPDIR:-/tmp}/innova-v5-evidence}"

# produce_asan_lsan_evidence.sh -> asan_lsan_sha256
producer_field() {
    local name
    name="$(basename "$1")"
    name="${name#produce_}"
    printf '%s_sha256\n' "${name%_evidence.sh}"
}

# A four-node differential needs four running nodes on one network with mining
# paused. Point these at a real inventory to produce the evidence; unset, the
# evidence gate reports it missing.
DIFFERENTIAL_INVENTORY="${IDAG_DIFFERENTIAL_INVENTORY:-}"
DIFFERENTIAL_TMP="${TMPDIR:-/tmp}"
DIFFERENTIAL_OUTPUT="${IDAG_DIFFERENTIAL_OUTPUT:-${DIFFERENTIAL_TMP%/}/idag-four-node-differential.json}"
RELEASE_POLICY="$SCRIPT_DIR/check_v5_release_policy.py"

INTEGRATION_SUITES=(
    "$SCRIPT_DIR/full_milestone_test.sh"
    "$SCRIPT_DIR/privacy_integration_test.sh"
    "$SCRIPT_DIR/shielded_fcmp_zsend_modes_test.sh --nullsend-smoke"
    "$SCRIPT_DIR/idag_1s_sync_regression_test.sh"
    "$SCRIPT_DIR/idag_tx_relay_test.sh"
    "$SCRIPT_DIR/idag_finality_2of3_test.sh"
    "$SCRIPT_DIR/idag_block_propagation_test.sh"
    "$SCRIPT_DIR/idag_hidden_finality_stress_test.sh"
    "$SCRIPT_DIR/idag_stress_test.sh"
    "$SCRIPT_DIR/idag_tps_test.sh"
    # The 2008 envelope is the shipping privacy system; unit tests do not reach
    # these end-to-end paths.
    "$SCRIPT_DIR/iv5_adversarial_regtest_test.sh"
    "$SCRIPT_DIR/iv5_spend_regtest_test.sh"
    "$SCRIPT_DIR/iv5_boundary_b_regtest_test.sh"
    "$SCRIPT_DIR/iv5_fee_note_regtest_test.sh"
    "$SCRIPT_DIR/iv5_migration_regtest_test.sh"
    "$SCRIPT_DIR/iv5_tree_store_regtest_test.sh"
    "$SCRIPT_DIR/iv5_leaf_index_catchup_regtest_test.sh"
    "$SCRIPT_DIR/iv5_dag_sibling_regtest_test.sh"
    "$SCRIPT_DIR/iv5_collateral_rpc_regtest_test.sh"
    "$SCRIPT_DIR/iv5_note_vote_regtest_test.sh"
    # Wallet recovery (phrase and hex seed, locked restart) and P2CS cold
    # staking (delegate, list, revoke): both driven from the GUI as well as RPC.
    "$SCRIPT_DIR/recovery_phrase_restore.sh"
    "$SCRIPT_DIR/cold_staking_test.sh"
    # Proof-of-data stamps: RPC surface and DAG effects (merged blocks, reorged anchors, finalized verdict).
    "$SCRIPT_DIR/pod_regtest_test.sh"
    "$SCRIPT_DIR/pod_post_dag_regtest_test.sh"
    # NullSend ships in v5, and the smoke flag above only reaches the wallet
    # side of it. This is the round: directory, coordinator, seats, settlement.
    "$SCRIPT_DIR/iv5_nullsend_regtest_test.sh"
    # What a node does around the chain rather than to it. The unit suite ends
    # where each of these starts: at the process boundary, at the orphan drop,
    # and at a branch the finality gate must refuse without scoring the peer.
    "$SCRIPT_DIR/shutdown_clean_exit_test.sh"
    "$SCRIPT_DIR/orphan_expiry_recovery_test.sh"
    "$SCRIPT_DIR/side_branch_sync_regtest_test.sh"
    "$SCRIPT_DIR/finality_switch_gate_fleet_test.sh"
)

log() {
    printf '[v5-release-gate] %s\n' "$*"
}

fail() {
    printf '[v5-release-gate] ERROR: %s\n' "$*" >&2
    exit 1
}

run_static() {
    log "checking shell syntax"
    local file
    while IFS= read -r -d '' file; do
        bash -n "$file"
    done < <(find "$ROOT/contrib" -type f -name '*.sh' -print0)

    log "checking Python syntax"
    while IFS= read -r -d '' file; do
        python3 -m py_compile "$file"
    done < <(find "$ROOT/contrib/test" "$ROOT/contrib/testnet_tools" \
        -type f -name '*.py' -print0)

    for file in "${STATIC_SHELL[@]}"; do
        [ -x "$file" ] || fail "required executable is missing: $file"
    done

    # Every --selftest below exercises a parser or comparator on synthetic
    # input. None of them observes a node, a build or an artifact, so none is
    # evidence about the candidate; run_evidence covers that separately.
    local command
    for command in "${STATIC_COMMANDS[@]}"; do
        log "running $command"
        # Repository-owned command plus fixed arguments; word splitting here
        # intentionally turns the flags into argv.
        # shellcheck disable=SC2086
        $command
    done
    log "static gate passed"
}

run_evidence() {
    local missing=0

    log "checking four-node Boundary-A differential evidence"
    if [ -n "$DIFFERENTIAL_INVENTORY" ]; then
        [ -f "$DIFFERENTIAL_INVENTORY" ] || \
            fail "IDAG_DIFFERENTIAL_INVENTORY does not name a file: $DIFFERENTIAL_INVENTORY"
        python3 "$SCRIPT_DIR/idag_four_node_differential.py" \
            --inventory "$DIFFERENTIAL_INVENTORY" \
            --output "$DIFFERENTIAL_OUTPUT" \
            --require-schema-v3
    else
        {
            printf '[v5-release-gate] MISSING EVIDENCE: four-node Boundary-A differential\n'
            printf '    --selftest compares two synthetic snapshots in memory. It contacts\n'
            printf '    no node and produces no differential, so it shows the comparator\n'
            printf '    parses, not that four nodes agree on DAG order, epoch state and\n'
            printf '    finality. Set IDAG_DIFFERENTIAL_INVENTORY to an inventory naming\n'
            printf '    four nodes on one network with mining paused, and optionally\n'
            printf '    IDAG_DIFFERENTIAL_OUTPUT to a path outside the repository\n'
            printf '    (default %s).\n' "$DIFFERENTIAL_OUTPUT"
        } >&2
        missing=1
    fi

    log "checking release-evidence digest producers"
    local orphaned
    orphaned="$(python3 - "$ROOT" "$RELEASE_POLICY" <<'PY'
import ast
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
policy = pathlib.Path(sys.argv[2])
consumer = policy.relative_to(root).as_posix()

fields = []
for node in ast.walk(ast.parse(policy.read_text())):
    if not isinstance(node, ast.Assign):
        continue
    if not any(isinstance(t, ast.Name) and t.id == "REQUIRED_VERIFICATION_FIELDS"
               for t in node.targets):
        continue
    fields = [c.value for c in ast.walk(node.value)
              if isinstance(c, ast.Constant) and isinstance(c.value, str)]

if not fields:
    sys.exit("cannot read REQUIRED_VERIFICATION_FIELDS from " + consumer)

SKIP = {".git", "vendor", "target", "node_modules"}


def walk_sources():
    # Prune build trees, and any nested checkout: a worktree under this root is a
    # second copy of the same sources and would be counted as its own producer.
    for base, directories, files in os.walk(root):
        directories[:] = [d for d in directories
                          if d not in SKIP
                          and not (pathlib.Path(base) / d / ".git").exists()]
        for name in files:
            yield pathlib.Path(base) / name


RUNNABLE = (".sh", ".py", ".yml", ".yaml")
# A report that names a field does not compute it, so reports cannot answer for it.
REPORTS = ("docs/",)


def runnable(relative):
    if relative == consumer or relative.startswith(REPORTS):
        return False
    name = relative.rsplit("/", 1)[-1]
    return relative.endswith(RUNNABLE) or name.lower().startswith("makefile")


def producers(name):
    found = subprocess.run(["git", "grep", "-l", "--fixed-strings", name],
                           cwd=root, capture_output=True, text=True)
    if found.returncode < 2:
        return [p for p in found.stdout.split() if runnable(p)]
    # Not a Git checkout: fall back to reading the tree directly.
    hits = []
    for path in walk_sources():
        relative = path.relative_to(root).as_posix()
        if not runnable(relative):
            continue
        try:
            if name in path.read_text(errors="ignore"):
                hits.append(relative)
        except OSError:
            continue
    return hits


for name in sorted(fields):
    if not producers(name):
        print(name)
PY
)"

    if [ -n "$orphaned" ]; then
        local field
        while IFS= read -r field; do
            [ -n "$field" ] || continue
            printf '[v5-release-gate] MISSING PRODUCER: %s\n' "$field" >&2
        done <<< "$orphaned"
        {
            printf '    No tracked file except %s names the fields above, so nothing in\n' \
                "$(basename "$RELEASE_POLICY")"
            printf '    this repository computes them. --selftest fills them with fixture\n'
            printf '    digests, which shows the policy parses a digest map, not that the\n'
            printf '    run behind each digest happened.\n'
        } >&2
        missing=1
    fi

    log "checking the evidence documents behind the verification digests"
    local producer field commit fields=() allow=()
    commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
    [ -n "$commit" ] || fail "the gate must run in a git checkout; the digests are keyed to a commit"
    [ "${V5_EVIDENCE_ALLOW_DIRTY:-0}" = "1" ] && allow=(--allow-dirty)
    for producer in "${VERIFICATION_PRODUCERS[@]}"; do
        [ -x "$producer" ] || fail "wired producer is missing or not executable: $producer"
        field="$(producer_field "$producer")"
        fields+=(--field "$field")
        if ! python3 "$EVIDENCE_TOOL" verify --field "$field" --dir "$EVIDENCE_DIR" \
                --commit "$commit" ${allow+"${allow[@]}"} >/dev/null 2>"${DIFFERENTIAL_TMP%/}/v5-evidence-$field.err"; then
            printf '[v5-release-gate] MISSING EVIDENCE: %s\n' "$field" >&2
            sed 's/^/    /' "${DIFFERENTIAL_TMP%/}/v5-evidence-$field.err" >&2 || true
            printf '    produce it with %s (it records the run, or fails)\n' \
                "${producer#$ROOT/}" >&2
            missing=1
        fi
        rm -f "${DIFFERENTIAL_TMP%/}/v5-evidence-$field.err"
    done
    # The index is the block a release manifest carries under "verification"; it is
    # written from the documents on disk, never transcribed.
    python3 "$EVIDENCE_TOOL" index "${fields[@]}" --dir "$EVIDENCE_DIR" \
        --commit "$commit" ${allow+"${allow[@]}"} >/dev/null 2>&1 || true

    [ "$missing" -eq 0 ] || fail "required release evidence is missing (see MISSING lines above)"
    log "evidence gate passed"
}

# Runs every wired producer. Each either reuses the document already written for
# this commit or performs its run; a host that can do neither fails here, because
# an obligation that exits 0 without evidence is the failure this chain prevents.
run_verification() {
    local producer field status=0 failed=()
    log "producing release verification evidence into $EVIDENCE_DIR"
    for producer in "${VERIFICATION_PRODUCERS[@]}"; do
        field="$(producer_field "$producer")"
        log "running $(basename "$producer") for $field"
        status=0
        V5_EVIDENCE_DIR="$EVIDENCE_DIR" "$producer" || status=$?
        [ "$status" -eq 0 ] || failed+=("$field (exit $status)")
    done
    if [ "${#failed[@]}" -gt 0 ]; then
        printf '[v5-release-gate] verification evidence not produced: %s\n' "${failed[*]}" >&2
        fail "one or more verification producers did not produce evidence"
    fi
    log "verification evidence complete"
}

print_suites() {
    local entry
    for entry in "${STATIC_COMMANDS[@]}"; do
        printf 'executed\tstatic\t%s\n' "$entry"
    done
    printf 'executed\tunit\tmake release-check\n'
    for entry in "${VERIFICATION_PRODUCERS[@]}"; do
        printf 'executed\tverification\t%s\n' "$entry"
    done
    for entry in "${INTEGRATION_SUITES[@]}"; do
        printf 'executed\tintegration\t%s\n' "$entry"
    done
    # Only report an entry as checked-only when nothing above executes it.
    local command executed
    for entry in "${STATIC_SHELL[@]}"; do
        executed=0
        for command in "${STATIC_COMMANDS[@]}"; do
            case " $command " in
                *" $entry "*) executed=1 ;;
            esac
        done
        [ "$executed" -eq 0 ] && printf 'checked-only\tstatic\t%s\n' "$entry"
    done
    return 0
}

run_unit() {
    local kernel jobs
    kernel="$(uname -s)"

    case "$kernel" in
        Darwin)
            jobs="$(sysctl -n hw.ncpu)"
            log "starting clean macOS daemon/test build"
            (
                cd "$ROOT/src"
                make STRICT_WARNINGS=1 INNOVA_SPINNER=0 -f makefile.osx clean
                make STRICT_WARNINGS=1 INNOVA_SPINNER=0 -f makefile.osx \
                    -j"$jobs" innovad test_innova
                make STRICT_WARNINGS=1 INNOVA_SPINNER=0 -f makefile.osx \
                    release-check
            )
            ;;
        Linux)
            jobs="$(nproc)"
            log "starting clean Linux daemon/test build"
            (
                cd "$ROOT/src"
                make USE_NATIVETOR=- INNOVA_SPINNER=0 \
                    -f makefile.unix clean
                make USE_NATIVETOR=- INNOVA_SPINNER=0 \
                    CXXFLAGS="-Werror=return-type -Werror=format" \
                    CFLAGS="-Werror=return-type -Werror=format" \
                    -f makefile.unix -j"$jobs" innovad test_innova
                make USE_NATIVETOR=- INNOVA_SPINNER=0 \
                    CXXFLAGS="-Werror=return-type -Werror=format" \
                    CFLAGS="-Werror=return-type -Werror=format" \
                    -f makefile.unix release-check
            )
            ;;
        *)
            fail "clean unit gate is unsupported on $kernel"
            ;;
    esac

    log "clean build and unit release-check passed"
}

run_integration() {
    [ -x "$ROOT/src/innovad" ] || fail "build src/innovad before running integration gates"
    local suite
    for suite in "${INTEGRATION_SUITES[@]}"; do
        log "running $suite"
        # Entries are repository-owned command plus fixed arguments; word
        # splitting here intentionally turns the optional smoke flag into argv.
        # shellcheck disable=SC2086
        INNOVAD="$ROOT/src/innovad" KEEP_DIR="${KEEP_DIR:-0}" $suite
    done
    log "integration gate passed"
}

case "$MODE" in
    --static)
        run_static
        run_evidence
        ;;
    --unit)
        run_unit
        ;;
    --integration)
        run_integration
        ;;
    --evidence)
        run_evidence
        ;;
    --verification)
        run_verification
        ;;
    --print-suites)
        print_suites
        ;;
    --all)
        run_static
        run_unit
        # The integration suites run here, once, through the producer that records
        # them; run_evidence then reads every document this produced.
        run_verification
        run_evidence
        ;;
    *)
        fail "usage: $0 [--static|--unit|--integration|--verification|--evidence|--print-suites|--all]"
        ;;
esac
