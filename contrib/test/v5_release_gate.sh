#!/bin/bash
# Local/CI orchestrator for the v5 internal release audit.
# --all means static checks, a clean platform build/release-check, and the
# repository integration suites. Hosted sanitizer and candidate-evidence policy
# remain separate mandatory release jobs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODE="${1:---all}"

STATIC_SHELL=(
    "$SCRIPT_DIR/audit_build_dependencies.sh"
    "$SCRIPT_DIR/idag_finality_relay_test.sh"
    "$SCRIPT_DIR/idag_finality_2of3_test.sh"
)

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
    done < <(find "$ROOT/contrib/test" "$ROOT/contrib/testnet_tools" -type f -name '*.py' -print0)

    for file in "${STATIC_SHELL[@]}"; do
        [ -x "$file" ] || fail "required executable is missing: $file"
    done

    "$SCRIPT_DIR/audit_build_dependencies.sh"
    python3 "$SCRIPT_DIR/idag_four_node_differential.py" --selftest
    python3 "$ROOT/contrib/testnet_tools/innova_testnet_tool.py" selftest
    python3 "$ROOT/contrib/testnet_tools/v5_testnet_rollout.py" --selftest
    python3 "$ROOT/contrib/testnet_tools/v5_mainnet_activation.py" --selftest
    python3 "$SCRIPT_DIR/check_v5_release_policy.py" --selftest
    python3 "$ROOT/src/privacy_vnext/rust/tools/verify_provenance.py"
    log "static gate passed"
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
                make USE_NATIVETOR=- USE_IPFS=- INNOVA_SPINNER=0 \
                    -f makefile.unix clean
                make USE_NATIVETOR=- USE_IPFS=- INNOVA_SPINNER=0 \
                    CXXFLAGS="-Werror=return-type -Werror=format" \
                    CFLAGS="-Werror=return-type -Werror=format" \
                    -f makefile.unix -j"$jobs" innovad test_innova
                make USE_NATIVETOR=- USE_IPFS=- INNOVA_SPINNER=0 \
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
        ;;
    --unit)
        run_unit
        ;;
    --integration)
        run_integration
        ;;
    --all)
        run_static
        run_unit
        run_integration
        ;;
    *)
        fail "usage: $0 [--static|--unit|--integration|--all]"
        ;;
esac
