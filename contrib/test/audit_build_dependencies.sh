#!/bin/sh
# Static release check for test-object dependency tracking and suite wiring.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

fail() {
    echo "audit_build_dependencies: ERROR: $*" >&2
    exit 1
}

tmp_objects=$(mktemp)
tmp_sources=$(mktemp)
tmp_replay=$(mktemp)
trap 'rm -f "$tmp_objects" "$tmp_sources" "$tmp_replay"' EXIT INT TERM

for name in makefile.unix makefile.osx; do
    makefile="$ROOT/src/$name"
    grep -Eq '^-include .*obj/\*/\*\.P' "$makefile" || \
        fail "$name does not include nested obj/test dependency files"
    grep -Eq '^[[:space:]]*\+\$\(MAKE\) -C leveldb ' "$makefile" || \
        fail "$name does not propagate the nested LevelDB build result"
    grep -Eq '^[[:space:]]*\+\$\(MAKE\) -C leveldb clean' "$makefile" || \
        fail "$name does not propagate the nested LevelDB clean result"
    if grep -Eq '^[[:space:]]*-.*leveldb.*clean|leveldb.*clean.*\|\| true' "$makefile"; then
        fail "$name ignores a nested LevelDB clean failure"
    fi

    for object in bulletproof_ac_tests finality_committee_sig_tests halfagg_stake_tests epoch_state_determinism_tests smessage_hmac_tests; do
        grep -q "obj/test/${object}\.o" "$makefile" || \
            fail "$name does not compile ${object}.o"
    done

    legacy_suites="allocator_tests base32_tests base58_tests base64_tests bignum_tests Checkpoints_tests DoS_tests getarg_tests key_tests mruset_tests multisig_tests netbase_tests ringsig_tests rpc_tests script_P2SH_tests script_tests sigopcount_tests transaction_tests uint160_tests uint256_tests util_tests wallet_tests accounting_tests miner_tests"
    for object in $legacy_suites; do
        grep -q "obj/test/${object}\.o" "$makefile" || \
            fail "$name does not compile legacy ${object}.o"
    done
    # Compare against the sources on disk rather than a fixed count: a suite
    # that is added but never wired compiles clean and silently never runs.
    sed -n '/^TEST_OBJS=/,/^$/p' "$makefile" \
        | grep -oE 'obj/test/[^[:space:]\\]+\.o' \
        | sed 's|obj/test/||; s|\.o$||' | sort -u > "$tmp_objects"
    find "$ROOT/src/test" -maxdepth 1 -name '*.cpp' -exec basename {} .cpp ';' \
        | sort -u > "$tmp_sources"

    missing=$(comm -13 "$tmp_objects" "$tmp_sources")
    [ -z "$missing" ] || \
        fail "$name does not compile these test translation units: $(echo $missing)"

    orphaned=$(comm -23 "$tmp_objects" "$tmp_sources")
    [ -z "$orphaned" ] || \
        fail "$name compiles test objects with no source: $(echo $orphaned)"

    legacy_target_body=$(sed -n '/^check-legacy-aggregate:/,/^$/p' "$makefile")
    for suite in $legacy_suites; do
        echo "$legacy_target_body" | grep -q "$suite" || \
            fail "$name check-legacy-aggregate omits $suite"
    done

    # The IV5 archive is a consensus input produced outside make's own dependency
    # graph. Both the freshness guard and the provenance gate have to stay reachable
    # from release-check, and the rule that builds the archive has to stay unconditional.
    for target in check-privacy-vnext-freshness check-privacy-vnext-provenance; do
        grep -q "^${target}:" "$makefile" || \
            fail "$name does not define $target"
        release_line=$(grep '^release-check:' "$makefile")
        case " $release_line " in
            *" $target "*) ;;
            *) fail "$name release-check does not require $target" ;;
        esac
    done
    grep -Eq '^\$\(PRIVACY_VNEXT_RUST_LIB\): FORCE' "$makefile" || \
        fail "$name does not rebuild the IV5 archive unconditionally"
    grep -Eq '^leveldb/libleveldb\.a: FORCE' "$makefile" || \
        fail "$name does not re-enter the nested LevelDB build unconditionally"

    for target in check-legacy-aggregate check-bpac check-finality-committee-sig check-halfagg-stake check-epoch-state-determinism check-smessage-hmac; do
        grep -q "^${target}: test_innova" "$makefile" || \
            fail "$name does not define $target"
        release_line=$(grep '^release-check:' "$makefile")
        case " $release_line " in
            *" $target "*) ;;
            *) fail "$name release-check does not require $target" ;;
        esac
    done
done

freshness_gate="$ROOT/contrib/test/check_privacy_vnext_freshness.sh"
[ -x "$freshness_gate" ] || fail "IV5 archive freshness guard is missing or not executable"
grep -q 'PROVENANCE_SHA256' "$ROOT/src/privacy_vnext/iv5_protocol.h" || \
    fail "consensus header declares no IV5 provenance digest to check the archive against"
grep -q 'iv5::PROVENANCE_SHA256' "$ROOT/src/privacy_vnext_ffi.cpp" || \
    fail "ABI load does not compare the linked archive's provenance against the header"
grep -q 'LoadPrivacyVNextAbiInfo' "$ROOT/src/init.cpp" || \
    fail "startup does not verify the linked IV5 decoder before running"

staged_gate="$ROOT/contrib/test/build_staged_index.sh"
[ -x "$staged_gate" ] || fail "isolated staged-index build helper is missing"
grep -q 'checkout-index --all' "$staged_gate" || \
    fail "staged-index build helper does not export the exact Git index"
grep -q 'diff --cached --check' "$staged_gate" || \
    fail "staged-index build helper does not reject malformed staged patches"

for flags in CFLAGS CXXFLAGS; do
    grep -Eq "^override ${flags} \+=" "$ROOT/src/leveldb/Makefile" || \
        fail "LevelDB drops parent-supplied audit flags or its required ${flags}"
done
grep -Eq '^override LDFLAGS \+=' "$ROOT/src/leveldb/Makefile" || \
    fail "LevelDB drops required platform linker flags when parent flags are supplied"
grep -q 'CXXFLAGS="$(xCXXFLAGS)"' "$ROOT/src/makefile.unix" || \
    fail "Linux parent does not propagate sanitizer/warning CXXFLAGS into LevelDB"
grep -q 'CFLAGS="$(xCFLAGS)"' "$ROOT/src/makefile.unix" || \
    fail "Linux parent does not propagate sanitizer/warning CFLAGS into LevelDB"
grep -q 'CXXFLAGS="$(CXXFLAGS)"' "$ROOT/src/makefile.osx" || \
    fail "macOS parent does not propagate CXXFLAGS into LevelDB"

grep -Eq 'make .*makefile\.unix clean' "$ROOT/.github/workflows/ci.yml" || \
    fail "CI does not start the Linux release gate from a clean object tree"
grep -Eq 'make .*makefile\.unix clean' "$ROOT/.github/workflows/build.yml" || \
    fail "release workflow does not start the Linux audit gate from a clean object tree"
grep -Eq 'make .*makefile\.osx clean' "$ROOT/.github/workflows/build.yml" || \
    fail "release workflow does not start the macOS gate from a clean object tree"
grep -q 'STRICT_WARNINGS=1 -f makefile.osx' "$ROOT/.github/workflows/build.yml" || \
    fail "release workflow does not enable the macOS return-type/format warning gate"
grep -q 'STRICT_WARNINGS=1 -f makefile.osx' "$ROOT/.github/workflows/ci.yml" || \
    fail "CI does not enable the macOS return-type/format warning gate"

release_gate="$ROOT/contrib/test/v5_release_gate.sh"
unit_gate_body=$(sed -n '/^run_unit()/,/^}/p' "$release_gate")
echo "$unit_gate_body" | grep -q -- '-f makefile\.osx clean' || \
    fail "local unit gate does not clean the macOS object tree"
echo "$unit_gate_body" | grep -q -- '-f makefile\.unix clean' || \
    fail "local unit gate does not clean the Linux object tree"
echo "$unit_gate_body" | grep -q 'release-check' || \
    fail "local unit gate does not run release-check"
all_gate_body=$(sed -n '/^[[:space:]]*--all)/,/^[[:space:]]*;;/p' "$release_gate")
echo "$all_gate_body" | grep -q 'run_static' || \
    fail "local --all gate omits static checks"
echo "$all_gate_body" | grep -q 'run_unit' || \
    fail "local --all gate omits the clean build/unit gate"
echo "$all_gate_body" | grep -q 'run_integration' || \
    fail "local --all gate omits integration checks"

upload_count=$(grep -c 'uses: actions/upload-artifact@v5' "$ROOT/.github/workflows/build.yml")
missing_file_error_count=$(grep -c 'if-no-files-found: error' "$ROOT/.github/workflows/build.yml")
[ "$upload_count" -eq "$missing_file_error_count" ] || \
    fail "every uploaded release/audit artifact must fail when its file is missing"
grep -q 'expected exactly one release asset' "$ROOT/.github/workflows/build.yml" || \
    fail "release collector does not require the complete platform asset set"
grep -B2 -q 'contrib/test/v5_release_gate.sh --integration' "$ROOT/.github/workflows/build.yml" || \
    fail "release workflow does not run the integration gate"
integration_context=$(grep -B3 'contrib/test/v5_release_gate.sh --integration' "$ROOT/.github/workflows/build.yml")
echo "$integration_context" | grep -q 'set -euo pipefail' || \
    fail "integration log pipeline can hide a failed release gate"
# Match within the job's own extent; a fixed -A window drifts as jobs change size.
workflow_job() {
    awk -v job="  $1:" '
        $0 == job { inside = 1; next }
        inside && /^  [^[:space:]#]/ { inside = 0 }
        inside { print }
    ' "$2"
}

policy_context=$(workflow_job release-policy "$ROOT/.github/workflows/build.yml")
echo "$policy_context" | grep -q 'fetch-depth: 0' || \
    fail "release policy cannot verify source ancestry from a shallow checkout"
echo "$policy_context" | grep -q 'environment: v5-release' || \
    fail "release policy does not use the protected release environment"
echo "$policy_context" | grep -q 'RUNNER_TEMP/v5-testnet-v3-preflight.json' || \
    fail "release policy evidence is not materialized outside the source checkout"
echo "$policy_context" | grep -q 'RUNNER_TEMP/v5-release-candidate-manifest.json' || \
    fail "release manifest is not materialized from protected external state"
echo "$policy_context" | grep -q 'RUNNER_TEMP/v5-release-gate-evidence.json' || \
    fail "release gate evidence is not materialized outside the source checkout"
echo "$policy_context" | grep -q 'V5_RELEASE_MANIFEST_BASE64' || \
    fail "release workflow does not source the candidate manifest from protected state"
echo "$policy_context" | grep -q 'V5_RELEASE_GATE_EVIDENCE_BASE64' || \
    fail "release workflow does not source signed/test evidence from protected state"
echo "$policy_context" | grep -q -- '--manifest "$manifest_path"' || \
    fail "release policy does not require an explicit external manifest path"
echo "$policy_context" | grep -q -- '--evidence "$evidence_path"' || \
    fail "release policy does not require an explicit external evidence path"
echo "$policy_context" | grep -q -- '--release-gate-evidence "$release_gate_evidence_path"' || \
    fail "release policy does not require explicit external release-gate evidence"
echo "$policy_context" | grep -q -- '--artifact-directory "$artifact_directory"' || \
    fail "release policy does not hash the downloaded signed/unsigned packages"
grep -q "if: github.event_name == 'workflow_dispatch'.*inputs.signed_run_id" "$ROOT/.github/workflows/build.yml" || \
    fail "release publication can bypass the operator-selected protected signing run"

signing_workflow="$ROOT/.github/workflows/sign-v5-desktop.yml"
[ -f "$signing_workflow" ] || fail "protected desktop signing workflow is missing"
grep -q 'environment: v5-release-signing' "$signing_workflow" || \
    fail "desktop signing does not require protected-environment approval"
grep -q -- '--options runtime' "$signing_workflow" || \
    fail "macOS signing does not enable hardened runtime"
grep -q 'notarytool submit' "$signing_workflow" || \
    fail "macOS package is not submitted for notarization"
grep -q 'stapler staple' "$signing_workflow" || \
    fail "macOS notarization ticket is not stapled"
grep -q 'codesign --verify --deep --strict' "$signing_workflow" || \
    fail "macOS nested signature verification is missing"
grep -q 'signtool sign /fd SHA256 /td SHA256 /tr' "$signing_workflow" || \
    fail "Windows signing does not require an RFC3161 SHA-256 timestamp"
grep -q 'signtool verify /pa /all /v' "$signing_workflow" || \
    fail "Windows Authenticode trust verification is missing"
grep -q 'name: innova-macOS-arm64-signed' "$signing_workflow" || \
    fail "signed macOS package is not published as a distinct artifact"
grep -q 'name: innova-win64-signed' "$signing_workflow" || \
    fail "signed Windows package is not published as a distinct artifact"
rust_audit_context=$(workflow_job audit-rust-vnext "$ROOT/.github/workflows/build.yml")
echo "$rust_audit_context" | grep -q 'rustup toolchain install 1.94.1' || \
    fail "Rust audit lane does not install the pinned 1.94.1 toolchain"
echo "$rust_audit_context" | grep -q 'src/privacy_vnext/rust/check.sh' || \
    fail "Rust audit lane does not run the locked offline provenance gate"
echo "$policy_context" | grep -q -- '--private-audit-sha256 "$V5_PRIVATE_AUDIT_SHA256"' || \
    fail "release policy does not require a supplied private-audit digest"
echo "$policy_context" | grep -q 'v5-immutable-source-artifact' || \
    fail "release policy does not download the immutable source artifact"
grep -q 'git archive --format=tar --prefix=innova-v5-source/' "$ROOT/.github/workflows/build.yml" || \
    fail "release workflow does not materialize the manifested source commit as a plain tar artifact"
grep -q 'name: v5-immutable-source-artifact' "$ROOT/.github/workflows/build.yml" || \
    fail "release workflow does not publish the immutable source artifact for policy verification"
echo "$policy_context" | grep -q -- '--source-artifact "$source_artifact_path"' || \
    fail "release policy does not bind the external source artifact"
echo "$policy_context" | grep -q -- '--specification-to-code-attestation "$specification_attestation_path"' || \
    fail "release policy does not require the specification-to-code attestation"
echo "$policy_context" | grep -q -- '--adversarial-composition-attestation "$adversarial_attestation_path"' || \
    fail "release policy does not require the adversarial-composition attestation"
echo "$policy_context" | grep -q 'V5_SPECIFICATION_TO_CODE_ATTESTATION_BASE64' || \
    fail "release workflow does not source the specification review from protected state"
echo "$policy_context" | grep -q 'V5_ADVERSARIAL_COMPOSITION_ATTESTATION_BASE64' || \
    fail "release workflow does not source the adversarial review from protected state"
if [ -e "$ROOT/docs/v5-release-candidate-manifest.json" ]; then
    fail "candidate manifests are generated only after freeze and must remain outside the source repository"
fi
grep -q '^MANIFEST_SCHEMA_VERSION = 5$' "$ROOT/contrib/test/check_v5_release_policy.py" || \
    fail "release policy does not reject pre-v5 candidate manifests"
if grep -Eq '^DEFAULT_(EVIDENCE|MANIFEST)[[:space:]]*=' "$ROOT/contrib/test/check_v5_release_policy.py"; then
    fail "release policy must not default to repository-local manifest/evidence"
fi

# Cross-database best-chain effects cannot join LevelDB's atomic WriteBatch.
# Keep the prebuilt journal, marker-last auxiliary indexes, and checked wallet
# recovery path wired whenever this legacy activation code is edited.
main_cpp="$ROOT/src/main.cpp"
main_hdr="$ROOT/src/main.h"
init_cpp="$ROOT/src/init.cpp"
sed -n '/if (mapArgs.count("-replayblocks"))/,/if (mapArgs.count("-loadblock"))/p' "$init_cpp" > "$tmp_replay"
grep -q 'fDaemon && mapArgs.count("-replayblocks")' "$init_cpp" || \
    fail "history replay can detach and hide its child exit status"
grep -q 'if (vFiles.empty())' "$tmp_replay" || \
    fail "history replay can succeed without an input block file"
grep -q 'if (!file)' "$tmp_replay" || \
    fail "history replay ignores block-file open failures"
grep -q 'if (!LoadExternalBlockFile(file))' "$tmp_replay" || \
    fail "history replay ignores block-loader failure"
grep -q 'mapArgs.count("-replayexpectedheight")' "$tmp_replay" || \
    fail "history replay does not require a trusted terminal height"
grep -q 'mapArgs.count("-replayexpectedhash")' "$tmp_replay" || \
    fail "history replay does not require a trusted terminal hash"
grep -q 'pindexBest->GetBlockHash() != hashExpected' "$tmp_replay" || \
    fail "history replay does not compare the resulting terminal hash"
grep -qE 'return .*nLoaded.*&& nFailed == 0 && !fRequestShutdown;' "$main_cpp" || \
    fail "history replay can report success after a rejected/corrupt block frame"

genbuild="$ROOT/share/genbuild.sh"
grep -q 'git rev-parse --verify HEAD' "$genbuild" || \
    fail "candidate build identifiers omit the complete source commit"
grep -q 'git status --porcelain --untracked-files=normal' "$genbuild" || \
    fail "candidate build identifiers do not detect untracked dirty source"
grep -q 'commit-${COMMIT}${DIRTY}' "$genbuild" || \
    fail "candidate build identifier does not bind commit and dirty state"
grep -Eq 'PrepareReorg\((txdb, )?vDisconnect, vConnect,' "$main_cpp" || \
    fail "best-chain reorg effects are not prebuilt before commit"
grep -Eq 'PrepareConnect\((txdb, )?pindexNew\)' "$main_cpp" || \
    fail "linear/genesis best-chain effects are not prebuilt before commit"
if grep -Eq 'AddConnect\(|AddDisconnect\(' "$main_cpp"; then
    fail "best-chain effects are still appended after commit"
fi
publish_replay_count=$(grep -c 'PublishAndReplayCommittedEffects(' "$main_cpp")
[ "$publish_replay_count" -ge 4 ] || \
    fail "each reorg/linear/postponed path must publish and replay its own commit"
best_chain_effect_replay=$(sed -n '/bool Replay(CTxDB& txdb) const/,/^    }/p' "$main_cpp")
name_connect_call=$(sed -n '/ApplyNameIndexConnectBlock(/,/strNameError))/p' "$main_cpp")
echo "$name_connect_call" | grep -q 'entry.setDAGSkippedTxs' || \
    fail "name-index connect replay does not use the persisted DAG skip set"
name_disconnect_call=$(sed -n '/ApplyNameIndexDisconnectBlock(/,/strNameError))/p' "$main_cpp")
echo "$name_disconnect_call" | grep -q 'entry.setDAGSkippedTxs' || \
    fail "name-index disconnect replay does not use the persisted DAG skip set"
if echo "$best_chain_effect_replay" | grep -q 'hooks->DisconnectInputs'; then
    fail "best-chain replay still bypasses exact block-level name disconnect recovery"
fi
grep -q 'DisconnectShieldedBlockRecoveryChecked(' "$main_cpp" || \
    fail "live shielded wallet recovery does not conservatively purge disconnected notes"
grep -q 'ReconcileShieldedNoteSpentStateChecked(' "$main_cpp" || \
    fail "live shielded wallet recovery does not reconcile canonical spent state"
grep -q '&entry.setDAGSkippedTxs' "$main_cpp" || \
    fail "live shielded-wallet connect does not consume the precommitted effect plan"
# Batched wallet best-block locator: derived from committed effects, flushed via the
# checked writer (fatal after a durable commit), drained at shutdown, repaired at startup
# by a checked rescan covering shielded payloads, and never written outside that path.
wallet_cpp="$ROOT/src/wallet.cpp"
publish_replay_body=$(sed -n '/^static bool PublishAndReplayCommittedEffects(/,/^}/p' "$main_cpp")
replay_line=$(echo "$publish_replay_body" | grep -n 'effects.Replay(txdb)' | head -1 | cut -d: -f1)
defer_line=$(echo "$publish_replay_body" | grep -n 'DeferWalletBestChain(' | head -1 | cut -d: -f1)
[ -n "$replay_line" ] || \
    fail "committed effects are not replayed on the wallet locator's publication path"
[ -n "$defer_line" ] || \
    fail "wallet recovery locator is not advanced from the committed-effect publication path"
[ "$replay_line" -lt "$defer_line" ] || \
    fail "wallet recovery locator advances before committed effects are replayed"
locator_branch=$(sed -n '/BLOCK_PHASE(BP_WALLET_LOCATOR)/,/^    }/p' "$main_cpp")
echo "$locator_branch" | grep -q 'DeferWalletBestChain(effects.GetLocator()' || \
    fail "wallet recovery locator is not derived from committed effects"
echo "$locator_branch" | grep -q 'FlushWalletBestChainLocator(' || \
    fail "wallet recovery locator is never flushed after committed effects"
echo "$locator_branch" | grep -q 'StartShutdown()' || \
    fail "a failed wallet locator flush after a durable commit is not fatal"
flush_locator_body=$(sed -n '/^bool FlushWalletBestChainLocator(/,/^}/p' "$main_cpp")
echo "$flush_locator_body" | grep -q 'SetWalletBestChainChecked(' || \
    fail "the deferred wallet locator is flushed outside the checked writer"
finalise_body=$(sed -n '/^bool Finalise()/,/^}/p' "$main_cpp")
echo "$finalise_body" | grep -q 'FlushWalletBestChainLocator(' || \
    fail "shutdown does not drain a pending wallet best-block locator"
grep -q 'ScanForWalletTransactionsChecked(' "$init_cpp" || \
    fail "startup does not repair a lagging wallet locator with a checked rescan"
grep -q 'SetBestChainChecked(CBlockLocator(pindexBest)' "$init_cpp" || \
    fail "startup does not re-persist the repaired wallet locator through the checked writer"
rescan_body=$(sed -n '/^bool CWallet::ScanForWalletTransactionsChecked(/,/^}/p' "$wallet_cpp")
echo "$rescan_body" | grep -q 'ScanBlockForShieldedNotesChecked(' || \
    fail "the wallet catch-up rescan does not drive the block-level shielded/IV5 scan"
checked_writer_body=$(sed -n '/^bool CWallet::SetBestChainChecked(/,/^}/p' "$wallet_cpp")
echo "$checked_writer_body" | grep -q 'WriteBestBlock(' || \
    fail "the checked wallet locator writer does not persist the locator"
locator_writes=$(grep -c 'WriteBestBlock(' "$wallet_cpp")
[ "$locator_writes" -eq 1 ] || \
    fail "the wallet best-block locator is written outside the checked writer"
if grep -Eq '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]+CWallet::SetBestChain\(' "$wallet_cpp"; then
    fail "an unchecked wallet best-block locator writer is back"
fi
outbox_write_count=$(grep -c 'WriteShieldedWalletRecovery(' "$main_cpp")
[ "$outbox_write_count" -ge 3 ] || \
    fail "shielded-wallet recovery outbox is not written on every best-chain commit path"
sync_commit_count=$(grep -c 'TxnCommit(true)' "$main_cpp")
[ "$sync_commit_count" -ge 4 ] || \
    fail "best-chain/outbox commits are not forced durable before wallet effects"
grep -q 'bitdb.FlushLog()' "$main_cpp" || \
    fail "runtime outbox acknowledgement can outrun Berkeley DB wallet durability"
grep -q 'bitdb.FlushLog()' "$init_cpp" || \
    fail "startup outbox acknowledgement can outrun Berkeley DB wallet durability"
grep -q 'ClearCommittedShieldedWalletRecovery(' "$main_cpp" || \
    fail "completed committed effects do not durably acknowledge the shielded-wallet outbox"

# The 2000--2007 encodings and their private-finality carriers never activated on
# mainnet/testnet; they are decoded/verified on regtest only. Boundary B still requires them.
grep -q 'IsLegacyShieldedTransactionVersion(nVersion) &&' "$main_hdr" || \
    fail "context-free validation does not identify legacy shielded versions"
grep -A2 'if (IsShielded() &&' "$main_cpp" | \
    grep -q 'IsLegacyPrivacyPolicyDisabled()' || \
    fail "public networks can still reach legacy shielded consensus validation"
if grep -q 'nContextHeight < 0 && IsLegacyPrivacyPolicyDisabled()' "$ROOT/src/finality.cpp"; then
    fail "legacy private finality is disabled only at relay, not at public-network consensus"
fi
grep -q '!IsLegacyNullSendEnabledAtHeight(nBestHeight)' "$ROOT/src/nullsend.cpp" || \
    fail "legacy NullSend P2P traffic bypasses the shared retirement gate"
grep -q 'IsBoundaryBActiveAtHeight(nCurrentHeight) && fVNextReady' "$ROOT/src/rpcshielded.cpp" || \
    fail "privacy RPC can claim Boundary-B activation without a ready vNext implementation"
grep -q 'SHIELDED_VNEXT_PRIVACY_MODE_COUNT = 8' "$ROOT/src/shielded.h" || \
    fail "Boundary-B product contract does not preserve privacy modes 0--7"
grep -q 'SHIELDED_VNEXT_NULLSTAKE_GENERATION_COUNT = 3' "$ROOT/src/shielded.h" || \
    fail "Boundary-B product contract does not preserve NullStake V1/V2/V3"
grep -q 'SHIELDED_VNEXT_OPERATION_NULLSEND' "$ROOT/src/shielded.h" || \
    fail "Boundary-B product contract omits NullSend"
grep -q 'privacy_vnext_post_dag_staking_role' "$ROOT/src/rpcshielded.cpp" || \
    fail "privacy status does not expose DAG finality as the staking role"
grep -q '^static const int MAINNET_V5_ACTIVATION_SHIFT = ' "$ROOT/src/v5activation.h" || \
    fail "mainnet v5 activation ladder has no one-piece reviewed shift"
python3 "$ROOT/contrib/testnet_tools/v5_mainnet_activation.py" --selftest >/dev/null
grep -q 'ReadShieldedWalletRecoveryStatus' "$ROOT/src/txdb-leveldb.cpp" || \
    fail "shielded-wallet recovery outbox has no exact read path"
grep -q 'AcknowledgeShieldedWalletRecovery(' "$ROOT/src/txdb-leveldb.cpp" || \
    fail "shielded-wallet recovery outbox has no exact conditional acknowledgement"
grep -q 'value.size() != nExpectedSize' "$ROOT/src/txdb-leveldb.cpp" || \
    fail "shielded-wallet recovery outbox is not bounded before deserialization"
if grep -Eq 'nConnect[[:space:]]*==[[:space:]]*0[^&|]*return false' "$ROOT/src/txdb-leveldb.h"; then
    fail "shielded-wallet recovery rejects a disconnect-only rollback"
fi
grep -q 'RecoverPendingShieldedWalletTransition(' "$init_cpp" || \
    fail "startup does not replay a committed shielded-wallet transition"
grep -q 'DisconnectShieldedBlockRecoveryChecked(' "$init_cpp" || \
    fail "startup recovery does not purge every raw old-branch shielded tx"
grep -q 'ReconcileShieldedNoteSpentStateChecked(' "$init_cpp" || \
    fail "startup recovery does not reconcile canonical shielded nullifiers"
grep -q 'ReadShieldedNullifierStatus' "$ROOT/src/wallet.cpp" || \
    fail "shielded spent-state reconciliation does not use exact tri-state nullifier reads"
recovery_body=$(sed -n '/bool RecoverPendingShieldedWalletTransition(/,/^} \/\/ namespace/p' "$init_cpp")
if echo "$recovery_body" | grep -Eq 'SyncWithWallets|UndoAnonTransaction|ScanForWalletTransactions'; then
    fail "shielded-only startup recovery invokes a legacy generic/ANON wallet callback"
fi
recovery_impl_body=$(sed -n '/bool RecoverPendingShieldedWalletTransitionImpl(/,/^bool RecoverPendingShieldedWalletTransition(/p' "$init_cpp")
if echo "$recovery_impl_body" | grep -Eq 'EraseShieldedWalletRecovery|AcknowledgeShieldedWalletRecovery|bitdb\.FlushLog'; then
    fail "startup shielded replay acknowledges before transparent-wallet recovery durability"
fi
acknowledgement_body=$(sed -n '/bool AcknowledgePendingShieldedWalletTransition(/,/^}/p' "$init_cpp")
echo "$acknowledgement_body" | grep -q 'bitdb.FlushLog()' || \
    fail "startup acknowledgement does not flush Berkeley DB logs"
echo "$acknowledgement_body" | grep -q 'AcknowledgeShieldedWalletRecovery(expected)' || \
    fail "startup acknowledgement does not conditionally erase the exact pending record"
flush_line=$(echo "$acknowledgement_body" | grep -n 'bitdb.FlushLog()' | cut -d: -f1)
erase_line=$(echo "$acknowledgement_body" | grep -n 'AcknowledgeShieldedWalletRecovery(expected)' | cut -d: -f1)
[ "$flush_line" -lt "$erase_line" ] || \
    fail "startup acknowledgement erases the outbox before flushing Berkeley DB logs"
recovery_line=$(grep -n 'RecoverPendingShieldedWalletTransition(' "$init_cpp" | tail -1 | cut -d: -f1)
name_validation_line=$(grep -n '!ValidateNameIndexTip(pindexBest' "$init_cpp" | tail -1 | cut -d: -f1)
cache_line=$(grep -n 'pwalletMain->CacheAnonStats()' "$init_cpp" | tail -1 | cut -d: -f1)
register_line=$(grep -n 'RegisterWallet(pwalletMain)' "$init_cpp" | tail -1 | cut -d: -f1)
[ "$name_validation_line" -lt "$recovery_line" ] || \
    fail "canonical name-index recovery must finish before startup outbox replay"
[ "$recovery_line" -lt "$cache_line" ] && [ "$recovery_line" -lt "$register_line" ] || \
    fail "shielded-wallet recovery must finish before anonymous caching and wallet registration"
grep -q 'ScanForWalletTransactionsChecked(' "$init_cpp" || \
    fail "startup wallet recovery does not propagate rescan failures"
grep -q 'pindexRecoveryRescan' "$init_cpp" || \
    fail "a pending recovery outbox does not force a transparent-wallet rescan from its fork"
rescan_line=$(grep -n 'pwalletMain->ScanForWalletTransactionsChecked(' "$init_cpp" | tail -1 | cut -d: -f1)
locator_line=$(grep -n 'pwalletMain->SetBestChainChecked(CBlockLocator(pindexBest))' "$init_cpp" | tail -1 | cut -d: -f1)
acknowledgement_line=$(grep -n 'AcknowledgePendingShieldedWalletTransition(' "$init_cpp" | tail -1 | cut -d: -f1)
[ "$recovery_line" -lt "$rescan_line" ] && \
    [ "$rescan_line" -lt "$locator_line" ] && \
    [ "$locator_line" -lt "$acknowledgement_line" ] || \
    fail "startup outbox acknowledgement must follow replay, transparent rescan and durable locator"
grep -q 'pindexRescan = pindexGenesisBlock' "$init_cpp" || \
    fail "a missing wallet locator does not force deterministic recovery"
if grep -q 'pwalletMain->CacheAnonStats()' "$main_cpp"; then
    fail "block-index loading dereferences the wallet before it is constructed"
fi
grep -q 'pwalletMain->CacheAnonStats()' "$init_cpp" || \
    fail "legacy anonymous statistics are not initialized after wallet load"
if grep -q 'pwalletMain->GetTxnPreImage' "$main_cpp"; then
    fail "ANON consensus preimage construction still depends on a wallet instance"
fi
grep -q 'GetAnonTxnPreImage(\*this, preimage)' "$main_cpp" || \
    fail "ANON validation is not using the wallet-independent bounded preimage helper"
grep -q 'ReadKeyImageStatus(vchImage, spentKeyImage)' "$main_cpp" || \
    fail "ANON consensus key-image reads are not exact/tri-state"
if grep -Eq '(ptxdb->|txdb\.)(WriteAnonOutput|EraseAnonOutput|WriteKeyImage|EraseKeyImage)\(' \
        "$ROOT/src/wallet.cpp"; then
    fail "wallet processing still mutates chain-owned ANON records"
fi
grep -q 'txdb.WriteAnonOutput(it->first, it->second)' "$main_cpp" || \
    fail "outer chain connect no longer owns ANON output writes"
grep -q 'txdb.EraseAnonOutput(pkCoin)' "$main_cpp" || \
    fail "outer chain disconnect no longer owns ANON output erases"
grep -q 'DB_DBT_USERMEM' "$ROOT/src/namecoin.cpp" || \
    fail "name-index recovery cursor is not read through a bounded exact buffer"
grep -A2 -q 'fV3ShieldedPersistence &&' "$main_cpp" || \
    fail "V3 shielded disconnect boundary guard is missing"

echo "audit_build_dependencies: dependency includes, nested builds, and release suites are wired"
