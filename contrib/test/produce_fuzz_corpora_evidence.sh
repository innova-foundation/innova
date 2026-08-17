#!/bin/bash
# Produces fuzz_corpora_sha256: runs run_fuzz_campaign.sh over the three targets,
# keeps the campaign beside the record, and refuses an empty or failing campaign.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin fuzz_corpora_sha256
evidence_reuse && exit 0

evidence_require_kernel Linux
evidence_require_command make
evidence_require_command clang++ "the libFuzzer targets are built with clang"
evidence_toolchain "$(clang++ --version 2>/dev/null | head -1)"
evidence_workdir

SECONDS_PER_TARGET="${V5_FUZZ_SECONDS:-1800}"
WORKERS="${V5_FUZZ_WORKERS:-4}"
CAMPAIGN="$EV_DIR/fuzz_corpora.campaign"
rm -rf "$CAMPAIGN"

# The fuzz targets compile version.cpp without depending on obj/build.h, so
# generate it (and its directory) first.
evidence_run "stamp the build identifier" \
    "cd src && mkdir -p obj && make USE_NATIVETOR=- USE_IPFS=- INNOVA_SPINNER=0 -f makefile.unix obj/build.h"
evidence_run "build the libFuzzer targets" \
    "cd src && make USE_NATIVETOR=- USE_IPFS=- INNOVA_SPINNER=0 -f makefile.unix fuzz-all-libfuzzer"
evidence_run "run the campaign" \
    "FUZZ_OUT='$CAMPAIGN' contrib/test/run_fuzz_campaign.sh $SECONDS_PER_TARGET $WORKERS"

MANIFEST="$CAMPAIGN/manifest.txt"
[ -f "$MANIFEST" ] || evidence_finish fail "the campaign wrote no manifest at $MANIFEST"

TARGETS=0
for target in fuzz_deserialize fuzz_script fuzz_block_header; do
    line="$(grep -m1 "^$target: " "$MANIFEST" || true)"
    [ -n "$line" ] || evidence_finish fail "the campaign manifest does not report $target"
    corpus="$(printf '%s' "$line" | sed -n 's/.*corpus=\([0-9]*\).*/\1/p')"
    findings="$(printf '%s' "$line" | sed -n 's/.*undefined_behavior=\([0-9]*\).*/\1/p')"
    artifacts="$(printf '%s' "$line" | sed -n 's/.*artifacts=\([0-9]*\).*/\1/p')"
    evidence_observe "${target}_corpus" "${corpus:-0}"
    evidence_observe "${target}_artifacts" "${artifacts:-0}"
    evidence_observe "${target}_undefined_behavior" "${findings:-0}"
    evidence_require_zero "$target crash/leak/timeout artifacts" "${artifacts:-0}"
    evidence_require_zero "$target undefined behaviour" "${findings:-0}"
    # A campaign whose corpus stayed empty executed no input worth keeping.
    [ "${corpus:-0}" -gt 0 ] || evidence_finish fail "$target kept no corpus entry"
    TARGETS=$(( TARGETS + 1 ))
done

evidence_observe targets "$TARGETS"
evidence_observe seconds_per_target "$SECONDS_PER_TARGET"
evidence_observe workers "$WORKERS"
evidence_observe campaign_manifest_sha256 "$(sha256sum "$MANIFEST" | awk '{print $1}')"
evidence_observe campaign_dir "$CAMPAIGN"

evidence_pass
