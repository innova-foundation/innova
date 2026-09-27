#!/bin/bash
# Produces history_replay_sha256: the candidate replays a best-chain-only block export
# from genesis through full validation to a trusted height and hash, both from the
# environment (V5_HISTORY_REPLAY_BLOCKS, V5_HISTORY_REPLAY_HEIGHT, V5_HISTORY_REPLAY_HASH).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/v5_evidence_lib.sh"

evidence_begin history_replay_sha256
evidence_reuse && exit 0

[ -x "$ROOT/src/innovad" ] || \
    evidence_die "build src/innovad before producing $EV_FIELD; it is the binary under test"

BLOCKS="${V5_HISTORY_REPLAY_BLOCKS:-}"
HEIGHT="${V5_HISTORY_REPLAY_HEIGHT:-}"
HASH="${V5_HISTORY_REPLAY_HASH:-}"
NETWORK="${V5_HISTORY_REPLAY_NETWORK:-mainnet}"

[ -n "$BLOCKS" ] || evidence_die \
    "set V5_HISTORY_REPLAY_BLOCKS to a directory of blkNNNN.dat files to replay"
[ -d "$BLOCKS" ] || evidence_die "V5_HISTORY_REPLAY_BLOCKS is not a directory: $BLOCKS"
[ -n "$HEIGHT" ] || evidence_die \
    "set V5_HISTORY_REPLAY_HEIGHT to the trusted terminal height of $BLOCKS"
[ -n "$HASH" ] || evidence_die \
    "set V5_HISTORY_REPLAY_HASH to the trusted terminal block hash of $BLOCKS"
case "$HEIGHT" in ''|*[!0-9]*) evidence_die "V5_HISTORY_REPLAY_HEIGHT is not a height: $HEIGHT";; esac
case "$HASH" in
    *[!0-9a-fA-F]*|"") evidence_die "V5_HISTORY_REPLAY_HASH is not a block hash: $HASH";;
esac
[ "${#HASH}" -eq 64 ] || evidence_die "V5_HISTORY_REPLAY_HASH is ${#HASH} characters, not 64"

# A directory with no block file replays nothing and would exit 0 over it.
FILES="$(find "$BLOCKS" -maxdepth 1 -type f -name 'blk*.dat' | wc -l | tr -d ' ')"
BYTES="$(find "$BLOCKS" -maxdepth 1 -type f -name 'blk*.dat' -exec cat {} + 2>/dev/null | wc -c | tr -d ' ')"
[ "$FILES" -gt 0 ] || \
    evidence_die "no blk*.dat under $BLOCKS, so there is no history to replay"

evidence_toolchain "$("$ROOT/src/innovad" -datadir="$EV_DIR" --help 2>/dev/null | head -1)"
evidence_require_binary_commit "$EV_TOOLCHAIN"
evidence_observe innovad_sha256 \
    "$( { sha256sum "$ROOT/src/innovad" 2>/dev/null || shasum -a 256 "$ROOT/src/innovad"; } | awk '{print $1}')"
evidence_observe network "$NETWORK"
evidence_observe block_files "$FILES"
evidence_observe block_bytes "$BYTES"
evidence_observe block_files_sha256 "$(find "$BLOCKS" -maxdepth 1 -type f -name 'blk*.dat' \
    | LC_ALL=C sort | xargs cat | { sha256sum 2>/dev/null || shasum -a 256; } | awk '{print $1}')"
evidence_observe expected_height "$HEIGHT"
evidence_observe expected_hash "$HASH"

NETFLAG=""
case "$NETWORK" in
    testnet) NETFLAG="-testnet" ;;
    regtest) NETFLAG="-regtest" ;;
    mainnet) NETFLAG="" ;;
    *) evidence_die "V5_HISTORY_REPLAY_NETWORK is not a network: $NETWORK" ;;
esac

# A fresh datadir so no existing index is reused; -daemon=0 so the exit status is the verdict.
REPLAY_DIR="$EV_DIR/replay-datadir"
rm -rf "$REPLAY_DIR"
mkdir -p "$REPLAY_DIR"

evidence_run "replay $FILES block file(s) to height $HEIGHT" \
    "src/innovad -datadir=$REPLAY_DIR $NETFLAG -daemon=0 -replayblocks=$BLOCKS \
     -replayexpectedheight=$HEIGHT -replayexpectedhash=$HASH"

# The daemon refuses a mismatched terminal; the covered range is recorded as well.
evidence_observe replay_completed 1

evidence_pass
