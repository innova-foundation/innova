#!/usr/bin/env bash
# Copyright (c) 2026 The Innova developers
# Runs the evidence scans against a cache with known contents; each must return
# exactly its own rows.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); echo "[PASS] $1"; }
bad()  { FAILED=$((FAILED+1)); echo "[FAIL] $1"; echo "       got: $2"; echo "       want: $3"; }
eq()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "$2" "$3"; }

# Stand in for the pass's own helpers; the scans use only SWEEP_CACHE.
# Source first: the module sets SWEEP_CACHE="" at load, and an empty filename
# argument makes awk read stdin and hang rather than fail.
info() { :; }
. "$SCRIPT_DIR/iv5_onechain_sweep.sh"
SWEEP_CACHE="$(mktemp -t iv5scan)"

# h  hash  cbver  idagN  idagP  imts  fee_vb  fee_fee  fee_mask
# dagparents  ntx  votes  certVers  certSets
row() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$SWEEP_CACHE"; }

AA=$(printf 'a%.0s' $(seq 64)); BB=$(printf 'b%.0s' $(seq 64))
ZERO=$(printf '0%.0s' $(seq 64))

# 10: pre-fork, nothing.
row 10 h10 1 0 - -    -      -  -  0 1 -               -   -
# 11: one parent, zero offset, one tx. Not a merge, not a stamp.
row 11 h11 1 1 "$AA" 0    -      -  -  1 1 -               -   -
# 12: two parents -- a merge -- and a nonzero offset.
row 12 h12 1 2 "$AA,$BB" 459 -   -  -  2 1 -               -   -
# 13: a fee note, mask 3, and a nonzero offset. One block, both features.
row 13 h13 2008 1 "$AA" 964 100000 0 3 1 2 -             -   -
# 14: a fee note declaring a zero balance -- not a note that credits the pool.
row 14 h14 2008 1 "$AA" 0   0      0  3 1 1 -             -   -
# 15: two votes, one transparent one nullstake.
row 15 h15 1 1 "$AA" 0    -      -  -  1 1 "transparent/-;nullstake_v3_cold/b2c_hidden" - -
# 16: a v2 certificate with a zero committee set hash.
row 16 h16 1 1 "$AA" 0    -      -  -  1 1 -               2   "$ZERO"
# 17: a v4 certificate with a real committee set hash -- the note lane.
row 17 h17 1 1 "$AA" 0    -      -  -  1 1 -               4   "$BB"
# 18: three parents, and three transactions.
row 18 h18 1 3 "$AA,$BB,$AA" 1 - -  -  3 3 -               -   -

echo "=== scan_merge_blocks: more than one parent, and only that ==="
got="$(scan_merge_blocks - 10 18 | tr '\n' '|')"
eq "returns only the multi-parent heights, with their counts" \
   "$(scan_merge_blocks - 10 18 | awk '{print $1":"$2}' | tr '\n' ' ')" \
   "12:2 18:3 "
eq "does not return the single-parent height 11" \
   "$(scan_merge_blocks - 10 18 | awk '$1==11' | wc -l | tr -d ' ')" "0"
eq "does not return the zero-parent height 10" \
   "$(scan_merge_blocks - 10 18 | awk '$1==10' | wc -l | tr -d ' ')" "0"
eq "carries the parent list through" \
   "$(scan_merge_blocks - 12 12 | awk '{print $3}')" "$AA,$BB"
eq "honours the range" "$(scan_merge_blocks - 13 18 | awk '{print $1}' | tr '\n' ' ')" "18 "

echo
echo "=== scan_ms_offsets: nonzero only ==="
eq "returns only the heights whose offset is nonzero" \
   "$(scan_ms_offsets - 10 18 | awk '{print $1":"$3}' | tr '\n' ' ')" \
   "12:459 13:964 18:1 "
eq "does not return a zero offset, which proves nothing" \
   "$(scan_ms_offsets - 10 18 | awk '$3==0' | wc -l | tr -d ' ')" "0"
eq "does not return a block with no commitment at all" \
   "$(scan_ms_offsets - 10 10 | wc -l | tr -d ' ')" "0"
eq "carries the coinbase version through" \
   "$(scan_ms_offsets - 13 13 | awk '{print $2}')" "2008"

echo
echo "=== scan_fee_notes: a note that actually credits the pool ==="
eq "returns the height whose note declares a nonzero balance" \
   "$(scan_fee_notes - 10 18 | awk '{print $1}' | tr '\n' ' ')" "13 "
eq "does not return the zero-balance note at 14" \
   "$(scan_fee_notes - 14 14 | wc -l | tr -d ' ')" "0"
eq "emits height, balance, fee and mask in that order" \
   "$(scan_fee_notes - 13 13)" "13 100000 0 3"

echo
echo "=== scan_votes: one row per vote, mode preserved ==="
eq "splits a block carrying two votes into two rows" \
   "$(scan_votes - 15 15 | wc -l | tr -d ' ')" "2"
eq "keeps each vote's proof mode" \
   "$(scan_votes - 15 15 | awk '{print $2}' | tr '\n' ' ')" \
   "transparent nullstake_v3_cold "
eq "keeps the authorization mode of the private vote" \
   "$(scan_votes - 15 15 | awk '$2 ~ /nullstake/ {print $3}')" "b2c_hidden"
eq "returns nothing for a block with no votes" \
   "$(scan_votes - 11 11 | wc -l | tr -d ' ')" "0"

echo
echo "=== scan_certificates: version and committee set hash ==="
eq "returns both certificate heights" \
   "$(scan_certificates - 10 18 | awk '{print $1":"$2}' | tr '\n' ' ')" "16:2 17:4 "
eq "carries the committee set hash through" \
   "$(scan_certificates - 17 17 | awk '{print $3}')" "$BB"
# The selection the private-lane check makes: version >= 4 AND a non-zero set
# hash. The v2-with-zero-hash row must not satisfy it.
eq "the v4 note-lane selector picks height 17 and not 16" \
   "$(scan_certificates - 10 18 | awk '$2 >= 4 && $3 !~ /^0+$/ {print $1}' | tr '\n' ' ')" "17 "
eq "the selector rejects a v4 certificate whose set hash is all zero" \
   "$(printf '17 4 %s\n' "$ZERO" | awk '$2 >= 4 && $3 !~ /^0+$/' | wc -l | tr -d ' ')" "0"

echo
echo "=== scan_multitx: blocks that can carry a user transfer ==="
eq "returns only the heights with more than a coinbase" \
   "$(scan_multitx - 10 18 | tr '\n' ' ')" "13 18 "

rm -f "$SWEEP_CACHE"
echo
echo "checks: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
