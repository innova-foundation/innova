// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_V5ACTIVATION_H
#define INN_V5ACTIVATION_H

// Effective first gate is BASE + SHIFT. SHIFT moves the whole ladder uniformly
// and must never change the relative gaps between gates.
//
// The release preflight recomputes SHIFT against a fresh trusted mainnet tip;
// a value is only valid while the tip is at least 100,000 blocks below the
// effective first gate. At the 15-second target spacing that floor is only
// about 17 days, which is a lower bound for an already-deployed release, not a
// deployment window: every gate is a flag day that needs the whole network on
// the new binary beforehand.
//
// Set against tip 7,917,298 (2026-08-16 02:15 UTC), established by a
// self-verifying getheaders walk from the hardcoded 7,750,000 checkpoint and
// cross-checked against two further peers. First gate 7,980,000 leads that tip
// by 62,702 blocks: ~10.6 days at the measured 14.6-second spacing, ~10.9 days
// at 15 seconds. Gates after the DAG gate (base 7,950,000) arrive at 1-second
// spacing, so the whole tail lands within ~14 hours of DAG activation rather
// than months later: DAGKNIGHT at base 8,000,000 is the last rung, 50,000
// blocks above the DAG gate. The figure was ~31 hours while the M-of-N
// cold-staking gates sat at base 8,060,000; those are retired.
//
// Recheck before tagging: the tip advances ~5,900 blocks a day, so this lead
// decays by a day for every day it sits unreleased. The release policy enforces
// a 50,000-block floor, which this clears by only ~2.2 days -- that short tag
// window is inherent to a 50,000-75,000 block lead, not an oversight. Re-run
// the preflight at tag time and step the shift by one granule if it has decayed.
//
// SHIFT is constrained three ways, and only multiples of 30,000 satisfy all of
// them:
//
//  1. The DAG gate must be a multiple of FINALITY_EPOCH_INTERVAL_PRE_DAG (60),
//     so the fork is itself an epoch boundary and the first post-DAG epoch is
//     votable immediately. The bases are multiples of 60, so SHIFT must be too.
//  2. The release policy works in 10,000-block granules.
//  3. The gate must stay strictly between the last unstretched emission rung
//     and the first stretched rung's 15s height -- currently (8,000,000,
//     8,250,000), i.e. SHIFT in (50,000, 300,000). Re-basing anywhere in that
//     range needs no further emission-literal changes.
//
// Changing SHIFT moves the DAG gate, and the PoW tier boundaries in
// GetProofOfWorkReward are derived from it: every boundary above the gate is
// stretched by the block-spacing ratio. Re-derive them whenever this moves.
// Terminal supply is invariant under that re-derivation (each tier still spans
// its wall-clock time and pays its INN); what is NOT invariant is leaving the
// literals behind, which silently pays whole tiers on the wrong side of the
// divisor. emission_curve_tests pins both halves.
static const int MAINNET_V5_ACTIVATION_BASE = 7800000;
static const int MAINNET_V5_ACTIVATION_SHIFT = 299940;    // first gate 8,099,940

inline int ShiftMainnetV5Activation(int nBaseHeight)
{
    return nBaseHeight + MAINNET_V5_ACTIVATION_SHIFT;
}

#endif // INN_V5ACTIVATION_H
