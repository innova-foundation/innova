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
// Set against tip 7,888,500 (2026-08-09). First gate 8,400,000 leads it by
// 511,500 blocks (~89 days); the last gate (base 8,060,000) lands ~134 days
// out. Recheck before tagging: the tip advances ~5,760 blocks a day, so this
// margin decays by a day for every day it sits unreleased.
static const int MAINNET_V5_ACTIVATION_BASE = 7800000;
static const int MAINNET_V5_ACTIVATION_SHIFT = 600000;    // first gate 8,400,000

inline int ShiftMainnetV5Activation(int nBaseHeight)
{
    return nBaseHeight + MAINNET_V5_ACTIVATION_SHIFT;
}

#endif // INN_V5ACTIVATION_H
