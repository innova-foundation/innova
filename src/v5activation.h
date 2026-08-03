// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_V5ACTIVATION_H
#define INN_V5ACTIVATION_H

// Effective first gate is BASE + SHIFT. SHIFT moves the whole ladder uniformly
// and must never change the relative gaps between gates.
//
// The release preflight recomputes SHIFT against a fresh trusted mainnet tip;
// a value is only valid while the tip is at least 100,000 blocks below the
// effective first gate.
static const int MAINNET_V5_ACTIVATION_BASE = 7800000;
static const int MAINNET_V5_ACTIVATION_SHIFT = 150000;    // first gate 7,950,000

inline int ShiftMainnetV5Activation(int nBaseHeight)
{
    return nBaseHeight + MAINNET_V5_ACTIVATION_SHIFT;
}

#endif // INN_V5ACTIVATION_H
