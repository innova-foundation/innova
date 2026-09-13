// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_V5ACTIVATION_H
#define INN_V5ACTIVATION_H

// Effective first gate is BASE + SHIFT; SHIFT moves the ladder uniformly, is a multiple of
// 30,000, lies in (300,000, 550,000) and is validated by check_v5_release_policy.py.
// Moving it requires re-deriving vPoWPostDagMainnet and GetProofOfWorkReward's tiers.
static const int MAINNET_V5_ACTIVATION_BASE = 7800000;
static const int MAINNET_V5_ACTIVATION_SHIFT = 420000;    // first gate 8,220,000

inline int ShiftMainnetV5Activation(int nBaseHeight)
{
    return nBaseHeight + MAINNET_V5_ACTIVATION_SHIFT;
}

#endif // INN_V5ACTIVATION_H
