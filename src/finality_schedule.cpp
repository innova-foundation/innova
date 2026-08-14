// Copyright (c) 2019-2026 Innova Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "finality_schedule.h"

void CFinalityVoteSchedule::Reset()
{
    nLatchedEpoch = -1;
    nLatchedBoundary = -1;
    nVotedEpoch = -1;
    nAttempts = 0;
    nInFlightEpoch = -1;
}

bool CFinalityVoteSchedule::OnTipChanged(int nHeight, int nEpoch, int nBoundary)
{
    if (nEpoch < 0 || nBoundary < 0 || nHeight < nBoundary)
        return false;
    // An edge, not a level: an epoch stays outstanding until it is voted, so
    // reporting "work exists" on every tip would stop the producer ever sleeping.
    if (nEpoch == nLatchedEpoch)
        return false;

    // Latched in either direction: a reorg that lands the tip back in an earlier
    // epoch reopens that epoch's vote, which is what the old sampler did too.
    nLatchedEpoch = nEpoch;
    nLatchedBoundary = nBoundary;
    nAttempts = 0;
    nInFlightEpoch = -1;
    return HasWork();
}

FinalityVoteClaim CFinalityVoteSchedule::Claim(int nTipHeight,
                                               int nProducerWindow,
                                               int nMaxAttempts,
                                               int& nEpochOut)
{
    nEpochOut = -1;
    if (!HasWork())
        return FINALITY_VOTE_CLAIM_IDLE;
    if (nInFlightEpoch == nLatchedEpoch)
        return FINALITY_VOTE_CLAIM_BUSY;
    // Measured against the tip now, not the tip that latched the boundary:
    // consensus only accepts the vote inside the inclusion window, so an epoch
    // observed late is already lost and must not cost a wallet scan.
    if (nProducerWindow > 0 && nTipHeight - nLatchedBoundary >= nProducerWindow)
        return FINALITY_VOTE_CLAIM_LATE;
    if (nMaxAttempts > 0 && nAttempts >= nMaxAttempts)
        return FINALITY_VOTE_CLAIM_SPENT;

    nAttempts++;
    nInFlightEpoch = nLatchedEpoch;
    nEpochOut = nLatchedEpoch;
    return FINALITY_VOTE_CLAIM_OK;
}

void CFinalityVoteSchedule::Release(int nEpoch, bool fProduced)
{
    if (nInFlightEpoch == nEpoch)
        nInFlightEpoch = -1;
    if (fProduced && nEpoch >= 0)
        nVotedEpoch = nEpoch;
}
