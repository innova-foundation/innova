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
    fMarginSignalled = false;
}

int CFinalityVoteSchedule::EffectiveEmitOffset(int nProducerWindow, int nEmitOffset)
{
    if (nEmitOffset <= 0)
        return 0;
    // Clamped below the producer window, which is what keeps the margin node-local and
    // unable to cost an epoch: the emission band is [min(offset, window-1), window),
    // non-empty for any window >= 1.
    if (nProducerWindow > 0 && nEmitOffset > nProducerWindow - 1)
        return nProducerWindow - 1;
    return nEmitOffset;
}

bool CFinalityVoteSchedule::OnTipChanged(int nHeight, int nEpoch, int nBoundary,
                                         int nProducerWindow, int nEmitOffset)
{
    if (nEpoch < 0 || nBoundary < 0 || nHeight < nBoundary)
        return false;

    if (nEpoch != nLatchedEpoch)
    {
        // Latched in either direction: a reorg that lands the tip back in an earlier
        // epoch reopens that epoch's vote, which is what the old sampler did too.
        nLatchedEpoch = nEpoch;
        nLatchedBoundary = nBoundary;
        nAttempts = 0;
        nInFlightEpoch = -1;
        fMarginSignalled = false;
    }

    // An edge, not a level: an epoch stays outstanding until it is voted, so
    // reporting "work exists" on every tip would stop the producer ever sleeping.
    if (!HasWork() || fMarginSignalled)
        return false;
    // With a margin, wake when the tip reaches the edge, not at the boundary; waking early
    // and sleeping a full poll lets a block burst cross the whole producer window.
    if (nHeight - nLatchedBoundary <
        EffectiveEmitOffset(nProducerWindow, nEmitOffset))
        return false;

    fMarginSignalled = true;
    return true;
}

FinalityVoteClaim CFinalityVoteSchedule::Claim(int nTipHeight,
                                               int nProducerWindow,
                                               int nMaxAttempts,
                                               int& nEpochOut,
                                               int nEmitOffset)
{
    nEpochOut = -1;
    if (!HasWork())
        return FINALITY_VOTE_CLAIM_IDLE;
    if (nInFlightEpoch == nLatchedEpoch)
        return FINALITY_VOTE_CLAIM_BUSY;
    // Ordering margin, in blocks: a vote names the boundary block, so it must not reach
    // peers before that block does. Both terms count off the same latched boundary, so a
    // reorg moves them together.
    if (nTipHeight - nLatchedBoundary <
        EffectiveEmitOffset(nProducerWindow, nEmitOffset))
        return FINALITY_VOTE_CLAIM_EARLY;
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
