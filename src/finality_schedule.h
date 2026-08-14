// Copyright (c) 2019-2026 Innova Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_FINALITY_SCHEDULE_H
#define INNOVA_FINALITY_SCHEDULE_H

// Node-local scheduling of finality vote production. Latches the epoch on the boundary block,
// since a wall-clock tip poll can step over the inclusion window.

/** Outcome of a producer's attempt to take the outstanding epoch. */
enum FinalityVoteClaim
{
    FINALITY_VOTE_CLAIM_OK = 0,   //!< caller now owns an attempt at nEpochOut
    FINALITY_VOTE_CLAIM_IDLE,     //!< nothing outstanding
    FINALITY_VOTE_CLAIM_BUSY,     //!< another producer holds the attempt
    FINALITY_VOTE_CLAIM_LATE,     //!< the producer window closed before the claim
    FINALITY_VOTE_CLAIM_SPENT,    //!< attempt budget for this epoch is used up
};

class CFinalityVoteSchedule
{
public:
    CFinalityVoteSchedule() { Reset(); }

    void Reset();

    /** Chain event: the durable tip is nHeight, in epoch nEpoch which starts at
     *  nBoundary. Returns true when this advance left an epoch outstanding, i.e.
     *  the producer has work and should be woken. */
    bool OnTipChanged(int nHeight, int nEpoch, int nBoundary);

    /** Producer: take an attempt at the outstanding epoch. nProducerWindow is the
     *  node-local deadline in blocks after the boundary; <= 0 disables it. */
    FinalityVoteClaim Claim(int nTipHeight,
                            int nProducerWindow,
                            int nMaxAttempts,
                            int& nEpochOut);

    /** Producer: hand an accepted claim back. fProduced settles the epoch. */
    void Release(int nEpoch, bool fProduced);

    bool HasWork() const { return nLatchedEpoch >= 0 && nLatchedEpoch != nVotedEpoch; }
    int LatchedEpoch() const { return nLatchedEpoch; }
    int LatchedBoundary() const { return nLatchedBoundary; }
    int VotedEpoch() const { return nVotedEpoch; }
    int Attempts() const { return nAttempts; }

private:
    int nLatchedEpoch;
    int nLatchedBoundary;
    int nVotedEpoch;
    int nAttempts;
    int nInFlightEpoch;
};

#endif // INNOVA_FINALITY_SCHEDULE_H
