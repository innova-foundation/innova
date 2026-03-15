// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_FINALITY_H
#define INN_FINALITY_H

#include "uint256.h"
#include "bignum.h"
#include "serialize.h"
#include "sync.h"
#include "key.h"
#include "hash.h"

#include <vector>
#include <map>
#include <set>
#include <stdint.h>

class CNode;
class CDataStream;

static const int FINALITY_EPOCH_INTERVAL_PRE_DAG = 60;    // blocks per epoch pre-DAG
static const int FINALITY_EPOCH_INTERVAL_POST_DAG = 300;  // blocks per epoch post-DAG (5 min at 1s blocks)
static const int FINALITY_THRESHOLD_NUM = 2;      // 2/3 threshold numerator
static const int FINALITY_THRESHOLD_DEN = 3;      // 2/3 threshold denominator
static const int64_t FINALITY_VOTE_MAX_AGE = 3600; // 1 hour max vote age
static const int FINALITY_MAX_VOTES = 10000;       // max votes per epoch
static const int FINALITY_VOTE_WINDOW = 5;         // blocks after epoch boundary to vote
static const int FINALITY_MIN_VOTERS = 2;          // minimum unique voters for finality
static const int64_t FINALITY_MIN_STAKE_DEFAULT = 25000 * COIN; // default minimum stake floor (configurable via -minfinalitystake)
static const int FINALITY_CONFIRMATION_EPOCHS = 3;  // consecutive HARD epochs before binding finality (P2P propagation safety)

/** Finality tier levels */
enum FinalityTier
{
    FINALITY_NONE      = 0,   // below minimum stake or too few voters
    FINALITY_TENTATIVE = 1,   // >= 1/3 of epoch vote weight
    FINALITY_SOFT      = 2,   // >= 1/2 of epoch vote weight
    FINALITY_HARD      = 3    // >= 2/3 of epoch vote weight
};

/** Get epoch interval for a given height: 60 pre-DAG, 300 post-DAG */
inline int GetEpochInterval(int nHeight)
{
    extern int GetForkHeightDAG();
    if (nHeight >= GetForkHeightDAG())
        return FINALITY_EPOCH_INTERVAL_POST_DAG;
    return FINALITY_EPOCH_INTERVAL_PRE_DAG;
}

/** Get the epoch number for a given height.
 *  Post-DAG epochs are numbered continuously from pre-DAG epoch count. */
inline int GetEpochForHeight(int nHeight)
{
    extern int GetForkHeightDAG();
    int nDAGFork = GetForkHeightDAG();
    if (nHeight >= nDAGFork)
    {
        // Post-DAG: continue epoch numbering from where pre-DAG left off
        // Use ceiling division to avoid epoch number collision at boundary
        int nPreDAGEpochs = (nDAGFork + FINALITY_EPOCH_INTERVAL_PRE_DAG - 1) / FINALITY_EPOCH_INTERVAL_PRE_DAG;
        return nPreDAGEpochs + (nHeight - nDAGFork) / FINALITY_EPOCH_INTERVAL_POST_DAG;
    }
    return nHeight / FINALITY_EPOCH_INTERVAL_PRE_DAG;
}

/** Get the block height of an epoch boundary */
inline int GetEpochBoundaryHeight(int nEpoch, int nHeight)
{
    extern int GetForkHeightDAG();
    int nDAGFork = GetForkHeightDAG();
    int nPreDAGEpochs = (nDAGFork + FINALITY_EPOCH_INTERVAL_PRE_DAG - 1) / FINALITY_EPOCH_INTERVAL_PRE_DAG;
    if (nEpoch >= nPreDAGEpochs)
    {
        // Post-DAG epoch: compute relative to DAG fork
        return nDAGFork + (nEpoch - nPreDAGEpochs) * FINALITY_EPOCH_INTERVAL_POST_DAG;
    }
    return nEpoch * FINALITY_EPOCH_INTERVAL_PRE_DAG;
}

/** Compute POEM entropy weight for a block hash.
 *  Returns a uint256 that is the approximate log2(2^256 - hash) with 32 sub-bits of precision.
 *  Lower hashes (harder blocks) yield higher entropy values.
 *  Result is directly summable for chain trust accumulation.
 */
uint256 GetBlockEntropy(const uint256& hashValue);


/** A finality vote cast by a staker at an epoch boundary */
class CFinalityVote
{
public:
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int64_t nTime;
    int64_t nVoteWeight;
    uint256 nullifier;    // H(pubkey || epoch)
    std::vector<unsigned char> vchPubKey;
    std::vector<unsigned char> vchSig;

    CFinalityVote()
    {
        nEpoch = 0;
        nHeight = 0;
        nTime = 0;
        nVoteWeight = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nEpoch);
        READWRITE(hashBlock);
        READWRITE(nHeight);
        READWRITE(VARINT(nTime));
        READWRITE(VARINT(nVoteWeight));
        READWRITE(nullifier);
        READWRITE(vchPubKey);
        READWRITE(vchSig);
    )

    uint256 GetHash() const;
    uint256 GetSignatureHash() const;
    bool Sign(CKey& key);
    bool CheckSignature() const;
    bool IsValid() const;
    bool IsExpired(int64_t nNow) const;
};


/** Tracks finality votes per epoch and determines when finality is achieved */
class CFinalityTracker
{
public:
    mutable CCriticalSection cs_finality;

    CFinalityTracker()
    {
        nLastFinalizedHeight = 0;
        hashLastFinalized = 0;
        nLastFinalityTier = FINALITY_NONE;
        nConsecutiveHardEpochs = 0;
        nPendingFinalizedHeight = 0;
        hashPendingFinalized = 0;
    }

    /** Add a vote to the tracker. Returns true if vote was accepted. */
    bool AddVote(const CFinalityVote& vote);

    /** Check if a block at the given height is finalized */
    bool IsFinalized(int nHeight) const;

    /** Check if an epoch has reached the finality threshold */
    bool CheckFinalityThreshold(int nEpoch);

    /** Get current finalized height */
    int GetFinalizedHeight() const
    {
        LOCK(cs_finality);
        return nLastFinalizedHeight;
    }

    /** Get finalized block hash */
    uint256 GetFinalizedHash() const
    {
        LOCK(cs_finality);
        return hashLastFinalized;
    }

    /** Get votes for a given epoch */
    std::vector<CFinalityVote> GetEpochVotes(int nEpoch) const;

    /** Get total vote weight for an epoch */
    int64_t GetEpochVoteWeight(int nEpoch) const;

    /** Get number of votes for an epoch */
    int GetEpochVoteCount(int nEpoch) const;

    /** Get number of unique voters for an epoch */
    int GetEpochVoterCount(int nEpoch) const;

    /** Get the finality tier for the current state */
    FinalityTier GetFinalityTier() const
    {
        LOCK(cs_finality);
        return nLastFinalityTier;
    }

    /** Prune old epochs (keep only last 10) */
    void PruneOldEpochs(int nCurrentEpoch);

private:
    int nLastFinalizedHeight;
    uint256 hashLastFinalized;
    FinalityTier nLastFinalityTier;
    int nConsecutiveHardEpochs;      // consecutive HARD epochs (for confirmation delay)
    int nPendingFinalizedHeight;     // height waiting for confirmation
    uint256 hashPendingFinalized;    // hash waiting for confirmation

    std::map<int, std::vector<CFinalityVote>> mapEpochVotes;
    std::map<int, int64_t> mapEpochVoteWeight;
    std::set<uint256> setVoteNullifiers;
    std::map<int, std::set<CKeyID>> mapEpochVoters;  // one vote per key per epoch
};


extern CFinalityTracker g_finalityTracker;

/** Process finality-related P2P messages (fvote, fvreq) */
bool ProcessMessageFinality(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);

/** Background thread that produces finality votes at epoch boundaries */
void ThreadFinalityVoter(void* parg);

/** Create and broadcast a finality vote for the current epoch */
bool ProduceFinalityVote();


#endif // INN_FINALITY_H
