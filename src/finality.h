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

static const int FINALITY_EPOCH_INTERVAL = 60;   // blocks per epoch
static const int FINALITY_THRESHOLD_NUM = 2;      // 2/3 threshold numerator
static const int FINALITY_THRESHOLD_DEN = 3;      // 2/3 threshold denominator
static const int64_t FINALITY_VOTE_MAX_AGE = 3600; // 1 hour max vote age
static const int FINALITY_MAX_VOTES = 10000;       // max votes per epoch
static const int FINALITY_VOTE_WINDOW = 5;         // blocks after epoch boundary to vote

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

    /** Prune old epochs (keep only last 10) */
    void PruneOldEpochs(int nCurrentEpoch);

private:
    int nLastFinalizedHeight;
    uint256 hashLastFinalized;

    std::map<int, std::vector<CFinalityVote>> mapEpochVotes;
    std::map<int, int64_t> mapEpochVoteWeight;
    std::set<uint256> setVoteNullifiers;
};


extern CFinalityTracker g_finalityTracker;

/** Process finality-related P2P messages (fvote, fvreq) */
bool ProcessMessageFinality(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);

/** Background thread that produces finality votes at epoch boundaries */
void ThreadFinalityVoter(void* parg);

/** Create and broadcast a finality vote for the current epoch */
bool ProduceFinalityVote();


#endif // INN_FINALITY_H
