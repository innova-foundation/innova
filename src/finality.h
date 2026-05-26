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
#include "core.h"
#include "script.h"
#include "curvetree.h"
#include "nullstake.h"

#include <vector>
#include <map>
#include <set>
#include <stdint.h>
#include <string>

class CNode;
class CDataStream;
class CTxDB;
class CTransaction;
class CBlock;

static const int FINALITY_EPOCH_INTERVAL_PRE_DAG = 60;    // blocks per epoch pre-DAG
static const int FINALITY_EPOCH_INTERVAL_POST_DAG = 300;  // blocks per epoch post-DAG (5 min at 1s blocks)
static const int FINALITY_THRESHOLD_NUM = 2;      // 2/3 threshold numerator
static const int FINALITY_THRESHOLD_DEN = 3;      // 2/3 threshold denominator
static const int64_t FINALITY_VOTE_MAX_AGE = 3600; // 1 hour max vote age
static const int FINALITY_MAX_VOTES = 10000;       // max votes per epoch
static const int FINALITY_VOTE_WINDOW = 5;         // blocks after epoch boundary to vote
static const int FINALITY_MIN_VOTERS = 2;          // minimum unique voters for finality
static const int FINALITY_CONFIRMATION_EPOCHS = 3;  // consecutive HARD epochs before binding finality (P2P propagation safety)
static const int FINALITY_MAX_STAKE_PROOFS = 8;      // keep coinbase vote commitments under standard script element size
static const int FINALITY_MAX_BLOCK_VOTES = 32;      // per-block vote inclusion cap
static const unsigned char FINALITY_VOTE_TAG[4] = { 0x49, 0x46, 0x56, 0x54 }; // "IFVT"
static const unsigned char FINALITY_TALLY_CERT_TAG[4] = { 0x49, 0x46, 0x54, 0x43 }; // "IFTC"
static const unsigned char FINALITY_TALLY_SHARE_TAG[4] = { 0x49, 0x46, 0x54, 0x53 }; // "IFTS"

/** Finality vote proof modes. Transparent is a compatibility path; NullStake
 *  modes carry hidden stake/reward commitments and are tallied by certificate. */
enum FinalityProofMode
{
    FINALITY_PROOF_TRANSPARENT       = 0,
    FINALITY_PROOF_NULLSTAKE_V2      = 2,
    FINALITY_PROOF_NULLSTAKE_V3_COLD = 3
};

/** Finality tier levels */
enum FinalityTier
{
    FINALITY_NONE      = 0,   // below threshold or too few voters
    FINALITY_TENTATIVE = 1,   // >= 1/3 of epoch vote weight
    FINALITY_SOFT      = 2,   // >= 1/2 of epoch vote weight
    FINALITY_HARD      = 3    // >= 2/3 of epoch vote weight
};

/** Get epoch interval for a given height: 60 pre-DAG, 300 post-DAG */
int GetForkHeightDAG(); // defined in main.h (inline)

inline int GetEpochInterval(int nHeight)
{
    if (nHeight >= GetForkHeightDAG())
        return FINALITY_EPOCH_INTERVAL_POST_DAG;
    return FINALITY_EPOCH_INTERVAL_PRE_DAG;
}

/** Get the epoch number for a given height.
 *  Post-DAG epochs are numbered continuously from pre-DAG epoch count. */
inline int GetEpochForHeight(int nHeight)
{
    // GetForkHeightDAG declared above
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
    // GetForkHeightDAG declared above
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

/** Deterministic finality reward for a vote of nVoteWeight over one epoch. */
int64_t GetFinalityVoteReward(int64_t nVoteWeight, int nEpochInterval);

/** Private NullStake finality proof envelope.
 *
 *  The witness proves membership, ownership/delegation and reward derivation
 *  in the NullStake circuit. Public validation only sees commitments and roots;
 *  aggregate threshold verification happens in CFinalityTallyCertificate.
 */
class CPrivateFinalityVoteProof
{
public:
    int nVersion;
    int nProofMode;
    int nEpoch;
    uint256 hashEpochBlock;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 nullifier;
    CPedersenCommitment stakeWeightCommitment;
    CPedersenCommitment rewardCommitment;
    CFCMPProof fcmpProof;
    CNullStakeKernelProofV2 nullStakeV2Proof;
    CNullStakeKernelProofV3 nullStakeV3Proof;
    std::vector<unsigned char> vchRewardOutputCommitment;
    std::vector<unsigned char> vchBindingProof;

    CPrivateFinalityVoteProof()
    {
        nVersion = 1;
        nProofMode = FINALITY_PROOF_TRANSPARENT;
        nEpoch = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(nProofMode);
        READWRITE(nEpoch);
        READWRITE(hashEpochBlock);
        READWRITE(hashCurveRoot);
        READWRITE(hashNullifierRoot);
        READWRITE(nullifier);
        READWRITE(stakeWeightCommitment);
        READWRITE(rewardCommitment);
        READWRITE(fcmpProof);
        READWRITE(nullStakeV2Proof);
        READWRITE(nullStakeV3Proof);
        READWRITE(vchRewardOutputCommitment);
        READWRITE(vchBindingProof);
    )

    bool IsNull() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
};

/** A finality vote cast by a staker at an epoch boundary */
class CFinalityVote
{
public:
    int nProofMode;
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int64_t nTime;
    int64_t nVoteWeight;
    int64_t nReward;
    uint256 nullifier;    // H(pubkey || epoch)
    std::vector<COutPoint> vStakeProof; // transparent UTXOs proving vote weight
    std::vector<unsigned char> vchPubKey;
    std::vector<unsigned char> vchSig;
    CPrivateFinalityVoteProof privateProof;

    CFinalityVote()
    {
        nProofMode = FINALITY_PROOF_TRANSPARENT;
        nEpoch = 0;
        nHeight = 0;
        nTime = 0;
        nVoteWeight = 0;
        nReward = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nProofMode);
        READWRITE(nEpoch);
        READWRITE(hashBlock);
        READWRITE(nHeight);
        READWRITE(VARINT(nTime));
        READWRITE(VARINT(nVoteWeight));
        READWRITE(VARINT(nReward));
        READWRITE(nullifier);
        READWRITE(vStakeProof);
        READWRITE(vchPubKey);
        READWRITE(vchSig);
        READWRITE(privateProof);
    )

    bool IsPrivate() const { return nProofMode == FINALITY_PROOF_NULLSTAKE_V2 || nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD; }
    uint256 GetHash() const;
    uint256 GetSignatureHash() const;
    bool Sign(CKey& key);
    bool CheckSignature() const;
    bool IsValid() const;
    bool IsExpired(int64_t nNow) const;
};

/** Per-voter aggregate-share message used to assemble a hidden tally. */
class CFinalityTallyShare
{
public:
    int nVersion;
    int nEpoch;
    uint256 voteNullifier;
    uint256 hashBlock;
    CPedersenCommitment stakeWeightCommitment;
    CPedersenCommitment rewardCommitment;
    std::vector<unsigned char> vchShareProof;

    CFinalityTallyShare()
    {
        nVersion = 1;
        nEpoch = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(nEpoch);
        READWRITE(voteNullifier);
        READWRITE(hashBlock);
        READWRITE(stakeWeightCommitment);
        READWRITE(rewardCommitment);
        READWRITE(vchShareProof);
    )

    uint256 GetHash() const;
    bool IsValidBasic() const;
};

/** Aggregate certificate proving hidden threshold and reward-budget validity. */
class CFinalityTallyCertificate
{
public:
    int nVersion;
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int nTier;
    int nConsecutiveHardCount;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    CPedersenCommitment activeWeightCommitment;
    CPedersenCommitment winningWeightCommitment;
    CPedersenCommitment rewardBudgetCommitment;
    int64_t nTransparentActiveWeight;
    int64_t nTransparentWinningWeight;
    int64_t nTransparentRewardBudget;
    std::vector<uint256> vVoteNullifiers;
    std::vector<uint256> vTallyShareHashes;
    std::vector<unsigned char> vchAggregateThresholdProof;
    std::vector<unsigned char> vchRewardBudgetProof;

    CFinalityTallyCertificate()
    {
        nVersion = 1;
        nEpoch = 0;
        nHeight = 0;
        nTier = FINALITY_NONE;
        nConsecutiveHardCount = 0;
        nTransparentActiveWeight = 0;
        nTransparentWinningWeight = 0;
        nTransparentRewardBudget = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(nEpoch);
        READWRITE(hashBlock);
        READWRITE(nHeight);
        READWRITE(nTier);
        READWRITE(nConsecutiveHardCount);
        READWRITE(hashCurveRoot);
        READWRITE(hashNullifierRoot);
        READWRITE(activeWeightCommitment);
        READWRITE(winningWeightCommitment);
        READWRITE(rewardBudgetCommitment);
        READWRITE(VARINT(nTransparentActiveWeight));
        READWRITE(VARINT(nTransparentWinningWeight));
        READWRITE(VARINT(nTransparentRewardBudget));
        READWRITE(vVoteNullifiers);
        READWRITE(vTallyShareHashes);
        READWRITE(vchAggregateThresholdProof);
        READWRITE(vchRewardBudgetProof);
    )

    uint256 GetHash() const;
    bool HasPrivateWeight() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
};

/** Build/extract finality vote commitments embedded in coinbase OP_RETURN outputs. */
CScript BuildFinalityVoteScript(const CFinalityVote& vote);
bool ExtractFinalityVote(const CScript& scriptPubKey, CFinalityVote& voteOut);
std::vector<CFinalityVote> ExtractFinalityVotesFromBlock(const CBlock& block);
CScript BuildFinalityTallyCertificateScript(const CFinalityTallyCertificate& cert);
bool ExtractFinalityTallyCertificate(const CScript& scriptPubKey, CFinalityTallyCertificate& certOut);
std::vector<CFinalityTallyCertificate> ExtractFinalityTallyCertificatesFromBlock(const CBlock& block);


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
        nLastHardEpoch = -1;
        nPendingFinalizedHeight = 0;
        hashPendingFinalized = 0;
    }

    /** Add a vote to the tracker. Returns true if vote was accepted. */
    bool AddVote(const CFinalityVote& vote, bool fCheckStake = true, bool fRecordFinality = false);

    /** Stateless consensus validation of a transparent or private finality vote. */
    bool CheckVote(const CFinalityVote& vote, CTxDB& txdb, std::string* pstrError = NULL) const;

    /** Stateless consensus validation of an aggregate hidden tally certificate. */
    bool CheckTallyCertificate(const CFinalityTallyCertificate& cert, CTxDB& txdb, std::string* pstrError = NULL) const;

    /** Add a pending or connected tally certificate. */
    bool AddTallyCertificate(const CFinalityTallyCertificate& cert, bool fCheck = true, bool fRecordFinality = false);

    /** Return pending votes miners may include in the next PoW block. */
    std::vector<CFinalityVote> GetPendingVotesForBlock(int nBlockHeight, unsigned int nMaxVotes = FINALITY_MAX_BLOCK_VOTES) const;
    std::vector<CFinalityTallyCertificate> GetPendingTallyCertificatesForBlock(int nBlockHeight, unsigned int nMaxCerts = 4) const;

    /** Connect/disconnect votes included in a block. */
    bool ConnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes);
    bool DisconnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes);
    bool ConnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts);
    bool DisconnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts);

    /** Load persisted connected votes from LevelDB at startup. */
    bool LoadVotes(CTxDB& txdb);
    bool LoadTallyCertificates(CTxDB& txdb);

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

    /** Get vote mode counts for RPC reporting. */
    void GetEpochVoteModeCounts(int nEpoch, int& nTransparentVotes, int& nPrivateVotes) const;

    /** Get current epoch tally certificates. */
    std::vector<CFinalityTallyCertificate> GetEpochTallyCertificates(int nEpoch) const;

    /** Get voter key ids for RPC reporting. */
    std::vector<CKeyID> GetEpochVoters(int nEpoch) const;

    /** Get pending vote count and reward totals for RPC reporting. */
    int GetPendingVoteCount() const;
    int64_t GetPendingRewardTotal() const;

    /** Get the finality tier for the current state */
    FinalityTier GetFinalityTier() const
    {
        LOCK(cs_finality);
        return nLastFinalityTier;
    }

    int GetConsecutiveHardEpochCount() const
    {
        LOCK(cs_finality);
        return nConsecutiveHardEpochs;
    }

    /** Prune old epochs (keep only last 10) */
    void PruneOldEpochs(int nCurrentEpoch);

private:
    int nLastFinalizedHeight;
    uint256 hashLastFinalized;
    FinalityTier nLastFinalityTier;
    int nConsecutiveHardEpochs;      // consecutive HARD epochs (for confirmation delay)
    int nLastHardEpoch;              // last epoch counted in the HARD streak
    int nPendingFinalizedHeight;     // height waiting for confirmation
    uint256 hashPendingFinalized;    // hash waiting for confirmation

    std::map<int, std::vector<CFinalityVote>> mapEpochVotes;
    std::map<int, int64_t> mapEpochVoteWeight;
    std::map<uint256, uint256> mapVoteHashByNullifier;
    std::map<uint256, CFinalityVote> mapPendingVotes;
    std::map<uint256, CFinalityVote> mapConnectedVotes;
    std::map<uint256, std::vector<uint256>> mapBlockConnectedVoteNullifiers;
    std::map<int, std::set<CKeyID>> mapEpochVoters;  // one vote per key per epoch
    std::map<int, int> mapEpochTransparentVoteCount;
    std::map<int, int> mapEpochPrivateVoteCount;
    std::map<uint256, CFinalityTallyShare> mapTallyShares;
    std::map<uint256, CFinalityTallyCertificate> mapPendingTallyCertificates;
    std::map<uint256, CFinalityTallyCertificate> mapConnectedTallyCertificates;
    std::map<int, std::vector<CFinalityTallyCertificate>> mapEpochTallyCertificates;
    std::map<uint256, std::vector<uint256>> mapBlockConnectedTallyCertificates;

    bool ApplyFinalityDecision(int nEpoch, const uint256& hashFinal, int nFinalHeight,
                               FinalityTier tier, int nVoterCount,
                               int64_t nBestBlockWeight, int64_t nEpochVoteWeight,
                               bool fFromCertificate);
};


extern CFinalityTracker g_finalityTracker;

/** Process finality-related P2P messages (fvote, fvreq) */
bool ProcessMessageFinality(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);

/** Background thread that produces finality votes at epoch boundaries */
void ThreadFinalityVoter(void* parg);

/** Create and broadcast a finality vote for the current epoch */
bool ProduceFinalityVote();


#endif // INN_FINALITY_H
