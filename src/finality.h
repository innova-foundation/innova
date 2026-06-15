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
static const unsigned int FINALITY_PRIVATE_VOTE_SEARCH_INTERVAL = 3600;
static const int FINALITY_MAX_VOTES = 10000;       // max votes per epoch
static const int FINALITY_VOTE_WINDOW = 5;         // blocks after epoch boundary to vote
// Connect-time vote-inclusion window (consensus, fork-gated by FORK_HEIGHT_VOTESET_ROOT).
// An epoch-E finality vote is block-valid only in a containing block at height in
// [H_E, H_E + FINALITY_VOTE_INCLUSION_WINDOW); a tally certificate for E is block-valid
// only at height >= H_E + FINALITY_VOTE_INCLUSION_WINDOW and must reference EXACTLY the
// epoch-E votes connected within that window (coverage equality). Suppressing a vote
// then requires censoring all K consecutive blocks of the window, while the latency cost
// (~K seconds at 1s blocks) is <1% of the 3-epoch HARD-finality window. Tunable pre-mainnet
// (the testnet remine makes a change free).
static const int FINALITY_VOTE_INCLUSION_WINDOW = 24;
static const int FINALITY_MIN_VOTERS = 2;          // minimum unique voters for finality
static const int FINALITY_CONFIRMATION_EPOCHS = 3;  // consecutive HARD epochs before binding finality (P2P propagation safety)
static const int FINALITY_MAX_STAKE_PROOFS = 8;      // keep coinbase vote commitments under standard script element size
static const int FINALITY_MAX_BLOCK_VOTES = 32;      // per-block vote inclusion cap
static const int FINALITY_MAX_TALLY_COMMITTEE = 64;  // bounded m-of-n committee descriptor
static const unsigned char FINALITY_VOTE_TAG[4] = { 0x49, 0x46, 0x56, 0x54 }; // "IFVT"
static const unsigned char FINALITY_TALLY_CERT_TAG[4] = { 0x49, 0x46, 0x54, 0x43 }; // "IFTC"
static const unsigned char FINALITY_TALLY_SHARE_TAG[4] = { 0x49, 0x46, 0x54, 0x53 }; // "IFTS"
static const unsigned char FINALITY_COMMITTEE_ROTATION_TAG[4] = { 0x49, 0x46, 0x43, 0x52 }; // "IFCR"

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

struct CFinalityTallyConfig
{
    std::string strMode;
    bool fModeValid;
    bool fEnabled;
    bool fThresholdValid;
    bool fPubKeyConfigured;
    bool fCommitteeValid;
    bool fPrivKeyConfigured;
    bool fPrivKeyValid;
    bool fEncryptedTallyReady;
    int nThresholdM;
    int nThresholdN;
    int nLocalCommitteeIndex;
    uint256 committeeSetHash;
    std::vector<CPubKey> vCommitteePubKeys;

    CFinalityTallyConfig()
    {
        strMode = "off";
        fModeValid = true;
        fEnabled = false;
        fThresholdValid = false;
        fPubKeyConfigured = false;
        fCommitteeValid = false;
        fPrivKeyConfigured = false;
        fPrivKeyValid = false;
        fEncryptedTallyReady = false;
        nThresholdM = 0;
        nThresholdN = 0;
        nLocalCommitteeIndex = -1;
    }

    bool CanRelayPrivateVotes() const
    {
        return fEnabled && fThresholdValid && fCommitteeValid && fEncryptedTallyReady;
    }

    bool CanProduceCertificates() const
    {
        return CanRelayPrivateVotes() && fPrivKeyValid && nLocalCommitteeIndex >= 0;
    }
};

bool ParseFinalityTallyThreshold(const std::string& strThreshold, int& nMOut, int& nNOut);
uint256 ComputeFinalityTallyCommitteeHash(int nM, const std::vector<CPubKey>& vPubKeys);
CFinalityTallyConfig GetFinalityTallyConfig();

/** D2: pin the canonical finality committee at startup (before rotations load).
 *  Testnet pins a consensus-constant committee; regtest pins from local config
 *  for test flexibility; mainnet pins the launch committee. Called once during
 *  block-index load, before LoadCommitteeRotations. Inert until the governance
 *  fork height regardless (CheckTallyCertificate is height-gated). */
void PinFinalityCommitteeConstants();

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
    // Nullifier binding: NF=r*G_nf tied to stakeWeightCommitment, with the vote
    // nullifier = FinalityNullifierTag(NF, epoch) so a stake votes once per epoch.
    std::vector<unsigned char> vchNullifierPoint;        // 33-byte compressed NF
    std::vector<unsigned char> vchNullifierBindingProof; // NULLIFIER_BINDING_PROOF_SIZE

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
        unsigned char fHasNfBind = (vchNullifierPoint.empty() && vchNullifierBindingProof.empty()) ? 0 : 1;
        READWRITE(fHasNfBind);
        if (fHasNfBind)
        {
            READWRITE(vchNullifierPoint);
            READWRITE(vchNullifierBindingProof);
        }
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
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;
    CPedersenCommitment stakeWeightCommitment;
    CPedersenCommitment rewardCommitment;
    std::vector<std::vector<unsigned char> > vEncryptedRecipientShares;
    std::vector<unsigned char> vchShareProof;

    CFinalityTallyShare()
    {
        nVersion = 2;
        nEpoch = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CFinalityTallyShare* pthis = const_cast<CFinalityTallyShare*>(this);
        READWRITE(nVersion);
        READWRITE(nEpoch);
        READWRITE(voteNullifier);
        READWRITE(hashBlock);
        if (nVersion >= 2)
        {
            READWRITE(pthis->hashCurveRoot);
            READWRITE(pthis->hashNullifierRoot);
            READWRITE(pthis->committeeSetHash);
        }
        READWRITE(stakeWeightCommitment);
        READWRITE(rewardCommitment);
        if (nVersion >= 2)
            READWRITE(pthis->vEncryptedRecipientShares);
        READWRITE(vchShareProof);
    )

    uint256 GetHash() const;
    bool IsValidBasic() const;
};

struct CFinalityTallyPlainShare
{
    int nRecipientIndex;
    int nX;
    uint256 evalWeight;
    uint256 evalReward;
    uint256 evalWeightBlind;
    uint256 evalRewardBlind;

    CFinalityTallyPlainShare()
    {
        nRecipientIndex = -1;
        nX = 0;
    }
};

/** Encrypted committee aggregate evaluation published by one tally member. */
class CFinalityTallyAggregatePartial
{
public:
    int nVersion;
    int nEpoch;
    uint256 hashBlock;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;
    int nSourceIndex;
    std::vector<uint256> vTallyShareHashes;
    std::vector<std::vector<unsigned char> > vEncryptedRecipientPartials;
    // nVersion >= 3 (D1.1): detached signature by the source committee member's
    // key over GetContentDigest(). Authenticates nSourceIndex so a partial is
    // attributable and equivocation is detectable; relay-layer (no fork).
    std::vector<unsigned char> vchSourceSig;

    CFinalityTallyAggregatePartial()
    {
        nVersion = 2;
        nEpoch = 0;
        nSourceIndex = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        CFinalityTallyAggregatePartial* pthis = const_cast<CFinalityTallyAggregatePartial*>(this);
        // The IMPLEMENT_SERIALIZE macro injects an `int nVersion` (stream version)
        // that shadows our member nVersion. The member is the partial's own version
        // and gates vchSourceSig below, so it MUST be (de)serialized as pthis->nVersion
        // and the conditional MUST test the member — otherwise a v3 signed partial
        // round-trips with the member left at its default (2) and the source-signature
        // check is skipped/rejected ("missing source signature") on relay.
        READWRITE(pthis->nVersion);
        READWRITE(nEpoch);
        READWRITE(hashBlock);
        READWRITE(hashCurveRoot);
        READWRITE(hashNullifierRoot);
        READWRITE(committeeSetHash);
        READWRITE(nSourceIndex);
        READWRITE(vTallyShareHashes);
        READWRITE(vEncryptedRecipientPartials);
        if (pthis->nVersion >= 3)
            READWRITE(pthis->vchSourceSig);
    )

    uint256 GetHash() const;            // full identity (includes vchSourceSig for v3)
    uint256 GetContentDigest() const;   // signed content, excludes vchSourceSig
    bool IsValidBasic() const;
};

/** Shared M-of-N helper: verify that vSignerIndexes are distinct, in [0,N), at
 *  least nThreshold of them, and each parallel signature verifies under the
 *  corresponding committee pubkey over hashDigest. Used by the certificate
 *  signer-set (D1.2) and reusable by the staking set checks. */
bool VerifyMofNCommitteeSignatures(const std::vector<CPubKey>& vCommitteePubKeys,
                                   int nThreshold,
                                   const std::vector<uint16_t>& vSignerIndexes,
                                   const std::vector<std::vector<unsigned char> >& vSignerSigs,
                                   const uint256& hashDigest,
                                   std::string* pstrError = NULL);

class CFinalityTallyCertificate;

/** D2: resolve the canonical finality committee for an epoch. The set is a
 *  consensus value (fork-pinned initial set, advanced by connected self-rotations
 *  — see GetForkHeightTallyGovernance). Returns false if no committee is pinned
 *  for nEpoch yet (pre-activation/transitional), in which case the signer-set
 *  rule is inert. nMOut/setHashOut are the threshold and committee-set hash. */
bool GetCanonicalFinalityCommittee(int nEpoch,
                                   std::vector<CPubKey>& vCommitteeOut,
                                   int& nMOut,
                                   uint256& setHashOut);

/** D2: verify a v3 tally certificate carries >= M canonical-committee signatures
 *  over its GetSignatureDigest(). Pure (no chain state) so it is unit-testable
 *  with an injected committee. */
bool CheckTallyCertificateCommitteeSignatures(const CFinalityTallyCertificate& cert,
                                              const std::vector<CPubKey>& vCommittee,
                                              int nThreshold,
                                              const uint256& setHash,
                                              std::string* pstrError = NULL);

bool BuildEncryptedFinalityTallyShares(CFinalityTallyShare& share,
                                       int64_t nWeight,
                                       int64_t nReward,
                                       const std::vector<unsigned char>& vchWeightBlind,
                                       const std::vector<unsigned char>& vchRewardBlind,
                                       const CFinalityTallyConfig& config);
bool DecryptFinalityTallyShareForRecipient(const CFinalityTallyShare& share,
                                           const CFinalityTallyConfig& config,
                                           const CKey& keyRecipient,
                                           int nRecipientIndex,
                                           CFinalityTallyPlainShare& plainOut);
bool AggregateFinalityTallyPlainShares(const std::vector<CFinalityTallyPlainShare>& vShares,
                                       CFinalityTallyPlainShare& aggregateOut);
bool RecoverFinalityTallySecrets(const std::vector<CFinalityTallyPlainShare>& vShares,
                                 int nThreshold,
                                 uint256& weightOut,
                                 uint256& rewardOut,
                                 uint256& weightBlindOut,
                                 uint256& rewardBlindOut);
bool BuildEncryptedFinalityTallyAggregatePartial(CFinalityTallyAggregatePartial& partial,
                                                 const CFinalityTallyPlainShare& aggregateShare,
                                                 const CFinalityTallyConfig& config,
                                                 const CKey& keySource);
bool DecryptFinalityTallyAggregatePartialForRecipient(const CFinalityTallyAggregatePartial& partial,
                                                      const CFinalityTallyConfig& config,
                                                      const CKey& keyRecipient,
                                                      int nRecipientIndex,
                                                      CFinalityTallyPlainShare& plainOut);

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
    uint256 committeeSetHash;
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
    // nVersion >= 3 (D2): committee signer-set. >= M distinct, strictly ascending
    // indexes into the canonical committee for nEpoch, with parallel detached
    // signatures over GetSignatureDigest(). Enforced in CheckTallyCertificate
    // from FORK_HEIGHT_TALLY_GOVERNANCE.
    std::vector<uint16_t> vSignerIndexes;
    std::vector<std::vector<unsigned char> > vSignerSigs;

    CFinalityTallyCertificate()
    {
        nVersion = 2;
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
        CFinalityTallyCertificate* pthis = const_cast<CFinalityTallyCertificate*>(this);
        // NOTE: the IMPLEMENT_SERIALIZE macro injects an `int nVersion` parameter
        // (the stream version) that shadows our member nVersion. The certificate's
        // own version is consensus data and gates the optional fields below, so it
        // MUST be (de)serialized as the member (pthis->nVersion) and the conditionals
        // MUST test the member — not the stream parameter. Using the bare `nVersion`
        // here would (de)serialize the stream version and leave the member at its
        // default, so a v3 cert would round-trip as v2-with-a-signer-set.
        READWRITE(pthis->nVersion);
        READWRITE(nEpoch);
        READWRITE(hashBlock);
        READWRITE(nHeight);
        READWRITE(nTier);
        READWRITE(nConsecutiveHardCount);
        READWRITE(hashCurveRoot);
        READWRITE(hashNullifierRoot);
        if (pthis->nVersion >= 2)
            READWRITE(pthis->committeeSetHash);
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
        if (pthis->nVersion >= 3)
        {
            READWRITE(pthis->vSignerIndexes);
            READWRITE(pthis->vSignerSigs);
        }
    )

    uint256 GetHash() const;            // full identity (includes signer-set for v3)
    uint256 GetSignatureDigest() const; // signed content, excludes vSignerIndexes/vSignerSigs
    bool HasPrivateWeight() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
};

/** D2 self-governance: the committee rotates itself. A rotation is authorized by
 *  >= M signatures from the CURRENT committee over the NEW set + threshold, takes
 *  effect at nEffectiveEpoch, and chains to the set it descends from
 *  (hashPrevCommitteeSet). No central key is involved. */
class CFinalityCommitteeRotation
{
public:
    int nVersion;
    int nEffectiveEpoch;
    uint256 hashPrevCommitteeSet;                          // canonical set this rotation descends from
    uint8_t nNewThresholdM;
    std::vector<std::vector<unsigned char> > vNewPubKeys;  // new N-set (compressed)
    std::vector<uint16_t> vSignerIndexes;                  // signers from the PREV set
    std::vector<std::vector<unsigned char> > vSignerSigs;

    CFinalityCommitteeRotation()
    {
        nVersion = 1;
        nEffectiveEpoch = 0;
        nNewThresholdM = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(nEffectiveEpoch);
        READWRITE(hashPrevCommitteeSet);
        READWRITE(nNewThresholdM);
        READWRITE(vNewPubKeys);
        READWRITE(vSignerIndexes);
        READWRITE(vSignerSigs);
    )

    uint256 GetHash() const;            // full identity (includes signatures)
    uint256 GetSignatureDigest() const; // what the prev committee signs (excludes sigs)
    bool IsValidBasic(std::string* pstrError = NULL) const;  // structural: new-set well-formed
    // Resolve the new set into pubkeys (returns false on any malformed key).
    bool GetNewCommittee(std::vector<CPubKey>& vOut, int& nMOut, uint256& setHashOut) const;
};

/** Verify a rotation is authorized by >= M signatures from the given PREV
 *  committee over its GetSignatureDigest(). Stateless (no chain context); the
 *  effective-epoch bound + prev-set chaining are checked when the rotation is
 *  applied to the canonical-set state. */
bool CheckFinalityCommitteeRotation(const CFinalityCommitteeRotation& rot,
                                    const std::vector<CPubKey>& vPrevPubKeys,
                                    int nPrevThresholdM,
                                    const uint256& hashPrevSet,
                                    std::string* pstrError = NULL);

/** Committee rotations ride the coinbase OP_RETURN, like votes/certs/shares. */
CScript BuildFinalityCommitteeRotationScript(const CFinalityCommitteeRotation& rot);
bool ExtractFinalityCommitteeRotation(const CScript& scriptPubKey, CFinalityCommitteeRotation& rotOut);
std::vector<CFinalityCommitteeRotation> ExtractFinalityCommitteeRotationsFromBlock(const CBlock& block);

/** Max epochs ahead a rotation may take effect (A2: keeps rotations timely and
 *  prevents pre-dating). */
static const int FINALITY_ROTATION_MAX_LOOKAHEAD = 4;

/** A1 recovery: if HARD finality has not advanced for more than this many epochs,
 *  a fork-pinned recovery committee may ALSO authorize a certificate (union with
 *  the canonical committee), so a dead or sub-threshold primary committee cannot
 *  freeze HARD finality — and thus FCMP shielded spends — permanently. */
static const int FINALITY_RECOVERY_GAP_EPOCHS = 6;

/** Pure predicate: is a certificate for nCertEpoch within the recovery window
 *  given the current finalized height? Deterministic (nFinalizedHeight is a pure
 *  function of the connected chain), so all nodes agree. */
bool FinalityCertInRecoveryWindow(int nCertEpoch, int nFinalizedHeight);

/** Resolve the fork-pinned recovery committee (returns false if not pinned). */
bool GetRecoveryFinalityCommittee(std::vector<CPubKey>& vOut, int& nMOut, uint256& setHashOut);

/** 2c-4b: M-of-N certificate production. Because the BPAC proofs are builder-
 *  randomized, committee members sign ONE builder's candidate certificate. This
 *  message carries the candidate + one member's signature over its
 *  GetSignatureDigest(); members collect M distinct signatures then assemble the
 *  complete signer-set. */
class CFinalityCertSignature
{
public:
    int nVersion;
    CFinalityTallyCertificate candidate;   // content being signed (signer-set ignored)
    uint16_t nSignerIndex;
    std::vector<unsigned char> vchSig;

    CFinalityCertSignature() { nVersion = 1; nSignerIndex = 0; }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(candidate);
        READWRITE(nSignerIndex);
        READWRITE(vchSig);
    )
    uint256 GetHash() const;
};

/** Pure helper: fill cert.vSignerIndexes/vSignerSigs from collected per-member
 *  signatures over cert.GetSignatureDigest(), keeping only valid ones for the
 *  given committee, in ascending index order. Returns true iff >= nThreshold
 *  valid distinct signatures were assembled (so the result passes
 *  CheckTallyCertificateCommitteeSignatures). Unit-testable (no chain state). */
bool AssembleCertificateFromSignatures(CFinalityTallyCertificate& cert,
                                       const std::map<uint16_t, std::vector<unsigned char> >& collected,
                                       const std::vector<CPubKey>& vCommittee,
                                       int nThreshold,
                                       const uint256& setHash);

bool CreateFinalityAggregateThresholdProofV2(const CFinalityTallyCertificate& cert,
                                             int64_t nPrivateActiveWeight,
                                             int64_t nPrivateWinningWeight,
                                             const std::vector<unsigned char>& vchActiveBlind,
                                             const std::vector<unsigned char>& vchWinningBlind,
                                             bool fRequireZeroPrivateWinning,
                                             std::vector<unsigned char>& vchProofOut);
bool VerifyFinalityAggregateThresholdProofV2(const CFinalityTallyCertificate& cert,
                                             int64_t nMatchedTransparentActiveWeight,
                                             int64_t nMatchedTransparentWinningWeight,
                                             bool fRequireZeroPrivateWinning,
                                             std::string* pstrError = NULL);
bool CreateFinalityRewardBudgetProofV2(const CFinalityTallyCertificate& cert,
                                       int64_t nPrivateActiveWeight,
                                       int64_t nPrivateRewardBudget,
                                       const std::vector<unsigned char>& vchActiveBlind,
                                       const std::vector<unsigned char>& vchRewardBlind,
                                       std::vector<unsigned char>& vchProofOut);
bool VerifyFinalityRewardBudgetProofV2(const CFinalityTallyCertificate& cert,
                                       int64_t nMatchedTransparentRewardBudget,
                                       std::string* pstrError = NULL);

/** Build/extract finality vote commitments embedded in coinbase OP_RETURN outputs. */
CScript BuildFinalityVoteScript(const CFinalityVote& vote);
bool ExtractFinalityVote(const CScript& scriptPubKey, CFinalityVote& voteOut);
std::vector<CFinalityVote> ExtractFinalityVotesFromBlock(const CBlock& block);
CScript BuildFinalityTallyCertificateScript(const CFinalityTallyCertificate& cert);
bool ExtractFinalityTallyCertificate(const CScript& scriptPubKey, CFinalityTallyCertificate& certOut);
std::vector<CFinalityTallyCertificate> ExtractFinalityTallyCertificatesFromBlock(const CBlock& block);
CScript BuildFinalityTallyShareScript(const CFinalityTallyShare& share);
bool ExtractFinalityTallyShare(const CScript& scriptPubKey, CFinalityTallyShare& shareOut);
std::vector<CFinalityTallyShare> ExtractFinalityTallySharesFromBlock(const CBlock& block);

/** Private-vote nullifier binding: epoch-scoped vote tag for a note-bound
 *  nullifier point, and the context hash its binding proof commits to. */
uint256 FinalityNullifierTag(const std::vector<unsigned char>& vchNullifierPoint, int nEpoch);
uint256 FinalityNullifierBindContext(int nEpoch, const uint256& hashEpochBlock);



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
        nInitialCommitteeM = 0;
        nRecoveryCommitteeM = 0;
    }

    /** Add a vote to the tracker. Returns true if vote was accepted. */
    bool AddVote(const CFinalityVote& vote, bool fCheckStake = true, bool fRecordFinality = false);

    /** Stateless consensus validation of a transparent or private finality vote.
     *  nContextHeight is the containing block's height: when >= 0 it enforces the
     *  fork-gated vote-inclusion window (R1); -1 (relay/pre-check) skips it. */
    bool CheckVote(const CFinalityVote& vote, CTxDB& txdb, std::string* pstrError = NULL,
                   int nContextHeight = -1) const;

    /** Stateless consensus validation of an aggregate hidden tally certificate.
     *  Block validation must pass fAllowPendingVotes=false so referenced votes
     *  resolve only from connected (on-chain) votes or pvBlockVotes; pending
     *  relay state is node-local and must not affect block validity. */
    bool CheckTallyCertificate(const CFinalityTallyCertificate& cert, CTxDB& txdb, std::string* pstrError = NULL,
                               const std::vector<CFinalityVote>* pvBlockVotes = NULL,
                               bool fAllowPendingVotes = true,
                               int nContextHeight = -1,
                               bool fSkipCommitteeSigs = false) const;

    /** Stateless validation of a relayed hidden tally share.
     *  Block validation must pass fAllowPendingVotes=false so the referenced
     *  vote resolves only from connected (on-chain) votes or pvBlockVotes;
     *  pending relay state is node-local and must not affect block validity.
     *  nContextHeight anchors the epoch-range check to the validated block
     *  instead of pindexBest when >= 0. */
    bool CheckTallyShare(const CFinalityTallyShare& share,
                         std::string* pstrError = NULL,
                         const std::vector<CFinalityVote>* pvBlockVotes = NULL,
                         bool fAllowPendingVotes = true,
                         int nContextHeight = -1) const;

    /** Add a relayed tally share. */
    bool AddTallyShare(const CFinalityTallyShare& share, bool fCheck = true);

    /** Stateless validation of a relayed encrypted committee aggregate partial. */
    bool CheckTallyAggregatePartial(const CFinalityTallyAggregatePartial& partial, std::string* pstrError = NULL) const;

    /** Add a relayed encrypted committee aggregate partial. */
    bool AddTallyAggregatePartial(const CFinalityTallyAggregatePartial& partial, bool fCheck = true);

    /** Add a pending or connected tally certificate. */
    bool AddTallyCertificate(const CFinalityTallyCertificate& cert, bool fCheck = true, bool fRecordFinality = false);

    /** Return pending votes miners may include in the next PoW block. */
    std::vector<CFinalityVote> GetPendingVotesForBlock(int nBlockHeight, unsigned int nMaxVotes = FINALITY_MAX_BLOCK_VOTES) const;
    /** Return pending tally shares safe to include in a block at nBlockHeight.
     *  Only shares whose votes resolve from connected votes or pvBlockVotes
     *  (the votes being embedded in the same block) are returned, so the
     *  template always satisfies block-context CheckTallyShare. */
    std::vector<CFinalityTallyShare> GetPendingTallySharesForBlock(int nBlockHeight, unsigned int nMaxShares = 16,
                                                                   const std::vector<CFinalityVote>* pvBlockVotes = NULL) const;
    std::vector<CFinalityTallyCertificate> GetPendingTallyCertificatesForBlock(int nBlockHeight, unsigned int nMaxCerts = 4) const;
    bool HasVoteNullifier(const uint256& nullifier) const;

    /** Connect/disconnect votes included in a block. */
    bool ConnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes, int nBlockHeight = -1);
    bool DisconnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes);
    bool ConnectBlockTallyShares(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyShare>& vShares, int nBlockHeight = -1);
    bool DisconnectBlockTallyShares(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyShare>& vShares);
    bool ConnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts, int nBlockHeight = -1);
    bool DisconnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts);

    /** Load persisted connected votes from LevelDB at startup. */
    bool LoadVotes(CTxDB& txdb);
    bool LoadTallyShares(CTxDB& txdb);
    bool LoadTallyCertificates(CTxDB& txdb);
    /** Drop persisted tally shares whose votes can no longer be resolved
     *  from connected votes (e.g. relayed shares whose pending votes were
     *  lost across a restart). Run after LoadVotes/LoadTallyShares once
     *  pindexBest is set; such shares would otherwise poison every miner
     *  template into deterministic ConnectBlock rejection. */
    void PurgeUnresolvableTallyShares(CTxDB& txdb);
    /** Recompute finalization state from the chain's connected votes and
     *  certificates. Re-merges the persisted connected set from LevelDB first
     *  so epoch pruning can never shrink the replay window (finalization is
     *  consensus state for FCMP spends and private votes). */
    void RebuildFinalityState();
    void ReloadConnectedFinalityFromDB();

    /** D2 self-governing committee. The canonical committee for an epoch is the
     *  fork-pinned initial set advanced by connected M-of-N self-rotations. */
    // Pin the initial committee (fork-pinned network constant, or test setup).
    void SetInitialFinalityCommittee(const std::vector<CPubKey>& vPubKeys, int nM);
    // Pin the A1 recovery committee (separate fork-pinned set).
    void SetRecoveryFinalityCommittee(const std::vector<CPubKey>& vPubKeys, int nM);
    bool GetRecoveryCommittee(std::vector<CPubKey>& vOut, int& nMOut, uint256& setHashOut) const;
    // Resolve the canonical committee for nEpoch (initial set + applied rotations
    // with effectiveEpoch <= nEpoch). Returns false if no committee is pinned.
    bool GetCommitteeForEpoch(int nEpoch, std::vector<CPubKey>& vOut, int& nMOut, uint256& setHashOut) const;
    // Apply a connected rotation (A2: at most one per effective epoch; must chain
    // to the set active just before it; lowest-hash tie-break on conflict).
    bool ConnectCommitteeRotation(const CFinalityCommitteeRotation& rot, std::string* pstrError = NULL);
    void DisconnectCommitteeRotation(int nEffectiveEpoch);
    // 2c-4b: collect a committee member's signature over a candidate certificate;
    // when M distinct valid signatures are gathered for the same candidate, the
    // complete certificate is assembled into *pAssembledOut (pfAssembled=true).
    bool AddCertSignature(const CFinalityCertSignature& msg, CTxDB& txdb,
                          CFinalityTallyCertificate* pAssembledOut, bool* pfAssembled,
                          std::string* pstrError = NULL);
    // Block-level: connect/disconnect rotations carried in a block, with the A2
    // effective-epoch lookahead bound enforced against the connecting block's
    // epoch, reorg-safe via a per-block carrier index + LevelDB persistence.
    bool ConnectBlockCommitteeRotations(CTxDB& txdb, const uint256& hashBlock,
                                        const std::vector<CFinalityCommitteeRotation>& vRots, int nBlockHeight);
    bool DisconnectBlockCommitteeRotations(CTxDB& txdb, const uint256& hashBlock,
                                           const std::vector<CFinalityCommitteeRotation>& vRots);
    // Reload connected rotations from LevelDB at startup (into the canonical state).
    bool LoadCommitteeRotations(CTxDB& txdb);

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
    /** Connected (on-chain) votes for an epoch, EXCLUDING node-local pending relay
     *  state. The tally-certificate producer must build coverage from exactly this
     *  set: the connect-time coverage rule (R3) requires cert.vVoteNullifiers to
     *  equal the connected set, so unioning pending votes would make every cert
     *  over-cover and be rejected (a single relayed-but-unconnected vote would
     *  otherwise stall finality). */
    std::vector<CFinalityVote> GetConnectedEpochVotes(int nEpoch) const;

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
    std::vector<CFinalityTallyShare> GetEpochTallyShares(int nEpoch) const;
    std::vector<CFinalityTallyAggregatePartial> GetEpochTallyAggregatePartials(int nEpoch) const;
    int GetEpochTallyShareCount(int nEpoch) const;
    int GetEpochTallyAggregatePartialCount(int nEpoch) const;

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
    std::set<uint256> setConnectedTallyShares;
    std::map<uint256, CFinalityTallyAggregatePartial> mapTallyAggregatePartials;
    // D1.1 equivocation index: (committeeSetHash, (epoch, sourceIndex)) -> the
    // content digest that source already signed. A different digest for the same
    // key is an equivocation.
    std::map<std::pair<uint256, std::pair<int,int> >, uint256> mapTallyPartialBySource;
    std::map<uint256, std::vector<uint256>> mapBlockConnectedTallyShares;
    // D2 canonical committee state: the fork-pinned initial set + connected
    // self-rotations keyed by effective epoch (a pure function of connected
    // rotations; reorg-safe via Disconnect).
    std::vector<CPubKey> vInitialCommittee;
    int nInitialCommitteeM;
    uint256 hashInitialCommitteeSet;
    std::vector<CPubKey> vRecoveryCommittee;
    int nRecoveryCommitteeM;
    uint256 hashRecoveryCommitteeSet;
    std::map<int, CFinalityCommitteeRotation> mapConnectedRotations;
    // Reorg-safe per-block carrier: block hash -> effective epochs it connected.
    std::map<uint256, std::vector<int> > mapBlockConnectedRotations;
    // 2c-4b cert-production: candidate certs + collected member signatures keyed
    // by the candidate's GetSignatureDigest() (in-memory; relay-time only).
    std::map<uint256, CFinalityTallyCertificate> mapCandidateCerts;
    std::map<uint256, std::map<uint16_t, std::vector<unsigned char> > > mapCollectedCertSigs;
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

/** Process finality-related P2P messages (fvote, ftshare, ftpart, ftcert, fvreq) */
bool ProcessMessageFinality(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);

/** Background thread that produces finality votes at epoch boundaries */
void ThreadFinalityVoter(void* parg);

/** Create and broadcast a finality vote for the current epoch */
bool ProduceFinalityVote();

/** Run one hidden-finality tally committee automation pass. */
bool ProcessFinalityTallyCommittee();

/** Count locally decryptable hidden-finality tally shares for RPC status. */
int CountDecryptableFinalityTallyShares(int nEpoch);


#endif // INN_FINALITY_H
