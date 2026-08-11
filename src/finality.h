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
#include "finality_note.h"
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
class CBlockIndex;

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

/** Three-way result used by consensus callers.  Relay-facing APIs retain their
 * bool return, while block connection can distinguish a provably bad object
 * from unavailable/corrupt local chain state that must never poison a block. */
enum FinalityResult
{
    FINALITY_RESULT_OK = 0,
    FINALITY_RESULT_INVALID,
    FINALITY_RESULT_LOCAL_STATE
};

/** Key authorized to cast a transparent finality vote for an output. P2CS resolves
 *  to the staker key, never the owner key. */
bool ExtractFinalityStakeKeyID(const CScript& scriptPubKey,
                               CKeyID& keyIDOut);

/** Decide whether an operator-selected finality vote mode may use a private
 * note of the given kind.  Plain shielded notes generate NullStake V2 proofs;
 * M-of-N delegated notes generate NullStake V3 cold-stake proofs. */
bool FinalityVoteModeAllowsPrivateNote(const std::string& strVoteMode,
                                       bool fIsMofN);

static const int FINALITY_MAX_BLOCK_VOTES = 32;      // per-block vote inclusion cap
static const int FINALITY_MAX_TALLY_COMMITTEE = 64;  // bounded m-of-n committee descriptor
static const unsigned char FINALITY_VOTE_TAG[4] = { 0x49, 0x46, 0x56, 0x54 }; // "IFVT"
static const unsigned char FINALITY_TALLY_CERT_TAG[4] = { 0x49, 0x46, 0x54, 0x43 }; // "IFTC"
static const unsigned char FINALITY_TALLY_SHARE_TAG[4] = { 0x49, 0x46, 0x54, 0x53 }; // "IFTS"
static const unsigned char FINALITY_COMMITTEE_ROTATION_TAG[4] = { 0x49, 0x46, 0x43, 0x52 }; // "IFCR"
// Boundary-A canonical transparent-finality envelopes deliberately use new
// tags and commands.  The legacy tags and commands above remain historical
// decoders and are never reinterpreted as the canonical schema.
static const unsigned char FINALITY_CANONICAL_VOTE_TAG[4] = { 0x49, 0x46, 0x43, 0x56 }; // "IFCV"
static const unsigned char FINALITY_CANONICAL_TALLY_CERT_TAG[4] = { 0x49, 0x46, 0x43, 0x43 }; // "IFCC"
// F2 note-vote carrier: one coinbase OP_RETURN output over a single push, bounded by
// MAX_SCRIPT_SIZE. Never the coinbase IV5 payload, whose value rule stays closed.
static const unsigned char FINALITY_NOTE_VOTE_TAG[4] = { 0x49, 0x46, 0x4e, 0x56 }; // "IFNV"
static const char FINALITY_CANONICAL_VOTE_COMMAND[] = "fvotea";
static const char FINALITY_CANONICAL_TALLY_CERT_COMMAND[] = "ftcerta";
static const char FINALITY_NOTE_VOTE_COMMAND[] = "fnvote";
// The note tally's aggregate partial. A separate command from "ftpart" because it carries
// a different object: mod-ell evaluations, not the legacy secp256k1 ones.
static const char FINALITY_NOTE_TALLY_PARTIAL_COMMAND[] = "fnpart";
static const uint32_t FINALITY_CANONICAL_VOTE_VERSION = 1;
static const uint32_t FINALITY_CANONICAL_TALLY_CERT_VERSION = 1;
// F2 note-tally schema. Schema 1 stays byte-identical; only a certificate that
// actually carries a note tally uses schema 2.
static const uint32_t FINALITY_CANONICAL_TALLY_CERT_VERSION_NOTE = 2;
// Per-block cap on note-vote carriers, mirroring FINALITY_MAX_BLOCK_VOTES for the
// transparent path. At the envelope's working size the full set sits inside the
// penalty-free generation target with room for ordinary traffic alongside.
static const int FINALITY_MAX_BLOCK_NOTE_VOTES = 32;
// LevelDB-only envelope generation, independent of network envelope versions: records
// the decoded carrier so a restart cannot change the object's hash/signature domain.
static const int FINALITY_DISK_ENVELOPE_GENERATION = 1;
// Keeps the fixed canonical certificate below MAX_SCRIPT_SIZE.
static const unsigned int FINALITY_CANONICAL_CERT_MAX_NULLIFIERS = 128;

enum FinalityEnvelopeDecodeResult
{
    FINALITY_ENVELOPE_NO_MATCH = 0,
    FINALITY_ENVELOPE_VALID,
    FINALITY_ENVELOPE_INVALID,
    FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY,
    FINALITY_ENVELOPE_CANONICAL_BEFORE_BOUNDARY
};

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
// Local committee tally private key (-finalitytallyprivkey). Used by the
// committee-rotation RPCs to sign a rotation as a current-committee member.
bool GetFinalityTallyPrivateKey(CKey& keyOut);

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

// Per-epoch finality-reward settlement.
//
// A vote is COUNTED once per epoch (keyed by nullifier) but may legitimately be
// carried by more than one canonical block inside the inclusion window
// [H_E, H_E + FINALITY_VOTE_INCLUSION_WINDOW). Paying the carrying block made the
// payout a function of how many canonical blocks re-embedded the vote, so a producer
// of several window blocks collected up to K payouts for one counted vote, with no
// per-epoch reconciliation.
//
// Payment is instead settled ONCE per epoch, in the canonical block at
// H_E + FINALITY_VOTE_INCLUSION_WINDOW: a single height (so a single canonical block),
// inside epoch E (K << the epoch interval), and exactly where the epoch's vote set is
// frozen -- the inclusion window has just closed, which is also the height at which a
// tally certificate for E becomes block-valid (R2). Producer and validators derive the
// payout from that same frozen, chain-derived set, never from node-local tracker state,
// so the coinbase money allowance cannot drift between them.
static const int FINALITY_SETTLEMENT_OFFSET = FINALITY_VOTE_INCLUSION_WINDOW;

/** Settlement height of epoch nEpoch (nHeightHint only selects the pre/post-DAG regime). */
inline int GetFinalitySettlementHeight(int nEpoch, int nHeightHint)
{
    return GetEpochBoundaryHeight(nEpoch, nHeightHint) + FINALITY_SETTLEMENT_OFFSET;
}

/** Base for the collateralnode share of a coinbase: the coinbase value minus the
 *  pass-through finality reward (nonzero only on the settlement block). */
inline int64_t FinalityCollateralnodePaymentBase(int64_t nCoinbaseValueOut, int64_t nFinalityRewardOut)
{
    int64_t nBase = nCoinbaseValueOut - nFinalityRewardOut;
    return (nBase < 0) ? 0 : nBase;
}

/** True iff nHeight is the settlement height of the epoch containing it. Settlement
 *  exists only post-DAG, where finality votes exist at all. */
inline bool IsFinalitySettlementHeight(int nHeight, int* pnEpochOut = NULL)
{
    if (nHeight < GetForkHeightDAG())
        return false;
    int nEpoch = GetEpochForHeight(nHeight);
    if (GetFinalitySettlementHeight(nEpoch, nHeight) != nHeight)
        return false;
    if (pnEpochOut)
        *pnEpochOut = nEpoch;
    return true;
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
        CPrivateFinalityVoteProof* pthis =
            const_cast<CPrivateFinalityVoteProof*>(this);
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
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchRewardOutputCommitment,
                                                 128, nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchBindingProof,
                                                 BPAC_V3_MAX_PROOF_SIZE,
                                                 nType, nVersion, ser_action);
        unsigned char fHasNfBind = (vchNullifierPoint.empty() && vchNullifierBindingProof.empty()) ? 0 : 1;
        READWRITE(fHasNfBind);
        if (fHasNfBind)
        {
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchNullifierPoint,
                                                     65, nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(s,
                                                     pthis->vchNullifierBindingProof,
                                                     NULLIFIER_BINDING_PROOF_SIZE,
                                                     nType, nVersion, ser_action);
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
    // Runtime provenance only; deliberately omitted from the legacy serializer.
    // Canonical envelope decode restores it, while historical/DB legacy decode
    // remains false so legacy hashes and signature domains never change.
    bool fCanonicalEnvelope;

    CFinalityVote()
    {
        nProofMode = FINALITY_PROOF_TRANSPARENT;
        nEpoch = 0;
        nHeight = 0;
        nTime = 0;
        nVoteWeight = 0;
        nReward = 0;
        fCanonicalEnvelope = false;
    }

    IMPLEMENT_SERIALIZE
    (
        CFinalityVote* pthis = const_cast<CFinalityVote*>(this);
        if (fRead)
            pthis->fCanonicalEnvelope = false;
        READWRITE(nProofMode);
        READWRITE(nEpoch);
        READWRITE(hashBlock);
        READWRITE(nHeight);
        READWRITE(VARINT(nTime));
        READWRITE(VARINT(nVoteWeight));
        READWRITE(VARINT(nReward));
        READWRITE(nullifier);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vStakeProof,
                                                 FINALITY_MAX_STAKE_PROOFS,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchPubKey, 65,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSig, 80,
                                                 nType, nVersion, ser_action);
        READWRITE(privateProof);
    )

    bool IsPrivate() const { return nProofMode == FINALITY_PROOF_NULLSTAKE_V2 || nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD; }
    bool IsCanonicalEnvelope() const { return fCanonicalEnvelope; }
    void MarkCanonicalEnvelope() { fCanonicalEnvelope = true; }
    uint256 GetHash() const;
    uint256 GetSignatureHash() const;
    bool Sign(CKey& key);
    bool CheckSignature() const;
    bool IsValid() const;
    bool IsExpired(int64_t nNow) const;
};

/** Boundary-A canonical transparent vote schema.  This is a new logical
 * envelope, not a repaired serialization of CFinalityVote.  In particular it
 * cannot encode CPrivateFinalityVoteProof. */
class CCanonicalFinalityVoteEnvelope
{
public:
    uint32_t nLogicalVersion;
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int64_t nTime;
    int64_t nVoteWeight;
    int64_t nReward;
    uint256 nullifier;
    std::vector<COutPoint> vStakeProof;
    std::vector<unsigned char> vchPubKey;
    std::vector<unsigned char> vchSig;

    CCanonicalFinalityVoteEnvelope()
        : nLogicalVersion(FINALITY_CANONICAL_VOTE_VERSION),
          nEpoch(0), nHeight(0), nTime(0), nVoteWeight(0), nReward(0)
    {
    }

    IMPLEMENT_SERIALIZE
    (
        CCanonicalFinalityVoteEnvelope* pthis =
            const_cast<CCanonicalFinalityVoteEnvelope*>(this);
        READWRITE(pthis->nLogicalVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->hashBlock);
        READWRITE(pthis->nHeight);
        READWRITE(pthis->nTime);
        READWRITE(pthis->nVoteWeight);
        READWRITE(pthis->nReward);
        READWRITE(pthis->nullifier);
        nSerSize += ::SerReadWriteLimitedVector(
            s, pthis->vStakeProof, FINALITY_MAX_STAKE_PROOFS,
            nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(
            s, pthis->vchPubKey, 65, nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(
            s, pthis->vchSig, 80, nType, nVersion, ser_action);
    )

    bool FromLogical(const CFinalityVote& vote);
    bool ToLogical(CFinalityVote& voteOut) const;
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
            nSerSize += ::SerReadWriteLimitedByteVectors(
                s, pthis->vEncryptedRecipientShares,
                FINALITY_MAX_TALLY_COMMITTEE, BPAC_V3_MAX_PROOF_SIZE,
                nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchShareProof,
                                                 BPAC_V3_MAX_PROOF_SIZE,
                                                 nType, nVersion, ser_action);
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
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vTallyShareHashes,
                                                 FINALITY_MAX_VOTES,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vEncryptedRecipientPartials,
            FINALITY_MAX_TALLY_COMMITTEE, BPAC_V3_MAX_PROOF_SIZE,
            nType, nVersion, ser_action);
        if (pthis->nVersion >= 3)
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSourceSig, 80,
                                                     nType, nVersion, ser_action);
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
    // nVersion >= 4 (F2): the note-vote side. The tags name which connected note votes the
    // certificate counts; the complaints are the only thing that lets it leave one out.
    // Neither aggregate point appears here: both are recomputed from the covered votes'
    // own commitments, so a certificate can never name a sum it did not earn.
    std::vector<uint256> vNoteVoteTags;
    std::vector<CNoteVoteComplaint> vNoteComplaints;
    CNoteTallyTierProofs noteTierProofs;
    // Runtime provenance only; never added to the legacy certificate bytes.
    bool fCanonicalEnvelope;

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
        fCanonicalEnvelope = false;
    }

    IMPLEMENT_SERIALIZE
    (
        CFinalityTallyCertificate* pthis = const_cast<CFinalityTallyCertificate*>(this);
        if (fRead)
            pthis->fCanonicalEnvelope = false;
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
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vVoteNullifiers,
                                                 FINALITY_MAX_VOTES,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vTallyShareHashes,
                                                 FINALITY_MAX_VOTES,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s,
                                                 pthis->vchAggregateThresholdProof,
                                                 BPAC_V3_MAX_PROOF_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchRewardBudgetProof,
                                                 BPAC_V3_MAX_PROOF_SIZE,
                                                 nType, nVersion, ser_action);
        if (pthis->nVersion >= 3)
        {
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vSignerIndexes,
                                                     FINALITY_MAX_TALLY_COMMITTEE,
                                                     nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedByteVectors(
                s, pthis->vSignerSigs, FINALITY_MAX_TALLY_COMMITTEE, 80,
                nType, nVersion, ser_action);
        }
        if (pthis->nVersion >= FINALITY_NOTE_CERT_VERSION)
        {
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vNoteVoteTags,
                                                     FINALITY_MAX_VOTES,
                                                     nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vNoteComplaints,
                                                     FINALITY_MAX_VOTES,
                                                     nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->noteTierProofs.vchTierSlack,
                FINALITY_NOTE_MAX_RANGE_PROOF_BYTES, nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->noteTierProofs.vchWinningCap,
                FINALITY_NOTE_MAX_RANGE_PROOF_BYTES, nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->noteTierProofs.vchActiveCap,
                FINALITY_NOTE_MAX_RANGE_PROOF_BYTES, nType, nVersion, ser_action);
        }
    )

    uint256 GetHash() const;            // full identity (includes signer-set for v3)
    uint256 GetSignatureDigest() const; // signed content, excludes vSignerIndexes/vSignerSigs
    bool IsCanonicalEnvelope() const { return fCanonicalEnvelope; }
    void MarkCanonicalEnvelope() { fCanonicalEnvelope = true; }
    bool HasPrivateWeight() const;
    /** F2: the certificate carries a note-vote tally. Deliberately NOT folded into
     *  HasPrivateWeight(): that predicate drives the retired-secp disable gates and
     *  the Boundary-A miner skip, which must keep rejecting the legacy path while
     *  admitting v4. */
    bool HasNoteWeight() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
};

/** Boundary-A canonical transparent certificate schema.  Private commitments,
 * tally-share hashes, and private proof blobs are intentionally absent.
 *
 * Logical schema 2 (F2) additionally transports the note-vote tally: the covered
 * tags, the complaints that justify every omission, the tier range proofs, and the
 * committee signer-set that authorizes them. Schema 1 keeps its exact bytes, so
 * pre-F2 certificates round-trip unchanged. */
class CCanonicalFinalityTallyCertificateEnvelope
{
public:
    uint32_t nLogicalVersion;
    int nCertificateVersion;
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int nTier;
    int nConsecutiveHardCount;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;
    int64_t nTransparentActiveWeight;
    int64_t nTransparentWinningWeight;
    int64_t nTransparentRewardBudget;
    std::vector<uint256> vVoteNullifiers;
    // nLogicalVersion >= 2 only.
    std::vector<uint16_t> vSignerIndexes;
    std::vector<std::vector<unsigned char> > vSignerSigs;
    std::vector<uint256> vNoteVoteTags;
    std::vector<CNoteVoteComplaint> vNoteComplaints;
    CNoteTallyTierProofs noteTierProofs;

    CCanonicalFinalityTallyCertificateEnvelope()
        : nLogicalVersion(FINALITY_CANONICAL_TALLY_CERT_VERSION),
          nCertificateVersion(2), nEpoch(0), nHeight(0),
          nTier(FINALITY_NONE), nConsecutiveHardCount(0),
          nTransparentActiveWeight(0), nTransparentWinningWeight(0),
          nTransparentRewardBudget(0)
    {
    }

    IMPLEMENT_SERIALIZE
    (
        CCanonicalFinalityTallyCertificateEnvelope* pthis =
            const_cast<CCanonicalFinalityTallyCertificateEnvelope*>(this);
        READWRITE(pthis->nLogicalVersion);
        READWRITE(pthis->nCertificateVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->hashBlock);
        READWRITE(pthis->nHeight);
        READWRITE(pthis->nTier);
        READWRITE(pthis->nConsecutiveHardCount);
        READWRITE(pthis->hashCurveRoot);
        READWRITE(pthis->hashNullifierRoot);
        READWRITE(pthis->committeeSetHash);
        READWRITE(pthis->nTransparentActiveWeight);
        READWRITE(pthis->nTransparentWinningWeight);
        READWRITE(pthis->nTransparentRewardBudget);
        nSerSize += ::SerReadWriteLimitedVector(
            s, pthis->vVoteNullifiers,
            FINALITY_CANONICAL_CERT_MAX_NULLIFIERS,
            nType, nVersion, ser_action);
        // The schema field is the envelope's own consensus data, so the gate must
        // test the member and not the stream version the macro injects.
        if (pthis->nLogicalVersion >= FINALITY_CANONICAL_TALLY_CERT_VERSION_NOTE)
        {
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vSignerIndexes, FINALITY_MAX_TALLY_COMMITTEE,
                nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedByteVectors(
                s, pthis->vSignerSigs, FINALITY_MAX_TALLY_COMMITTEE, 80,
                nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vNoteVoteTags, FINALITY_MAX_VOTES,
                nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vNoteComplaints, FINALITY_MAX_VOTES,
                nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->noteTierProofs.vchTierSlack,
                FINALITY_NOTE_MAX_RANGE_PROOF_BYTES, nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->noteTierProofs.vchWinningCap,
                FINALITY_NOTE_MAX_RANGE_PROOF_BYTES, nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->noteTierProofs.vchActiveCap,
                FINALITY_NOTE_MAX_RANGE_PROOF_BYTES, nType, nVersion, ser_action);
        }
    )

    bool FromLogical(const CFinalityTallyCertificate& cert);
    bool ToLogical(CFinalityTallyCertificate& certOut) const;
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
        CFinalityCommitteeRotation* pthis =
            const_cast<CFinalityCommitteeRotation*>(this);
        READWRITE(nVersion);
        READWRITE(nEffectiveEpoch);
        READWRITE(hashPrevCommitteeSet);
        READWRITE(nNewThresholdM);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vNewPubKeys, FINALITY_MAX_TALLY_COMMITTEE, 33,
            nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vSignerIndexes,
                                                 FINALITY_MAX_TALLY_COMMITTEE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vSignerSigs, FINALITY_MAX_TALLY_COMMITTEE, 80,
            nType, nVersion, ser_action);
    )

    uint256 GetHash() const;            // full identity (includes signatures)
    uint256 GetSignatureDigest() const; // what the prev committee signs (excludes sigs)
    bool IsValidBasic(std::string* pstrError = NULL) const;  // structural: new-set well-formed
    // Resolve the new set into pubkeys (returns false on any malformed key).
    bool GetNewCommittee(std::vector<CPubKey>& vOut, int& nMOut, uint256& setHashOut) const;
};

/** A connected canonical-pprev block carrying one committee-rotation
 *  candidate. Production connects these carriers at distinct, strictly
 *  increasing heights; the explicit position also lets restart/disconnect
 *  reject persistence that violates that invariant. */
struct CFinalityCommitteeRotationCarrier
{
    int nBlockHeight;
    uint256 hashBlock;
    CFinalityCommitteeRotation rotation;

    CFinalityCommitteeRotationCarrier()
        : nBlockHeight(-1)
    {
    }

    CFinalityCommitteeRotationCarrier(int nHeightIn, const uint256& hashBlockIn,
                                      const CFinalityCommitteeRotation& rotationIn)
        : nBlockHeight(nHeightIn), hashBlock(hashBlockIn), rotation(rotationIn)
    {
    }
};

/** Select the canonical candidate for one effective epoch.  Candidates carried
 *  before nV3ActivationHeight preserve the historical lowest-content-digest
 *  rule.  If none predate V3, the earliest canonical-pprev carrier wins and
 *  later, necessarily higher, valid carriers are no-ops.  The hash tie-break is
 *  fail-closed determinism for malformed/non-production carrier sets. */
bool SelectCanonicalFinalityCommitteeRotation(
    const std::vector<CFinalityCommitteeRotationCarrier>& vCarriers,
    int nV3ActivationHeight,
    CFinalityCommitteeRotation& rotationOut,
    uint256* phashCarrierOut = NULL);

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
// Gossip a fully-signed pending rotation (ftrot) so non-proposing miners can embed it.
void RelayFinalityCommitteeRotation(const CFinalityCommitteeRotation& rot);
/** Relay a validated tally certificate using the command/envelope selected for
 *  the next candidate height. */
void RelayFinalityTallyCertificate(const CFinalityTallyCertificate& cert);

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
        CFinalityCertSignature* pthis = const_cast<CFinalityCertSignature*>(this);
        READWRITE(nVersion);
        READWRITE(candidate);
        READWRITE(nSignerIndex);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSig, 80,
                                                 nType, nVersion, ser_action);
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

/** Boundary-A canonical envelope APIs.  The legacy APIs above remain unchanged
 * for historical decoding.  Height-aware extraction explicitly reports a
 * legacy tag after Boundary A so ConnectBlock can fail closed when integrated. */
bool BuildCanonicalFinalityVoteScript(const CFinalityVote& vote, CScript& scriptOut);
bool ExtractCanonicalFinalityVote(const CScript& scriptPubKey, CFinalityVote& voteOut);
bool BuildCanonicalFinalityTallyCertificateScript(const CFinalityTallyCertificate& cert,
                                                    CScript& scriptOut);
bool ExtractCanonicalFinalityTallyCertificate(const CScript& scriptPubKey,
                                               CFinalityTallyCertificate& certOut);
/** Deterministically aggregate a complete connected transparent vote set into
 *  the Boundary-A canonical certificate domain.  This is deliberately pure:
 *  callers supply the frozen epoch vote set, and relay/miner state is updated
 *  only after the complete certificate has been constructed and validated. */
bool BuildCanonicalTransparentFinalityCertificate(
    const std::vector<CFinalityVote>& vVotes,
    CFinalityTallyCertificate& certOut,
    std::string* pstrError = NULL);
bool BuildFinalityVoteScriptForHeight(const CFinalityVote& vote, int nHeight,
                                      CScript& scriptOut);
bool BuildFinalityTallyCertificateScriptForHeight(const CFinalityTallyCertificate& cert,
                                                   int nHeight, CScript& scriptOut);
FinalityEnvelopeDecodeResult ExtractFinalityVoteForHeight(const CScript& scriptPubKey,
                                                          int nHeight,
                                                          CFinalityVote& voteOut);
FinalityEnvelopeDecodeResult ExtractFinalityTallyCertificateForHeight(
    const CScript& scriptPubKey, int nHeight, CFinalityTallyCertificate& certOut);
bool ExtractFinalityVotesFromBlockForHeight(const CBlock& block, int nHeight,
                                            std::vector<CFinalityVote>& vVotesOut,
                                            FinalityEnvelopeDecodeResult* pFailure = NULL);
bool ExtractFinalityTallyCertificatesFromBlockForHeight(
    const CBlock& block, int nHeight,
    std::vector<CFinalityTallyCertificate>& vCertsOut,
    FinalityEnvelopeDecodeResult* pFailure = NULL);
/** Note-vote carrier: one vote, one coinbase output, one push. Unknown data below the
 *  F2 height; at and above it a tagged script must decode or the block is invalid. */
bool BuildNoteFinalityVoteScript(const CNoteFinalityVote& vote, CScript& scriptOut);
bool ExtractNoteFinalityVote(const CScript& scriptPubKey, CNoteFinalityVote& voteOut);
FinalityEnvelopeDecodeResult ExtractNoteFinalityVoteForHeight(
    const CScript& scriptPubKey, int nHeight, CNoteFinalityVote& voteOut);
bool ExtractNoteFinalityVotesFromBlockForHeight(
    const CBlock& block, int nHeight, std::vector<CNoteFinalityVote>& vVotesOut,
    FinalityEnvelopeDecodeResult* pFailure = NULL);

/** How one note-vote tag resolves across every connected carrier that names it. */
enum NoteVoteCountingState
{
    NOTE_VOTE_UNSEEN = 0,
    NOTE_VOTE_COUNTED,      // one semantic identity, carried by one or more blocks
    NOTE_VOTE_EQUIVOCATED   // two identities under one tag: counts for neither
};

/** Tally identity of a note vote. A tag carried with two identities counts for
 *  neither (vote-level drop, carrier blocks stay valid); identical statements in
 *  different encodings are one vote. */
uint256 GetNoteVoteSemanticIdentity(const CNoteFinalityVote& vote);
void ResolveNoteVoteCounting(
    const std::vector<const CNoteFinalityVote*>& vCarried,
    std::map<uint256, const CNoteFinalityVote*>& mapCountedOut,
    std::set<uint256>& setEquivocatedOut);

const char* GetFinalityVoteCommandForHeight(int nHeight);
const char* GetFinalityTallyCertificateCommandForHeight(int nHeight);
/** P2P relay objects target tip+1.  Exposed as a pure helper so the A-1
 *  command transition is unit-testable without mutating global chain state. */
bool UseCanonicalFinalityTrafficForTip(int nTipHeight);
/** True when the next candidate after nTipHeight is at/after the first legal
 *  certificate height for nEpoch. */
bool IsFinalityVoteWindowClosedForTip(int nEpoch, int nTipHeight);

/** Frozen vote set that epoch nEpoch settles: walks pindexPrev's ancestors over
 *  [H_E, H_E + K) and returns epoch-E votes deduped by nullifier in canonical order.
 *  Pure function of the ancestor chain; both tiers are returned. */
bool GatherFinalitySettlementVotes(const CBlockIndex* pindexPrev, int nEpoch,
                                   std::vector<CFinalityVote>& vVotesOut,
                                   std::string* pstrError = NULL);

/** Dedupe half of the enumerator. vWindowBlockVotes is in ascending window-block order;
 *  the first occurrence of each nullifier is kept, so a re-carried vote is paid once. */
void CollectFinalitySettlementVotes(const std::vector<std::vector<CFinalityVote> >& vWindowBlockVotes,
                                    int nEpoch,
                                    std::vector<CFinalityVote>& vVotesOut);

/** Transparent settlement leg: exactly one P2PKH output per counted transparent voter,
 *  paying that vote's consensus-bound nReward, in canonical (nullifier-sorted) order.
 *  nTotalOut is the sum, which is the settlement block's extra coinbase allowance. */
bool BuildFinalitySettlementOutputs(const std::vector<CFinalityVote>& vCountedVotes,
                                    std::vector<CTxOut>& vOutputsOut,
                                    int64_t& nTotalOut,
                                    std::string* pstrError = NULL);

/** Consensus check for a settlement block: its coinbase must carry the full settlement
 *  leg for vCountedVotes. Returns the settled total in nTotalOut (0 on failure). */
bool CheckFinalitySettlementOutputs(const CBlock& block,
                                    const std::vector<CFinalityVote>& vCountedVotes,
                                    int64_t& nTotalOut,
                                    std::string* pstrError = NULL);

/** Structural check for the vote commitments a non-settlement block carries. Carrying a
 *  vote pays nothing, so this validates shape only (per-block cap, no duplicate
 *  nullifier in one block, valid payee key, reward in range). */
bool CheckFinalityVoteCommitments(const CBlock& block,
                                  const std::vector<CFinalityVote>& vVotes,
                                  std::string* pstrError = NULL);

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
        nFinalitySummaryDirtyFromEpoch = -1;
        nInitialCommitteeM = 0;
        nRecoveryCommitteeM = 0;
    }

    /** Add a vote to the tracker. Returns true if vote was accepted. */
    bool AddVote(const CFinalityVote& vote, bool fCheckStake = true, bool fRecordFinality = false);

    /** Stateless consensus validation of a transparent or private finality vote.
     *  nContextHeight is the containing block's height: when >= 0 it enforces the
     *  fork-gated vote-inclusion window (R1); -1 (relay/pre-check) skips it. */
    bool CheckVote(const CFinalityVote& vote, CTxDB& txdb, std::string* pstrError = NULL,
                   int nContextHeight = -1,
                   FinalityResult* pResult = NULL) const;

    /** Stateless consensus validation of an aggregate hidden tally certificate.
     *  Block validation must pass fAllowPendingVotes=false so referenced votes
     *  resolve only from connected (on-chain) votes or pvBlockVotes; pending
     *  relay state is node-local and must not affect block validity. */
    bool CheckTallyCertificate(const CFinalityTallyCertificate& cert, CTxDB& txdb, std::string* pstrError = NULL,
                               const std::vector<CFinalityVote>* pvBlockVotes = NULL,
                               bool fAllowPendingVotes = true,
                               int nContextHeight = -1,
                               bool fSkipCommitteeSigs = false,
                               FinalityResult* pResult = NULL) const;

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

    /** Validate a relayed note-tally partial against this node's view.
     *
     *  Relay admission only. Every covered tag must be a counted note vote for the epoch
     *  and every complaint must verify against the vote it names, which bounds what one
     *  source can flood; nothing here reaches a consensus decision, so a node with a
     *  behind-the-tip view refuses a partial rather than disagreeing about a block. */
    bool CheckNoteTallyAggregatePartial(const CNoteTallyAggregatePartial& partial,
                                        std::string* pstrError = NULL) const;
    bool AddNoteTallyAggregatePartial(const CNoteTallyAggregatePartial& partial,
                                      bool fCheck = true);
    std::vector<CNoteTallyAggregatePartial> GetEpochNoteTallyPartials(int nEpoch) const;
    int GetEpochNoteTallyPartialCount(int nEpoch) const;

    /** Add a pending or connected tally certificate. */
    bool AddTallyCertificate(const CFinalityTallyCertificate& cert, bool fCheck = true, bool fRecordFinality = false);

    /** Return pending votes miners may include in the next PoW block. */
    std::vector<CFinalityVote> GetPendingVotesForBlock(int nBlockHeight, unsigned int nMaxVotes = FINALITY_MAX_BLOCK_VOTES) const;
    /** Enforce the Boundary-A epoch-wide vote bound required by the canonical
     *  certificate's exact nullifier list. */
    bool CheckCanonicalVoteSetCapacity(
        const std::vector<CFinalityVote>& vBlockVotes, int nBlockHeight,
        std::string* pstrError = NULL) const;
    /** Return pending tally shares safe to include in a block at nBlockHeight.
     *  Only shares whose votes resolve from connected votes or pvBlockVotes
     *  (the votes being embedded in the same block) are returned, so the
     *  template always satisfies block-context CheckTallyShare. */
    std::vector<CFinalityTallyShare> GetPendingTallySharesForBlock(int nBlockHeight, unsigned int nMaxShares = 16,
                                                                   const std::vector<CFinalityVote>* pvBlockVotes = NULL) const;
    std::vector<CFinalityTallyCertificate> GetPendingTallyCertificatesForBlock(int nBlockHeight, unsigned int nMaxCerts = 4) const;
    bool HasVoteNullifier(const uint256& nullifier) const;

    /** Connect/disconnect votes included in a block. */
    bool ConnectBlockVotes(CTxDB& txdb, const uint256& hashBlock,
                           const std::vector<CFinalityVote>& vVotes,
                           int nBlockHeight = -1,
                           FinalityResult* pResult = NULL);
    bool DisconnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes);

    /** Stateless + chain-context validation of one note vote carried at nContextHeight.
     *  nContextHeight < 0 is a relay pre-check and skips the inclusion window. */
    bool CheckNoteVoteForContext(const CNoteFinalityVote& vote, CTxDB& txdb,
                                 std::string* pstrError = NULL,
                                 int nContextHeight = -1,
                                 FinalityResult* pResult = NULL) const;

    /** Connect/disconnect a block's note votes. Validation invalidates the block;
     *  recording never does. fCheckVotes=false skips validation (tests only). The carrier
     *  index records every carried instance so reorg teardown stays symmetric. */
    bool ConnectBlockNoteVotes(CTxDB& txdb, const uint256& hashBlock,
                               const std::vector<CNoteFinalityVote>& vVotes,
                               int nBlockHeight = -1,
                               FinalityResult* pResult = NULL,
                               bool fCheckVotes = true);
    bool DisconnectBlockNoteVotes(CTxDB& txdb, const uint256& hashBlock,
                                  const std::vector<CNoteFinalityVote>& vVotes);
    /** Load persisted connected note votes and their carrier index at startup. */
    bool LoadNoteVotes(CTxDB& txdb);
    /** Relay-side pending note votes (verify-once, gossiped). */
    bool AddPendingNoteVote(const CNoteFinalityVote& vote, CTxDB& txdb,
                            std::string* pstrError = NULL);
    bool HaveNoteVote(const uint256& hashVote) const;
    std::vector<CNoteFinalityVote> GetPendingNoteVotesForBlock(
        int nBlockHeight,
        unsigned int nMaxVotes = FINALITY_MAX_BLOCK_NOTE_VOTES) const;
    /** Note votes an epoch's tally may count: the tags that resolved to exactly one
     *  identity. Equivocated tags are deliberately absent, so certificate coverage and
     *  connect-time agree on one set. */
    std::vector<CNoteFinalityVote> GetCountedEpochNoteVotes(int nEpoch) const;
    int GetEpochNoteVoteCount(int nEpoch) const;
    int GetEpochEquivocatedNoteVoteCount(int nEpoch) const;
    NoteVoteCountingState GetNoteVoteCountingState(int nEpoch, const uint256& tag) const;
    bool ConnectBlockTallyShares(CTxDB& txdb, const uint256& hashBlock,
                                 const std::vector<CFinalityTallyShare>& vShares,
                                 int nBlockHeight = -1,
                                 FinalityResult* pResult = NULL);
    bool DisconnectBlockTallyShares(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyShare>& vShares);
    bool ConnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock,
                                       const std::vector<CFinalityTallyCertificate>& vCerts,
                                       int nBlockHeight = -1,
                                       FinalityResult* pResult = NULL);
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
    bool PurgeUnresolvableTallyShares(CTxDB& txdb);
    /** Recompute finalization state from the chain's connected votes and
     *  certificates. Re-merges the persisted connected set from LevelDB first
     *  so epoch pruning can never shrink the replay window (finalization is
     *  consensus state for FCMP spends and private votes). */
    bool RebuildFinalityState();
    bool ReloadConnectedFinalityFromDB();
    /** Rebuild connected finality maps from committed LevelDB state after a best-chain
     *  transaction aborts. Memory-only relay objects are discarded. */
    bool RestoreCommittedStateAfterAbort();

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
                                        const std::vector<CFinalityCommitteeRotation>& vRots,
                                        int nBlockHeight,
                                        FinalityResult* pResult = NULL);
    bool DisconnectBlockCommitteeRotations(CTxDB& txdb, const uint256& hashBlock,
                                           const std::vector<CFinalityCommitteeRotation>& vRots);
    // Reload connected rotations from LevelDB at startup (into the canonical state).
    bool LoadCommitteeRotations(CTxDB& txdb);
    // D2 production rotation: hold a fully-signed (>= M) rotation that has been
    // proposed but not yet mined, so the miner can embed it. Validated against the
    // committee active immediately before its effective epoch, exactly as
    // ConnectCommitteeRotation will re-check it at connect time.
    bool AddPendingCommitteeRotation(const CFinalityCommitteeRotation& rot, std::string* pstrError = NULL);
    // Pending rotations a block at nBlockHeight may embed: still in the future
    // (effective epoch > the block's epoch), within the A2 lookahead, and not yet
    // connected. Drops any that no longer validate against the current canonical set.
    std::vector<CFinalityCommitteeRotation> GetPendingCommitteeRotationsForBlock(int nBlockHeight, unsigned int nMax = 2) const;
    bool HasPendingCommitteeRotation() const;
    // Connected (applied) committee rotations, keyed by effective epoch — for RPC
    // observability (getfinalityinfo) and rotation e2e verification.
    std::map<int, CFinalityCommitteeRotation> GetConnectedRotations() const;

    /** Check if a block at the given height is finalized */
    bool IsFinalized(int nHeight) const;

    /** Check if an epoch has reached the finality threshold */
    bool CheckFinalityThreshold(int nEpoch, bool fLog = true);

    /** Deterministic per-epoch finality tier from the epoch's own blocks: its own-block
     *  best cert (from CEpochState::vBlockHashes, not the global cert map) and its
     *  in-window votes. Independent of the live streak and connect order. */
    bool ComputeDeterministicEpochTier(int nEpoch, bool fHaveEpochCert,
                                        const CFinalityTallyCertificate& epochBestCert,
                                        int& nTierOut, uint256& hashWinnerOut,
                                        int& nWinnerHeightOut, int& nVoterCountOut) const;

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

    /** Prune old relay/automation objects. Connected carrier-backed state is
     *  retained because this locally scheduled call must not change consensus
     *  validation or reorg behavior. */
    void PruneOldEpochs(int nCurrentEpoch);

private:
    struct CFinalitySummarySnapshot
    {
        int nFinalizedHeight;
        uint256 hashFinalized;
        FinalityTier nTier;
        int nConsecutiveHardEpochs;
        int nLastHardEpoch;
        int nPendingFinalizedHeight;
        uint256 hashPendingFinalized;
    };

    int nLastFinalizedHeight;
    uint256 hashLastFinalized;
    FinalityTier nLastFinalityTier;
    int nConsecutiveHardEpochs;      // consecutive HARD epochs (for confirmation delay)
    int nLastHardEpoch;              // last epoch counted in the HARD streak
    int nPendingFinalizedHeight;     // height waiting for confirmation
    uint256 hashPendingFinalized;    // hash waiting for confirmation
    // Prefix cache: recomputation replays only the changed epoch suffix.
    std::map<int, CFinalitySummarySnapshot> mapFinalitySummaryAfterEpoch;
    int nFinalitySummaryDirtyFromEpoch;

    std::map<int, std::vector<CFinalityVote>> mapEpochVotes;
    std::map<int, int64_t> mapEpochVoteWeight;
    std::map<uint256, uint256> mapVoteHashByNullifier;
    std::map<uint256, CFinalityVote> mapPendingVotes;
    std::map<uint256, CFinalityVote> mapConnectedVotes;
    std::map<uint256, std::vector<uint256>> mapBlockConnectedVoteNullifiers;
    // F2 note votes. The carrier index is the single maintained record; the per-epoch
    // counted/equivocated view below is recomputed from it in full and never patched, so
    // connect, disconnect, restart and fresh sync cannot drift apart.
    std::map<uint256, CNoteFinalityVote> mapNoteVotesByHash;
    std::map<uint256, std::vector<uint256>> mapBlockConnectedNoteVotes;
    std::map<int, std::map<uint256, uint256>> mapEpochCountedNoteVotes;   // epoch -> tag -> vote hash
    std::map<int, std::set<uint256>> mapEpochEquivocatedNoteVotes;
    std::map<uint256, CNoteFinalityVote> mapPendingNoteVotes;
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
    // F2 note-tally partials, relay/automation state only. The equivocation index keys on
    // GetSourceSlot(), which folds the covered set into the slot: convergence requires a
    // member to republish over a shrunken set, so only two contents for ONE covered set
    // are an equivocation.
    std::map<uint256, CNoteTallyAggregatePartial> mapNoteTallyPartials;
    std::map<uint256, uint256> mapNoteTallyPartialBySlot;
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
    // D2 production: fully-signed rotations proposed but not yet mined, keyed by
    // effective epoch (in-memory; relay/RPC-time only, like pending certs).
    std::map<int, CFinalityCommitteeRotation> mapPendingRotations;
    // 2c-4b cert-production: candidate certs + collected member signatures keyed
    // by the candidate's GetSignatureDigest() (in-memory; relay-time only).
    std::map<uint256, CFinalityTallyCertificate> mapCandidateCerts;
    std::map<uint256, std::map<uint16_t, std::vector<unsigned char> > > mapCollectedCertSigs;
    std::map<uint256, CFinalityTallyCertificate> mapPendingTallyCertificates;
    std::map<uint256, CFinalityTallyCertificate> mapConnectedTallyCertificates;
    // automation-context hash -> canonical minimum certificate hash
    std::map<uint256, uint256> mapConnectedTallyCertificateByContext;
    std::map<int, std::vector<CFinalityTallyCertificate>> mapEpochTallyCertificates;
    std::map<uint256, std::vector<uint256>> mapBlockConnectedTallyCertificates;

    bool ApplyFinalityDecision(int nEpoch, const uint256& hashFinal, int nFinalHeight,
                               FinalityTier tier, int nVoterCount,
                               int64_t nBestBlockWeight, int64_t nEpochVoteWeight,
                               bool fFromCertificate, bool fLog = true);
    void MarkFinalitySummaryDirty(int nEpoch);
    void ResetFinalitySummary();
    void CaptureFinalitySummary(CFinalitySummarySnapshot& snapshot) const;
    void RestoreFinalitySummary(const CFinalitySummarySnapshot& snapshot);
    /** Replay only the dirty epoch suffix in canonical epoch order. The cached
     *  prefix makes ordinary connect/disconnect work bounded by the affected
     *  finality window instead of total chain history. cs_finality must be held. */
    bool RecomputeFinalityStateFromEpoch(int nRequestedEpoch);
    /** Rebuild the counted/equivocated view of every epoch the carrier index touches.
     *  cs_finality must be held. */
    void RecomputeNoteVoteCounting();
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
