// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_FINALITY_NOTE_H
#define INN_FINALITY_NOTE_H

#include <string>
#include <vector>

#include "key.h"
#include "privacy_vnext_ffi.h"
#include "serialize.h"
#include "uint256.h"

struct CFinalityTallyConfig;

// A note vote weighs a shielded note without naming it, so its weight can only be summed
// by the tally committee. The objects below are the three the F2 fork introduces: the vote,
// the encrypted share that lets the committee sum it, and the complaint that attributes a
// share nobody can use.

static const uint32_t FINALITY_NOTE_VOTE_VERSION = 1;
static const uint32_t FINALITY_NOTE_SHARE_VERSION = 1;
static const uint32_t FINALITY_NOTE_COMPLAINT_VERSION = 1;
static const int FINALITY_NOTE_CERT_VERSION = 4;

static const size_t FINALITY_NOTE_POINT_SIZE = 32;
static const size_t FINALITY_NOTE_SIGMA_SIZE = 128;
static const size_t FINALITY_NOTE_DLEQ_SIZE = 64;
static const size_t FINALITY_NOTE_MAX_MEMBERSHIP_BYTES = 32768;
static const size_t FINALITY_NOTE_MAX_ENVELOPE_BYTES = 4096;
static const size_t FINALITY_NOTE_MAX_RANGE_PROOF_BYTES = 4096;
// One coefficient per polynomial degree, so this tracks the committee threshold.
static const size_t FINALITY_NOTE_MAX_VSS_COEFFICIENTS = 64;

// Fixed layout of a one-input membership verification request, which is where a vote's
// O~ and C~ live. Reading them from the proof is what stops a vote from naming one pair
// and proving another.
static const size_t FINALITY_NOTE_MEMBERSHIP_HEADER = 8;
static const size_t FINALITY_NOTE_MEMBERSHIP_TUPLE = 128;
static const size_t FINALITY_NOTE_MEMBERSHIP_MIN =
    FINALITY_NOTE_MEMBERSHIP_HEADER + 32 + FINALITY_NOTE_MEMBERSHIP_TUPLE + 4;

/** Scalar arithmetic modulo the ed25519 group order.
 *
 *  The legacy tally shares live modulo the secp256k1 order because its commitments do.
 *  A note's weight commitment is an ed25519 point, so its openings and every Shamir
 *  evaluation over them have to reduce modulo ell instead.
 *
 *  uint256 stores its bytes little-endian, which is already the canonical ed25519 scalar
 *  encoding, so a reduced value converts to a wire scalar by copy. */
uint256 Ed25519ScalarReduce(const uint256& value);
uint256 Ed25519ScalarAdd(const uint256& a, const uint256& b);
uint256 Ed25519ScalarSub(const uint256& a, const uint256& b);
uint256 Ed25519ScalarMul(const uint256& a, const uint256& b);
uint256 Ed25519ScalarInv(const uint256& a);
uint256 Ed25519ScalarNeg(const uint256& a);
uint256 Ed25519ScalarFromUint64(uint64_t value);
/** Signed constants reach the field through their negation, never through a cast. */
uint256 Ed25519ScalarFromInt64(int64_t value);
bool Ed25519ScalarIsCanonical(const uint256& value);
bool Ed25519ScalarToMoney(const uint256& value, int64_t& nOut);
PrivacyVNextDigest Ed25519ScalarToDigest(const uint256& value);
uint256 Ed25519ScalarFromDigest(const PrivacyVNextDigest& digest);

/** One committee member's evaluation of a voter's (or a group's) polynomials. */
struct CNoteTallyPlainShare
{
    int nRecipientIndex;
    int nX;
    uint256 evalWeight;
    uint256 evalWeightBlind;
    uint256 evalReward;
    uint256 evalRewardBlind;

    CNoteTallyPlainShare()
    {
        nRecipientIndex = -1;
        nX = 0;
    }
};

/** Encrypted Shamir shares of one note vote's weight opening, with the Pedersen-VSS
 *  coefficients that make a share verifiable against the vote's own commitment.
 *
 *  Without the coefficients nothing checks a share against anything: one voter sharing
 *  values that do not open its commitment makes the whole epoch's private tally
 *  unopenable, with no way to say whose fault it was. */
class CNoteVoteShare
{
public:
    uint32_t nVersion;
    int nEpoch;
    uint256 committeeSetHash;
    // K_k = a_k*H + b_k*G over the weight and blind polynomials. K_0 must equal the
    // vote's C~, which is what ties every accepted share set to the vote's own weight.
    std::vector<std::vector<unsigned char> > vVssCoefficients;
    std::vector<std::vector<unsigned char> > vEncryptedRecipientShares;

    CNoteVoteShare()
    {
        nVersion = FINALITY_NOTE_SHARE_VERSION;
        nEpoch = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CNoteVoteShare* pthis = const_cast<CNoteVoteShare*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->committeeSetHash);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vVssCoefficients, FINALITY_NOTE_MAX_VSS_COEFFICIENTS,
            FINALITY_NOTE_POINT_SIZE, nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vEncryptedRecipientShares, FINALITY_NOTE_MAX_VSS_COEFFICIENTS,
            FINALITY_NOTE_MAX_ENVELOPE_BYTES, nType, nVersion, ser_action);
    )

    uint256 GetHash() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
    /** K_0, the coefficient consensus requires to equal the vote's C~. */
    bool GetCommitment(PrivacyVNextDigest& commitmentOut) const;
};

/** A note-weighted finality vote.
 *
 *  The membership proof binds no message at all, so the vote's whole identity comes from
 *  the sigma: it proves the tag was derived from the same one-time key the membership
 *  proof re-randomized, under a challenge covering every field below. */
class CNoteFinalityVote
{
public:
    uint32_t nVersion;
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int64_t nTime;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;
    std::vector<unsigned char> vchMembership;   // canonical membership verify request
    std::vector<unsigned char> vchTag;          // T_e = x*U_e, the once-per-epoch dedup key
    std::vector<unsigned char> vchSigma;
    CNoteVoteShare share;

    CNoteFinalityVote()
    {
        nVersion = FINALITY_NOTE_VOTE_VERSION;
        nEpoch = 0;
        nHeight = 0;
        nTime = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CNoteFinalityVote* pthis = const_cast<CNoteFinalityVote*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->hashBlock);
        READWRITE(pthis->nHeight);
        READWRITE(pthis->nTime);
        READWRITE(pthis->hashCurveRoot);
        READWRITE(pthis->hashNullifierRoot);
        READWRITE(pthis->committeeSetHash);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchMembership,
                                                 FINALITY_NOTE_MAX_MEMBERSHIP_BYTES,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchTag,
                                                 FINALITY_NOTE_POINT_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSigma,
                                                 FINALITY_NOTE_SIGMA_SIZE,
                                                 nType, nVersion, ser_action);
        READWRITE(pthis->share);
    )

    uint256 GetHash() const;
    /** The tag as a map key. One note reaches one tag per epoch and cannot mint a second. */
    uint256 GetVoteTag() const;
    bool GetOTilde(PrivacyVNextDigest& out) const;
    bool GetCTilde(PrivacyVNextDigest& out) const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
};

/** A publicly verifiable accusation that one share envelope is unusable.
 *
 *  Revealing the ECDH shared point lets anyone redo the recipient's decryption and the VSS
 *  check for that one envelope. Exclusion from a certificate's coverage requires one of
 *  these, so a censor cannot drop a vote it merely dislikes, and one hostile voter cannot
 *  jam an epoch it does not like the look of. */
class CNoteVoteComplaint
{
public:
    uint32_t nVersion;
    int nEpoch;
    uint256 voteTag;
    uint256 hashShare;
    int nRecipientIndex;
    std::vector<unsigned char> vchSharedPoint;   // 33-byte compressed secp256k1 point
    std::vector<unsigned char> vchDleqProof;     // Chaum-Pedersen (challenge, response)

    CNoteVoteComplaint()
    {
        nVersion = FINALITY_NOTE_COMPLAINT_VERSION;
        nEpoch = 0;
        nRecipientIndex = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        CNoteVoteComplaint* pthis = const_cast<CNoteVoteComplaint*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->voteTag);
        READWRITE(pthis->hashShare);
        READWRITE(pthis->nRecipientIndex);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSharedPoint, 33,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchDleqProof,
                                                 FINALITY_NOTE_DLEQ_SIZE,
                                                 nType, nVersion, ser_action);
    )

    uint256 GetHash() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
};

/** The digest the vote's sigma challenge covers. Every field a whole valid vote could
 *  otherwise be replayed under has to reach this, because nothing else binds them. */
uint256 ComputeNoteVoteBinding(const CNoteFinalityVote& vote);

/** Full validation of one vote in isolation: structure, the K_0 == C~ rule, the sigma, and
 *  the membership proof. Chain context (the anchor the roots must equal, the inclusion
 *  window, tag uniqueness) is the caller's, exactly as for transparent votes. */
bool CheckNoteVote(const CNoteFinalityVote& vote, std::string* pstrError = NULL);

/** Build the encrypted shares and the VSS coefficients for one vote's opening.
 *  `maskTilde` is the note mask shifted by the membership proof's commitment blind, so
 *  amount*H + maskTilde*G is exactly the vote's C~. */
bool BuildNoteVoteShare(CNoteVoteShare& share,
                        int64_t nAmount,
                        const uint256& maskTilde,
                        int64_t nReward,
                        const uint256& rewardBlind,
                        const CFinalityTallyConfig& config,
                        std::string* pstrError = NULL);

/** Decrypt one recipient's envelope and check it against the VSS coefficients.
 *  `fVssFailed` separates a share that decrypts but does not open the commitment from one
 *  that does not decrypt at all; both are complainable, neither is a local error. */
bool DecryptNoteVoteShareForRecipient(const CNoteVoteShare& share,
                                      const CFinalityTallyConfig& config,
                                      const CKey& keyRecipient,
                                      int nRecipientIndex,
                                      CNoteTallyPlainShare& plainOut,
                                      bool* pfComplainable = NULL);

/** Check one evaluation against the coefficient vector: a*H + b*G == sum x^k K_k. */
bool CheckNoteVoteVssEvaluation(const CNoteVoteShare& share,
                                const CNoteTallyPlainShare& plain,
                                std::string* pstrError = NULL);

/** Sum evaluations at one x. Shamir is linear, so the sum of evaluations at x is the
 *  evaluation at x of the sum polynomial, and only the sum is ever reconstructed. */
bool AggregateNoteTallyPlainShares(const std::vector<CNoteTallyPlainShare>& vShares,
                                   CNoteTallyPlainShare& aggregateOut);

/** Lagrange-interpolate the aggregate at zero. Never called on a single voter's shares. */
bool RecoverNoteTallySecrets(const std::vector<CNoteTallyPlainShare>& vShares,
                             int nThreshold,
                             uint256& weightOut,
                             uint256& weightBlindOut,
                             uint256& rewardOut,
                             uint256& rewardBlindOut);

/** File a complaint against one envelope, revealing only that envelope's shared point. */
bool BuildNoteVoteComplaint(CNoteVoteComplaint& complaint,
                            const CNoteFinalityVote& vote,
                            const CFinalityTallyConfig& config,
                            const CKey& keyRecipient,
                            int nRecipientIndex,
                            std::string* pstrError = NULL);

/** Re-run the accused decryption from the revealed point. True only when the envelope is
 *  genuinely unusable, so an honest share can never be complained away. */
bool CheckNoteVoteComplaint(const CNoteVoteComplaint& complaint,
                            const CNoteFinalityVote& vote,
                            const CFinalityTallyConfig& config,
                            std::string* pstrError = NULL);

/** Validator-side aggregates. Supplied points are never accepted anywhere: both are
 *  recomputed from the covered votes' own commitments. */
bool DeriveNoteTallyAggregates(const std::vector<const CNoteFinalityVote*>& vVotes,
                               const uint256& hashWinner,
                               PrivacyVNextDigest& activeOut,
                               PrivacyVNextDigest& winningOut,
                               std::string* pstrError = NULL);

/** The three statements a certificate's private tier claim rests on, in cert order. */
struct CNoteTallyTierProofs
{
    std::vector<unsigned char> vchTierSlack;
    std::vector<unsigned char> vchWinningCap;
    std::vector<unsigned char> vchActiveCap;

    bool IsNull() const
    {
        return vchTierSlack.empty() && vchWinningCap.empty() && vchActiveCap.empty();
    }
};

/** Tier comparison coefficients, matching FinalityDetermineTier exactly. */
bool GetNoteTallyTierCoefficients(int nTier, int64_t& nWinningCoeff, int64_t& nActiveCoeff);

/** Committee side: range-prove the tier claim from the recovered aggregate opening. */
bool BuildNoteTallyTierProofs(int nTier,
                              int64_t nPrivateActive,
                              const uint256& privateActiveBlind,
                              int64_t nPrivateWinning,
                              const uint256& privateWinningBlind,
                              int64_t nTransparentActive,
                              int64_t nTransparentWinning,
                              const PrivacyVNextDigest& entropy,
                              CNoteTallyTierProofs& proofsOut,
                              std::string* pstrError = NULL);

/** Validator side: rebuild each statement point and verify its proof against that point. */
bool CheckNoteTallyTierProofs(int nTier,
                              const PrivacyVNextDigest& activePoint,
                              const PrivacyVNextDigest& winningPoint,
                              int64_t nTransparentActive,
                              int64_t nTransparentWinning,
                              const CNoteTallyTierProofs& proofs,
                              std::string* pstrError = NULL);

/** Resolve which connected note votes a certificate covers.
 *
 *  Coverage is equality with one carve-out: a connected vote may be left out only when the
 *  certificate carries a valid complaint against its share. Exclusion therefore costs a
 *  proof that exists only for a genuinely unusable share, so a censor cannot drop a vote it
 *  merely dislikes, while a self-poisoning voter is excluded instead of jamming the epoch. */
bool ResolveNoteTallyCoverage(const std::vector<const CNoteFinalityVote*>& vConnectedVotes,
                              const std::vector<uint256>& vCertVoteTags,
                              const std::vector<CNoteVoteComplaint>& vComplaints,
                              const CFinalityTallyConfig& config,
                              std::vector<const CNoteFinalityVote*>& vCoveredOut,
                              std::string* pstrError = NULL);

/** The whole private side of a certificate, as a pure function of the connected vote set.
 *  Both aggregates are recomputed here; a certificate never supplies them. */
bool CheckNoteTallyCertificate(int nTier,
                               const uint256& hashWinner,
                               const std::vector<const CNoteFinalityVote*>& vConnectedVotes,
                               const std::vector<uint256>& vCertVoteTags,
                               const std::vector<CNoteVoteComplaint>& vComplaints,
                               const CFinalityTallyConfig& config,
                               int64_t nTransparentActive,
                               int64_t nTransparentWinning,
                               const CNoteTallyTierProofs& proofs,
                               std::string* pstrError = NULL);

#endif // INN_FINALITY_NOTE_H
