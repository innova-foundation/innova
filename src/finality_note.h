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
#include "util.h"

struct CFinalityTallyConfig;

// A note vote weighs a shielded note without naming it, so its weight can only be summed
// by the tally committee. The objects below are the three the F2 fork introduces: the vote,
// the encrypted share that lets the committee sum it, and the complaint that attributes a
// share nobody can use.

static const uint32_t FINALITY_NOTE_VOTE_VERSION = 1;
static const uint32_t FINALITY_NOTE_SHARE_VERSION = 1;
static const uint32_t FINALITY_NOTE_COMPLAINT_VERSION = 1;
static const uint32_t FINALITY_NOTE_TALLY_PARTIAL_VERSION = 1;
static const int FINALITY_NOTE_CERT_VERSION = 4;

/** Bound on the tags and complaints one tally partial may name.
 *
 *  An epoch's note-vote set is capped at the canonical certificate's vote-set bound
 *  (ConnectBlockNoteVotes counts distinct tags, seen or dropped), so a partial naming more
 *  than that names a set no epoch can hold. Kept here rather than reused from finality.h,
 *  which includes this header and not the reverse. */
static const size_t FINALITY_NOTE_MAX_TALLY_TAGS = 128;

static const size_t FINALITY_NOTE_POINT_SIZE = 32;
static const size_t FINALITY_NOTE_SIGMA_SIZE = 128;
static const size_t FINALITY_NOTE_DLEQ_SIZE = 64;
static const size_t FINALITY_NOTE_MAX_MEMBERSHIP_BYTES = 32768;
static const size_t FINALITY_NOTE_MAX_ENVELOPE_BYTES = 4096;
static const size_t FINALITY_NOTE_MAX_RANGE_PROOF_BYTES = 4096;
// One coefficient per polynomial degree, so this tracks the committee threshold.
static const size_t FINALITY_NOTE_MAX_VSS_COEFFICIENTS = 64;

/** The statements a vote's reward-correctness proof is made of, in wire order.
 *
 *  GetFinalityVoteReward is three truncating divisions:
 *
 *      w*interval = COIN*q1 + r1,  0 <= r1 < COIN
 *      q1         = 86400*a  + r2, 0 <= r2 < 86400
 *      CYR*a      = 365*f    + r3, 0 <= r3 < 365
 *
 *  The vote publishes Pedersen commitments to q1 and a; the three remainders are not
 *  published at all, because each is a fixed linear combination of commitments both
 *  sides derive (r1 from C~ and Q, r2 from Q and A, r3 from A and R). The three
 *  equations therefore hold by construction rather than by proof, and every statement
 *  left is a range statement over a derived point.
 *
 *  Each remainder needs two: the proof itself for `0 <= r`, and a proof over
 *  (bound-1)*H - P for `r <= bound-1`. Only the lower halves bound the reward from
 *  above, so they are what supply safety rests on; the upper halves are what makes the
 *  committed reward EQUAL the formula rather than merely not exceed it. */
enum NoteVoteRewardStatement
{
    NOTE_VOTE_REWARD_COIN_REMAINDER = 0,        // r1 >= 0
    NOTE_VOTE_REWARD_COIN_REMAINDER_SLACK = 1,  // r1 <= COIN-1
    NOTE_VOTE_REWARD_DAY_REMAINDER = 2,         // r2 >= 0
    NOTE_VOTE_REWARD_DAY_REMAINDER_SLACK = 3,   // r2 <= 86399
    NOTE_VOTE_REWARD_COIN_AGE = 4,              // a  >= 0
    NOTE_VOTE_REWARD_YEAR_REMAINDER = 5,        // r3 >= 0
    NOTE_VOTE_REWARD_YEAR_REMAINDER_SLACK = 6,  // r3 <= 364
    NOTE_VOTE_REWARD_VALUE = 7,                 // f  >= 0
    NOTE_VOTE_REWARD_STATEMENT_COUNT = 8
};

/** Consensus floor on the weight one finality vote may carry.
 *
 *  The tally denominator is cast weight, and an epoch's canonical vote set is capped, so
 *  without a floor an attacker fills every slot with dust, crowds out the honest heavy
 *  votes, and owns ~100% of the weight the tiers compare against. The floor prices that
 *  capture: filling the epoch cap costs at least
 *  FINALITY_CANONICAL_CERT_MAX_NULLIFIERS * FINALITY_MIN_VOTE_WEIGHT of real stake.
 *
 *  A transparent vote proves it in the clear; a note vote proves C~ - W_min*H opens to a
 *  non-negative amount, leaking the single bit "at least the floor". Review this against
 *  circulating supply before scheduling the activation on a public network. */
static const int64_t FINALITY_MIN_VOTE_WEIGHT = 100 * COIN;

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
    // L_k = c_k*H + d_k*G over the reward and reward-blind polynomials, the same
    // construction one curve-pair over. L_0 must equal the vote's R, so a reward
    // evaluation is checkable against a published commitment exactly as a weight
    // evaluation is. Without it a voter shares any reward scalar it likes and nothing
    // detects it, and a garbage scalar jams the epoch's whole private tally with no way
    // to name who did it.
    std::vector<std::vector<unsigned char> > vRewardVssCoefficients;
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
            s, pthis->vRewardVssCoefficients, FINALITY_NOTE_MAX_VSS_COEFFICIENTS,
            FINALITY_NOTE_POINT_SIZE, nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vEncryptedRecipientShares, FINALITY_NOTE_MAX_VSS_COEFFICIENTS,
            FINALITY_NOTE_MAX_ENVELOPE_BYTES, nType, nVersion, ser_action);
    )

    uint256 GetHash() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
    /** K_0, the coefficient consensus requires to equal the vote's C~. */
    bool GetCommitment(PrivacyVNextDigest& commitmentOut) const;
    /** L_0, the coefficient consensus requires to equal the vote's R. */
    bool GetRewardCommitment(PrivacyVNextDigest& commitmentOut) const;
};

/** The proof that a vote's committed reward is the formula's reward for its own weight.
 *
 *  Two auxiliary commitments and the range proofs over the points derived from them; see
 *  NoteVoteRewardStatement for what each statement is. Q and A hide their values under
 *  fresh blinds, so nothing here narrows the weight beyond what the vote already leaks.
 *
 *  Carried beside the vote rather than inside it. One note vote is one OP_RETURN and one
 *  script is MAX_SCRIPT_SIZE; the membership proof alone is ~7 KB of that 10 KB, and
 *  eight single-value range proofs are ~4.7 KB more, so a vote carrying this could not be
 *  put in a block at all. The vote commits to it by hash instead, which binds it just as
 *  tightly -- and nothing reads the reward until it is paid, so a vote whose proof was
 *  never carried is unpayable rather than invalid. */
class CNoteVoteRewardProof
{
public:
    std::vector<unsigned char> vchQuotient;   // Q = q1*H + b_q*G
    std::vector<unsigned char> vchCoinAge;    // A = a*H  + b_a*G
    std::vector<std::vector<unsigned char> > vProofs;

    IMPLEMENT_SERIALIZE
    (
        CNoteVoteRewardProof* pthis = const_cast<CNoteVoteRewardProof*>(this);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchQuotient,
                                                 FINALITY_NOTE_POINT_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchCoinAge,
                                                 FINALITY_NOTE_POINT_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vProofs, NOTE_VOTE_REWARD_STATEMENT_COUNT,
            FINALITY_NOTE_MAX_RANGE_PROOF_BYTES, nType, nVersion, ser_action);
    )

    uint256 GetHash() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
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
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;
    std::vector<unsigned char> vchMembership;   // canonical membership verify request
    std::vector<unsigned char> vchTag;          // T_e = x*U_e, the once-per-epoch dedup key
    std::vector<unsigned char> vchSigma;
    // Range proof over C~ - W_min*H: the vote weighs at least the consensus floor.
    std::vector<unsigned char> vchWeightFloorProof;
    // R, the vote's own reward commitment. Consensus requires it to equal the share's
    // L_0, so the reward a voter shares is the reward it published and not some other
    // scalar.
    std::vector<unsigned char> vchRewardCommitment;
    // CNoteVoteRewardProof::GetHash() of the proof that R commits GetFinalityVoteReward
    // of the weight inside this vote's own C~. The proof does not fit in the same script
    // as the membership proof, so it rides beside the vote and this pins which one is
    // the vote's: with C~ tied to a real tree leaf by the membership proof, a proof that
    // hashes to this bounds the reward by staked value rather than by a claim.
    uint256 hashRewardProof;
    CNoteVoteShare share;

    // No timestamp: an anonymous vote stamped at proving time is a wallet-pipeline
    // fingerprint, and every field the tally needs is already an epoch-derived constant.

    CNoteFinalityVote()
    {
        nVersion = FINALITY_NOTE_VOTE_VERSION;
        nEpoch = 0;
        nHeight = 0;
        hashRewardProof = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CNoteFinalityVote* pthis = const_cast<CNoteFinalityVote*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->hashBlock);
        READWRITE(pthis->nHeight);
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
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchWeightFloorProof,
                                                 FINALITY_NOTE_MAX_RANGE_PROOF_BYTES,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchRewardCommitment,
                                                 FINALITY_NOTE_POINT_SIZE,
                                                 nType, nVersion, ser_action);
        READWRITE(pthis->hashRewardProof);
        READWRITE(pthis->share);
    )

    uint256 GetHash() const;
    /** The tag as a map key. One note reaches one tag per epoch and cannot mint a second. */
    uint256 GetVoteTag() const;
    bool GetOTilde(PrivacyVNextDigest& out) const;
    bool GetCTilde(PrivacyVNextDigest& out) const;
    /** R as a point. False when the field is not a 32-byte encoding. */
    bool GetRewardCommitment(PrivacyVNextDigest& out) const;
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

/** Recompute C~ - W_min*H, the point the weight-floor proof must be over.
 *
 *  The commitment comes from the vote's own membership instance, which its sigma binds.
 *  A supplied point would let any weight claim any floor, so this is the only source the
 *  verifier ever reads. */
bool DeriveNoteVoteWeightFloorPoint(const PrivacyVNextDigest& cTilde,
                                    PrivacyVNextDigest& pointOut,
                                    std::string* pstrError = NULL);

/** Prove the vote's note weighs at least the floor. `maskTilde` opens C~ with `nAmount`.
 *  Fails for an amount under the floor: the shifted point's H-coefficient is negative and
 *  has no in-range opening. */
bool BuildNoteVoteWeightFloorProof(int64_t nAmount,
                                   const uint256& maskTilde,
                                   const PrivacyVNextDigest& entropy,
                                   std::vector<unsigned char>& vchProofOut,
                                   std::string* pstrError = NULL);

/** Verify a weight-floor proof against the point derived from the vote's own C~. */
bool CheckNoteVoteWeightFloorProof(const CNoteFinalityVote& vote,
                                   std::string* pstrError = NULL);

/** Rebuild the points the reward statements are over, identically on both sides.
 *
 *  Every point is a linear combination of C~, R, Q and A under public coefficients, so a
 *  prover cannot pick one and a validator cannot accept one from the wire. `nEpochInterval`
 *  is GetEpochInterval of the vote's own epoch-boundary height, never a value the vote
 *  carries. Returns NOTE_VOTE_REWARD_STATEMENT_COUNT points in enum order. */
bool DeriveNoteVoteRewardStatementPoints(const PrivacyVNextDigest& cTilde,
                                         const PrivacyVNextDigest& rewardCommitment,
                                         const CNoteVoteRewardProof& proof,
                                         int nEpochInterval,
                                         std::vector<PrivacyVNextDigest>& vPointsOut,
                                         std::string* pstrError = NULL);

/** Build the reward-correctness proof for one vote.
 *
 *  `maskTilde` opens C~ with `nAmount` and `rewardBlind` opens the reward commitment with
 *  GetFinalityVoteReward(nAmount, nEpochInterval); the reward is recomputed here rather
 *  than taken from the caller, so a caller that miscomputed it cannot smuggle the wrong
 *  value past its own proof. `rewardCommitmentOut` is the R the vote must publish. */
bool BuildNoteVoteRewardProof(int64_t nAmount,
                              const uint256& maskTilde,
                              const uint256& rewardBlind,
                              int nEpochInterval,
                              CNoteVoteRewardProof& proofOut,
                              PrivacyVNextDigest& rewardCommitmentOut,
                              std::string* pstrError = NULL);

/** Verify a reward proof against the points derived from one vote's own C~ and R.
 *
 *  The proof travels beside the vote, so the first thing checked is that it is the proof
 *  the vote committed to: without that a payer could pick whichever carried proof it
 *  liked. Not part of CheckNoteVote -- a vote is valid without its proof having been
 *  carried, and unpayable until it has. */
bool CheckNoteVoteRewardProof(const CNoteFinalityVote& vote,
                              const CNoteVoteRewardProof& proof,
                              std::string* pstrError = NULL);

/** Full validation of one vote against the committee its epoch names: structure, the share
 *  shape, the K_0 == C~ rule, the sigma, and the membership proof. Chain context (the
 *  anchor the roots must equal, the inclusion window, tag uniqueness) is the caller's,
 *  exactly as for transparent votes.
 *
 *  The threshold and committee size are consensus values, not the voter's to pick: a share
 *  of degree 0 lets one member open that voter's exact weight, and one of a degree above
 *  the committee's threshold interpolates to the wrong sum while every individual
 *  evaluation still passes its own check, which is unopenable and unattributable at once. */
bool CheckNoteVote(const CNoteFinalityVote& vote,
                   int nThresholdM,
                   int nCommitteeN,
                   std::string* pstrError = NULL);

/** What one note vote's construction takes from consensus state.
 *
 *  None of it is the voter's to choose. `hashAnchorRoot` is the IV5 note-tree root of the
 *  finalized epoch the including block will resolve, which is both the root the membership
 *  proof is against and the value the vote declares; anchoring to anything a node computes
 *  locally is what splits a chain when two nodes disagree about it. */
struct CNoteVoteBuildContext
{
    int nEpoch;
    int nHeight;
    uint256 hashBlock;
    uint256 hashAnchorRoot;
    uint256 hashNullifierRoot;
    int64_t nAmount;

    // No reward field: the reward is GetFinalityVoteReward of nAmount at this height's
    // interval and nothing else, so the builder derives it and the caller cannot name a
    // different one. Carrying it here made the same value reachable from two places, and
    // the proof and the share would then be over two different rewards.

    CNoteVoteBuildContext()
    {
        nEpoch = 0;
        nHeight = 0;
        hashBlock = 0;
        hashAnchorRoot = 0;
        hashNullifierRoot = 0;
        nAmount = 0;
    }
};

/** Build one note vote from a note the caller holds, in the order the checks read it.
 *
 *  Membership comes first because it produces the re-randomized O~/C~ every later step is
 *  over, then the share of that commitment's opening, then the weight-floor proof, and the
 *  sigma last: its challenge covers all of them, which is the only thing making the vote
 *  undetachable from the proof it was built from.
 *
 *  `input` carries the note's spend and commitment scalars and the witness record cut from
 *  the anchor tree; `noteMask` opens the note's own commitment. Proving entropy is drawn
 *  here rather than taken from the caller, so it is never a function of note material.
 *
 *  No timestamp is stamped anywhere: an anonymous vote dated at proving time is a
 *  wallet-pipeline fingerprint.
 *
 *  `rewardProofOut` is the proof the vote's hashRewardProof names. It comes back beside
 *  the vote rather than inside it because it does not fit the vote's script; a producer
 *  that drops it has cast a vote it cannot be paid for.
 *
 *  Fails closed. A failure leaves `voteOut` null rather than partially built, and the
 *  result is re-checked with CheckNoteVote before it is returned. */
bool BuildNoteFinalityVote(const CNoteVoteBuildContext& ctx,
                           const PrivacyVNextSpendInput& input,
                           const PrivacyVNextDigest& noteMask,
                           const CFinalityTallyConfig& config,
                           CNoteFinalityVote& voteOut,
                           CNoteVoteRewardProof& rewardProofOut,
                           std::string* pstrError = NULL);

/** Build the encrypted shares and both VSS coefficient vectors for one vote's opening.
 *  `maskTilde` is the note mask shifted by the membership proof's commitment blind, so
 *  amount*H + maskTilde*G is exactly the vote's C~, and reward*H + rewardBlind*G is
 *  exactly the R the vote publishes. */
bool BuildNoteVoteShare(CNoteVoteShare& share,
                        int64_t nAmount,
                        const uint256& maskTilde,
                        int64_t nReward,
                        const uint256& rewardBlind,
                        const CFinalityTallyConfig& config,
                        std::string* pstrError = NULL);

/** Decrypt one recipient's envelope and check it against the VSS coefficients.
 *  `pfComplainable` marks a failure the share itself caused, whether it did not decrypt or
 *  decrypted to values that open no coefficient; both are the voter's fault and a complaint
 *  covers either. A false result with it clear is a local failure and accuses nobody. */
bool DecryptNoteVoteShareForRecipient(const CNoteVoteShare& share,
                                      const CFinalityTallyConfig& config,
                                      const CKey& keyRecipient,
                                      int nRecipientIndex,
                                      CNoteTallyPlainShare& plainOut,
                                      bool* pfComplainable = NULL);

/** Check one evaluation against both coefficient vectors: the weight pair against
 *  sum x^k K_k and the reward pair against sum x^k L_k. A share that opens one and not
 *  the other is as unusable as one that opens neither, and is complainable for the same
 *  reason: it is the voter's own material either way. */
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

/** Validator-side aggregates. Supplied points are never accepted anywhere: all three are
 *  recomputed from the covered votes' own commitments.
 *
 *  `rewardOut` is sum R_i over the SAME covered set as `activeOut`, not over the winning
 *  subset: a counted vote is paid whether or not it named the winner, exactly as the
 *  transparent settlement pays every counted voter. */
bool DeriveNoteTallyAggregates(const std::vector<const CNoteFinalityVote*>& vVotes,
                               const uint256& hashWinner,
                               PrivacyVNextDigest& activeOut,
                               PrivacyVNextDigest& winningOut,
                               PrivacyVNextDigest& rewardOut,
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

/** What one committee member produces from an epoch's connected note votes. */
struct CNoteTallyCommitteePass
{
    std::vector<uint256> vAcceptedTags;
    std::vector<CNoteVoteComplaint> vComplaints;
    // Evaluations at this member's own x, summed over the accepted votes. Only the sum
    // ever leaves the member, which is what keeps an individual weight unopenable.
    CNoteTallyPlainShare aggregateActive;
    CNoteTallyPlainShare aggregateWinning;
    bool fHaveActive;
    bool fHaveWinning;

    CNoteTallyCommitteePass()
    {
        fHaveActive = false;
        fHaveWinning = false;
    }
};

/** Decrypt this member's evaluation of every connected vote, complain about the ones that
 *  do not open their coefficients, and sum the rest. A vote is taken at most once: the tag
 *  is the note's one identity per epoch. */
bool RunNoteTallyCommitteePass(const std::vector<const CNoteFinalityVote*>& vConnectedVotes,
                               const uint256& hashWinner,
                               const CFinalityTallyConfig& config,
                               const CKey& keyMember,
                               int nMemberIndex,
                               CNoteTallyCommitteePass& passOut,
                               std::string* pstrError = NULL);

/** Interpolate an aggregate opening from M members' partials and require it to open the
 *  points a validator recomputes. Deriving the check from the votes rather than trusting
 *  the interpolation is what makes a poisoned share show up as a failure to open.
 *
 *  Both pairs open strictly. Both are authenticated the same way -- an evaluation reaches
 *  a member only through CheckNoteVoteVssEvaluation, which now checks the reward pair
 *  against L_k as it checks the weight pair against K_k -- so a reward that will not open
 *  is an unusable share, and an unusable share is what a complaint names. Failing here is
 *  therefore attributable, which is exactly what tolerating it used to cost. */
bool OpenNoteTallyAggregate(const std::vector<CNoteTallyPlainShare>& vPartials,
                            int nThreshold,
                            const PrivacyVNextDigest& expectedPoint,
                            const PrivacyVNextDigest& expectedRewardPoint,
                            int64_t& nWeightOut,
                            uint256& weightBlindOut,
                            int64_t& nRewardOut,
                            uint256& rewardBlindOut,
                            std::string* pstrError = NULL);

/** One committee member's summed evaluations for one epoch's note tally, sealed to the
 *  other members.
 *
 *  Not a CFinalityTallyAggregatePartial: that object carries secp256k1 scalars because the
 *  legacy tally commitments live on that curve, and every note evaluation is modulo the
 *  ed25519 group order.
 *
 *  Relay/automation state only. Consensus reads certificates and connected votes; a partial
 *  never reaches a validation path, so a producer working from a stale view builds a
 *  certificate that fails the connect-time recompute rather than one that splits a chain.
 *
 *  The complaints ride here because that is what makes the covered set converge: a member
 *  that summed over a vote another member can prove unusable re-runs against the smaller
 *  set and republishes. vAcceptedTags names the set the evaluations below are over, so a
 *  producer can select exactly the partials that agree on it. */
class CNoteTallyAggregatePartial
{
public:
    uint32_t nVersion;
    int nEpoch;
    uint256 committeeSetHash;
    uint256 hashWinner;
    int nSourceIndex;
    // Sorted, unique. The counted tags this member's evaluations were summed over.
    std::vector<uint256> vAcceptedTags;
    std::vector<CNoteVoteComplaint> vComplaints;
    std::vector<std::vector<unsigned char> > vEncryptedRecipientPartials;
    // Detached signature by the source member over GetContentDigest(): the source index
    // has to be attributable or an equivocating member is unnameable.
    std::vector<unsigned char> vchSourceSig;

    CNoteTallyAggregatePartial()
    {
        nVersion = FINALITY_NOTE_TALLY_PARTIAL_VERSION;
        nEpoch = 0;
        nSourceIndex = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        CNoteTallyAggregatePartial* pthis = const_cast<CNoteTallyAggregatePartial*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->committeeSetHash);
        READWRITE(pthis->hashWinner);
        READWRITE(pthis->nSourceIndex);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vAcceptedTags,
                                                 FINALITY_NOTE_MAX_TALLY_TAGS,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vComplaints,
                                                 FINALITY_NOTE_MAX_TALLY_TAGS,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedByteVectors(
            s, pthis->vEncryptedRecipientPartials,
            FINALITY_NOTE_MAX_VSS_COEFFICIENTS, FINALITY_NOTE_MAX_ENVELOPE_BYTES,
            nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSourceSig, 80,
                                                 nType, nVersion, ser_action);
    )

    uint256 GetHash() const;            // full identity, source signature included
    uint256 GetContentDigest() const;   // the signed content, source signature excluded
    /** The (committee, epoch, source, winner, covered set) a member may sign once.
     *  The covered set is part of the slot on purpose: convergence requires a member to
     *  republish over a shrunken set, and only two contents for ONE set are equivocation. */
    uint256 GetSourceSlot() const;
    bool IsValidBasic(std::string* pstrError = NULL) const;
};

/** Seal one member's pass to every committee member and sign it. */
bool BuildEncryptedNoteTallyAggregatePartial(CNoteTallyAggregatePartial& partial,
                                             const CNoteTallyCommitteePass& pass,
                                             const CFinalityTallyConfig& config,
                                             const CKey& keySource,
                                             std::string* pstrError = NULL);

/** Open one recipient's envelope. Both aggregates travel together because the tier
 *  comparison needs the winning subset opened against the same covered set. */
bool DecryptNoteTallyAggregatePartialForRecipient(const CNoteTallyAggregatePartial& partial,
                                                  const CFinalityTallyConfig& config,
                                                  const CKey& keyRecipient,
                                                  int nRecipientIndex,
                                                  CNoteTallyPlainShare& activeOut,
                                                  bool& fHaveActiveOut,
                                                  CNoteTallyPlainShare& winningOut,
                                                  bool& fHaveWinningOut);

/** Verify the source member's signature against the committee it names. */
bool CheckNoteTallyAggregatePartialSignature(const CNoteTallyAggregatePartial& partial,
                                             const CFinalityTallyConfig& config,
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
