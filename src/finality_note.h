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

// A note vote names a shielded note without revealing it. Its weight is not tallied:
// eligibility is the stake floor below and a counted vote is one vote, so the certificate
// commits to the counted tag set by root and carries no per-vote weight.

static const uint32_t FINALITY_NOTE_VOTE_VERSION = 1;
static const int FINALITY_NOTE_CERT_VERSION = 4;

static const size_t FINALITY_NOTE_POINT_SIZE = 32;
static const size_t FINALITY_NOTE_SIGMA_SIZE = 128;
static const size_t FINALITY_NOTE_MAX_MEMBERSHIP_BYTES = 32768;
static const size_t FINALITY_NOTE_MAX_RANGE_PROOF_BYTES = 4096;


/** Consensus floor on the weight one finality vote may carry.
 *
 *  The tally denominator is cast weight, and an epoch's canonical vote set is capped, so
 *  without a floor an attacker fills every slot with dust, crowds out the honest heavy
 *  votes, and owns ~100% of the weight the tiers compare against. The floor prices that
 *  capture: filling the epoch cap costs at least
 *  FINALITY_MAX_EPOCH_NOTE_VOTES * FINALITY_MIN_VOTE_WEIGHT of real stake.
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

/** Scalar arithmetic modulo the ed25519 group order (weight commitments are ed25519
 *  points). uint256 little-endian bytes are already the canonical scalar encoding. */
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

/** A note finality vote. The membership proof binds no message, so the sigma carries the
 *  vote's identity: the tag derives from the re-randomized one-time key, under a
 *  challenge covering every field below. */
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

    // No timestamp: an anonymous vote stamped at proving time is a wallet-pipeline
    // fingerprint, and every field a counted vote needs is an epoch-derived constant.

    CNoteFinalityVote()
    {
        nVersion = FINALITY_NOTE_VOTE_VERSION;
        nEpoch = 0;
        nHeight = 0;
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
    )

    uint256 GetHash() const;
    /** The tag as a map key. One note reaches one tag per epoch and cannot mint a second. */
    uint256 GetVoteTag() const;
    bool GetOTilde(PrivacyVNextDigest& out) const;
    bool GetCTilde(PrivacyVNextDigest& out) const;
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

/** Full validation of one vote: structure, the sigma binding, the stake-floor range proof
 *  and the membership proof. Chain context (the anchor the roots must equal, the inclusion
 *  window, tag uniqueness) is the caller's, exactly as for transparent votes. */
bool CheckNoteVote(const CNoteFinalityVote& vote,
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
    uint256 committeeSetHash;
    int64_t nAmount;

    // No reward field: a counted vote's reward is a consensus formula of its epoch, not
    // a value the vote carries.

    CNoteVoteBuildContext()
    {
        nEpoch = 0;
        nHeight = 0;
        hashBlock = 0;
        hashAnchorRoot = 0;
        hashNullifierRoot = 0;
        committeeSetHash = 0;
        nAmount = 0;
    }
};

/** Build one note vote from a note the caller holds, in the order the checks read it.
 *
 *  Membership comes first because it produces the re-randomized O~/C~ every later step is
 *  over, then the weight-floor proof, and the sigma last: its challenge covers all of them,
 *  which is the only thing making the vote undetachable from the proof it was built from.
 *
 *  `input` carries the note's spend and commitment scalars and the witness record cut from
 *  the anchor tree; `noteMask` opens the note's own commitment. Proving entropy is drawn
 *  here rather than taken from the caller, so it is never a function of note material.
 *
 *  No timestamp is stamped anywhere: an anonymous vote dated at proving time is a
 *  wallet-pipeline fingerprint.
 *
 *  Fails closed. A failure leaves `voteOut` null rather than partially built, and the
 *  result is re-checked with CheckNoteVote before it is returned. */
bool BuildNoteFinalityVote(const CNoteVoteBuildContext& ctx,
                           const PrivacyVNextSpendInput& input,
                           const PrivacyVNextDigest& noteMask,
                           CNoteFinalityVote& voteOut,
                           std::string* pstrError = NULL);

#endif // INN_FINALITY_NOTE_H
