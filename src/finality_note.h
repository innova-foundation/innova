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


/** Height-keyed consensus floor on one finality vote's weight; keeps a capped vote set
 *  from filling with dust. W_min is in the proof statement, so prover and verifier must
 *  select the same rung: the first whose last height is >= nHeight. */
struct CFinalityVoteWeightFloorRung
{
    int nHeightLast;        // the last height this floor is in force at
    int64_t nMinWeight;
};

int64_t GetFinalityMinVoteWeight(int nHeight);

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

/** Recompute C~ - W_min*H, the point the weight-floor proof must be over, at the floor
 *  in force at nHeight.
 *
 *  The commitment comes from the vote's own membership instance, which its sigma binds.
 *  A supplied point would let any weight claim any floor, so this is the only source the
 *  verifier ever reads. The height is the vote's own, so the statement a verifier checks
 *  is the statement the prover made. */
bool DeriveNoteVoteWeightFloorPoint(const PrivacyVNextDigest& cTilde,
                                    int nHeight,
                                    PrivacyVNextDigest& pointOut,
                                    std::string* pstrError = NULL);

/** Prove the vote's note weighs at least the floor in force at nHeight. `maskTilde` opens
 *  C~ with `nAmount`. Fails for an amount under that floor: the shifted point's
 *  H-coefficient is negative and has no in-range opening. */
bool BuildNoteVoteWeightFloorProof(int64_t nAmount,
                                   int nHeight,
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


#endif // INN_FINALITY_NOTE_H
