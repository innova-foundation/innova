// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "finality_note.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <utility>

#include "finality.h"
#include "hash.h"
#include "main.h"
#include "privacy_vnext/iv5_protocol.h"
#include "zkproof.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

namespace
{
void Fail(std::string* pstrError, const char* strReason)
{
    if (pstrError)
        *pstrError = strReason;
}

// ell = 2^252 + 27742317777372353535851937790883648493, big-endian.
const unsigned char ED25519_ORDER_BE[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
    0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
};

BIGNUM* NewOrder()
{
    return BN_bin2bn(ED25519_ORDER_BE, 32, NULL);
}

// uint256 keeps its bytes little-endian, which is the canonical scalar encoding, so the
// only conversion either direction is a byte reversal against OpenSSL's big-endian BN.
void ScalarToBN(const uint256& value, BIGNUM* out)
{
    unsigned char be[32];
    const unsigned char* le = value.begin();
    for (int i = 0; i < 32; i++)
        be[i] = le[31 - i];
    BN_bin2bn(be, 32, out);
    OPENSSL_cleanse(be, sizeof(be));
}

uint256 ScalarFromBN(const BIGNUM* value)
{
    unsigned char be[32];
    memset(be, 0, sizeof(be));
    const int nBytes = BN_num_bytes(value);
    if (nBytes > 32)
        return uint256(0);
    BN_bn2bin(value, be + (32 - nBytes));
    uint256 out = 0;
    unsigned char* le = out.begin();
    for (int i = 0; i < 32; i++)
        le[i] = be[31 - i];
    OPENSSL_cleanse(be, sizeof(be));
    return out;
}

uint256 ScalarBinary(const uint256& a, const uint256& b,
                     int (*op)(BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*))
{
    uint256 result = 0;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bnA = BN_new();
    BIGNUM* bnB = BN_new();
    BIGNUM* bnOrder = NewOrder();
    BIGNUM* bnOut = BN_new();
    if (ctx && bnA && bnB && bnOrder && bnOut)
    {
        ScalarToBN(a, bnA);
        ScalarToBN(b, bnB);
        if (op(bnOut, bnA, bnB, bnOrder, ctx) == 1)
            result = ScalarFromBN(bnOut);
    }
    if (bnOut) BN_clear_free(bnOut);
    if (bnOrder) BN_free(bnOrder);
    if (bnB) BN_clear_free(bnB);
    if (bnA) BN_clear_free(bnA);
    if (ctx) BN_CTX_free(ctx);
    return result;
}

const char* NOTE_VOTE_BINDING_DOMAIN = "Innova/IV5/NoteVote/Binding/v1";

PrivacyVNextDigest ZeroDigest()
{
    PrivacyVNextDigest zero;
    zero.fill(0);
    return zero;
}

// Combine one commitment: value*H + blind*G. The prover and the validator reach the same
// point from opposite sides, which is what makes the derived-point rule checkable.
bool CommitScaled(const uint256& valueScalar, const uint256& blindScalar,
                  PrivacyVNextDigest& out, std::string* pstrError)
{
    std::vector<PrivacyVNextCombineTerm> vTerms(2);
    vTerms[0].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vTerms[0].scalar = Ed25519ScalarToDigest(valueScalar);
    vTerms[1].nSource = PRIVACY_VNEXT_TERM_ED25519_G;
    vTerms[1].scalar = Ed25519ScalarToDigest(blindScalar);
    std::string error;
    if (!CombinePrivacyVNextPoints(vTerms, out, error))
    {
        Fail(pstrError, "note vote commitment could not be derived");
        return false;
    }
    return true;
}

// Proving entropy, drawn fresh per proof. It is never derived from note material: the
// re-randomization is the only thing separating the vote's O~/C~ from the leaf, so entropy
// anyone could recompute from the note would undo it.
bool DrawProofEntropy(PrivacyVNextDigest& out)
{
    for (int nTry = 0; nTry < 8; nTry++)
    {
        if (RAND_bytes(out.data(), (int)out.size()) != 1)
            return false;
        // The prover rejects an all-zero draw, so retry rather than hand it one.
        for (size_t i = 0; i < out.size(); i++)
        {
            if (out[i] != 0)
                return true;
        }
    }
    return false;
}

} // namespace

uint256 Ed25519ScalarReduce(const uint256& value)
{
    uint256 result = 0;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn = BN_new();
    BIGNUM* bnOrder = NewOrder();
    if (ctx && bn && bnOrder)
    {
        ScalarToBN(value, bn);
        if (BN_nnmod(bn, bn, bnOrder, ctx) == 1)
            result = ScalarFromBN(bn);
    }
    if (bnOrder) BN_free(bnOrder);
    if (bn) BN_clear_free(bn);
    if (ctx) BN_CTX_free(ctx);
    return result;
}

uint256 Ed25519ScalarAdd(const uint256& a, const uint256& b)
{
    return ScalarBinary(a, b, BN_mod_add);
}

uint256 Ed25519ScalarSub(const uint256& a, const uint256& b)
{
    return ScalarBinary(a, b, BN_mod_sub);
}

uint256 Ed25519ScalarMul(const uint256& a, const uint256& b)
{
    return ScalarBinary(a, b, BN_mod_mul);
}

uint256 Ed25519ScalarNeg(const uint256& a)
{
    return Ed25519ScalarSub(uint256(0), a);
}

uint256 Ed25519ScalarInv(const uint256& a)
{
    uint256 result = 0;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn = BN_new();
    BIGNUM* bnOrder = NewOrder();
    BIGNUM* bnOut = BN_new();
    if (ctx && bn && bnOrder && bnOut)
    {
        ScalarToBN(a, bn);
        if (BN_nnmod(bn, bn, bnOrder, ctx) == 1 && !BN_is_zero(bn) &&
            BN_mod_inverse(bnOut, bn, bnOrder, ctx) != NULL)
            result = ScalarFromBN(bnOut);
    }
    if (bnOut) BN_clear_free(bnOut);
    if (bnOrder) BN_free(bnOrder);
    if (bn) BN_clear_free(bn);
    if (ctx) BN_CTX_free(ctx);
    return result;
}

uint256 Ed25519ScalarFromUint64(uint64_t value)
{
    uint256 out = 0;
    unsigned char* le = out.begin();
    for (int i = 0; i < 8; i++)
        le[i] = (unsigned char)((value >> (8 * i)) & 0xff);
    return out;
}

uint256 Ed25519ScalarFromInt64(int64_t value)
{
    if (value >= 0)
        return Ed25519ScalarFromUint64((uint64_t)value);
    return Ed25519ScalarNeg(Ed25519ScalarFromUint64((uint64_t)(-(value + 1)) + 1));
}

bool Ed25519ScalarIsCanonical(const uint256& value)
{
    return Ed25519ScalarReduce(value) == value;
}

bool Ed25519ScalarToMoney(const uint256& value, int64_t& nOut)
{
    const unsigned char* le = value.begin();
    for (int i = 8; i < 32; i++)
    {
        if (le[i] != 0)
            return false;
    }
    uint64_t nValue = 0;
    for (int i = 0; i < 8; i++)
        nValue |= ((uint64_t)le[i]) << (8 * i);
    if (nValue > (uint64_t)MAX_MONEY)
        return false;
    nOut = (int64_t)nValue;
    return true;
}

PrivacyVNextDigest Ed25519ScalarToDigest(const uint256& value)
{
    PrivacyVNextDigest out;
    const uint256 reduced = Ed25519ScalarReduce(value);
    memcpy(out.data(), reduced.begin(), 32);
    return out;
}

uint256 Ed25519ScalarFromDigest(const PrivacyVNextDigest& digest)
{
    uint256 out = 0;
    memcpy(out.begin(), digest.data(), 32);
    return out;
}

uint256 CNoteFinalityVote::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CNoteFinalityVote::GetVoteTag() const
{
    uint256 tag = 0;
    if (vchTag.size() == FINALITY_NOTE_POINT_SIZE)
        memcpy(tag.begin(), &vchTag[0], FINALITY_NOTE_POINT_SIZE);
    return tag;
}

bool CNoteFinalityVote::GetOTilde(PrivacyVNextDigest& out) const
{
    if (vchMembership.size() < FINALITY_NOTE_MEMBERSHIP_MIN)
        return false;
    memcpy(out.data(), &vchMembership[FINALITY_NOTE_MEMBERSHIP_HEADER + 32], 32);
    return true;
}

bool CNoteFinalityVote::GetCTilde(PrivacyVNextDigest& out) const
{
    if (vchMembership.size() < FINALITY_NOTE_MEMBERSHIP_MIN)
        return false;
    memcpy(out.data(), &vchMembership[FINALITY_NOTE_MEMBERSHIP_HEADER + 32 + 96], 32);
    return true;
}

bool CNoteFinalityVote::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != FINALITY_NOTE_VOTE_VERSION)
    {
        Fail(pstrError, "note vote version is not the F2 version");
        return false;
    }
    if (nEpoch < 0 || nHeight < 0)
    {
        Fail(pstrError, "note vote carries a negative epoch or height");
        return false;
    }
    if (hashBlock == 0 || hashCurveRoot == 0 || hashNullifierRoot == 0 ||
        committeeSetHash == 0)
    {
        Fail(pstrError, "note vote leaves a bound field empty");
        return false;
    }
    if (vchTag.size() != FINALITY_NOTE_POINT_SIZE)
    {
        Fail(pstrError, "note vote tag is not a point");
        return false;
    }
    if (vchSigma.size() != FINALITY_NOTE_SIGMA_SIZE)
    {
        Fail(pstrError, "note vote sigma has the wrong length");
        return false;
    }
    if (vchWeightFloorProof.empty() ||
        vchWeightFloorProof.size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
    {
        Fail(pstrError, "note vote weight-floor proof has an unusable length");
        return false;
    }
    if (vchMembership.size() < FINALITY_NOTE_MEMBERSHIP_MIN ||
        vchMembership.size() > FINALITY_NOTE_MAX_MEMBERSHIP_BYTES)
    {
        Fail(pstrError, "note vote membership instance has an unusable length");
        return false;
    }
    // Pin the shape the O~/C~ offsets assume, so a multi-input or foreign-curve request
    // can never be read as if it were the one-input layout.
    if (vchMembership[0] != (unsigned char)iv5::PROTOCOL_SCHEMA ||
        vchMembership[1] != 0 ||
        vchMembership[2] != iv5::TREE_LAYERS ||
        vchMembership[3] != 2 ||
        vchMembership[4] != 1 ||
        vchMembership[5] != 0 || vchMembership[6] != 0 || vchMembership[7] != 0)
    {
        Fail(pstrError, "note vote membership instance is not the pinned one-input shape");
        return false;
    }
    // The anchor is consensus data: the proof must be against the epoch's own curve root,
    // never a root the vote merely declares alongside it.
    if (memcmp(&vchMembership[FINALITY_NOTE_MEMBERSHIP_HEADER],
               hashCurveRoot.begin(), 32) != 0)
    {
        Fail(pstrError, "note vote membership root differs from the declared anchor");
        return false;
    }
    return true;
}

uint256 ComputeNoteVoteBinding(const CNoteFinalityVote& vote)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(NOTE_VOTE_BINDING_DOMAIN);
    ss << vote.nVersion;
    ss << vote.nEpoch;
    ss << vote.hashCurveRoot;
    ss << vote.hashNullifierRoot;
    ss << vote.hashBlock;
    ss << vote.nHeight;
    ss << Hash(vote.vchMembership.begin(), vote.vchMembership.end());
    ss << vote.committeeSetHash;
    // A re-randomized floor proof over the same point verifies just as well, so leaving it
    // unbound would let a relaying peer mint a second byte-distinct vote under one tag.
    ss << Hash(vote.vchWeightFloorProof.begin(), vote.vchWeightFloorProof.end());
    return ss.GetHash();
}

bool DeriveNoteVoteWeightFloorPoint(const PrivacyVNextDigest& cTilde,
                                    PrivacyVNextDigest& pointOut,
                                    std::string* pstrError)
{
    std::vector<PrivacyVNextCombineTerm> vTerms(2);
    vTerms[0].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vTerms[0].scalar = Ed25519ScalarToDigest(Ed25519ScalarFromUint64(1));
    vTerms[0].point = cTilde;
    vTerms[1].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vTerms[1].scalar = Ed25519ScalarToDigest(
        Ed25519ScalarNeg(Ed25519ScalarFromInt64(FINALITY_MIN_VOTE_WEIGHT)));

    std::string error;
    if (!CombinePrivacyVNextPoints(vTerms, pointOut, error))
    {
        Fail(pstrError, "note vote weight-floor point could not be derived");
        return false;
    }
    return true;
}

bool BuildNoteVoteWeightFloorProof(int64_t nAmount,
                                   const uint256& maskTilde,
                                   const PrivacyVNextDigest& entropy,
                                   std::vector<unsigned char>& vchProofOut,
                                   std::string* pstrError)
{
    vchProofOut.clear();
    if (nAmount < FINALITY_MIN_VOTE_WEIGHT || nAmount > MAX_MONEY)
    {
        Fail(pstrError, "note vote weight is outside the range the floor allows");
        return false;
    }

    PrivacyVNextDigest commitment = ZeroDigest();
    std::string error;
    if (!ProvePrivacyVNextRange((uint64_t)(nAmount - FINALITY_MIN_VOTE_WEIGHT),
                                Ed25519ScalarToDigest(maskTilde), entropy, commitment,
                                vchProofOut, error))
    {
        Fail(pstrError, "note vote weight floor could not be range-proved");
        vchProofOut.clear();
        return false;
    }
    if (vchProofOut.size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
    {
        Fail(pstrError, "note vote weight-floor proof exceeds its carrier bound");
        vchProofOut.clear();
        return false;
    }

    // The proof is only usable if it lands on the point a validator reaches from C~ alone.
    // Surfacing a divergent opening here beats emitting a vote the network rejects.
    PrivacyVNextDigest cTilde = ZeroDigest();
    if (!CommitScaled(Ed25519ScalarFromInt64(nAmount), maskTilde, cTilde, pstrError))
    {
        vchProofOut.clear();
        return false;
    }
    PrivacyVNextDigest expected = ZeroDigest();
    if (!DeriveNoteVoteWeightFloorPoint(cTilde, expected, pstrError))
    {
        vchProofOut.clear();
        return false;
    }
    if (commitment != expected)
    {
        Fail(pstrError, "note vote weight-floor proof is over a point the validator misses");
        vchProofOut.clear();
        return false;
    }
    return true;
}

bool CheckNoteVoteWeightFloorProof(const CNoteFinalityVote& vote, std::string* pstrError)
{
    if (vote.vchWeightFloorProof.empty() ||
        vote.vchWeightFloorProof.size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
    {
        Fail(pstrError, "note vote weight-floor proof has an unusable length");
        return false;
    }

    PrivacyVNextDigest cTilde = ZeroDigest();
    if (!vote.GetCTilde(cTilde))
    {
        Fail(pstrError, "note vote membership instance carries no input tuple");
        return false;
    }
    PrivacyVNextDigest floorPoint = ZeroDigest();
    if (!DeriveNoteVoteWeightFloorPoint(cTilde, floorPoint, pstrError))
        return false;

    std::string error;
    if (!VerifyPrivacyVNextRange(floorPoint, ZeroDigest(), vote.vchWeightFloorProof, error))
    {
        Fail(pstrError, "note vote does not reach the minimum vote weight");
        return false;
    }
    return true;
}

bool CheckNoteVote(const CNoteFinalityVote& vote, std::string* pstrError)
{
    if (!vote.IsValidBasic(pstrError))
        return false;

    PrivacyVNextDigest oTilde = ZeroDigest();
    PrivacyVNextDigest cTilde = ZeroDigest();
    if (!vote.GetOTilde(oTilde) || !vote.GetCTilde(cTilde))
    {
        Fail(pstrError, "note vote membership instance carries no input tuple");
        return false;
    }

    const uint256 binding = ComputeNoteVoteBinding(vote);
    PrivacyVNextDigest bindingDigest;
    memcpy(bindingDigest.data(), binding.begin(), 32);
    PrivacyVNextDigest tag;
    memcpy(tag.data(), &vote.vchTag[0], 32);

    // Sigma first: it is one scalar-mul pair, the membership proof is tens of
    // milliseconds, and both are reachable from the network.
    std::string error;
    if (!VerifyPrivacyVNextVoteSigma((uint64_t)vote.nEpoch, oTilde, cTilde, bindingDigest,
                                     tag, vote.vchSigma, error))
    {
        Fail(pstrError, "note vote sigma does not verify");
        return false;
    }
    if (!CheckNoteVoteWeightFloorProof(vote, pstrError))
        return false;
    if (!VerifyPrivacyVNextVoteMembership(vote.vchMembership, error))
    {
        Fail(pstrError, "note vote membership proof does not verify");
        return false;
    }
    return true;
}

bool BuildNoteFinalityVote(const CNoteVoteBuildContext& ctx,
                           const PrivacyVNextSpendInput& input,
                           const PrivacyVNextDigest& noteMask,
                           CNoteFinalityVote& voteOut,
                           std::string* pstrError)
{
    voteOut = CNoteFinalityVote();

    if (ctx.nEpoch < 0 || ctx.nHeight < 0 || ctx.hashBlock == 0 ||
        ctx.hashAnchorRoot == 0 || ctx.hashNullifierRoot == 0 ||
        ctx.committeeSetHash == 0)
    {
        Fail(pstrError, "note vote has no finalized anchor to build against");
        return false;
    }
    // Below the floor there is no weight-floor proof to make: the shifted point's
    // H-coefficient is negative and opens to nothing in range.
    if (ctx.nAmount < FINALITY_MIN_VOTE_WEIGHT || ctx.nAmount > MAX_MONEY)
    {
        Fail(pstrError, "note vote weight is outside the range a vote may carry");
        return false;
    }
    if (input.vchWitnessRecord.empty())
    {
        Fail(pstrError, "note vote has no membership witness for the anchor tree");
        return false;
    }

    PrivacyVNextDigest finalizedRoot = ZeroDigest();
    memcpy(finalizedRoot.data(), ctx.hashAnchorRoot.begin(), 32);

    // Membership first: O~ and C~ come out of this request, and the vote reads them back
    // out of it rather than restating them alongside.
    PrivacyVNextDigest entropy = ZeroDigest();
    if (!DrawProofEntropy(entropy))
    {
        Fail(pstrError, "note vote could not draw proving entropy");
        return false;
    }
    PrivacyVNextVoteMembership membership;
    std::string error;
    const bool fMembership = ProvePrivacyVNextVoteMembership(finalizedRoot, entropy,
                                                             input, membership, error);
    OPENSSL_cleanse(entropy.data(), entropy.size());
    if (!fMembership)
    {
        Fail(pstrError, "note vote membership proof could not be built");
        return false;
    }

    // The re-randomization shifted the commitment's blind, so amount*H + maskTilde*G is
    // C~ and the note's own mask opens nothing the vote publishes.
    uint256 maskTilde = Ed25519ScalarAdd(Ed25519ScalarFromDigest(noteMask),
                                         Ed25519ScalarFromDigest(membership.maskDelta));

    voteOut.nVersion = FINALITY_NOTE_VOTE_VERSION;
    voteOut.nEpoch = ctx.nEpoch;
    voteOut.hashBlock = ctx.hashBlock;
    voteOut.nHeight = ctx.nHeight;
    voteOut.hashCurveRoot = ctx.hashAnchorRoot;
    voteOut.hashNullifierRoot = ctx.hashNullifierRoot;
    voteOut.committeeSetHash = ctx.committeeSetHash;
    voteOut.vchMembership = membership.vchRequest;

    bool fOk = true;
    {
        PrivacyVNextDigest floorEntropy = ZeroDigest();
        fOk = DrawProofEntropy(floorEntropy);
        if (!fOk)
            Fail(pstrError, "note vote could not draw proving entropy");
        else
        {
            fOk = BuildNoteVoteWeightFloorProof(ctx.nAmount, maskTilde, floorEntropy,
                                                voteOut.vchWeightFloorProof, pstrError);
            OPENSSL_cleanse(floorEntropy.data(), floorEntropy.size());
        }
    }

    // Sigma last. Its challenge covers the binding over every field above, so nothing
    // already built can be restated under this signature.
    if (fOk)
    {
        const uint256 binding = ComputeNoteVoteBinding(voteOut);
        PrivacyVNextDigest bindingDigest = ZeroDigest();
        memcpy(bindingDigest.data(), binding.begin(), 32);
        PrivacyVNextDigest sigmaEntropy = ZeroDigest();
        fOk = DrawProofEntropy(sigmaEntropy);
        if (!fOk)
            Fail(pstrError, "note vote could not draw proving entropy");
        else
        {
            PrivacyVNextDigest tag = ZeroDigest();
            std::vector<unsigned char> vchSigma;
            fOk = ProvePrivacyVNextVoteSigma((uint64_t)ctx.nEpoch, membership.oTilde,
                                             membership.cTilde, bindingDigest,
                                             input.spendScalar, membership.rerandomizedY,
                                             sigmaEntropy, tag, vchSigma, error);
            OPENSSL_cleanse(sigmaEntropy.data(), sigmaEntropy.size());
            if (!fOk)
                Fail(pstrError, "note vote sigma could not be proved");
            else
            {
                voteOut.vchTag.assign(tag.begin(), tag.end());
                voteOut.vchSigma = vchSigma;
            }
        }
    }

    // Construction material, not vote content: holding it past here would let anything
    // that later reads this process reopen the commitment the vote exists to hide.
    OPENSSL_cleanse(maskTilde.begin(), 32);
    OPENSSL_cleanse(membership.maskDelta.data(), membership.maskDelta.size());
    OPENSSL_cleanse(membership.rerandomizedY.data(), membership.rerandomizedY.size());

    // Verify what was built with the checker consensus runs, so a vote that would be
    // rejected on arrival never leaves the producer.
    if (fOk)
        fOk = CheckNoteVote(voteOut, pstrError);
    if (!fOk)
        voteOut = CNoteFinalityVote();
    return fOk;
}
