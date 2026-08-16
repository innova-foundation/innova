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

const char* NOTE_SHARE_ECDH_DOMAIN = "Innova/IV5/NoteVote/ShareECDH/v1";
const char* NOTE_SHARE_AAD_DOMAIN = "Innova/IV5/NoteVote/ShareAAD/v1";
const char* NOTE_VOTE_BINDING_DOMAIN = "Innova/IV5/NoteVote/Binding/v1";
const char* NOTE_COMPLAINT_DLEQ_DOMAIN = "Innova/IV5/NoteVote/ComplaintDLEQ/v1";

// Derive the envelope key from the ECDH shared point alone, so a complaint that reveals
// only that point reproduces the recipient's key without its private key.
bool DeriveNoteShareKeyFromSharedPoint(const unsigned char sharedBytes[33],
                                       const CPubKey& pubRecipient,
                                       const CPubKey& pubEphemeral,
                                       int nRecipientIndex,
                                       const uint256& committeeSetHash,
                                       std::vector<unsigned char>& vchKeyOut)
{
    if (!pubRecipient.IsValid() || !pubRecipient.IsCompressed() ||
        !pubEphemeral.IsValid() || !pubEphemeral.IsCompressed())
        return false;
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(NOTE_SHARE_ECDH_DOMAIN);
    for (size_t i = 0; i < 33; i++)
        ss << sharedBytes[i];
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    ss << std::vector<unsigned char>(pubRecipient.begin(), pubRecipient.end());
    ss << committeeSetHash;
    ss << nRecipientIndex;
    uint256 hashKey = ss.GetHash();
    vchKeyOut.assign(hashKey.begin(), hashKey.begin() + 32);
    return true;
}

bool ComputeSharedPoint(const CKey& keyPrivate,
                        const CPubKey& pubPeer,
                        unsigned char sharedBytesOut[33])
{
    if (!keyPrivate.IsValid() || !pubPeer.IsValid() || !pubPeer.IsCompressed())
        return false;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX* ctx = group ? BN_CTX_new() : NULL;
    if (!group || !ctx)
    {
        if (ctx) BN_CTX_free(ctx);
        if (group) EC_GROUP_free(group);
        return false;
    }
    BIGNUM* bnPriv = BN_bin2bn(keyPrivate.begin(), 32, NULL);
    EC_POINT* peerPoint = EC_POINT_new(group);
    EC_POINT* sharedPoint = EC_POINT_new(group);
    const bool fOk =
        bnPriv && peerPoint && sharedPoint &&
        EC_POINT_oct2point(group, peerPoint, pubPeer.begin(), pubPeer.size(), ctx) == 1 &&
        EC_POINT_is_on_curve(group, peerPoint, ctx) == 1 &&
        !EC_POINT_is_at_infinity(group, peerPoint) &&
        EC_POINT_mul(group, sharedPoint, NULL, peerPoint, bnPriv, ctx) == 1 &&
        !EC_POINT_is_at_infinity(group, sharedPoint) &&
        EC_POINT_point2oct(group, sharedPoint, POINT_CONVERSION_COMPRESSED,
                           sharedBytesOut, 33, ctx) == 33;
    if (sharedPoint) EC_POINT_free(sharedPoint);
    if (peerPoint) EC_POINT_free(peerPoint);
    if (bnPriv) BN_clear_free(bnPriv);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return fOk;
}

std::vector<unsigned char> BuildNoteShareAAD(const CNoteVoteShare& share,
                                             int nRecipientIndex,
                                             const CPubKey& pubEphemeral)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << std::string(NOTE_SHARE_AAD_DOMAIN);
    ss << share.nVersion;
    ss << share.nEpoch;
    ss << share.committeeSetHash;
    ss << share.vVssCoefficients;
    // The reward coefficients are what the sealed reward evaluation is now checked
    // against, so they belong to what this ciphertext is authenticated under.
    ss << share.vRewardVssCoefficients;
    ss << nRecipientIndex;
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

bool ParseNoteShareEnvelope(const std::vector<unsigned char>& vchEnvelope,
                            int& nRecipientIndexOut,
                            CPubKey& pubEphemeralOut,
                            std::vector<unsigned char>& vchCiphertextOut)
{
    try
    {
        CDataStream ss(vchEnvelope, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nEnvelopeVersion = 0;
        std::vector<unsigned char> vchEphemeral;
        ss >> nEnvelopeVersion;
        ss >> nRecipientIndexOut;
        ss >> vchEphemeral;
        ss >> vchCiphertextOut;
        if (nEnvelopeVersion != FINALITY_NOTE_SHARE_VERSION ||
            nRecipientIndexOut < 0 ||
            vchEphemeral.size() != 33 ||
            vchCiphertextOut.size() < 28)
            return false;
        pubEphemeralOut = CPubKey(vchEphemeral);
        return pubEphemeralOut.IsValid() && pubEphemeralOut.IsCompressed();
    }
    catch (const std::exception&)
    {
        return false;
    }
}

bool BuildShamirPolynomial(const uint256& secret, int nDegree,
                           std::vector<uint256>& vCoeffOut)
{
    if (nDegree < 0)
        return false;
    vCoeffOut.assign(nDegree + 1, uint256(0));
    vCoeffOut[0] = Ed25519ScalarReduce(secret);
    for (int i = 1; i <= nDegree; i++)
    {
        unsigned char buf[32];
        if (RAND_bytes(buf, sizeof(buf)) != 1)
            return false;
        uint256 draw = 0;
        memcpy(draw.begin(), buf, sizeof(buf));
        OPENSSL_cleanse(buf, sizeof(buf));
        vCoeffOut[i] = Ed25519ScalarReduce(draw);
    }
    return true;
}

bool EvaluatePolynomial(const std::vector<uint256>& vCoeff, int nX, uint256& yOut)
{
    if (vCoeff.empty() || nX <= 0)
        return false;
    const uint256 x = Ed25519ScalarFromUint64((uint64_t)nX);
    uint256 power = Ed25519ScalarFromUint64(1);
    yOut = vCoeff[0];
    for (size_t i = 1; i < vCoeff.size(); i++)
    {
        power = Ed25519ScalarMul(power, x);
        yOut = Ed25519ScalarAdd(yOut, Ed25519ScalarMul(vCoeff[i], power));
    }
    return true;
}

bool InterpolateAtZero(const std::vector<int>& vX, const std::vector<uint256>& vY,
                       int nThreshold, uint256& secretOut)
{
    if (nThreshold <= 0 || (int)vX.size() < nThreshold || vX.size() != vY.size())
        return false;

    std::set<int> setX;
    secretOut = uint256(0);
    for (int i = 0; i < nThreshold; i++)
    {
        if (vX[i] <= 0 || !setX.insert(vX[i]).second)
            return false;
        const uint256 xi = Ed25519ScalarFromUint64((uint64_t)vX[i]);
        uint256 coeff = Ed25519ScalarFromUint64(1);
        for (int j = 0; j < nThreshold; j++)
        {
            if (i == j)
                continue;
            const uint256 xj = Ed25519ScalarFromUint64((uint64_t)vX[j]);
            const uint256 denominator = Ed25519ScalarSub(xi, xj);
            if (denominator == uint256(0))
                return false;
            coeff = Ed25519ScalarMul(
                coeff, Ed25519ScalarMul(Ed25519ScalarNeg(xj), Ed25519ScalarInv(denominator)));
        }
        secretOut = Ed25519ScalarAdd(secretOut, Ed25519ScalarMul(vY[i], coeff));
    }
    return true;
}

PrivacyVNextDigest ZeroDigest()
{
    PrivacyVNextDigest zero;
    zero.fill(0);
    return zero;
}

bool DigestFromBytes(const std::vector<unsigned char>& vch, PrivacyVNextDigest& out)
{
    if (vch.size() != FINALITY_NOTE_POINT_SIZE)
        return false;
    memcpy(out.data(), &vch[0], FINALITY_NOTE_POINT_SIZE);
    return true;
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

bool DrawScalar(uint256& out)
{
    unsigned char buf[32];
    if (RAND_bytes(buf, sizeof(buf)) != 1)
        return false;
    out = 0;
    memcpy(out.begin(), buf, sizeof(buf));
    OPENSSL_cleanse(buf, sizeof(buf));
    out = Ed25519ScalarReduce(out);
    return true;
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

uint256 CNoteVoteShare::GetHash() const
{
    return SerializeHash(*this);
}

bool CNoteVoteShare::GetCommitment(PrivacyVNextDigest& commitmentOut) const
{
    if (vVssCoefficients.empty())
        return false;
    return DigestFromBytes(vVssCoefficients[0], commitmentOut);
}

bool CNoteVoteShare::GetRewardCommitment(PrivacyVNextDigest& commitmentOut) const
{
    if (vRewardVssCoefficients.empty())
        return false;
    return DigestFromBytes(vRewardVssCoefficients[0], commitmentOut);
}

uint256 CNoteVoteRewardProof::GetHash() const
{
    return SerializeHash(*this);
}

bool CNoteVoteRewardProof::IsValidBasic(std::string* pstrError) const
{
    if (vchQuotient.size() != FINALITY_NOTE_POINT_SIZE ||
        vchCoinAge.size() != FINALITY_NOTE_POINT_SIZE)
    {
        Fail(pstrError, "note vote reward proof auxiliary commitment is not a point");
        return false;
    }
    if (vProofs.size() != (size_t)NOTE_VOTE_REWARD_STATEMENT_COUNT)
    {
        Fail(pstrError, "note vote reward proof does not carry every statement");
        return false;
    }
    for (size_t i = 0; i < vProofs.size(); i++)
    {
        if (vProofs[i].empty() || vProofs[i].size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
        {
            Fail(pstrError, "note vote reward proof statement has an unusable length");
            return false;
        }
    }
    return true;
}

bool CNoteVoteShare::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != FINALITY_NOTE_SHARE_VERSION)
    {
        Fail(pstrError, "note vote share version is not the F2 version");
        return false;
    }
    if (nEpoch < 0)
    {
        Fail(pstrError, "note vote share epoch is negative");
        return false;
    }
    if (committeeSetHash == 0)
    {
        Fail(pstrError, "note vote share names no committee");
        return false;
    }
    if (vVssCoefficients.empty() ||
        vVssCoefficients.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS)
    {
        Fail(pstrError, "note vote share has an unusable coefficient count");
        return false;
    }
    for (size_t i = 0; i < vVssCoefficients.size(); i++)
    {
        if (vVssCoefficients[i].size() != FINALITY_NOTE_POINT_SIZE)
        {
            Fail(pstrError, "note vote share coefficient is not a point");
            return false;
        }
    }
    // One reward coefficient per weight coefficient. A shorter reward vector would let a
    // voter share a reward polynomial of a degree the committee never agreed to, which
    // interpolates to the wrong sum while every individual evaluation still checks.
    if (vRewardVssCoefficients.size() != vVssCoefficients.size())
    {
        Fail(pstrError, "note vote share reward coefficient count is not the weight count");
        return false;
    }
    for (size_t i = 0; i < vRewardVssCoefficients.size(); i++)
    {
        if (vRewardVssCoefficients[i].size() != FINALITY_NOTE_POINT_SIZE)
        {
            Fail(pstrError, "note vote share reward coefficient is not a point");
            return false;
        }
    }
    if (vEncryptedRecipientShares.size() < vVssCoefficients.size() ||
        vEncryptedRecipientShares.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS)
    {
        Fail(pstrError, "note vote share has fewer envelopes than the threshold needs");
        return false;
    }
    for (size_t i = 0; i < vEncryptedRecipientShares.size(); i++)
    {
        if (vEncryptedRecipientShares[i].empty() ||
            vEncryptedRecipientShares[i].size() > FINALITY_NOTE_MAX_ENVELOPE_BYTES)
        {
            Fail(pstrError, "note vote share envelope has an unusable length");
            return false;
        }
    }
    return true;
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

bool CNoteFinalityVote::GetRewardCommitment(PrivacyVNextDigest& out) const
{
    return DigestFromBytes(vchRewardCommitment, out);
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
    if (vchRewardCommitment.size() != FINALITY_NOTE_POINT_SIZE)
    {
        Fail(pstrError, "note vote reward commitment is not a point");
        return false;
    }
    if (hashRewardProof == 0)
    {
        Fail(pstrError, "note vote names no reward proof");
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
    if (share.nEpoch != nEpoch || share.committeeSetHash != committeeSetHash)
    {
        Fail(pstrError, "note vote share does not name the vote's epoch and committee");
        return false;
    }
    return share.IsValidBasic(pstrError);
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
    // R and its proof. R decides what this vote is paid, so leaving it unbound would let
    // a relaying peer swap in another commitment -- one it can open -- under a sigma that
    // still verifies, and be paid out of the epoch's mint for a vote it did not cast.
    ss << vote.vchRewardCommitment;
    ss << vote.hashRewardProof;
    // The share hash is what makes one share structurally the vote's own: a mutated or
    // duplicated share reaches a different digest and no longer matches any sigma.
    ss << vote.share.GetHash();
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

namespace
{
// One term of a statement point. A generator term carries no point of its own.
PrivacyVNextCombineTerm SuppliedTerm(const uint256& scalar, const PrivacyVNextDigest& point)
{
    PrivacyVNextCombineTerm term;
    term.nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    term.scalar = Ed25519ScalarToDigest(scalar);
    term.point = point;
    return term;
}

PrivacyVNextCombineTerm MoneroHTerm(const uint256& scalar)
{
    PrivacyVNextCombineTerm term;
    term.nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    term.scalar = Ed25519ScalarToDigest(scalar);
    return term;
}

// The three divisors the reward formula truncates by, as field scalars.
const int64_t NOTE_REWARD_SECONDS_PER_DAY = 24 * 60 * 60;
const int64_t NOTE_REWARD_DAYS_PER_YEAR = 365;

/** Split one weight into the quotients and remainders GetFinalityVoteReward truncates by.
 *
 *  Every product below is bounded by MAX_MONEY * nEpochInterval, so the int64 arithmetic
 *  is exact for any weight and interval consensus can present; the caller range-checks
 *  both before calling. */
bool DecomposeNoteVoteReward(int64_t nAmount, int nEpochInterval, int64_t nRatePerCoinYear,
                             int64_t& nQuotientOut, int64_t& nCoinRemainderOut,
                             int64_t& nCoinAgeOut, int64_t& nDayRemainderOut,
                             int64_t& nRewardOut, int64_t& nYearRemainderOut)
{
    if (nAmount < 0 || nAmount > MAX_MONEY || nEpochInterval <= 0 || nRatePerCoinYear <= 0)
        return false;
    if (nAmount != 0 && nEpochInterval > std::numeric_limits<int64_t>::max() / nAmount)
        return false;

    const int64_t nProduct = nAmount * (int64_t)nEpochInterval;
    nQuotientOut = nProduct / COIN;
    nCoinRemainderOut = nProduct % COIN;
    nCoinAgeOut = nQuotientOut / NOTE_REWARD_SECONDS_PER_DAY;
    nDayRemainderOut = nQuotientOut % NOTE_REWARD_SECONDS_PER_DAY;

    if (nCoinAgeOut != 0 &&
        nRatePerCoinYear > std::numeric_limits<int64_t>::max() / nCoinAgeOut)
        return false;
    const int64_t nRewardProduct = nCoinAgeOut * nRatePerCoinYear;
    nRewardOut = nRewardProduct / NOTE_REWARD_DAYS_PER_YEAR;
    nYearRemainderOut = nRewardProduct % NOTE_REWARD_DAYS_PER_YEAR;

    // GetFinalityVoteReward saturates at MAX_MONEY, which would break the exact identity
    // the proof rests on. Unreachable for a weight in the money range at any interval
    // this chain schedules, so refuse rather than silently prove a different statement.
    if (nRewardOut > MAX_MONEY)
        return false;
    return nRewardOut == GetFinalityVoteReward(nAmount, nEpochInterval, nRatePerCoinYear);
}
} // namespace

bool DeriveNoteVoteRewardStatementPoints(const PrivacyVNextDigest& cTilde,
                                         const PrivacyVNextDigest& rewardCommitment,
                                         const CNoteVoteRewardProof& proof,
                                         int nHeight,
                                         std::vector<PrivacyVNextDigest>& vPointsOut,
                                         std::string* pstrError)
{
    vPointsOut.clear();
    // Both constants come from the height, never from anything the vote carries, so a
    // voter cannot name the pair that pays best and the two sides cannot disagree.
    const int nEpochInterval = GetFinalityRewardUnits(nHeight);
    const int64_t nRatePerCoinYear = GetFinalityVoteRate(nHeight);
    if (nEpochInterval <= 0 || nRatePerCoinYear <= 0)
    {
        Fail(pstrError, "note vote reward statement has no epoch interval");
        return false;
    }
    PrivacyVNextDigest quotient = ZeroDigest();
    PrivacyVNextDigest coinAge = ZeroDigest();
    if (!DigestFromBytes(proof.vchQuotient, quotient) ||
        !DigestFromBytes(proof.vchCoinAge, coinAge))
    {
        Fail(pstrError, "note vote reward proof auxiliary commitment is not a point");
        return false;
    }

    const uint256 one = Ed25519ScalarFromUint64(1);
    const uint256 interval = Ed25519ScalarFromInt64((int64_t)nEpochInterval);
    const uint256 negInterval = Ed25519ScalarNeg(interval);
    const uint256 coin = Ed25519ScalarFromInt64(COIN);
    const uint256 negCoin = Ed25519ScalarNeg(coin);
    const uint256 day = Ed25519ScalarFromInt64(NOTE_REWARD_SECONDS_PER_DAY);
    const uint256 negDay = Ed25519ScalarNeg(day);
    const uint256 yearReward = Ed25519ScalarFromInt64(nRatePerCoinYear);
    const uint256 negYearReward = Ed25519ScalarNeg(yearReward);
    const uint256 year = Ed25519ScalarFromInt64(NOTE_REWARD_DAYS_PER_YEAR);
    const uint256 negYear = Ed25519ScalarNeg(year);
    const uint256 negOne = Ed25519ScalarNeg(one);

    std::vector<std::vector<PrivacyVNextCombineTerm> > vStatements(
        NOTE_VOTE_REWARD_STATEMENT_COUNT);

    // r1 = interval*w - COIN*q1, as a point: interval*C~ - COIN*Q.
    vStatements[NOTE_VOTE_REWARD_COIN_REMAINDER].push_back(SuppliedTerm(interval, cTilde));
    vStatements[NOTE_VOTE_REWARD_COIN_REMAINDER].push_back(SuppliedTerm(negCoin, quotient));
    // COIN-1-r1, the other half of 0 <= r1 < COIN.
    vStatements[NOTE_VOTE_REWARD_COIN_REMAINDER_SLACK].push_back(
        MoneroHTerm(Ed25519ScalarFromInt64(COIN - 1)));
    vStatements[NOTE_VOTE_REWARD_COIN_REMAINDER_SLACK].push_back(
        SuppliedTerm(negInterval, cTilde));
    vStatements[NOTE_VOTE_REWARD_COIN_REMAINDER_SLACK].push_back(
        SuppliedTerm(coin, quotient));

    // r2 = q1 - 86400*a.
    vStatements[NOTE_VOTE_REWARD_DAY_REMAINDER].push_back(SuppliedTerm(one, quotient));
    vStatements[NOTE_VOTE_REWARD_DAY_REMAINDER].push_back(SuppliedTerm(negDay, coinAge));
    vStatements[NOTE_VOTE_REWARD_DAY_REMAINDER_SLACK].push_back(
        MoneroHTerm(Ed25519ScalarFromInt64(NOTE_REWARD_SECONDS_PER_DAY - 1)));
    vStatements[NOTE_VOTE_REWARD_DAY_REMAINDER_SLACK].push_back(
        SuppliedTerm(negOne, quotient));
    vStatements[NOTE_VOTE_REWARD_DAY_REMAINDER_SLACK].push_back(SuppliedTerm(day, coinAge));

    // a itself. Without it a prover could pick a remainder that makes the quotient
    // non-integral, which leaves the "quotient" a field element of no bounded size.
    vStatements[NOTE_VOTE_REWARD_COIN_AGE].push_back(SuppliedTerm(one, coinAge));

    // r3 = COIN_YEAR_REWARD*a - 365*f.
    vStatements[NOTE_VOTE_REWARD_YEAR_REMAINDER].push_back(
        SuppliedTerm(yearReward, coinAge));
    vStatements[NOTE_VOTE_REWARD_YEAR_REMAINDER].push_back(
        SuppliedTerm(negYear, rewardCommitment));
    vStatements[NOTE_VOTE_REWARD_YEAR_REMAINDER_SLACK].push_back(
        MoneroHTerm(Ed25519ScalarFromInt64(NOTE_REWARD_DAYS_PER_YEAR - 1)));
    vStatements[NOTE_VOTE_REWARD_YEAR_REMAINDER_SLACK].push_back(
        SuppliedTerm(negYearReward, coinAge));
    vStatements[NOTE_VOTE_REWARD_YEAR_REMAINDER_SLACK].push_back(
        SuppliedTerm(year, rewardCommitment));

    // f itself, so the epoch's sum of rewards cannot be made to wrap the group order.
    vStatements[NOTE_VOTE_REWARD_VALUE].push_back(SuppliedTerm(one, rewardCommitment));

    vPointsOut.resize(NOTE_VOTE_REWARD_STATEMENT_COUNT);
    for (size_t i = 0; i < vStatements.size(); i++)
    {
        std::string error;
        if (!CombinePrivacyVNextPoints(vStatements[i], vPointsOut[i], error))
        {
            vPointsOut.clear();
            Fail(pstrError, "note vote reward statement point could not be derived");
            return false;
        }
    }
    return true;
}

bool BuildNoteVoteRewardProof(int64_t nAmount,
                              const uint256& maskTilde,
                              const uint256& rewardBlind,
                              int nHeight,
                              CNoteVoteRewardProof& proofOut,
                              PrivacyVNextDigest& rewardCommitmentOut,
                              std::string* pstrError)
{
    proofOut = CNoteVoteRewardProof();
    rewardCommitmentOut = ZeroDigest();

    const int nEpochInterval = GetFinalityRewardUnits(nHeight);
    const int64_t nRatePerCoinYear = GetFinalityVoteRate(nHeight);

    int64_t nQuotient = 0, nCoinRemainder = 0, nCoinAge = 0;
    int64_t nDayRemainder = 0, nReward = 0, nYearRemainder = 0;
    if (!DecomposeNoteVoteReward(nAmount, nEpochInterval, nRatePerCoinYear, nQuotient, nCoinRemainder,
                                 nCoinAge, nDayRemainder, nReward, nYearRemainder))
    {
        Fail(pstrError, "note vote reward could not be decomposed for its weight");
        return false;
    }

    uint256 quotientBlind = 0;
    uint256 coinAgeBlind = 0;
    if (!DrawScalar(quotientBlind) || !DrawScalar(coinAgeBlind))
    {
        Fail(pstrError, "note vote reward proof could not draw its blinds");
        return false;
    }

    PrivacyVNextDigest quotientPoint = ZeroDigest();
    PrivacyVNextDigest coinAgePoint = ZeroDigest();
    bool fOk = CommitScaled(Ed25519ScalarFromInt64(nQuotient), quotientBlind,
                            quotientPoint, pstrError) &&
               CommitScaled(Ed25519ScalarFromInt64(nCoinAge), coinAgeBlind,
                            coinAgePoint, pstrError) &&
               CommitScaled(Ed25519ScalarFromInt64(nReward), rewardBlind,
                            rewardCommitmentOut, pstrError);
    if (fOk)
    {
        proofOut.vchQuotient.assign(quotientPoint.begin(), quotientPoint.end());
        proofOut.vchCoinAge.assign(coinAgePoint.begin(), coinAgePoint.end());
    }

    // The blind of every derived point follows from the three the prover drew, exactly as
    // its value follows from the three equations. Deriving them rather than drawing them
    // is what makes each statement land on the point the validator recomputes.
    const uint256 interval = Ed25519ScalarFromInt64((int64_t)nEpochInterval);
    const uint256 coin = Ed25519ScalarFromInt64(COIN);
    const uint256 day = Ed25519ScalarFromInt64(NOTE_REWARD_SECONDS_PER_DAY);
    const uint256 yearReward = Ed25519ScalarFromInt64(nRatePerCoinYear);
    const uint256 year = Ed25519ScalarFromInt64(NOTE_REWARD_DAYS_PER_YEAR);

    const uint256 coinRemainderBlind =
        Ed25519ScalarSub(Ed25519ScalarMul(interval, maskTilde),
                         Ed25519ScalarMul(coin, quotientBlind));
    const uint256 dayRemainderBlind =
        Ed25519ScalarSub(quotientBlind, Ed25519ScalarMul(day, coinAgeBlind));
    const uint256 yearRemainderBlind =
        Ed25519ScalarSub(Ed25519ScalarMul(yearReward, coinAgeBlind),
                         Ed25519ScalarMul(year, rewardBlind));

    std::vector<int64_t> vValues(NOTE_VOTE_REWARD_STATEMENT_COUNT, 0);
    std::vector<uint256> vBlinds(NOTE_VOTE_REWARD_STATEMENT_COUNT);
    vValues[NOTE_VOTE_REWARD_COIN_REMAINDER] = nCoinRemainder;
    vBlinds[NOTE_VOTE_REWARD_COIN_REMAINDER] = coinRemainderBlind;
    vValues[NOTE_VOTE_REWARD_COIN_REMAINDER_SLACK] = COIN - 1 - nCoinRemainder;
    vBlinds[NOTE_VOTE_REWARD_COIN_REMAINDER_SLACK] = Ed25519ScalarNeg(coinRemainderBlind);
    vValues[NOTE_VOTE_REWARD_DAY_REMAINDER] = nDayRemainder;
    vBlinds[NOTE_VOTE_REWARD_DAY_REMAINDER] = dayRemainderBlind;
    vValues[NOTE_VOTE_REWARD_DAY_REMAINDER_SLACK] =
        NOTE_REWARD_SECONDS_PER_DAY - 1 - nDayRemainder;
    vBlinds[NOTE_VOTE_REWARD_DAY_REMAINDER_SLACK] = Ed25519ScalarNeg(dayRemainderBlind);
    vValues[NOTE_VOTE_REWARD_COIN_AGE] = nCoinAge;
    vBlinds[NOTE_VOTE_REWARD_COIN_AGE] = coinAgeBlind;
    vValues[NOTE_VOTE_REWARD_YEAR_REMAINDER] = nYearRemainder;
    vBlinds[NOTE_VOTE_REWARD_YEAR_REMAINDER] = yearRemainderBlind;
    vValues[NOTE_VOTE_REWARD_YEAR_REMAINDER_SLACK] =
        NOTE_REWARD_DAYS_PER_YEAR - 1 - nYearRemainder;
    vBlinds[NOTE_VOTE_REWARD_YEAR_REMAINDER_SLACK] = Ed25519ScalarNeg(yearRemainderBlind);
    vValues[NOTE_VOTE_REWARD_VALUE] = nReward;
    vBlinds[NOTE_VOTE_REWARD_VALUE] = rewardBlind;

    // Derive the points the validator will reach from this weight's own C~ and prove
    // against those, so a proof that would be rejected on arrival never leaves the
    // producer.
    PrivacyVNextDigest cTilde = ZeroDigest();
    std::vector<PrivacyVNextDigest> vPoints;
    if (fOk)
        fOk = CommitScaled(Ed25519ScalarFromInt64(nAmount), maskTilde, cTilde, pstrError) &&
              DeriveNoteVoteRewardStatementPoints(cTilde, rewardCommitmentOut, proofOut,
                                                  nHeight, vPoints, pstrError);

    for (size_t i = 0; fOk && i < vPoints.size(); i++)
    {
        if (vValues[i] < 0)
        {
            Fail(pstrError, "note vote reward statement value is negative");
            fOk = false;
            break;
        }
        PrivacyVNextDigest entropy = ZeroDigest();
        if (!DrawProofEntropy(entropy))
        {
            Fail(pstrError, "note vote reward proof could not draw proving entropy");
            fOk = false;
            break;
        }
        PrivacyVNextDigest commitment = ZeroDigest();
        std::vector<unsigned char> vchProof;
        std::string error;
        const bool fProved = ProvePrivacyVNextRange((uint64_t)vValues[i],
                                                    Ed25519ScalarToDigest(vBlinds[i]),
                                                    entropy, commitment, vchProof, error);
        OPENSSL_cleanse(entropy.data(), entropy.size());
        if (!fProved || vchProof.empty() ||
            vchProof.size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
        {
            Fail(pstrError, "note vote reward statement could not be range-proved");
            fOk = false;
            break;
        }
        if (commitment != vPoints[i])
        {
            Fail(pstrError, "note vote reward statement lands on a point the validator misses");
            fOk = false;
            break;
        }
        proofOut.vProofs.push_back(vchProof);
    }

    OPENSSL_cleanse(quotientBlind.begin(), 32);
    OPENSSL_cleanse(coinAgeBlind.begin(), 32);
    for (size_t i = 0; i < vBlinds.size(); i++)
        OPENSSL_cleanse(vBlinds[i].begin(), 32);

    if (fOk)
        fOk = proofOut.IsValidBasic(pstrError);
    if (!fOk)
    {
        proofOut = CNoteVoteRewardProof();
        rewardCommitmentOut = ZeroDigest();
    }
    return fOk;
}

bool CheckNoteVoteRewardProof(const CNoteFinalityVote& vote,
                              const CNoteVoteRewardProof& proof,
                              std::string* pstrError)
{
    if (!proof.IsValidBasic(pstrError))
        return false;
    // The vote's own choice of proof, not whichever one a payer found lying about.
    if (proof.GetHash() != vote.hashRewardProof)
    {
        Fail(pstrError, "note vote reward proof is not the one the vote names");
        return false;
    }

    PrivacyVNextDigest cTilde = ZeroDigest();
    PrivacyVNextDigest rewardCommitment = ZeroDigest();
    if (!vote.GetCTilde(cTilde))
    {
        Fail(pstrError, "note vote membership instance carries no input tuple");
        return false;
    }
    if (!vote.GetRewardCommitment(rewardCommitment))
    {
        Fail(pstrError, "note vote reward commitment is not a point");
        return false;
    }

    // The reward constants are the ones the vote's own epoch-boundary height selects.
    std::vector<PrivacyVNextDigest> vPoints;
    if (!DeriveNoteVoteRewardStatementPoints(cTilde, rewardCommitment, proof,
                                             vote.nHeight, vPoints, pstrError))
        return false;
    if (vPoints.size() != proof.vProofs.size())
    {
        Fail(pstrError, "note vote reward proof statement count does not match");
        return false;
    }

    for (size_t i = 0; i < vPoints.size(); i++)
    {
        std::string error;
        if (!VerifyPrivacyVNextRange(vPoints[i], ZeroDigest(), proof.vProofs[i], error))
        {
            Fail(pstrError, "note vote reward proof does not show the formula's reward");
            return false;
        }
    }
    return true;
}

bool CheckNoteVote(const CNoteFinalityVote& vote,
                   int nThresholdM,
                   int nCommitteeN,
                   std::string* pstrError)
{
    if (!vote.IsValidBasic(pstrError))
        return false;

    // A threshold of one would let a single member open this voter's exact weight, which
    // is the one thing the share split exists to prevent.
    if (nThresholdM < 2 || nThresholdM > nCommitteeN ||
        nCommitteeN > (int)FINALITY_NOTE_MAX_VSS_COEFFICIENTS)
    {
        Fail(pstrError, "note vote has no usable committee to check its share against");
        return false;
    }
    if ((int)vote.share.vVssCoefficients.size() != nThresholdM ||
        (int)vote.share.vRewardVssCoefficients.size() != nThresholdM)
    {
        Fail(pstrError, "note vote share degree is not the committee threshold");
        return false;
    }
    if ((int)vote.share.vEncryptedRecipientShares.size() != nCommitteeN)
    {
        Fail(pstrError, "note vote share does not reach every committee member");
        return false;
    }

    PrivacyVNextDigest oTilde = ZeroDigest();
    PrivacyVNextDigest cTilde = ZeroDigest();
    if (!vote.GetOTilde(oTilde) || !vote.GetCTilde(cTilde))
    {
        Fail(pstrError, "note vote membership instance carries no input tuple");
        return false;
    }

    // K_0 == C~. Without it a voter could share an opening of some other commitment, and
    // the epoch's recovered sum would fail to open the validator-recomputed total with
    // nothing to say who caused it.
    PrivacyVNextDigest commitment = ZeroDigest();
    if (!vote.share.GetCommitment(commitment) || commitment != cTilde)
    {
        Fail(pstrError, "note vote share coefficient K_0 is not the vote's commitment");
        return false;
    }

    // L_0 == R, the reward side of the same rule. Without it the reward evaluations
    // authenticate against a commitment the vote never published and the reward proof
    // constrains, so a voter could prove the right reward and share a different one.
    PrivacyVNextDigest rewardCommitment = ZeroDigest();
    PrivacyVNextDigest rewardCoefficient = ZeroDigest();
    if (!vote.GetRewardCommitment(rewardCommitment) ||
        !vote.share.GetRewardCommitment(rewardCoefficient) ||
        rewardCoefficient != rewardCommitment)
    {
        Fail(pstrError, "note vote share coefficient L_0 is not the vote's reward commitment");
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
    // The reward proof is deliberately not checked here: it rides beside the vote, so a
    // validator holding only the vote cannot check it, and a vote whose proof was never
    // carried has to be a vote that counts and cannot be paid rather than an invalid one.
    // CheckNoteVoteRewardProof is what the payer runs, against the proof this vote named.
    return true;
}

bool BuildNoteFinalityVote(const CNoteVoteBuildContext& ctx,
                           const PrivacyVNextSpendInput& input,
                           const PrivacyVNextDigest& noteMask,
                           const CFinalityTallyConfig& config,
                           CNoteFinalityVote& voteOut,
                           CNoteVoteRewardProof& rewardProofOut,
                           std::string* pstrError)
{
    voteOut = CNoteFinalityVote();
    rewardProofOut = CNoteVoteRewardProof();

    if (ctx.nEpoch < 0 || ctx.nHeight < 0 || ctx.hashBlock == 0 ||
        ctx.hashAnchorRoot == 0 || ctx.hashNullifierRoot == 0)
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
    const int64_t nReward = GetFinalityVoteRewardAtHeight(ctx.nAmount, ctx.nHeight);
    if (nReward < 0 || nReward > MAX_MONEY)
    {
        Fail(pstrError, "note vote reward is outside the range a vote may carry");
        return false;
    }
    if (!config.fCommitteeValid || config.nThresholdM < 2 ||
        config.nThresholdM > (int)config.vCommitteePubKeys.size() ||
        config.vCommitteePubKeys.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS ||
        config.committeeSetHash == 0)
    {
        Fail(pstrError, "note vote needs a valid M-of-N committee with M above one");
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
    uint256 rewardBlind = 0;
    bool fOk = DrawScalar(rewardBlind);
    if (!fOk)
        Fail(pstrError, "note vote could not draw its reward blind");

    if (fOk)
    {
        voteOut.nVersion = FINALITY_NOTE_VOTE_VERSION;
        voteOut.nEpoch = ctx.nEpoch;
        voteOut.hashBlock = ctx.hashBlock;
        voteOut.nHeight = ctx.nHeight;
        voteOut.hashCurveRoot = ctx.hashAnchorRoot;
        voteOut.hashNullifierRoot = ctx.hashNullifierRoot;
        voteOut.committeeSetHash = config.committeeSetHash;
        voteOut.vchMembership = membership.vchRequest;

        voteOut.share.nEpoch = ctx.nEpoch;
        voteOut.share.committeeSetHash = config.committeeSetHash;
        fOk = BuildNoteVoteShare(voteOut.share, ctx.nAmount, maskTilde, nReward,
                                 rewardBlind, config, pstrError);
    }

    // The reward proof recomputes the reward from the weight, so it is what decides what
    // R commits to; ctx.nReward only has to agree with it. Building R here and requiring
    // the share's L_0 to equal it keeps one value behind both.
    PrivacyVNextDigest rewardCommitment = ZeroDigest();
    if (fOk)
    {
        fOk = BuildNoteVoteRewardProof(ctx.nAmount, maskTilde, rewardBlind,
                                       ctx.nHeight, rewardProofOut,
                                       rewardCommitment, pstrError);
        if (fOk)
        {
            voteOut.vchRewardCommitment.assign(rewardCommitment.begin(),
                                               rewardCommitment.end());
            voteOut.hashRewardProof = rewardProofOut.GetHash();
        }
    }

    // K_0 == C~ and L_0 == R are consensus rules, so a share that does not reach the
    // membership proof's own commitment, or the reward the proof is over, is a vote the
    // network would reject: stop here instead.
    if (fOk)
    {
        PrivacyVNextDigest commitment = ZeroDigest();
        fOk = voteOut.share.GetCommitment(commitment) && commitment == membership.cTilde;
        if (!fOk)
            Fail(pstrError, "note vote share does not open the membership proof's commitment");
    }
    if (fOk)
    {
        PrivacyVNextDigest rewardCoefficient = ZeroDigest();
        fOk = voteOut.share.GetRewardCommitment(rewardCoefficient) &&
              rewardCoefficient == rewardCommitment;
        if (!fOk)
            Fail(pstrError, "note vote share does not open the vote's reward commitment");
    }

    if (fOk)
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
    OPENSSL_cleanse(rewardBlind.begin(), 32);
    OPENSSL_cleanse(membership.maskDelta.data(), membership.maskDelta.size());
    OPENSSL_cleanse(membership.rerandomizedY.data(), membership.rerandomizedY.size());

    // Verify what was built with the checker consensus runs, so a vote that would be
    // rejected on arrival never leaves the producer.
    if (fOk)
        fOk = CheckNoteVote(voteOut, config.nThresholdM,
                            (int)config.vCommitteePubKeys.size(), pstrError);
    // The proof is checked here rather than at connect, because this is the only place
    // both halves are in hand at once. A producer that emits a vote whose proof does not
    // verify has cast a vote it can never be paid for.
    if (fOk)
        fOk = CheckNoteVoteRewardProof(voteOut, rewardProofOut, pstrError);
    if (!fOk)
    {
        voteOut = CNoteFinalityVote();
        rewardProofOut = CNoteVoteRewardProof();
    }
    return fOk;
}

bool BuildNoteVoteShare(CNoteVoteShare& share,
                        int64_t nAmount,
                        const uint256& maskTilde,
                        int64_t nReward,
                        const uint256& rewardBlind,
                        const CFinalityTallyConfig& config,
                        std::string* pstrError)
{
    // M of one is a committee that opens individual weights, so it is not a committee a
    // note vote can share to.
    if (!config.fCommitteeValid || config.nThresholdM < 2 ||
        config.nThresholdM > (int)config.vCommitteePubKeys.size() ||
        config.vCommitteePubKeys.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS)
    {
        Fail(pstrError, "note vote share needs a valid M-of-N committee with M above one");
        return false;
    }
    if (nAmount < 0 || nAmount > MAX_MONEY || nReward < 0 || nReward > MAX_MONEY)
    {
        Fail(pstrError, "note vote share amount is out of range");
        return false;
    }
    if (share.nEpoch < 0 || share.committeeSetHash != config.committeeSetHash)
    {
        Fail(pstrError, "note vote share does not name the configured committee");
        return false;
    }

    share.nVersion = FINALITY_NOTE_SHARE_VERSION;
    share.vVssCoefficients.clear();
    share.vRewardVssCoefficients.clear();
    share.vEncryptedRecipientShares.clear();

    const int nDegree = config.nThresholdM - 1;
    std::vector<uint256> vWeight, vWeightBlind, vReward, vRewardBlind;
    if (!BuildShamirPolynomial(Ed25519ScalarFromInt64(nAmount), nDegree, vWeight) ||
        !BuildShamirPolynomial(maskTilde, nDegree, vWeightBlind) ||
        !BuildShamirPolynomial(Ed25519ScalarFromInt64(nReward), nDegree, vReward) ||
        !BuildShamirPolynomial(rewardBlind, nDegree, vRewardBlind))
    {
        Fail(pstrError, "note vote share could not draw its polynomials");
        return false;
    }

    // K_k = a_k*H + b_k*G. K_0 is the vote's own commitment by construction, so any M
    // accepted evaluations interpolate to an opening of it and of nothing else. L_k is
    // the same construction over the reward pair, so the same holds of the reward.
    for (size_t k = 0; k < vWeight.size(); k++)
    {
        PrivacyVNextDigest coefficient = ZeroDigest();
        if (!CommitScaled(vWeight[k], vWeightBlind[k], coefficient, pstrError))
            return false;
        share.vVssCoefficients.push_back(
            std::vector<unsigned char>(coefficient.begin(), coefficient.end()));

        PrivacyVNextDigest rewardCoefficient = ZeroDigest();
        if (!CommitScaled(vReward[k], vRewardBlind[k], rewardCoefficient, pstrError))
            return false;
        share.vRewardVssCoefficients.push_back(
            std::vector<unsigned char>(rewardCoefficient.begin(), rewardCoefficient.end()));
    }

    for (size_t i = 0; i < config.vCommitteePubKeys.size(); i++)
    {
        const int nRecipientIndex = (int)i;
        const int nX = nRecipientIndex + 1;
        uint256 evalWeight, evalWeightBlind, evalReward, evalRewardBlind;
        if (!EvaluatePolynomial(vWeight, nX, evalWeight) ||
            !EvaluatePolynomial(vWeightBlind, nX, evalWeightBlind) ||
            !EvaluatePolynomial(vReward, nX, evalReward) ||
            !EvaluatePolynomial(vRewardBlind, nX, evalRewardBlind))
        {
            Fail(pstrError, "note vote share could not evaluate its polynomials");
            return false;
        }

        CKey ephemeralKey;
        ephemeralKey.MakeNewKey(true);
        const CPubKey ephemeralPubKey = ephemeralKey.GetPubKey();
        if (!ephemeralKey.IsValid() || !ephemeralPubKey.IsValid() ||
            !ephemeralPubKey.IsCompressed())
        {
            Fail(pstrError, "note vote share could not draw an ephemeral key");
            return false;
        }
        unsigned char sharedBytes[33];
        std::vector<unsigned char> vchKey;
        if (!ComputeSharedPoint(ephemeralKey, config.vCommitteePubKeys[i], sharedBytes) ||
            !DeriveNoteShareKeyFromSharedPoint(sharedBytes, config.vCommitteePubKeys[i],
                                               ephemeralPubKey, nRecipientIndex,
                                               config.committeeSetHash, vchKey))
        {
            OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));
            Fail(pstrError, "note vote share could not derive its envelope key");
            return false;
        }
        OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));

        CDataStream ssPlain(SER_NETWORK, PROTOCOL_VERSION);
        ssPlain << (uint32_t)FINALITY_NOTE_SHARE_VERSION;
        ssPlain << nRecipientIndex;
        ssPlain << nX;
        ssPlain << evalWeight;
        ssPlain << evalWeightBlind;
        ssPlain << evalReward;
        ssPlain << evalRewardBlind;
        const std::vector<unsigned char> vchPlain(ssPlain.begin(), ssPlain.end());
        const std::vector<unsigned char> vchAAD =
            BuildNoteShareAAD(share, nRecipientIndex, ephemeralPubKey);
        std::vector<unsigned char> vchCiphertext;
        const bool fEncrypted =
            ChaCha20Poly1305Encrypt(vchKey, vchPlain, vchAAD, vchCiphertext);
        OPENSSL_cleanse(&vchKey[0], vchKey.size());
        if (!fEncrypted)
        {
            Fail(pstrError, "note vote share envelope could not be sealed");
            return false;
        }

        CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
        ssOut << (uint32_t)FINALITY_NOTE_SHARE_VERSION;
        ssOut << nRecipientIndex;
        ssOut << std::vector<unsigned char>(ephemeralPubKey.begin(), ephemeralPubKey.end());
        ssOut << vchCiphertext;
        share.vEncryptedRecipientShares.push_back(
            std::vector<unsigned char>(ssOut.begin(), ssOut.end()));
    }
    return share.vEncryptedRecipientShares.size() == config.vCommitteePubKeys.size();
}

bool CheckNoteVoteVssEvaluation(const CNoteVoteShare& share,
                                const CNoteTallyPlainShare& plain,
                                std::string* pstrError)
{
    if (share.vVssCoefficients.empty() || plain.nX <= 0 ||
        share.vRewardVssCoefficients.size() != share.vVssCoefficients.size())
    {
        Fail(pstrError, "note vote share has nothing to check the evaluation against");
        return false;
    }

    std::vector<PrivacyVNextCombineTerm> vTerms;
    std::vector<PrivacyVNextCombineTerm> vRewardTerms;
    const uint256 x = Ed25519ScalarFromUint64((uint64_t)plain.nX);
    uint256 power = Ed25519ScalarFromUint64(1);
    for (size_t k = 0; k < share.vVssCoefficients.size(); k++)
    {
        PrivacyVNextCombineTerm term;
        term.nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
        term.scalar = Ed25519ScalarToDigest(power);
        PrivacyVNextCombineTerm rewardTerm = term;
        if (!DigestFromBytes(share.vVssCoefficients[k], term.point) ||
            !DigestFromBytes(share.vRewardVssCoefficients[k], rewardTerm.point))
        {
            Fail(pstrError, "note vote share coefficient is not a point");
            return false;
        }
        vTerms.push_back(term);
        vRewardTerms.push_back(rewardTerm);
        power = Ed25519ScalarMul(power, x);
    }

    PrivacyVNextDigest expected = ZeroDigest();
    PrivacyVNextDigest expectedReward = ZeroDigest();
    std::string error;
    if (!CombinePrivacyVNextPoints(vTerms, expected, error) ||
        !CombinePrivacyVNextPoints(vRewardTerms, expectedReward, error))
    {
        Fail(pstrError, "note vote share coefficient sum could not be derived");
        return false;
    }
    PrivacyVNextDigest actual = ZeroDigest();
    if (!CommitScaled(plain.evalWeight, plain.evalWeightBlind, actual, pstrError))
        return false;
    if (actual != expected)
    {
        Fail(pstrError, "note vote share evaluation does not open its coefficients");
        return false;
    }
    // The reward pair, against L_k. This is what makes a shared reward the voter's own
    // published R rather than any scalar it liked, and it is what lets the aggregate
    // reward open strictly instead of being tolerated when it will not.
    PrivacyVNextDigest actualReward = ZeroDigest();
    if (!CommitScaled(plain.evalReward, plain.evalRewardBlind, actualReward, pstrError))
        return false;
    if (actualReward != expectedReward)
    {
        Fail(pstrError, "note vote share reward evaluation does not open its coefficients");
        return false;
    }
    return true;
}

bool DecryptNoteVoteShareForRecipient(const CNoteVoteShare& share,
                                      const CFinalityTallyConfig& config,
                                      const CKey& keyRecipient,
                                      int nRecipientIndex,
                                      CNoteTallyPlainShare& plainOut,
                                      bool* pfComplainable)
{
    if (pfComplainable)
        *pfComplainable = false;
    if (nRecipientIndex < 0 ||
        nRecipientIndex >= (int)config.vCommitteePubKeys.size() ||
        nRecipientIndex >= (int)share.vEncryptedRecipientShares.size() ||
        share.nVersion != FINALITY_NOTE_SHARE_VERSION ||
        share.committeeSetHash != config.committeeSetHash ||
        !keyRecipient.IsValid())
        return false;

    const CPubKey pubRecipient = keyRecipient.GetPubKey();
    if (!pubRecipient.IsValid() || !pubRecipient.IsCompressed() ||
        pubRecipient != config.vCommitteePubKeys[nRecipientIndex])
        return false;

    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    if (!ParseNoteShareEnvelope(share.vEncryptedRecipientShares[nRecipientIndex],
                                nEnvelopeRecipient, pubEphemeral, vchCiphertext) ||
        nEnvelopeRecipient != nRecipientIndex)
    {
        if (pfComplainable)
            *pfComplainable = true;
        return false;
    }

    unsigned char sharedBytes[33];
    std::vector<unsigned char> vchKey;
    if (!ComputeSharedPoint(keyRecipient, pubEphemeral, sharedBytes) ||
        !DeriveNoteShareKeyFromSharedPoint(sharedBytes, pubRecipient, pubEphemeral,
                                           nRecipientIndex, config.committeeSetHash,
                                           vchKey))
    {
        OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));
        if (pfComplainable)
            *pfComplainable = true;
        return false;
    }
    OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));

    const std::vector<unsigned char> vchAAD =
        BuildNoteShareAAD(share, nRecipientIndex, pubEphemeral);
    std::vector<unsigned char> vchPlain;
    const bool fOk = ChaCha20Poly1305Decrypt(vchCiphertext, vchKey, vchAAD, vchPlain);
    OPENSSL_cleanse(&vchKey[0], vchKey.size());
    if (!fOk)
    {
        if (pfComplainable)
            *pfComplainable = true;
        return false;
    }

    try
    {
        CDataStream ss(vchPlain, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nPlainVersion = 0;
        ss >> nPlainVersion;
        ss >> plainOut.nRecipientIndex;
        ss >> plainOut.nX;
        ss >> plainOut.evalWeight;
        ss >> plainOut.evalWeightBlind;
        ss >> plainOut.evalReward;
        ss >> plainOut.evalRewardBlind;
        if (nPlainVersion != FINALITY_NOTE_SHARE_VERSION ||
            plainOut.nRecipientIndex != nRecipientIndex ||
            plainOut.nX != nRecipientIndex + 1)
        {
            if (pfComplainable)
                *pfComplainable = true;
            return false;
        }
    }
    catch (const std::exception&)
    {
        if (pfComplainable)
            *pfComplainable = true;
        return false;
    }

    if (!CheckNoteVoteVssEvaluation(share, plainOut))
    {
        if (pfComplainable)
            *pfComplainable = true;
        return false;
    }
    return true;
}

bool AggregateNoteTallyPlainShares(const std::vector<CNoteTallyPlainShare>& vShares,
                                   CNoteTallyPlainShare& aggregateOut)
{
    if (vShares.empty())
        return false;

    aggregateOut = CNoteTallyPlainShare();
    aggregateOut.nRecipientIndex = vShares[0].nRecipientIndex;
    aggregateOut.nX = vShares[0].nX;
    for (size_t i = 0; i < vShares.size(); i++)
    {
        const CNoteTallyPlainShare& plain = vShares[i];
        if (plain.nRecipientIndex != aggregateOut.nRecipientIndex ||
            plain.nX != aggregateOut.nX || plain.nRecipientIndex < 0 || plain.nX <= 0)
            return false;
        aggregateOut.evalWeight = Ed25519ScalarAdd(aggregateOut.evalWeight, plain.evalWeight);
        aggregateOut.evalWeightBlind =
            Ed25519ScalarAdd(aggregateOut.evalWeightBlind, plain.evalWeightBlind);
        aggregateOut.evalReward = Ed25519ScalarAdd(aggregateOut.evalReward, plain.evalReward);
        aggregateOut.evalRewardBlind =
            Ed25519ScalarAdd(aggregateOut.evalRewardBlind, plain.evalRewardBlind);
    }
    return true;
}

bool RecoverNoteTallySecrets(const std::vector<CNoteTallyPlainShare>& vShares,
                             int nThreshold,
                             uint256& weightOut,
                             uint256& weightBlindOut,
                             uint256& rewardOut,
                             uint256& rewardBlindOut)
{
    if (nThreshold <= 0 || (int)vShares.size() < nThreshold)
        return false;

    std::vector<int> vX;
    std::vector<uint256> vWeight, vWeightBlind, vReward, vRewardBlind;
    for (size_t i = 0; i < vShares.size(); i++)
    {
        if (vShares[i].nX <= 0)
            return false;
        vX.push_back(vShares[i].nX);
        vWeight.push_back(vShares[i].evalWeight);
        vWeightBlind.push_back(vShares[i].evalWeightBlind);
        vReward.push_back(vShares[i].evalReward);
        vRewardBlind.push_back(vShares[i].evalRewardBlind);
    }
    return InterpolateAtZero(vX, vWeight, nThreshold, weightOut) &&
           InterpolateAtZero(vX, vWeightBlind, nThreshold, weightBlindOut) &&
           InterpolateAtZero(vX, vReward, nThreshold, rewardOut) &&
           InterpolateAtZero(vX, vRewardBlind, nThreshold, rewardBlindOut);
}

uint256 CNoteVoteComplaint::GetHash() const
{
    return SerializeHash(*this);
}

bool CNoteVoteComplaint::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != FINALITY_NOTE_COMPLAINT_VERSION)
    {
        Fail(pstrError, "note vote complaint version is not the F2 version");
        return false;
    }
    if (nEpoch < 0 || nRecipientIndex < 0 ||
        nRecipientIndex >= (int)FINALITY_NOTE_MAX_VSS_COEFFICIENTS)
    {
        Fail(pstrError, "note vote complaint names no usable recipient");
        return false;
    }
    if (voteTag == 0 || hashShare == 0)
    {
        Fail(pstrError, "note vote complaint names no vote");
        return false;
    }
    // An envelope that carries no ephemeral key names no shared point, so there is nothing
    // to reveal and nothing to prove: the share is its own evidence. That case is the one
    // empty form; every other complaint must carry both fields.
    if (vchSharedPoint.empty() && vchDleqProof.empty())
        return true;
    if (vchSharedPoint.size() != 33 || vchDleqProof.size() != FINALITY_NOTE_DLEQ_SIZE)
    {
        Fail(pstrError, "note vote complaint proof has the wrong length");
        return false;
    }
    return true;
}

namespace
{
// Chaum-Pedersen over secp256k1: the same secret opens the member's public key under G
// and the revealed point under the envelope's ephemeral key, so the point really is the
// shared secret that keyed this one envelope.
uint256 ComplaintChallenge(const CNoteVoteComplaint& complaint,
                           const CPubKey& pubMember,
                           const CPubKey& pubEphemeral,
                           const unsigned char sharedBytes[33],
                           const unsigned char nonceG[33],
                           const unsigned char nonceE[33])
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(NOTE_COMPLAINT_DLEQ_DOMAIN);
    ss << complaint.nEpoch;
    ss << complaint.voteTag;
    ss << complaint.hashShare;
    ss << complaint.nRecipientIndex;
    ss << std::vector<unsigned char>(pubMember.begin(), pubMember.end());
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    ss << std::vector<unsigned char>(sharedBytes, sharedBytes + 33);
    ss << std::vector<unsigned char>(nonceG, nonceG + 33);
    ss << std::vector<unsigned char>(nonceE, nonceE + 33);
    return ss.GetHash();
}

struct Secp256k1Context
{
    EC_GROUP* group;
    BN_CTX* ctx;
    BIGNUM* order;

    Secp256k1Context()
    {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        ctx = BN_CTX_new();
        order = BN_new();
        if (!group || !ctx || !order || EC_GROUP_get_order(group, order, ctx) != 1)
            Clear();
    }

    ~Secp256k1Context() { Clear(); }

    bool IsValid() const { return group && ctx && order; }

    void Clear()
    {
        if (order) { BN_free(order); order = NULL; }
        if (ctx) { BN_CTX_free(ctx); ctx = NULL; }
        if (group) { EC_GROUP_free(group); group = NULL; }
    }
};

bool PointFromBytes(const Secp256k1Context& c, const unsigned char* bytes, size_t nSize,
                    EC_POINT* out)
{
    return EC_POINT_oct2point(c.group, out, bytes, nSize, c.ctx) == 1 &&
           EC_POINT_is_on_curve(c.group, out, c.ctx) == 1 &&
           !EC_POINT_is_at_infinity(c.group, out);
}

bool PointToBytes(const Secp256k1Context& c, const EC_POINT* point, unsigned char out[33])
{
    return EC_POINT_point2oct(c.group, point, POINT_CONVERSION_COMPRESSED, out, 33,
                              c.ctx) == 33;
}
} // namespace

bool BuildNoteVoteComplaint(CNoteVoteComplaint& complaint,
                            const CNoteFinalityVote& vote,
                            const CFinalityTallyConfig& config,
                            const CKey& keyRecipient,
                            int nRecipientIndex,
                            std::string* pstrError)
{
    if (nRecipientIndex < 0 ||
        nRecipientIndex >= (int)config.vCommitteePubKeys.size() ||
        nRecipientIndex >= (int)vote.share.vEncryptedRecipientShares.size() ||
        !keyRecipient.IsValid())
    {
        Fail(pstrError, "note vote complaint has no envelope to accuse");
        return false;
    }
    const CPubKey pubMember = keyRecipient.GetPubKey();
    if (!pubMember.IsValid() || !pubMember.IsCompressed() ||
        pubMember != config.vCommitteePubKeys[nRecipientIndex])
    {
        Fail(pstrError, "note vote complaint is not signed by the accused recipient");
        return false;
    }

    complaint.nVersion = FINALITY_NOTE_COMPLAINT_VERSION;
    complaint.nEpoch = vote.nEpoch;
    complaint.voteTag = vote.GetVoteTag();
    complaint.hashShare = vote.share.GetHash();
    complaint.nRecipientIndex = nRecipientIndex;
    complaint.vchSharedPoint.clear();
    complaint.vchDleqProof.clear();

    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    if (!ParseNoteShareEnvelope(vote.share.vEncryptedRecipientShares[nRecipientIndex],
                                nEnvelopeRecipient, pubEphemeral, vchCiphertext) ||
        nEnvelopeRecipient != nRecipientIndex)
    {
        // An envelope that does not parse names no ephemeral key, so there is no shared
        // point to reveal and no discrete log to relate. Anyone sees this from the share.
        return true;
    }

    unsigned char sharedBytes[33];
    if (!ComputeSharedPoint(keyRecipient, pubEphemeral, sharedBytes))
    {
        Fail(pstrError, "note vote complaint could not derive the shared point");
        return false;
    }

    complaint.vchSharedPoint.assign(sharedBytes, sharedBytes + 33);

    Secp256k1Context c;
    bool fOk = false;
    if (c.IsValid())
    {
        BIGNUM* bnSecret = BN_bin2bn(keyRecipient.begin(), 32, NULL);
        BIGNUM* bnNonce = BN_new();
        BIGNUM* bnChallenge = BN_new();
        BIGNUM* bnResponse = BN_new();
        EC_POINT* pointE = EC_POINT_new(c.group);
        EC_POINT* nonceG = EC_POINT_new(c.group);
        EC_POINT* nonceE = EC_POINT_new(c.group);
        unsigned char bytesG[33];
        unsigned char bytesE[33];
        if (bnSecret && bnNonce && bnChallenge && bnResponse && pointE && nonceG && nonceE &&
            PointFromBytes(c, pubEphemeral.begin(), pubEphemeral.size(), pointE) &&
            BN_rand_range(bnNonce, c.order) == 1 && !BN_is_zero(bnNonce) &&
            EC_POINT_mul(c.group, nonceG, bnNonce, NULL, NULL, c.ctx) == 1 &&
            EC_POINT_mul(c.group, nonceE, NULL, pointE, bnNonce, c.ctx) == 1 &&
            PointToBytes(c, nonceG, bytesG) && PointToBytes(c, nonceE, bytesE))
        {
            const uint256 challenge = ComplaintChallenge(complaint, pubMember, pubEphemeral,
                                                         sharedBytes, bytesG, bytesE);
            unsigned char be[32];
            for (int i = 0; i < 32; i++)
                be[i] = challenge.begin()[31 - i];
            BN_bin2bn(be, 32, bnChallenge);
            OPENSSL_cleanse(be, sizeof(be));
            if (BN_mod(bnChallenge, bnChallenge, c.order, c.ctx) == 1 &&
                BN_mod_mul(bnResponse, bnChallenge, bnSecret, c.order, c.ctx) == 1 &&
                BN_mod_add(bnResponse, bnResponse, bnNonce, c.order, c.ctx) == 1)
            {
                complaint.vchDleqProof.assign(FINALITY_NOTE_DLEQ_SIZE, 0);
                BN_bn2binpad(bnChallenge, &complaint.vchDleqProof[0], 32);
                BN_bn2binpad(bnResponse, &complaint.vchDleqProof[32], 32);
                fOk = true;
            }
        }
        if (nonceE) EC_POINT_free(nonceE);
        if (nonceG) EC_POINT_free(nonceG);
        if (pointE) EC_POINT_free(pointE);
        if (bnResponse) BN_clear_free(bnResponse);
        if (bnChallenge) BN_clear_free(bnChallenge);
        if (bnNonce) BN_clear_free(bnNonce);
        if (bnSecret) BN_clear_free(bnSecret);
    }
    OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));
    if (!fOk)
    {
        Fail(pstrError, "note vote complaint could not be proved");
        return false;
    }
    return true;
}

bool CheckNoteVoteComplaint(const CNoteVoteComplaint& complaint,
                            const CNoteFinalityVote& vote,
                            const CFinalityTallyConfig& config,
                            std::string* pstrError)
{
    if (!complaint.IsValidBasic(pstrError))
        return false;
    if (complaint.nEpoch != vote.nEpoch ||
        complaint.voteTag != vote.GetVoteTag() ||
        complaint.hashShare != vote.share.GetHash())
    {
        Fail(pstrError, "note vote complaint does not name this vote's share");
        return false;
    }
    if (complaint.nRecipientIndex >= (int)config.vCommitteePubKeys.size() ||
        complaint.nRecipientIndex >= (int)vote.share.vEncryptedRecipientShares.size())
    {
        Fail(pstrError, "note vote complaint names a recipient the committee has not");
        return false;
    }
    const CPubKey& pubMember = config.vCommitteePubKeys[complaint.nRecipientIndex];

    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    if (!ParseNoteShareEnvelope(
            vote.share.vEncryptedRecipientShares[complaint.nRecipientIndex],
            nEnvelopeRecipient, pubEphemeral, vchCiphertext) ||
        nEnvelopeRecipient != complaint.nRecipientIndex)
    {
        // Anyone sees this without a proof, so the complaint stands on the share alone —
        // but only in its one canonical empty form.
        if (!complaint.vchSharedPoint.empty() || !complaint.vchDleqProof.empty())
        {
            Fail(pstrError, "note vote complaint reveals a point for an unopenable envelope");
            return false;
        }
        return true;
    }
    if (complaint.vchSharedPoint.size() != 33 ||
        complaint.vchDleqProof.size() != FINALITY_NOTE_DLEQ_SIZE)
    {
        Fail(pstrError, "note vote complaint reveals nothing about a readable envelope");
        return false;
    }

    // The DLEQ is what makes the revealed point the recipient's own shared secret rather
    // than a point chosen to make an honest envelope look undecryptable.
    Secp256k1Context c;
    if (!c.IsValid())
    {
        Fail(pstrError, "note vote complaint could not be checked");
        return false;
    }
    bool fDleqOk = false;
    {
        BIGNUM* bnChallenge = BN_bin2bn(&complaint.vchDleqProof[0], 32, NULL);
        BIGNUM* bnResponse = BN_bin2bn(&complaint.vchDleqProof[32], 32, NULL);
        BIGNUM* bnNegChallenge = BN_new();
        EC_POINT* pointE = EC_POINT_new(c.group);
        EC_POINT* pointS = EC_POINT_new(c.group);
        EC_POINT* pointP = EC_POINT_new(c.group);
        EC_POINT* nonceG = EC_POINT_new(c.group);
        EC_POINT* nonceE = EC_POINT_new(c.group);
        unsigned char bytesG[33];
        unsigned char bytesE[33];
        if (bnChallenge && bnResponse && bnNegChallenge && pointE && pointS && pointP &&
            nonceG && nonceE &&
            BN_cmp(bnChallenge, c.order) < 0 && BN_cmp(bnResponse, c.order) < 0 &&
            PointFromBytes(c, pubEphemeral.begin(), pubEphemeral.size(), pointE) &&
            PointFromBytes(c, &complaint.vchSharedPoint[0], 33, pointS) &&
            PointFromBytes(c, pubMember.begin(), pubMember.size(), pointP) &&
            BN_sub(bnNegChallenge, c.order, bnChallenge) == 1)
        {
            // nonce_G = s*G - c*P and nonce_E = s*E - c*S, both as one multi-scalar step.
            const EC_POINT* pointsG[1] = { pointP };
            const BIGNUM* scalarsG[1] = { bnNegChallenge };
            const EC_POINT* pointsE[2] = { pointE, pointS };
            const BIGNUM* scalarsE[2] = { bnResponse, bnNegChallenge };
            if (EC_POINTs_mul(c.group, nonceG, bnResponse, 1, pointsG, scalarsG, c.ctx) == 1 &&
                EC_POINTs_mul(c.group, nonceE, NULL, 2, pointsE, scalarsE, c.ctx) == 1 &&
                !EC_POINT_is_at_infinity(c.group, nonceG) &&
                !EC_POINT_is_at_infinity(c.group, nonceE) &&
                PointToBytes(c, nonceG, bytesG) && PointToBytes(c, nonceE, bytesE))
            {
                const uint256 expected =
                    ComplaintChallenge(complaint, pubMember, pubEphemeral,
                                       &complaint.vchSharedPoint[0], bytesG, bytesE);
                unsigned char be[32];
                for (int i = 0; i < 32; i++)
                    be[i] = expected.begin()[31 - i];
                BIGNUM* bnExpected = BN_bin2bn(be, 32, NULL);
                OPENSSL_cleanse(be, sizeof(be));
                if (bnExpected && BN_mod(bnExpected, bnExpected, c.order, c.ctx) == 1)
                    fDleqOk = BN_cmp(bnExpected, bnChallenge) == 0;
                if (bnExpected) BN_clear_free(bnExpected);
            }
        }
        if (nonceE) EC_POINT_free(nonceE);
        if (nonceG) EC_POINT_free(nonceG);
        if (pointP) EC_POINT_free(pointP);
        if (pointS) EC_POINT_free(pointS);
        if (pointE) EC_POINT_free(pointE);
        if (bnNegChallenge) BN_clear_free(bnNegChallenge);
        if (bnResponse) BN_clear_free(bnResponse);
        if (bnChallenge) BN_clear_free(bnChallenge);
    }
    if (!fDleqOk)
    {
        Fail(pstrError, "note vote complaint does not open the accused envelope");
        return false;
    }

    unsigned char sharedBytes[33];
    memcpy(sharedBytes, &complaint.vchSharedPoint[0], 33);
    std::vector<unsigned char> vchKey;
    if (!DeriveNoteShareKeyFromSharedPoint(sharedBytes, pubMember, pubEphemeral,
                                           complaint.nRecipientIndex,
                                           vote.share.committeeSetHash, vchKey))
    {
        Fail(pstrError, "note vote complaint could not rebuild the envelope key");
        return false;
    }
    const std::vector<unsigned char> vchAAD =
        BuildNoteShareAAD(vote.share, complaint.nRecipientIndex, pubEphemeral);
    std::vector<unsigned char> vchPlain;
    const bool fDecrypted =
        ChaCha20Poly1305Decrypt(vchCiphertext, vchKey, vchAAD, vchPlain);
    OPENSSL_cleanse(&vchKey[0], vchKey.size());
    if (!fDecrypted)
        return true;

    CNoteTallyPlainShare plain;
    try
    {
        CDataStream ss(vchPlain, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nPlainVersion = 0;
        ss >> nPlainVersion;
        ss >> plain.nRecipientIndex;
        ss >> plain.nX;
        ss >> plain.evalWeight;
        ss >> plain.evalWeightBlind;
        ss >> plain.evalReward;
        ss >> plain.evalRewardBlind;
        if (nPlainVersion != FINALITY_NOTE_SHARE_VERSION ||
            plain.nRecipientIndex != complaint.nRecipientIndex ||
            plain.nX != complaint.nRecipientIndex + 1)
            return true;
    }
    catch (const std::exception&)
    {
        return true;
    }

    if (CheckNoteVoteVssEvaluation(vote.share, plain))
    {
        Fail(pstrError, "note vote complaint accuses a share that opens correctly");
        return false;
    }
    return true;
}

bool DeriveNoteTallyAggregates(const std::vector<const CNoteFinalityVote*>& vVotes,
                               const uint256& hashWinner,
                               PrivacyVNextDigest& activeOut,
                               PrivacyVNextDigest& winningOut,
                               PrivacyVNextDigest& rewardOut,
                               std::string* pstrError)
{
    const uint256 one = Ed25519ScalarFromUint64(1);
    std::vector<PrivacyVNextCombineTerm> vActive;
    std::vector<PrivacyVNextCombineTerm> vWinning;
    std::vector<PrivacyVNextCombineTerm> vReward;
    for (size_t i = 0; i < vVotes.size(); i++)
    {
        if (vVotes[i] == NULL)
        {
            Fail(pstrError, "note tally aggregate was handed a missing vote");
            return false;
        }
        PrivacyVNextCombineTerm term;
        term.nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
        term.scalar = Ed25519ScalarToDigest(one);
        PrivacyVNextCombineTerm rewardTerm = term;
        if (!vVotes[i]->GetCTilde(term.point) ||
            !vVotes[i]->GetRewardCommitment(rewardTerm.point))
        {
            Fail(pstrError, "note tally aggregate could not read a vote commitment");
            return false;
        }
        vActive.push_back(term);
        vReward.push_back(rewardTerm);
        if (vVotes[i]->hashBlock == hashWinner)
            vWinning.push_back(term);
    }

    std::string error;
    if (!CombinePrivacyVNextPoints(vActive, activeOut, error) ||
        !CombinePrivacyVNextPoints(vWinning, winningOut, error) ||
        !CombinePrivacyVNextPoints(vReward, rewardOut, error))
    {
        Fail(pstrError, "note tally aggregate could not be derived");
        return false;
    }
    return true;
}

bool GetNoteTallyTierCoefficients(int nTier, int64_t& nWinningCoeff, int64_t& nActiveCoeff,
                                  int64_t* pnStrictOffset)
{
    int64_t nOffset = 0;
    switch (nTier)
    {
    case FINALITY_HARD:
        nWinningCoeff = 3;
        nActiveCoeff = 2;
        break;
    case FINALITY_SOFT:
        nWinningCoeff = 2;
        nActiveCoeff = 1;
        // 2W - A - 1 >= 0, i.e. 2W > A. The unshifted statement would prove 2W >= A,
        // which two blocks can satisfy at once at an even A, and a note-only
        // certificate has nothing but this statement to name one winner with.
        nOffset = 1;
        break;
    case FINALITY_TENTATIVE:
        nWinningCoeff = 3;
        nActiveCoeff = 1;
        break;
    default:
        return false;
    }
    if (pnStrictOffset)
        *pnStrictOffset = nOffset;
    return true;
}

namespace
{
const char* NOTE_TALLY_STATEMENT_SHIFT_DOMAIN =
    "Innova/IV5/NoteTally/StatementShift/v1";

/** A public multiple of G every statement point is shifted by.
 *
 *  A statement whose opening is (0, 0) is the identity point, and there is no range proof
 *  over it. That is not a corner case: it is exactly the shape an honest epoch takes when
 *  every covered note vote names the winner, which makes the active and winning aggregates
 *  equal and the winning cap's value AND blind both zero. Shifting by a scalar both sides
 *  derive from the same public inputs leaves the H coefficient -- the value the range proof
 *  is about -- untouched, and makes a zero blind unreachable except by grinding a fixed
 *  point of the hash. */
uint256 TierStatementShift(int nTier,
                           const PrivacyVNextDigest& activePoint,
                           const PrivacyVNextDigest& winningPoint,
                           int64_t nTransparentActive,
                           int64_t nTransparentWinning,
                           int nStatement)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(NOTE_TALLY_STATEMENT_SHIFT_DOMAIN);
    ss << nTier;
    ss << std::vector<unsigned char>(activePoint.begin(), activePoint.end());
    ss << std::vector<unsigned char>(winningPoint.begin(), winningPoint.end());
    ss << nTransparentActive;
    ss << nTransparentWinning;
    ss << nStatement;
    return Ed25519ScalarReduce(ss.GetHash());
}

// Derive the three statement points from the aggregates, exactly the same way on both
// sides. The prover uses them only to self-check; the validator uses them as the points
// it verifies against, and never accepts one from the wire.
bool DeriveTierStatementPoints(int nTier,
                               const PrivacyVNextDigest& activePoint,
                               const PrivacyVNextDigest& winningPoint,
                               int64_t nTransparentActive,
                               int64_t nTransparentWinning,
                               PrivacyVNextDigest& tierOut,
                               PrivacyVNextDigest& winningCapOut,
                               PrivacyVNextDigest& activeCapOut,
                               std::string* pstrError)
{
    int64_t nWinningCoeff = 0;
    int64_t nActiveCoeff = 0;
    int64_t nStrictOffset = 0;
    if (!GetNoteTallyTierCoefficients(nTier, nWinningCoeff, nActiveCoeff, &nStrictOffset))
    {
        Fail(pstrError, "note tally tier has no comparison coefficients");
        return false;
    }
    if (nTransparentActive < 0 || nTransparentActive > MAX_MONEY ||
        nTransparentWinning < 0 || nTransparentWinning > nTransparentActive)
    {
        Fail(pstrError, "note tally transparent weights are out of range");
        return false;
    }

    const uint256 one = Ed25519ScalarFromUint64(1);
    const uint256 negOne = Ed25519ScalarNeg(one);

    // a_w*D_win - a_a*D_act + (a_w*T_win - a_a*T_act - offset)*H. The H coefficient is
    // the tier slack, which an honest tally can range-prove and an overclaimed one
    // cannot. The offset is the tier's strictness: SOFT proves 2W - A - 1 >= 0.
    std::vector<PrivacyVNextCombineTerm> vTier(4);
    vTier[0].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vTier[0].scalar = Ed25519ScalarToDigest(Ed25519ScalarFromInt64(nWinningCoeff));
    vTier[0].point = winningPoint;
    vTier[1].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vTier[1].scalar = Ed25519ScalarToDigest(Ed25519ScalarNeg(Ed25519ScalarFromInt64(nActiveCoeff)));
    vTier[1].point = activePoint;
    vTier[2].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vTier[2].scalar = Ed25519ScalarToDigest(Ed25519ScalarSub(
        Ed25519ScalarSub(
            Ed25519ScalarMul(Ed25519ScalarFromInt64(nWinningCoeff),
                             Ed25519ScalarFromInt64(nTransparentWinning)),
            Ed25519ScalarMul(Ed25519ScalarFromInt64(nActiveCoeff),
                             Ed25519ScalarFromInt64(nTransparentActive))),
        Ed25519ScalarFromInt64(nStrictOffset)));

    // D_act - D_win keeps the winning sum under the active sum.
    std::vector<PrivacyVNextCombineTerm> vWinningCap(3);
    vWinningCap[0].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vWinningCap[0].scalar = Ed25519ScalarToDigest(one);
    vWinningCap[0].point = activePoint;
    vWinningCap[1].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vWinningCap[1].scalar = Ed25519ScalarToDigest(negOne);
    vWinningCap[1].point = winningPoint;

    // (MAX_MONEY - T_act)*H - D_act keeps the summed weights inside the int64 the tier
    // arithmetic downstream is computed in.
    std::vector<PrivacyVNextCombineTerm> vActiveCap(3);
    vActiveCap[0].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vActiveCap[0].scalar =
        Ed25519ScalarToDigest(Ed25519ScalarFromInt64(MAX_MONEY - nTransparentActive));
    vActiveCap[1].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vActiveCap[1].scalar = Ed25519ScalarToDigest(negOne);
    vActiveCap[1].point = activePoint;

    // The public G shift, one per statement. See TierStatementShift: without it the
    // winning cap is the identity point whenever every covered note vote names the
    // winner, and no range proof exists over the identity.
    std::vector<PrivacyVNextCombineTerm>* vAll[3] = { &vTier, &vWinningCap, &vActiveCap };
    for (int i = 0; i < 3; i++)
    {
        PrivacyVNextCombineTerm& shift = vAll[i]->back();
        shift.nSource = PRIVACY_VNEXT_TERM_ED25519_G;
        shift.scalar = Ed25519ScalarToDigest(
            TierStatementShift(nTier, activePoint, winningPoint, nTransparentActive,
                               nTransparentWinning, i));
    }

    std::string error;
    if (!CombinePrivacyVNextPoints(vTier, tierOut, error) ||
        !CombinePrivacyVNextPoints(vWinningCap, winningCapOut, error) ||
        !CombinePrivacyVNextPoints(vActiveCap, activeCapOut, error))
    {
        Fail(pstrError, "note tally statement points could not be derived");
        return false;
    }
    return true;
}
} // namespace

bool BuildNoteTallyTierProofs(int nTier,
                              int64_t nPrivateActive,
                              const uint256& privateActiveBlind,
                              int64_t nPrivateWinning,
                              const uint256& privateWinningBlind,
                              int64_t nTransparentActive,
                              int64_t nTransparentWinning,
                              const PrivacyVNextDigest& entropy,
                              CNoteTallyTierProofs& proofsOut,
                              std::string* pstrError)
{
    proofsOut = CNoteTallyTierProofs();

    int64_t nWinningCoeff = 0;
    int64_t nActiveCoeff = 0;
    int64_t nStrictOffset = 0;
    if (!GetNoteTallyTierCoefficients(nTier, nWinningCoeff, nActiveCoeff, &nStrictOffset))
    {
        Fail(pstrError, "note tally tier has no comparison coefficients");
        return false;
    }
    if (nPrivateActive < 0 || nPrivateActive > MAX_MONEY ||
        nPrivateWinning < 0 || nPrivateWinning > nPrivateActive ||
        nTransparentActive < 0 || nTransparentActive > MAX_MONEY ||
        nTransparentWinning < 0 || nTransparentWinning > nTransparentActive ||
        nPrivateActive > MAX_MONEY - nTransparentActive)
    {
        Fail(pstrError, "note tally opening is outside the range the caps allow");
        return false;
    }

    const int64_t nSlack = (nWinningCoeff * (nPrivateWinning + nTransparentWinning)) -
                           (nActiveCoeff * (nPrivateActive + nTransparentActive)) -
                           nStrictOffset;
    if (nSlack < 0)
    {
        Fail(pstrError, "note tally opening does not reach the claimed tier");
        return false;
    }

    // Derive the same points the validator will, from the openings this builder holds. A
    // proof over a point the validator does not reach is unusable on the network, so the
    // divergence has to surface here rather than as a rejected certificate.
    PrivacyVNextDigest activePoint = ZeroDigest();
    PrivacyVNextDigest winningPoint = ZeroDigest();
    if (!CommitScaled(Ed25519ScalarFromInt64(nPrivateActive), privateActiveBlind,
                      activePoint, pstrError) ||
        !CommitScaled(Ed25519ScalarFromInt64(nPrivateWinning), privateWinningBlind,
                      winningPoint, pstrError))
        return false;

    // Each statement's blind carries the same public G shift the validator's derived
    // point does, so the value proved is unchanged and a (0, 0) opening -- the identity,
    // which nothing can range-prove -- is unreachable.
    const uint256 tierBlind = Ed25519ScalarAdd(
        Ed25519ScalarSub(
            Ed25519ScalarMul(Ed25519ScalarFromInt64(nWinningCoeff), privateWinningBlind),
            Ed25519ScalarMul(Ed25519ScalarFromInt64(nActiveCoeff), privateActiveBlind)),
        TierStatementShift(nTier, activePoint, winningPoint, nTransparentActive,
                           nTransparentWinning, 0));
    const uint256 winningCapBlind = Ed25519ScalarAdd(
        Ed25519ScalarSub(privateActiveBlind, privateWinningBlind),
        TierStatementShift(nTier, activePoint, winningPoint, nTransparentActive,
                           nTransparentWinning, 1));
    const uint256 activeCapBlind = Ed25519ScalarAdd(
        Ed25519ScalarNeg(privateActiveBlind),
        TierStatementShift(nTier, activePoint, winningPoint, nTransparentActive,
                           nTransparentWinning, 2));

    struct Statement
    {
        uint64_t nValue;
        uint256 blind;
        std::vector<unsigned char>* pvchOut;
    };
    Statement vStatements[3];
    vStatements[0].nValue = (uint64_t)nSlack;
    vStatements[0].blind = tierBlind;
    vStatements[0].pvchOut = &proofsOut.vchTierSlack;
    vStatements[1].nValue = (uint64_t)(nPrivateActive - nPrivateWinning);
    vStatements[1].blind = winningCapBlind;
    vStatements[1].pvchOut = &proofsOut.vchWinningCap;
    vStatements[2].nValue = (uint64_t)(MAX_MONEY - nTransparentActive - nPrivateActive);
    vStatements[2].blind = activeCapBlind;
    vStatements[2].pvchOut = &proofsOut.vchActiveCap;

    PrivacyVNextDigest vExpected[3];
    if (!DeriveTierStatementPoints(nTier, activePoint, winningPoint, nTransparentActive,
                                   nTransparentWinning, vExpected[0], vExpected[1],
                                   vExpected[2], pstrError))
        return false;

    for (int i = 0; i < 3; i++)
    {
        PrivacyVNextDigest seed = entropy;
        seed[0] = (unsigned char)(seed[0] ^ (unsigned char)(i + 1));
        PrivacyVNextDigest commitment;
        std::string error;
        if (!ProvePrivacyVNextRange(vStatements[i].nValue,
                                    Ed25519ScalarToDigest(vStatements[i].blind), seed,
                                    commitment, *vStatements[i].pvchOut, error))
        {
            Fail(pstrError, "note tally statement could not be range-proved");
            return false;
        }
        if (commitment != vExpected[i])
        {
            Fail(pstrError, "note tally range proof is over a point the validator misses");
            return false;
        }
        if (vStatements[i].pvchOut->size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
        {
            Fail(pstrError, "note tally range proof exceeds its carrier bound");
            return false;
        }
    }
    return true;
}

bool CheckNoteTallyTierProofs(int nTier,
                              const PrivacyVNextDigest& activePoint,
                              const PrivacyVNextDigest& winningPoint,
                              int64_t nTransparentActive,
                              int64_t nTransparentWinning,
                              const CNoteTallyTierProofs& proofs,
                              std::string* pstrError)
{
    PrivacyVNextDigest tierPoint = ZeroDigest();
    PrivacyVNextDigest winningCapPoint = ZeroDigest();
    PrivacyVNextDigest activeCapPoint = ZeroDigest();
    if (!DeriveTierStatementPoints(nTier, activePoint, winningPoint, nTransparentActive,
                                   nTransparentWinning, tierPoint, winningCapPoint,
                                   activeCapPoint, pstrError))
        return false;

    const PrivacyVNextDigest* vPoints[3] = { &tierPoint, &winningCapPoint, &activeCapPoint };
    const std::vector<unsigned char>* vProofs[3] = {
        &proofs.vchTierSlack, &proofs.vchWinningCap, &proofs.vchActiveCap
    };
    for (int i = 0; i < 3; i++)
    {
        if (vProofs[i]->empty() ||
            vProofs[i]->size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
        {
            Fail(pstrError, "note tally range proof has an unusable length");
            return false;
        }
        std::string error;
        if (!VerifyPrivacyVNextRange(*vPoints[i], ZeroDigest(), *vProofs[i], error))
        {
            Fail(pstrError, "note tally range proof does not verify against its point");
            return false;
        }
    }
    return true;
}

bool RunNoteTallyCommitteePass(const std::vector<const CNoteFinalityVote*>& vConnectedVotes,
                               const uint256& hashWinner,
                               const CFinalityTallyConfig& config,
                               const CKey& keyMember,
                               int nMemberIndex,
                               CNoteTallyCommitteePass& passOut,
                               std::string* pstrError)
{
    passOut = CNoteTallyCommitteePass();
    if (nMemberIndex < 0 || nMemberIndex >= (int)config.vCommitteePubKeys.size() ||
        !keyMember.IsValid() || config.nThresholdM <= 0)
    {
        Fail(pstrError, "note tally pass has no usable committee position");
        return false;
    }

    std::vector<CNoteTallyPlainShare> vActive;
    std::vector<CNoteTallyPlainShare> vWinning;
    std::set<uint256> setSeenTags;
    for (size_t i = 0; i < vConnectedVotes.size(); i++)
    {
        const CNoteFinalityVote* pvote = vConnectedVotes[i];
        if (pvote == NULL)
        {
            Fail(pstrError, "note tally pass was handed a missing vote");
            return false;
        }
        const uint256 tag = pvote->GetVoteTag();
        if (tag == 0 || !setSeenTags.insert(tag).second)
        {
            Fail(pstrError, "note tally pass saw a repeated vote tag");
            return false;
        }

        CNoteTallyPlainShare plain;
        bool fComplainable = false;
        if (DecryptNoteVoteShareForRecipient(pvote->share, config, keyMember, nMemberIndex,
                                             plain, &fComplainable))
        {
            passOut.vAcceptedTags.push_back(tag);
            vActive.push_back(plain);
            if (pvote->hashBlock == hashWinner)
                vWinning.push_back(plain);
            continue;
        }
        if (!fComplainable)
        {
            Fail(pstrError, "note tally pass could not read its own share");
            return false;
        }
        // A share this member cannot use is excluded only with evidence, so a member
        // that simply dislikes a voter cannot drop it. A vote that ends up neither
        // accepted nor complained of would leave a cover set no certificate can satisfy,
        // so failing to build the evidence has to fail the pass rather than pass quietly.
        CNoteVoteComplaint complaint;
        if (!BuildNoteVoteComplaint(complaint, *pvote, config, keyMember, nMemberIndex,
                                    pstrError))
            return false;
        passOut.vComplaints.push_back(complaint);
    }

    passOut.fHaveActive = AggregateNoteTallyPlainShares(vActive, passOut.aggregateActive);
    passOut.fHaveWinning = AggregateNoteTallyPlainShares(vWinning, passOut.aggregateWinning);
    return true;
}

bool OpenNoteTallyAggregate(const std::vector<CNoteTallyPlainShare>& vPartials,
                            int nThreshold,
                            const PrivacyVNextDigest& expectedPoint,
                            const PrivacyVNextDigest& expectedRewardPoint,
                            int64_t& nWeightOut,
                            uint256& weightBlindOut,
                            int64_t& nRewardOut,
                            uint256& rewardBlindOut,
                            std::string* pstrError)
{
    nWeightOut = 0;
    nRewardOut = 0;

    uint256 weight, reward;
    if (!RecoverNoteTallySecrets(vPartials, nThreshold, weight, weightBlindOut, reward,
                                 rewardBlindOut))
    {
        Fail(pstrError, "note tally aggregate could not be interpolated");
        return false;
    }
    if (!Ed25519ScalarToMoney(weight, nWeightOut))
    {
        Fail(pstrError, "note tally aggregate opened outside the money range");
        return false;
    }
    // Strict, now that the reward evaluations authenticate against L_k. A reward that
    // will not open is a share that did not pass its coefficient check, which is what a
    // complaint names -- so this fails against a nameable voter instead of jamming the
    // epoch's whole private weight anonymously.
    if (!Ed25519ScalarToMoney(reward, nRewardOut))
    {
        nRewardOut = 0;
        Fail(pstrError, "note tally reward aggregate opened outside the money range");
        return false;
    }

    // The opening is only usable if it opens the points the validator recomputes. A share
    // that passed its coefficient check cannot fail here, so a failure means the covered
    // set the committee summed is not the set the certificate will name.
    PrivacyVNextDigest derived = ZeroDigest();
    if (!CommitScaled(weight, weightBlindOut, derived, pstrError))
        return false;
    if (derived != expectedPoint)
    {
        Fail(pstrError, "note tally aggregate does not open the recomputed commitment");
        return false;
    }
    PrivacyVNextDigest derivedReward = ZeroDigest();
    if (!CommitScaled(reward, rewardBlindOut, derivedReward, pstrError))
        return false;
    if (derivedReward != expectedRewardPoint)
    {
        Fail(pstrError, "note tally reward aggregate does not open the recomputed commitment");
        return false;
    }
    return true;
}

// --- The tally partial ------------------------------------------------------------
//
// The envelope encoding is the note share's, so one parser serves both; the AAD domain
// below is what keeps a share envelope from ever opening as a partial envelope.

static const char* NOTE_TALLY_PARTIAL_AAD_DOMAIN = "Innova/IV5/NoteTally/PartialAAD/v1";
static const char* NOTE_TALLY_PARTIAL_CONTENT_DOMAIN =
    "Innova/IV5/NoteTally/PartialContent/v1";
static const char* NOTE_TALLY_PARTIAL_SLOT_DOMAIN = "Innova/IV5/NoteTally/PartialSlot/v1";

template <typename Stream>
static void AppendNoteTallyPartialContent(Stream& ss,
                                          const CNoteTallyAggregatePartial& partial)
{
    ss << partial.nVersion;
    ss << partial.nEpoch;
    ss << partial.committeeSetHash;
    ss << partial.hashWinner;
    ss << partial.nSourceIndex;
    ss << partial.vAcceptedTags;
    ss << partial.vComplaints;
    ss << partial.vEncryptedRecipientPartials;
}

static std::vector<unsigned char> BuildNoteTallyPartialAAD(
    const CNoteTallyAggregatePartial& partial,
    int nRecipientIndex,
    const CPubKey& pubEphemeral)
{
    // Deliberately not over vEncryptedRecipientPartials: the envelopes are what this AAD
    // authenticates, and they do not exist yet while the first of them is being sealed.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << std::string(NOTE_TALLY_PARTIAL_AAD_DOMAIN);
    ss << partial.nVersion;
    ss << partial.nEpoch;
    ss << partial.committeeSetHash;
    ss << partial.hashWinner;
    ss << partial.nSourceIndex;
    ss << partial.vAcceptedTags;
    ss << partial.vComplaints;
    ss << nRecipientIndex;
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

uint256 CNoteTallyAggregatePartial::GetContentDigest() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(NOTE_TALLY_PARTIAL_CONTENT_DOMAIN);
    AppendNoteTallyPartialContent(ss, *this);
    return ss.GetHash();
}

uint256 CNoteTallyAggregatePartial::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(NOTE_TALLY_PARTIAL_CONTENT_DOMAIN);
    AppendNoteTallyPartialContent(ss, *this);
    ss << vchSourceSig;
    return ss.GetHash();
}

uint256 CNoteTallyAggregatePartial::GetSourceSlot() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(NOTE_TALLY_PARTIAL_SLOT_DOMAIN);
    ss << nVersion;
    ss << nEpoch;
    ss << committeeSetHash;
    ss << hashWinner;
    ss << nSourceIndex;
    ss << vAcceptedTags;
    return ss.GetHash();
}

bool CNoteTallyAggregatePartial::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != FINALITY_NOTE_TALLY_PARTIAL_VERSION)
    {
        Fail(pstrError, "unsupported note tally partial version");
        return false;
    }
    if (nEpoch < 0 || committeeSetHash == 0 || hashWinner == 0)
    {
        Fail(pstrError, "note tally partial names no epoch, committee or winner");
        return false;
    }
    if (nSourceIndex < 0 ||
        nSourceIndex >= (int)FINALITY_NOTE_MAX_VSS_COEFFICIENTS)
    {
        Fail(pstrError, "note tally partial source index out of range");
        return false;
    }
    if (vAcceptedTags.size() > FINALITY_NOTE_MAX_TALLY_TAGS ||
        vComplaints.size() > FINALITY_NOTE_MAX_TALLY_TAGS)
    {
        Fail(pstrError, "note tally partial exceeds its epoch vote bound");
        return false;
    }
    if (vAcceptedTags.empty() && vComplaints.empty())
    {
        Fail(pstrError, "note tally partial carries neither a covered set nor evidence");
        return false;
    }
    // Strictly ascending: the covered set is part of the slot a member signs once, so two
    // orderings of one set must not be two signable contents.
    for (size_t i = 0; i < vAcceptedTags.size(); i++)
    {
        if (vAcceptedTags[i] == 0)
        {
            Fail(pstrError, "note tally partial covers a zero tag");
            return false;
        }
        if (i > 0 && !(vAcceptedTags[i - 1] < vAcceptedTags[i]))
        {
            Fail(pstrError, "note tally partial tags are not strictly ascending");
            return false;
        }
    }
    std::set<uint256> setAccepted(vAcceptedTags.begin(), vAcceptedTags.end());
    std::set<uint256> setComplained;
    for (size_t i = 0; i < vComplaints.size(); i++)
    {
        if (!vComplaints[i].IsValidBasic(pstrError))
            return false;
        if (vComplaints[i].nEpoch != nEpoch ||
            vComplaints[i].nRecipientIndex != nSourceIndex)
        {
            Fail(pstrError, "note tally partial carries a complaint it did not file");
            return false;
        }
        if (!setComplained.insert(vComplaints[i].voteTag).second)
        {
            Fail(pstrError, "note tally partial complains of one vote twice");
            return false;
        }
        if (setAccepted.count(vComplaints[i].voteTag))
        {
            Fail(pstrError, "note tally partial both covers and complains of a vote");
            return false;
        }
    }
    if (vEncryptedRecipientPartials.empty() ||
        vEncryptedRecipientPartials.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS ||
        nSourceIndex >= (int)vEncryptedRecipientPartials.size())
    {
        Fail(pstrError, "note tally partial envelope count does not fit its committee");
        return false;
    }
    for (size_t i = 0; i < vEncryptedRecipientPartials.size(); i++)
    {
        if (vEncryptedRecipientPartials[i].empty() ||
            vEncryptedRecipientPartials[i].size() > FINALITY_NOTE_MAX_ENVELOPE_BYTES)
        {
            Fail(pstrError, "note tally partial envelope has an unusable length");
            return false;
        }
    }
    if (vchSourceSig.empty() || vchSourceSig.size() > 80)
    {
        Fail(pstrError, "note tally partial has no usable source signature");
        return false;
    }
    return true;
}

bool BuildEncryptedNoteTallyAggregatePartial(CNoteTallyAggregatePartial& partial,
                                             const CNoteTallyCommitteePass& pass,
                                             const CFinalityTallyConfig& config,
                                             const CKey& keySource,
                                             std::string* pstrError)
{
    if (!config.fCommitteeValid || config.nThresholdM <= 0 ||
        config.nThresholdM > (int)config.vCommitteePubKeys.size() ||
        config.vCommitteePubKeys.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS ||
        partial.committeeSetHash != config.committeeSetHash ||
        partial.nEpoch < 0 || partial.hashWinner == 0 ||
        partial.nSourceIndex < 0 ||
        partial.nSourceIndex >= (int)config.vCommitteePubKeys.size() ||
        !keySource.IsValid())
    {
        Fail(pstrError, "note tally partial has no usable committee position");
        return false;
    }

    const CPubKey pubSource = keySource.GetPubKey();
    if (!pubSource.IsValid() || !pubSource.IsCompressed() ||
        !(pubSource == config.vCommitteePubKeys[partial.nSourceIndex]))
    {
        Fail(pstrError, "note tally partial source key is not the committee member it names");
        return false;
    }

    // An evaluation sealed under one index but computed at another x interpolates to a
    // different polynomial, so the pass has to be the one this member ran at this seat.
    if ((pass.fHaveActive &&
         (pass.aggregateActive.nRecipientIndex != partial.nSourceIndex ||
          pass.aggregateActive.nX != partial.nSourceIndex + 1)) ||
        (pass.fHaveWinning &&
         (pass.aggregateWinning.nRecipientIndex != partial.nSourceIndex ||
          pass.aggregateWinning.nX != partial.nSourceIndex + 1)))
    {
        Fail(pstrError, "note tally partial was handed a pass from another committee seat");
        return false;
    }

    partial.nVersion = FINALITY_NOTE_TALLY_PARTIAL_VERSION;
    partial.vAcceptedTags = pass.vAcceptedTags;
    std::sort(partial.vAcceptedTags.begin(), partial.vAcceptedTags.end());
    partial.vComplaints = pass.vComplaints;
    partial.vEncryptedRecipientPartials.clear();
    partial.vchSourceSig.clear();

    for (size_t i = 0; i < config.vCommitteePubKeys.size(); i++)
    {
        const int nRecipientIndex = (int)i;
        CKey ephemeralKey;
        ephemeralKey.MakeNewKey(true);
        const CPubKey ephemeralPubKey = ephemeralKey.GetPubKey();
        if (!ephemeralKey.IsValid() || !ephemeralPubKey.IsValid() ||
            !ephemeralPubKey.IsCompressed())
        {
            Fail(pstrError, "note tally partial could not draw an ephemeral key");
            return false;
        }

        unsigned char sharedBytes[33];
        std::vector<unsigned char> vchKey;
        if (!ComputeSharedPoint(ephemeralKey, config.vCommitteePubKeys[i], sharedBytes) ||
            !DeriveNoteShareKeyFromSharedPoint(sharedBytes, config.vCommitteePubKeys[i],
                                               ephemeralPubKey, nRecipientIndex,
                                               config.committeeSetHash, vchKey))
        {
            OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));
            Fail(pstrError, "note tally partial could not derive its envelope key");
            return false;
        }
        OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));

        CDataStream ssPlain(SER_NETWORK, PROTOCOL_VERSION);
        ssPlain << (uint32_t)FINALITY_NOTE_TALLY_PARTIAL_VERSION;
        ssPlain << partial.nSourceIndex;
        ssPlain << (int)(partial.nSourceIndex + 1);
        ssPlain << (unsigned char)(pass.fHaveActive ? 1 : 0);
        ssPlain << pass.aggregateActive.evalWeight;
        ssPlain << pass.aggregateActive.evalWeightBlind;
        ssPlain << pass.aggregateActive.evalReward;
        ssPlain << pass.aggregateActive.evalRewardBlind;
        ssPlain << (unsigned char)(pass.fHaveWinning ? 1 : 0);
        ssPlain << pass.aggregateWinning.evalWeight;
        ssPlain << pass.aggregateWinning.evalWeightBlind;
        ssPlain << pass.aggregateWinning.evalReward;
        ssPlain << pass.aggregateWinning.evalRewardBlind;

        const std::vector<unsigned char> vchAAD =
            BuildNoteTallyPartialAAD(partial, nRecipientIndex, ephemeralPubKey);
        std::vector<unsigned char> vchCiphertext;
        const bool fEncrypted = ChaCha20Poly1305Encrypt(
            vchKey, std::vector<unsigned char>(ssPlain.begin(), ssPlain.end()),
            vchAAD, vchCiphertext);
        OPENSSL_cleanse(&vchKey[0], vchKey.size());
        if (!fEncrypted)
        {
            Fail(pstrError, "note tally partial envelope could not be sealed");
            return false;
        }

        CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
        ssOut << (uint32_t)FINALITY_NOTE_SHARE_VERSION;
        ssOut << nRecipientIndex;
        ssOut << std::vector<unsigned char>(ephemeralPubKey.begin(), ephemeralPubKey.end());
        ssOut << vchCiphertext;
        partial.vEncryptedRecipientPartials.push_back(
            std::vector<unsigned char>(ssOut.begin(), ssOut.end()));
    }

    if (!keySource.Sign(partial.GetContentDigest(), partial.vchSourceSig) ||
        partial.vchSourceSig.empty())
    {
        Fail(pstrError, "note tally partial could not be signed by its source");
        return false;
    }
    return partial.IsValidBasic(pstrError);
}

bool DecryptNoteTallyAggregatePartialForRecipient(const CNoteTallyAggregatePartial& partial,
                                                  const CFinalityTallyConfig& config,
                                                  const CKey& keyRecipient,
                                                  int nRecipientIndex,
                                                  CNoteTallyPlainShare& activeOut,
                                                  bool& fHaveActiveOut,
                                                  CNoteTallyPlainShare& winningOut,
                                                  bool& fHaveWinningOut)
{
    activeOut = CNoteTallyPlainShare();
    winningOut = CNoteTallyPlainShare();
    fHaveActiveOut = false;
    fHaveWinningOut = false;

    if (nRecipientIndex < 0 ||
        nRecipientIndex >= (int)config.vCommitteePubKeys.size() ||
        nRecipientIndex >= (int)partial.vEncryptedRecipientPartials.size() ||
        partial.nVersion != FINALITY_NOTE_TALLY_PARTIAL_VERSION ||
        partial.committeeSetHash != config.committeeSetHash ||
        partial.nSourceIndex < 0 ||
        partial.nSourceIndex >= (int)config.vCommitteePubKeys.size() ||
        !keyRecipient.IsValid())
        return false;

    const CPubKey pubRecipient = keyRecipient.GetPubKey();
    if (!pubRecipient.IsValid() || !pubRecipient.IsCompressed() ||
        !(pubRecipient == config.vCommitteePubKeys[nRecipientIndex]))
        return false;

    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    if (!ParseNoteShareEnvelope(partial.vEncryptedRecipientPartials[nRecipientIndex],
                                nEnvelopeRecipient, pubEphemeral, vchCiphertext) ||
        nEnvelopeRecipient != nRecipientIndex)
        return false;

    unsigned char sharedBytes[33];
    std::vector<unsigned char> vchKey;
    if (!ComputeSharedPoint(keyRecipient, pubEphemeral, sharedBytes) ||
        !DeriveNoteShareKeyFromSharedPoint(sharedBytes, pubRecipient, pubEphemeral,
                                           nRecipientIndex, config.committeeSetHash,
                                           vchKey))
    {
        OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));
        return false;
    }
    OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));

    const std::vector<unsigned char> vchAAD =
        BuildNoteTallyPartialAAD(partial, nRecipientIndex, pubEphemeral);
    std::vector<unsigned char> vchPlain;
    const bool fDecrypted =
        ChaCha20Poly1305Decrypt(vchCiphertext, vchKey, vchAAD, vchPlain);
    OPENSSL_cleanse(&vchKey[0], vchKey.size());
    if (!fDecrypted)
        return false;

    try
    {
        CDataStream ss(vchPlain, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nPlainVersion = 0;
        int nSourceIndex = -1;
        int nX = 0;
        unsigned char fActive = 0;
        unsigned char fWinning = 0;
        ss >> nPlainVersion;
        ss >> nSourceIndex;
        ss >> nX;
        ss >> fActive;
        ss >> activeOut.evalWeight;
        ss >> activeOut.evalWeightBlind;
        ss >> activeOut.evalReward;
        ss >> activeOut.evalRewardBlind;
        ss >> fWinning;
        ss >> winningOut.evalWeight;
        ss >> winningOut.evalWeightBlind;
        ss >> winningOut.evalReward;
        ss >> winningOut.evalRewardBlind;
        if (!ss.empty() ||
            nPlainVersion != FINALITY_NOTE_TALLY_PARTIAL_VERSION ||
            nSourceIndex != partial.nSourceIndex ||
            nX != partial.nSourceIndex + 1)
            return false;
        activeOut.nRecipientIndex = nSourceIndex;
        activeOut.nX = nX;
        winningOut.nRecipientIndex = nSourceIndex;
        winningOut.nX = nX;
        fHaveActiveOut = (fActive != 0);
        fHaveWinningOut = (fWinning != 0);
    }
    catch (const std::exception&)
    {
        return false;
    }
    return true;
}

bool CheckNoteTallyAggregatePartialSignature(const CNoteTallyAggregatePartial& partial,
                                             const CFinalityTallyConfig& config,
                                             std::string* pstrError)
{
    if (partial.committeeSetHash != config.committeeSetHash ||
        config.vCommitteePubKeys.empty())
    {
        Fail(pstrError, "note tally partial names a committee this node cannot check");
        return false;
    }
    if (partial.nSourceIndex < 0 ||
        partial.nSourceIndex >= (int)config.vCommitteePubKeys.size())
    {
        Fail(pstrError, "note tally partial source index out of committee range");
        return false;
    }
    const CPubKey& pubSource = config.vCommitteePubKeys[partial.nSourceIndex];
    if (!pubSource.IsValid() ||
        !pubSource.Verify(partial.GetContentDigest(), partial.vchSourceSig))
    {
        Fail(pstrError, "note tally partial source signature invalid");
        return false;
    }
    return true;
}

bool ResolveNoteTallyCoverage(const std::vector<const CNoteFinalityVote*>& vConnectedVotes,
                              const std::vector<uint256>& vCertVoteTags,
                              const std::vector<CNoteVoteComplaint>& vComplaints,
                              const CFinalityTallyConfig& config,
                              std::vector<const CNoteFinalityVote*>& vCoveredOut,
                              std::string* pstrError)
{
    vCoveredOut.clear();

    std::map<uint256, const CNoteFinalityVote*> mapConnected;
    for (size_t i = 0; i < vConnectedVotes.size(); i++)
    {
        if (vConnectedVotes[i] == NULL)
        {
            Fail(pstrError, "note tally coverage was handed a missing vote");
            return false;
        }
        const uint256 tag = vConnectedVotes[i]->GetVoteTag();
        if (tag == 0 || !mapConnected.insert(std::make_pair(tag, vConnectedVotes[i])).second)
        {
            Fail(pstrError, "note tally coverage saw a repeated vote tag");
            return false;
        }
    }

    std::set<uint256> setExcluded;
    for (size_t i = 0; i < vComplaints.size(); i++)
    {
        std::map<uint256, const CNoteFinalityVote*>::const_iterator it =
            mapConnected.find(vComplaints[i].voteTag);
        if (it == mapConnected.end())
        {
            Fail(pstrError, "note tally complaint names no connected vote");
            return false;
        }
        if (!CheckNoteVoteComplaint(vComplaints[i], *it->second, config, pstrError))
            return false;
        setExcluded.insert(vComplaints[i].voteTag);
    }

    std::set<uint256> setCovered;
    for (size_t i = 0; i < vCertVoteTags.size(); i++)
    {
        const uint256& tag = vCertVoteTags[i];
        std::map<uint256, const CNoteFinalityVote*>::const_iterator it =
            mapConnected.find(tag);
        if (it == mapConnected.end())
        {
            Fail(pstrError, "note tally certificate covers an unconnected vote");
            return false;
        }
        if (!setCovered.insert(tag).second)
        {
            Fail(pstrError, "note tally certificate covers one vote twice");
            return false;
        }
        if (setExcluded.count(tag))
        {
            Fail(pstrError, "note tally certificate both covers and complains of a vote");
            return false;
        }
        vCoveredOut.push_back(it->second);
    }

    // Coverage equality: anything connected and uncomplained must be counted, or the
    // denominator could be deflated by leaving honest voters out.
    for (std::map<uint256, const CNoteFinalityVote*>::const_iterator it = mapConnected.begin();
         it != mapConnected.end(); ++it)
    {
        if (!setCovered.count(it->first) && !setExcluded.count(it->first))
        {
            Fail(pstrError, "note tally certificate omits a vote with no valid complaint");
            return false;
        }
    }
    return true;
}

bool CheckNoteTallyCertificate(int nTier,
                               const uint256& hashWinner,
                               const std::vector<const CNoteFinalityVote*>& vConnectedVotes,
                               const std::vector<uint256>& vCertVoteTags,
                               const std::vector<CNoteVoteComplaint>& vComplaints,
                               const CFinalityTallyConfig& config,
                               int64_t nTransparentActive,
                               int64_t nTransparentWinning,
                               const CNoteTallyTierProofs& proofs,
                               std::string* pstrError)
{
    std::vector<const CNoteFinalityVote*> vCovered;
    if (!ResolveNoteTallyCoverage(vConnectedVotes, vCertVoteTags, vComplaints, config,
                                  vCovered, pstrError))
        return false;

    PrivacyVNextDigest activePoint = ZeroDigest();
    PrivacyVNextDigest winningPoint = ZeroDigest();
    PrivacyVNextDigest rewardPoint = ZeroDigest();
    if (!DeriveNoteTallyAggregates(vCovered, hashWinner, activePoint, winningPoint,
                                   rewardPoint, pstrError))
        return false;

    return CheckNoteTallyTierProofs(nTier, activePoint, winningPoint, nTransparentActive,
                                    nTransparentWinning, proofs, pstrError);
}
