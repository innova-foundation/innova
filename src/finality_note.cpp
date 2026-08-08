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

bool CNoteFinalityVote::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != FINALITY_NOTE_VOTE_VERSION)
    {
        Fail(pstrError, "note vote version is not the F2 version");
        return false;
    }
    if (nEpoch < 0 || nHeight < 0 || nTime < 0)
    {
        Fail(pstrError, "note vote carries a negative epoch, height or time");
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
    ss << vote.nTime;
    ss << Hash(vote.vchMembership.begin(), vote.vchMembership.end());
    ss << vote.committeeSetHash;
    // The share hash is what makes one share structurally the vote's own: a mutated or
    // duplicated share reaches a different digest and no longer matches any sigma.
    ss << vote.share.GetHash();
    return ss.GetHash();
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

    // K_0 == C~. Without it a voter could share an opening of some other commitment, and
    // the epoch's recovered sum would fail to open the validator-recomputed total with
    // nothing to say who caused it.
    PrivacyVNextDigest commitment = ZeroDigest();
    if (!vote.share.GetCommitment(commitment) || commitment != cTilde)
    {
        Fail(pstrError, "note vote share coefficient K_0 is not the vote's commitment");
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
    if (!VerifyPrivacyVNextVoteMembership(vote.vchMembership, error))
    {
        Fail(pstrError, "note vote membership proof does not verify");
        return false;
    }
    return true;
}

bool BuildNoteVoteShare(CNoteVoteShare& share,
                        int64_t nAmount,
                        const uint256& maskTilde,
                        int64_t nReward,
                        const uint256& rewardBlind,
                        const CFinalityTallyConfig& config,
                        std::string* pstrError)
{
    if (!config.fCommitteeValid || config.nThresholdM <= 0 ||
        config.nThresholdM > (int)config.vCommitteePubKeys.size() ||
        config.vCommitteePubKeys.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS)
    {
        Fail(pstrError, "note vote share needs a valid M-of-N committee");
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
    // accepted evaluations interpolate to an opening of it and of nothing else.
    for (size_t k = 0; k < vWeight.size(); k++)
    {
        PrivacyVNextDigest coefficient = ZeroDigest();
        if (!CommitScaled(vWeight[k], vWeightBlind[k], coefficient, pstrError))
            return false;
        share.vVssCoefficients.push_back(
            std::vector<unsigned char>(coefficient.begin(), coefficient.end()));
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
    if (share.vVssCoefficients.empty() || plain.nX <= 0)
    {
        Fail(pstrError, "note vote share has nothing to check the evaluation against");
        return false;
    }

    std::vector<PrivacyVNextCombineTerm> vTerms;
    const uint256 x = Ed25519ScalarFromUint64((uint64_t)plain.nX);
    uint256 power = Ed25519ScalarFromUint64(1);
    for (size_t k = 0; k < share.vVssCoefficients.size(); k++)
    {
        PrivacyVNextCombineTerm term;
        term.nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
        term.scalar = Ed25519ScalarToDigest(power);
        if (!DigestFromBytes(share.vVssCoefficients[k], term.point))
        {
            Fail(pstrError, "note vote share coefficient is not a point");
            return false;
        }
        vTerms.push_back(term);
        power = Ed25519ScalarMul(power, x);
    }

    PrivacyVNextDigest expected = ZeroDigest();
    std::string error;
    if (!CombinePrivacyVNextPoints(vTerms, expected, error))
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

    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    if (!ParseNoteShareEnvelope(vote.share.vEncryptedRecipientShares[nRecipientIndex],
                                nEnvelopeRecipient, pubEphemeral, vchCiphertext))
    {
        // An envelope that does not even parse names no ephemeral key, so there is no
        // shared point to reveal and no DLEQ to make. The share itself is the evidence.
        Fail(pstrError, "note vote share envelope carries no ephemeral key to open");
        return false;
    }

    unsigned char sharedBytes[33];
    if (!ComputeSharedPoint(keyRecipient, pubEphemeral, sharedBytes))
    {
        Fail(pstrError, "note vote complaint could not derive the shared point");
        return false;
    }

    complaint.nVersion = FINALITY_NOTE_COMPLAINT_VERSION;
    complaint.nEpoch = vote.nEpoch;
    complaint.voteTag = vote.GetVoteTag();
    complaint.hashShare = vote.share.GetHash();
    complaint.nRecipientIndex = nRecipientIndex;
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
        // Anyone can see this without a proof, so the complaint stands on the share.
        return true;
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
                               std::string* pstrError)
{
    const uint256 one = Ed25519ScalarFromUint64(1);
    std::vector<PrivacyVNextCombineTerm> vActive;
    std::vector<PrivacyVNextCombineTerm> vWinning;
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
        if (!vVotes[i]->GetCTilde(term.point))
        {
            Fail(pstrError, "note tally aggregate could not read a vote commitment");
            return false;
        }
        vActive.push_back(term);
        if (vVotes[i]->hashBlock == hashWinner)
            vWinning.push_back(term);
    }

    std::string error;
    if (!CombinePrivacyVNextPoints(vActive, activeOut, error) ||
        !CombinePrivacyVNextPoints(vWinning, winningOut, error))
    {
        Fail(pstrError, "note tally aggregate could not be derived");
        return false;
    }
    return true;
}

bool GetNoteTallyTierCoefficients(int nTier, int64_t& nWinningCoeff, int64_t& nActiveCoeff)
{
    switch (nTier)
    {
    case FINALITY_HARD:
        nWinningCoeff = 3;
        nActiveCoeff = 2;
        return true;
    case FINALITY_SOFT:
        nWinningCoeff = 2;
        nActiveCoeff = 1;
        return true;
    case FINALITY_TENTATIVE:
        nWinningCoeff = 3;
        nActiveCoeff = 1;
        return true;
    default:
        return false;
    }
}

namespace
{
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
    if (!GetNoteTallyTierCoefficients(nTier, nWinningCoeff, nActiveCoeff))
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

    // a_w*D_win - a_a*D_act + (a_w*T_win - a_a*T_act)*H. The H coefficient is the tier
    // slack, which an honest tally can range-prove and an overclaimed one cannot.
    std::vector<PrivacyVNextCombineTerm> vTier(3);
    vTier[0].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vTier[0].scalar = Ed25519ScalarToDigest(Ed25519ScalarFromInt64(nWinningCoeff));
    vTier[0].point = winningPoint;
    vTier[1].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vTier[1].scalar = Ed25519ScalarToDigest(Ed25519ScalarNeg(Ed25519ScalarFromInt64(nActiveCoeff)));
    vTier[1].point = activePoint;
    vTier[2].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vTier[2].scalar = Ed25519ScalarToDigest(Ed25519ScalarSub(
        Ed25519ScalarMul(Ed25519ScalarFromInt64(nWinningCoeff),
                         Ed25519ScalarFromInt64(nTransparentWinning)),
        Ed25519ScalarMul(Ed25519ScalarFromInt64(nActiveCoeff),
                         Ed25519ScalarFromInt64(nTransparentActive))));

    // D_act - D_win keeps the winning sum under the active sum.
    std::vector<PrivacyVNextCombineTerm> vWinningCap(2);
    vWinningCap[0].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vWinningCap[0].scalar = Ed25519ScalarToDigest(one);
    vWinningCap[0].point = activePoint;
    vWinningCap[1].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vWinningCap[1].scalar = Ed25519ScalarToDigest(negOne);
    vWinningCap[1].point = winningPoint;

    // (MAX_MONEY - T_act)*H - D_act keeps the summed weights inside the int64 the tier
    // arithmetic downstream is computed in.
    std::vector<PrivacyVNextCombineTerm> vActiveCap(2);
    vActiveCap[0].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vActiveCap[0].scalar =
        Ed25519ScalarToDigest(Ed25519ScalarFromInt64(MAX_MONEY - nTransparentActive));
    vActiveCap[1].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vActiveCap[1].scalar = Ed25519ScalarToDigest(negOne);
    vActiveCap[1].point = activePoint;

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
    if (!GetNoteTallyTierCoefficients(nTier, nWinningCoeff, nActiveCoeff))
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
                           (nActiveCoeff * (nPrivateActive + nTransparentActive));
    if (nSlack < 0)
    {
        Fail(pstrError, "note tally opening does not reach the claimed tier");
        return false;
    }

    const uint256 tierBlind = Ed25519ScalarSub(
        Ed25519ScalarMul(Ed25519ScalarFromInt64(nWinningCoeff), privateWinningBlind),
        Ed25519ScalarMul(Ed25519ScalarFromInt64(nActiveCoeff), privateActiveBlind));
    const uint256 winningCapBlind =
        Ed25519ScalarSub(privateActiveBlind, privateWinningBlind);
    const uint256 activeCapBlind = Ed25519ScalarNeg(privateActiveBlind);

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
        // that simply dislikes a voter cannot drop it.
        CNoteVoteComplaint complaint;
        if (BuildNoteVoteComplaint(complaint, *pvote, config, keyMember, nMemberIndex))
            passOut.vComplaints.push_back(complaint);
    }

    passOut.fHaveActive = AggregateNoteTallyPlainShares(vActive, passOut.aggregateActive);
    passOut.fHaveWinning = AggregateNoteTallyPlainShares(vWinning, passOut.aggregateWinning);
    return true;
}

bool OpenNoteTallyAggregate(const std::vector<CNoteTallyPlainShare>& vPartials,
                            int nThreshold,
                            const PrivacyVNextDigest& expectedPoint,
                            int64_t& nWeightOut,
                            uint256& weightBlindOut,
                            int64_t& nRewardOut,
                            uint256& rewardBlindOut,
                            std::string* pstrError)
{
    uint256 weight, reward;
    if (!RecoverNoteTallySecrets(vPartials, nThreshold, weight, weightBlindOut, reward,
                                 rewardBlindOut))
    {
        Fail(pstrError, "note tally aggregate could not be interpolated");
        return false;
    }
    if (!Ed25519ScalarToMoney(weight, nWeightOut) ||
        !Ed25519ScalarToMoney(reward, nRewardOut))
    {
        Fail(pstrError, "note tally aggregate opened outside the money range");
        return false;
    }

    // The opening is only usable if it opens the point the validator recomputes. A share
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
    if (!DeriveNoteTallyAggregates(vCovered, hashWinner, activePoint, winningPoint,
                                   pstrError))
        return false;

    return CheckNoteTallyTierProofs(nTier, activePoint, winningPoint, nTransparentActive,
                                    nTransparentWinning, proofs, pstrError);
}
